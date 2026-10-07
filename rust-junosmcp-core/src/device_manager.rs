//! Connection lifecycle management with per-router session pooling.
//!
//! `DeviceManager::open()` returns a `PooledDevice` RAII guard. When the guard
//! is dropped, the underlying `rustez::Device` is returned to a single-slot
//! pool (keyed by router name) for reuse by the next caller — unless the
//! config-db was left open, in which case the session is closed instead.

use crate::error::JmcpError;
use crate::inventory::{AuthConfig, Inventory};
use arc_swap::ArcSwap;
use rustez::{Device, HostKeyVerification, SshConfigFile};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ── Pool constants ──────────────────────────────────────────────────────

const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const POOL_REAPER_INTERVAL: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Per-RPC timeout pushed into `rustez::Device` at connect time. Set high so
/// the MCP per-call `tokio::time::timeout(args.timeout, ...)` is the
/// user-visible bound. Without this, `rustez` defaults to 30 s and silently
/// truncates any long-running operational command (e.g. `request system
/// software add ...`) regardless of the MCP-side timeout.
const POOL_RPC_TIMEOUT: Duration = Duration::from_secs(3600);

/// Max connect attempts on the fresh-connect path before giving up. Covers a
/// brief reboot/transport flap (issue #83) where the device accepted us a
/// moment ago but a follow-up `open()` lands mid-blip with "No route to host"
/// / "connection refused". Long reboot waits are handled separately by
/// `upgrade_junos::wait_for_netconf`; this only absorbs short transients.
const CONNECT_MAX_ATTEMPTS: u32 = 3;

/// Fixed backoff between fresh-connect retry attempts.
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(3);

// ── Transient-error classification ──────────────────────────────────────

/// Classify whether an error string indicates a transient/stale condition
/// (peer rebooted, transport dropped, keepalive probe failed, connect blip)
/// such that the operation is worth retrying on a fresh session (issue #83).
///
/// Must NOT match genuine command/RPC/auth errors (syntax error, rpc-error,
/// permission denied, host-key mismatch, unknown router) — those are real and
/// must propagate without retry. This is the single canonical classifier;
/// `upgrade_junos::error_indicates_stale_session` delegates here.
pub(crate) fn error_is_transient(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    [
        "session expired",
        "keepalive probe failed",
        "connection closed",
        "connection reset",
        "connection refused",
        "connection failed",
        "broken pipe",
        "unexpected eof",
        "early eof",
        "channel closed",
        "session closed",
        "no route to host",
        "transport error",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Retry an async operation on transient errors with bounded attempts and a
/// fixed backoff. The op closure receives the 1-based attempt number. Returns
/// the first `Ok`, or the last `Err`. Non-transient errors short-circuit
/// immediately (no retry), so genuine failures (auth, unknown router, RPC
/// errors) still fail fast.
async fn retry_transient<F, Fut, T>(
    max_attempts: u32,
    backoff: Duration,
    mut op: F,
) -> Result<T, JmcpError>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, JmcpError>>,
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op(attempt).await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < max_attempts && error_is_transient(&err.to_string()) => {
                tracing::warn!(
                    attempt,
                    max_attempts,
                    error = %err,
                    "transient error; retrying after backoff"
                );
                tokio::time::sleep(backoff).await;
            }
            Err(err) => return Err(err),
        }
    }
}

// ── Session pool ────────────────────────────────────────────────────────

struct PoolEntry {
    device: Device,
    returned_at: Instant,
}

/// Record of a partial cleanup failure, retained until cleared by successful
/// lock acquisition or evicted after the idle timeout (#260).
#[derive(Clone)]
struct CleanupTaint {
    /// When the cleanup failure occurred.
    failed_at: Instant,
    /// Which cleanup phases failed (rollback, unlock, session close).
    phases: String,
}

struct SessionPool {
    slots: Mutex<HashMap<String, PoolEntry>>,
    /// Per-device cleanup failures. Warned on next open, cleared on successful
    /// lock acquisition. Shares the same idle timeout as the session pool.
    taints: Mutex<HashMap<String, CleanupTaint>>,
    idle_timeout: Duration,
}

impl SessionPool {
    fn new() -> Arc<Self> {
        let pool = Arc::new(Self {
            slots: Mutex::new(HashMap::new()),
            taints: Mutex::new(HashMap::new()),
            idle_timeout: POOL_IDLE_TIMEOUT,
        });
        // Spawn the reaper only if we're inside a tokio runtime
        // (unit tests using #[test] don't have one).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&pool);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(POOL_REAPER_INTERVAL);
                loop {
                    interval.tick().await;
                    let pool = match weak.upgrade() {
                        Some(p) => p,
                        None => return,
                    };
                    pool.evict_expired().await;
                }
            });
        }
        pool
    }

    async fn evict_expired(&self) {
        let mut slots = self.slots.lock().await;
        let now = Instant::now();
        let expired: Vec<String> = slots
            .iter()
            .filter(|(_, e)| now.duration_since(e.returned_at) > self.idle_timeout)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            if let Some(entry) = slots.remove(&key) {
                tokio::spawn(async move {
                    let mut d = entry.device;
                    let _ = d.close().await;
                });
            }
        }

        // Evict cleanup taints older than the idle timeout.
        let mut taints = self.taints.lock().await;
        let expired_taints: Vec<String> = taints
            .iter()
            .filter(|(_, t)| now.duration_since(t.failed_at) > self.idle_timeout)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_taints {
            taints.remove(&key);
        }
    }

    async fn try_checkout(&self, name: &str) -> Option<Device> {
        let mut slots = self.slots.lock().await;
        let entry = slots.remove(name)?;
        let now = Instant::now();
        if now.duration_since(entry.returned_at) > self.idle_timeout {
            tokio::spawn(async move {
                let mut d = entry.device;
                let _ = d.close().await;
            });
            return None;
        }
        if !entry.device.session_alive() {
            tokio::spawn(async move {
                let mut d = entry.device;
                let _ = d.close().await;
            });
            return None;
        }
        Some(entry.device)
    }

    async fn return_session(&self, name: String, dev: Device) {
        if !dev.session_alive() {
            let mut d = dev;
            let _ = d.close().await;
            return;
        }
        let mut slots = self.slots.lock().await;
        if let Some(old) = slots.insert(
            name,
            PoolEntry {
                device: dev,
                returned_at: Instant::now(),
            },
        ) {
            tokio::spawn(async move {
                let mut d = old.device;
                let _ = d.close().await;
            });
        }
    }

    async fn invalidate(&self, names: &[String]) {
        let mut slots = self.slots.lock().await;
        for name in names {
            if let Some(entry) = slots.remove(name) {
                tokio::spawn(async move {
                    let mut d = entry.device;
                    let _ = d.close().await;
                });
            }
        }
    }

    /// Record a cleanup failure for a device. The taint is cleared on successful
    /// lock acquisition or evicted after the idle timeout.
    async fn record_cleanup_taint(&self, router: &str, phases: String) {
        let mut taints = self.taints.lock().await;
        taints.insert(
            router.to_string(),
            CleanupTaint {
                failed_at: Instant::now(),
                phases,
            },
        );
    }

    /// Check for and return any existing cleanup taint for this device.
    /// Warns the caller that the device may still hold a configuration lock.
    async fn check_cleanup_taint(&self, router: &str) -> Option<CleanupTaint> {
        let taints = self.taints.lock().await;
        taints.get(router).cloned()
    }

    /// Clear any cleanup taint for this device (called after successful lock
    /// acquisition proves the device is not locked).
    async fn clear_cleanup_taint(&self, router: &str) {
        let mut taints = self.taints.lock().await;
        taints.remove(router);
    }
}

// ── PooledDevice RAII guard ─────────────────────────────────────────────

/// RAII guard that returns a NETCONF session to the pool on drop.
///
/// Derefs to `rustez::Device` for direct RPC access. When dropped, the session
/// is returned to the single-slot per-device pool for reuse by the next caller,
/// unless `reuse_allowed` is false (candidate state uncertain) or the config
/// DB is open — in which case the session is closed instead.
pub struct PooledDevice {
    dev: Option<Device>,
    router_name: String,
    pool: Arc<SessionPool>,
    reuse_allowed: bool,
}

/// How a candidate lock was given up.
///
/// The distinction is the difference between a device telling us the lock is
/// free and our inferring it from a closed socket, and it decides whether an
/// operation may be reported as reconciled (#316).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockRelease {
    /// `<unlock>` was acknowledged by the device.
    Confirmed,
    /// The session was closed instead, because its candidate was still flagged
    /// dirty. Junos frees the lock when a session ends, but rustnetconf's close
    /// is best-effort and reports success regardless, so this is an inference
    /// from our own transport being shut — not proof.
    ClosedUnverified,
}

/// Whether a session in this state may go back into the pool.
///
/// Three ways a session fails to qualify:
/// - `reuse_allowed` is false — candidate state is uncertain.
/// - The configuration database is open. A confirmed commit calls `allow_reuse`
///   without unlocking, so the flag alone can be true while the session still
///   holds the lock.
/// - The candidate is still marked dirty, so the session carries an armed
///   `<discard-changes/>` into its eventual close. That is harmless for its own
///   changes but not for whatever the shared candidate holds by the time the
///   pool evicts it (#316).
///
///   Since rustez 0.14.2 a successful `commit_with_comment` **clears** that flag
///   — it goes through rustnetconf's typed `commit_configuration_with_log`
///   rather than the raw `rpc()` path — so an attributed commit pools normally
///   again and stops costing a reconnect (#322). The guard stays because the
///   cases it was written for have not gone anywhere: a failed apply, a staged
///   session that never committed, or a rollback load all still leave the
///   candidate dirty, and those must close under the lock rather than pool.
fn should_pool(reuse_allowed: bool, config_db_open: bool, touched_candidate: bool) -> bool {
    reuse_allowed && !config_db_open && !touched_candidate
}

impl PooledDevice {
    /// Keep a session with uncertain candidate state out of the pool.
    pub(crate) fn prevent_reuse(&mut self) {
        self.reuse_allowed = false;
    }

    /// Re-enable pooling only after candidate cleanup completed successfully.
    pub(crate) fn allow_reuse(&mut self) {
        self.reuse_allowed = true;
    }

    /// Whether this session is clean enough to go back to the pool.
    ///
    /// `commit` sets it after a successful commit *and* unlock, so it doubles as
    /// "this session holds no lock and has nothing staged" — which is what tells
    /// cleanup not to force a discarding close on it (#312).
    pub(crate) fn is_reusable(&self) -> bool {
        // Same rule `Drop` applies, so "clean enough to pool" and "clean enough
        // to skip a discarding close" can never disagree.
        should_pool(
            self.reuse_allowed,
            self.dev.as_ref().is_some_and(Device::is_config_db_open),
            self.dev.as_ref().is_some_and(Device::touched_candidate),
        )
    }

    /// Close the session now, rather than leaving it to `Drop`.
    ///
    /// `Drop` can only *spawn* the close, so a caller that needs the device's
    /// configuration lock free — or its candidate discarded — before it looks
    /// again cannot rely on it (#312). Taking `self` by value leaves
    /// `Drop` nothing to do.
    pub(crate) async fn close_now(mut self) -> Result<(), JmcpError> {
        self.close_in_place().await
    }

    /// Give up the candidate lock this session holds.
    ///
    /// A session whose candidate is still flagged dirty carries an armed
    /// `<discard-changes/>` into its eventual close: rustez's
    /// `commit_with_comment` commits through the raw `rpc()` path and cannot
    /// clear rustnetconf's flag, and `rollback` sets it. Unlocking such a
    /// session and letting it live on would fire that discard later, against a
    /// candidate this operation no longer owns — on standalone Junos the
    /// candidate is shared, so what it erases is an operator's work.
    ///
    /// So a dirty session is closed here instead, while the lock is still ours:
    /// the discard can only reach what we own, and ending the session is how
    /// Junos frees a candidate lock. A clean session unlocks and becomes
    /// poolable as before (#316).
    ///
    /// The two are not equally strong, and the returned value says which
    /// happened. An `<unlock>` is acknowledged by the device. A close is not:
    /// rustnetconf's close sequence is best-effort throughout and returns `Ok`
    /// even when `<close-session/>` never lands, so the only thing it
    /// establishes is that *our* end of the transport is shut — which frees the
    /// lock on any device still reachable, and says nothing about one that is
    /// not. Callers that report a lock as released must not treat the two the
    /// same.
    ///
    /// The close is bounded by the per-phase cleanup budget. `Device::close`
    /// applies no timeout of its own — unlike rustez's config wrappers — so a
    /// peer that acknowledges the commit and then stops replying would
    /// otherwise hold this future open indefinitely, on the path every
    /// attributed commit now takes.
    ///
    /// # Errors
    ///
    /// Returns an error if the unlock failed, or if the close failed or
    /// exceeded the cleanup budget. In each case the caller has no proof the
    /// lock was released.
    pub(crate) async fn release_lock(&mut self) -> Result<LockRelease, JmcpError> {
        if self.dev.as_ref().is_some_and(Device::touched_candidate) {
            let budget = crate::tools::candidate_transaction::cleanup_timeout();
            return match tokio::time::timeout(budget, self.close_in_place()).await {
                Ok(result) => result.map(|()| LockRelease::ClosedUnverified),
                Err(_) => Err(JmcpError::Validation(format!(
                    "closing the session to release the candidate lock exceeded the {}s cleanup budget; lock state unknown",
                    budget.as_secs()
                ))),
            };
        }
        self.config()?.unlock().await?;
        self.allow_reuse();
        Ok(LockRelease::Confirmed)
    }

    /// Close the session through a mutable borrow.
    ///
    /// Callers that hold the session behind a guard cannot move out of it to
    /// call [`close_now`](Self::close_now). Afterwards the handle owns no
    /// session, so `Drop` has nothing to close or pool.
    pub(crate) async fn close_in_place(&mut self) -> Result<(), JmcpError> {
        match self.dev.take() {
            Some(mut dev) => dev.close().await.map_err(JmcpError::from),
            None => Ok(()),
        }
    }
}

impl Deref for PooledDevice {
    type Target = Device;
    fn deref(&self) -> &Device {
        self.dev.as_ref().expect("PooledDevice used after drop")
    }
}

impl DerefMut for PooledDevice {
    fn deref_mut(&mut self) -> &mut Device {
        self.dev.as_mut().expect("PooledDevice used after drop")
    }
}

impl Drop for PooledDevice {
    fn drop(&mut self) {
        if let Some(dev) = self.dev.take() {
            let Ok(handle) = tokio::runtime::Handle::try_current() else {
                return; // No runtime — session leaks but process doesn't crash
            };
            if !should_pool(
                self.reuse_allowed,
                dev.is_config_db_open(),
                dev.touched_candidate(),
            ) {
                // Candidate state is uncertain or a config DB was left open.
                if dev.touched_candidate() {
                    // Every path that gives up a lock is supposed to have
                    // released this session explicitly, under the lock, via
                    // `release_lock`. Reaching `Drop` still dirty means the
                    // discard goes out on a spawned task instead — after the
                    // call returned, against a candidate that is shared again.
                    // That is the #316 hazard re-entering by the back door, so
                    // it is logged rather than left silent.
                    tracing::warn!(
                        router = %self.router_name,
                        reuse_allowed = self.reuse_allowed,
                        config_db_open = dev.is_config_db_open(),
                        "closing a candidate-dirty session from Drop; its discard is not \
                         bounded by the lock that made it safe (#316)"
                    );
                }
                handle.spawn(async move {
                    let mut d = dev;
                    let _ = d.close().await;
                });
            } else {
                // Return to pool for reuse.
                let pool = self.pool.clone();
                let name = self.router_name.clone();
                handle.spawn(async move {
                    pool.return_session(name, dev).await;
                });
            }
        }
    }
}

// ── DeviceManager ───────────────────────────────────────────────────────

/// Device inventory and NETCONF connection pool manager.
///
/// Maintains an `Arc<Inventory>` swappable at runtime (`reload_devices`) and a
/// single-slot session pool keyed by device name. Sessions are reused when
/// clean; otherwise they are closed and a fresh connection is opened. All NETCONF
/// operations acquire a `PooledDevice` guard from `open()` or `open_fresh()`.
///
/// Cloning is cheap (shared Arc refs). Host-key verification policy is set once
/// at construction via `with_host_key_policy()` and applies to every connect.
#[derive(Clone)]
pub struct DeviceManager {
    inventory: Arc<ArcSwap<Inventory>>,
    inventory_path: Arc<ArcSwap<PathBuf>>,
    inventory_hash: Arc<ArcSwap<[u8; 32]>>,
    inventory_write_lock: Arc<Mutex<()>>,
    inventory_readonly: bool,
    allow_password_auth_add: bool,
    /// SSH host-key verification policy applied to every NETCONF connect.
    /// Defaults to `AcceptAll` for unit-test ergonomics; production callers
    /// (`main.rs`) override via [`Self::with_host_key_policy`].
    host_key_policy: HostKeyVerification,
    pool: Arc<SessionPool>,
}

impl DeviceManager {
    /// Construct a manager with the given inventory and default settings.
    ///
    /// Host-key verification defaults to `AcceptAll` for test ergonomics.
    /// Production callers must override via `with_host_key_policy()`.
    pub fn new(inventory: Arc<Inventory>) -> Self {
        Self::with_path(inventory, PathBuf::new(), [0u8; 32], false, false)
    }

    /// Construct a manager with inventory path tracking and write permissions.
    ///
    /// `path` and `hash` enable CAS checks for `add_device` / `reload_devices`.
    /// `inventory_readonly` gates write operations; `allow_password_auth_add`
    /// gates password-auth device additions.
    pub fn with_path(
        inventory: Arc<Inventory>,
        path: PathBuf,
        hash: [u8; 32],
        inventory_readonly: bool,
        allow_password_auth_add: bool,
    ) -> Self {
        Self {
            inventory: Arc::new(ArcSwap::from(inventory)),
            inventory_path: Arc::new(ArcSwap::from_pointee(path)),
            inventory_hash: Arc::new(ArcSwap::from_pointee(hash)),
            inventory_write_lock: Arc::new(Mutex::new(())),
            inventory_readonly,
            allow_password_auth_add,
            host_key_policy: HostKeyVerification::AcceptAll,
            pool: SessionPool::new(),
        }
    }

    /// Set the SSH host-key verification policy for all future connections.
    ///
    /// Production deployments should use `HostKeyVerification::KnownHosts(<path>)`
    /// (strict); lab environments may use `AcceptAll` (TOFU mode, no MITM
    /// protection). The default is `AcceptAll` for test convenience.
    pub fn with_host_key_policy(mut self, policy: HostKeyVerification) -> Self {
        self.host_key_policy = policy;
        self
    }

    /// Snapshot the current inventory.
    pub fn inventory(&self) -> Arc<Inventory> {
        self.inventory.load_full()
    }

    /// Path from which the inventory was loaded (for reload and add_device CAS).
    pub fn inventory_path(&self) -> PathBuf {
        (**self.inventory_path.load()).clone()
    }

    /// SHA-256 of the inventory file when it was last loaded. Used by
    /// `add_device` to detect concurrent modifications.
    pub fn inventory_hash(&self) -> [u8; 32] {
        **self.inventory_hash.load()
    }

    /// True if the manager was started with `--inventory-readonly`. `add_device`
    /// checks this and returns `InventoryReadonly` before attempting a write.
    pub fn inventory_readonly(&self) -> bool {
        self.inventory_readonly
    }

    /// True if password-auth devices may be added via `add_device`.
    pub fn allow_password_auth_add(&self) -> bool {
        self.allow_password_auth_add
    }

    /// Inventory write mutex. Held by `add_device` and `reload_devices` to
    /// serialize file modifications.
    pub fn write_lock(&self) -> Arc<Mutex<()>> {
        self.inventory_write_lock.clone()
    }

    /// Atomically swap the in-memory inventory and its file metadata.
    ///
    /// Called by `reload_devices` after successfully loading and parsing the
    /// new inventory. All subsequent `open()` calls see the new device set;
    /// existing pooled sessions are unaffected (invalidation is explicit).
    pub fn store_inventory(&self, inv: Arc<Inventory>, path: PathBuf, hash: [u8; 32]) {
        self.inventory.store(inv);
        self.inventory_path.store(Arc::new(path));
        self.inventory_hash.store(Arc::new(hash));
    }

    /// Close and evict pooled sessions for the named devices.
    ///
    /// Called by `reload_devices` after swapping the inventory to purge stale
    /// sessions for removed or reconfigured devices. Next `open()` for these
    /// devices will establish a fresh connection.
    pub async fn invalidate_pool(&self, names: &[String]) {
        self.pool.invalidate(names).await;
    }

    /// Record a cleanup failure for a device (#260). The taint persists until
    /// cleared by successful lock acquisition or evicted after the idle timeout.
    pub(crate) async fn record_cleanup_taint(&self, router: &str, phases: String) {
        self.pool.record_cleanup_taint(router, phases).await;
    }

    /// Check for and return any existing cleanup taint for this device.
    /// Returns None if no taint exists or if it has expired.
    pub(crate) async fn check_cleanup_taint(&self, router: &str) -> Option<String> {
        self.pool
            .check_cleanup_taint(router)
            .await
            .map(|t| t.phases)
    }

    /// Clear any cleanup taint for this device (called after successful lock
    /// acquisition proves the device is accessible).
    pub(crate) async fn clear_cleanup_taint(&self, router: &str) {
        self.pool.clear_cleanup_taint(router).await;
    }

    /// Open or reuse a NETCONF session for the named device.
    ///
    /// If a pooled session exists and is healthy, it is returned immediately.
    /// Otherwise a fresh connection is established with retry on transient
    /// errors (issue #83). Returns `UnknownRouter` if the device is not in the
    /// current inventory. The returned `PooledDevice` guard is automatically
    /// returned to the pool on drop.
    pub async fn open(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        // Try the pool first.
        if let Some(dev) = self.pool.try_checkout(router_name).await {
            tracing::debug!(router = %router_name, "reusing pooled NETCONF session");
            return Ok(PooledDevice {
                dev: Some(dev),
                router_name: router_name.to_string(),
                pool: self.pool.clone(),
                reuse_allowed: true,
            });
        }

        // No pooled session — open fresh.
        self.connect_fresh(router_name).await
    }

    /// Open a guaranteed-fresh NETCONF session, evicting any pooled entry first.
    ///
    /// Use this on the reconnect path after a pooled RPC fails with a
    /// stale-session error (keepalive probe failed, connection reset, etc.).
    /// The pooled entry is closed and a new connection is established with
    /// retry on transient errors. Returns `UnknownRouter` if the device is not
    /// in the current inventory.
    pub async fn open_fresh(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        self.pool.invalidate(&[router_name.to_string()]).await;
        self.connect_fresh(router_name).await
    }

    /// Run a Junos operational CLI command with automatic stale-session retry.
    ///
    /// Opens a pooled session and executes `command`. If the RPC fails with a
    /// transient error (session expired, keepalive probe failed, connection
    /// reset), the pooled session is dropped, a fresh one is opened, and the
    /// command is retried once. Genuine command/RPC errors (syntax error,
    /// permission denied, unknown command) are non-transient and propagate
    /// immediately. Returns the command output as a string.
    pub async fn run_cli(&self, router_name: &str, command: &str) -> Result<String, JmcpError> {
        let mut dev = self.open(router_name).await?;
        match dev.cli(command).await {
            Ok(output) => Ok(output),
            Err(err) if error_is_transient(&err.to_string()) => {
                tracing::warn!(
                    router = %router_name,
                    error = %err,
                    "pooled session stale on cli; reconnecting fresh and retrying once"
                );
                drop(dev);
                let mut fresh = self.open_fresh(router_name).await?;
                Ok(fresh.cli(command).await?)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Establish a brand-new NETCONF connection for `router_name` (no pool
    /// checkout). Shared by [`Self::open`]'s cache-miss path and
    /// [`Self::open_fresh`].
    async fn connect_fresh(&self, router_name: &str) -> Result<PooledDevice, JmcpError> {
        // Snapshot the inventory entry up front so the retry closure owns its
        // connection parameters (the ArcSwap guard must not be held across the
        // retry/backoff awaits).
        let entry = {
            let inventory = self.inventory.load();
            inventory.get(router_name)?.clone()
        };
        let policy = self.host_key_policy.clone();

        // Retry the fresh connect on transient transport errors (issue #83):
        // a reboot/transport flap can make an `open()` land mid-blip with
        // "No route to host" / "connection refused" even though the device is
        // coming back. Genuine errors (auth, ssh_config, host-key) are
        // non-transient and fail fast on the first attempt.
        let dev = retry_transient(CONNECT_MAX_ATTEMPTS, CONNECT_RETRY_BACKOFF, |_attempt| {
            let entry = entry.clone();
            let policy = policy.clone();
            async move {
                let mut builder = Device::connect(&entry.ip)
                    .port(entry.port)
                    .username(&entry.username)
                    .keepalive_interval(KEEPALIVE_INTERVAL)
                    .rpc_timeout(POOL_RPC_TIMEOUT)
                    .host_key_verification(policy);

                if let Some(ssh_config_path) = &entry.ssh_config {
                    let cfg = SshConfigFile::load(ssh_config_path).map_err(|source| {
                        JmcpError::SshConfigInvalid {
                            router: router_name.to_string(),
                            source,
                        }
                    })?;
                    let resolved = cfg.resolve(&entry.ip);
                    if !resolved.jump_hosts.is_empty() {
                        builder = builder.jump_hosts(resolved.jump_hosts);
                    }
                    if let Some(command) = resolved.proxy_command {
                        builder = builder.proxy_command(&command);
                    }
                }

                builder = match &entry.auth {
                    AuthConfig::Password { password } => builder.password(password),
                    AuthConfig::SshKey { private_key_path } => {
                        let path_str = private_key_path.to_str().ok_or_else(|| {
                            JmcpError::InventoryInvalid(format!(
                                "private_key_path is not valid UTF-8: {}",
                                private_key_path.display()
                            ))
                        })?;
                        builder.key_file(path_str)
                    }
                    AuthConfig::PasswordEnv { password_env } => {
                        // Read fresh on every connect, not cached on the
                        // entry: a cached value would survive a credential
                        // rotation until the next inventory reload, and the
                        // whole point of `PasswordEnv` is that rotating the
                        // variable (and restarting the container, or just
                        // re-running `docker run` with a new secret) takes
                        // effect without editing devices.json.
                        let secret = mecmcp_secret::load_from_env(
                            password_env,
                            mecmcp_secret::SecretLimits::default(),
                        )
                        .map_err(|e| {
                            JmcpError::InventoryInvalid(format!(
                                "router '{router_name}': reading password_env {password_env}: {e}"
                            ))
                        })?;
                        builder.password(secret.expose())
                    }
                };

                Ok(builder.open().await?)
            }
        })
        .await?;

        Ok(PooledDevice {
            dev: Some(dev),
            router_name: router_name.to_string(),
            pool: self.pool.clone(),
            reuse_allowed: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_inventory(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    use std::sync::atomic::{AtomicU32, Ordering};

    // ── should_pool: what may go back in the pool (issue #316) ──────────

    #[test]
    fn a_clean_committed_session_is_pooled() {
        assert!(should_pool(true, false, false));
    }

    #[test]
    fn an_open_config_db_is_never_pooled() {
        // A confirmed commit re-allows reuse without unlocking, so the flag
        // alone can be true while the session still holds the lock.
        assert!(!should_pool(true, true, false));
    }

    #[test]
    fn an_uncertain_candidate_is_never_pooled() {
        assert!(!should_pool(false, false, false));
    }

    /// `commit_with_comment` goes through rustez's raw `rpc()` path, which
    /// cannot clear rustnetconf's candidate-dirty flag. Pooling such a session
    /// arms a `<discard-changes/>` that fires whenever the pool later closes it
    /// — by then the shared candidate may hold an operator's edits, made after
    /// the MCP released its lock, and the discard erases them.
    #[test]
    fn a_session_that_touched_the_candidate_is_never_pooled() {
        assert!(!should_pool(true, false, true));
    }

    // ── error_is_transient classifier (issue #83) ───────────────────────

    #[test]
    fn transient_detects_no_route_to_host() {
        assert!(error_is_transient(
            "netconf error: transport error: connection failed: SSH connect to 192.168.1.233:22 failed: No route to host (os error 113)"
        ));
    }

    #[test]
    fn transient_detects_keepalive_probe_failed() {
        assert!(error_is_transient(
            "netconf error: protocol error: session expired: keepalive probe failed"
        ));
    }

    #[test]
    fn transient_detects_connection_reset_and_refused() {
        assert!(error_is_transient("Connection reset by peer"));
        assert!(error_is_transient("connect: Connection refused"));
    }

    #[test]
    fn transient_does_not_match_syntax_or_auth_errors() {
        assert!(!error_is_transient("error: syntax error, expecting <name>"));
        assert!(!error_is_transient("rpc-error: package not found"));
        assert!(!error_is_transient("Permission denied (publickey)"));
        assert!(!error_is_transient(
            "router 'r99' not found in device mapping"
        ));
        assert!(!error_is_transient(""));
    }

    // ── retry_transient bounded-backoff helper (issue #83) ───────────────

    #[tokio::test]
    async fn retry_transient_succeeds_after_two_transient_failures() {
        let calls = AtomicU32::new(0);
        let out = retry_transient(5, Duration::ZERO, |_attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n < 3 {
                    Err(JmcpError::Validation("connection refused".into()))
                } else {
                    Ok::<u32, JmcpError>(n)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(out, 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_transient_returns_immediately_on_non_transient() {
        let calls = AtomicU32::new(0);
        let res: Result<u32, JmcpError> = retry_transient(5, Duration::ZERO, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(JmcpError::UnknownRouter("r1".into())) }
        })
        .await;
        assert!(matches!(res, Err(JmcpError::UnknownRouter(_))));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not retry non-transient"
        );
    }

    #[tokio::test]
    async fn retry_transient_exhausts_attempts_on_persistent_transient() {
        let calls = AtomicU32::new(0);
        let res: Result<u32, JmcpError> = retry_transient(3, Duration::ZERO, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(JmcpError::Validation("no route to host".into())) }
        })
        .await;
        assert!(res.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3, "must stop at max_attempts");
    }

    #[test]
    fn pool_rpc_timeout_is_at_least_one_hour() {
        // POOL_RPC_TIMEOUT must comfortably exceed any plausible per-call
        // MCP timeout so that the MCP-side `tokio::time::timeout` is the
        // user-visible bound, not rustez's internal cap.
        assert!(
            POOL_RPC_TIMEOUT >= Duration::from_secs(3600),
            "POOL_RPC_TIMEOUT must be >= 1h to cover long-running ops; got {:?}",
            POOL_RPC_TIMEOUT
        );
    }

    #[tokio::test]
    async fn unknown_router_returns_unknown_router_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    // #83: open_fresh bypasses the pool but still validates inventory; an
    // unknown router must surface UnknownRouter rather than attempting a
    // connection.
    #[tokio::test]
    async fn open_fresh_unknown_router_returns_unknown_router_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open_fresh("nope").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[test]
    fn default_host_key_policy_is_accept_all() {
        // Backward-compat: `DeviceManager::new` and `with_path` default to
        // AcceptAll so the ~40 unit-test call sites don't have to plumb a
        // policy through. Production wiring (`main.rs`) overrides via
        // `.with_host_key_policy(...)`.
        let inv = build_inventory(r#"{}"#);
        let dm = DeviceManager::new(inv);
        assert!(matches!(dm.host_key_policy, HostKeyVerification::AcceptAll));
    }

    #[test]
    fn with_host_key_policy_overrides_default() {
        let inv = build_inventory(r#"{}"#);
        let dm = DeviceManager::new(inv).with_host_key_policy(HostKeyVerification::KnownHosts(
            PathBuf::from("/etc/jmcp/known_hosts"),
        ));
        match &dm.host_key_policy {
            HostKeyVerification::KnownHosts(p) => {
                assert_eq!(p, &PathBuf::from("/etc/jmcp/known_hosts"))
            }
            other => panic!("expected KnownHosts, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn ssh_config_missing_file_returns_invalid_error() {
        let inv = build_inventory(
            r#"{
            "r1":{"ip":"127.0.0.1","username":"u",
                  "ssh_config":"/nonexistent/ssh/config",
                  "auth":{"type":"password","password":"x"}}
        }"#,
        );
        let dm = DeviceManager::new(inv);
        let r = dm.open("r1").await;
        assert!(matches!(
            r,
            Err(JmcpError::SshConfigInvalid { ref router, .. }) if router == "r1"
        ));
    }

    // ── cleanup taint (#260) ────────────────────────────────────────────

    fn taint_manager() -> DeviceManager {
        DeviceManager::new(build_inventory(
            r#"{"r1":{"ip":"203.0.113.1","port":830,"username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"203.0.113.2","port":830,"username":"u","auth":{"type":"password","password":"x"}}}"#,
        ))
    }

    /// A failed cleanup must be visible to the *next* caller for that device.
    ///
    /// The whole point of #260 is that the information already existed and was
    /// dropped on the floor. Without this test, deleting the `record_cleanup_taint`
    /// call leaves the feature inert and the entire suite green — which is exactly
    /// what happened when it was first written.
    #[tokio::test]
    async fn recorded_taint_is_visible_to_the_next_caller() {
        let dm = taint_manager();
        assert_eq!(dm.check_cleanup_taint("r1").await, None, "clean to start");

        dm.record_cleanup_taint("r1", "rollback; unlock".to_owned())
            .await;

        assert_eq!(
            dm.check_cleanup_taint("r1").await,
            Some("rollback; unlock".to_owned()),
            "the next caller must learn which cleanup phases failed"
        );
    }

    /// Taint is per-device: one device's failed cleanup must not implicate another.
    #[tokio::test]
    async fn taint_does_not_leak_across_devices() {
        let dm = taint_manager();
        dm.record_cleanup_taint("r1", "unlock".to_owned()).await;
        assert_eq!(dm.check_cleanup_taint("r2").await, None);
    }

    /// Proving the device is usable clears the warning, so it is not sticky
    /// forever once the situation has resolved.
    #[tokio::test]
    async fn clearing_taint_removes_the_warning() {
        let dm = taint_manager();
        dm.record_cleanup_taint("r1", "unlock".to_owned()).await;
        dm.clear_cleanup_taint("r1").await;
        assert_eq!(dm.check_cleanup_taint("r1").await, None);
    }
}

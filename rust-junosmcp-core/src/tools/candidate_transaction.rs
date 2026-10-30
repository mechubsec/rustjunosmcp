//! Shared candidate configuration transaction lifecycle.

use crate::config_authority::JunosAuthority;
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::plane_guard::{self, AuthoritySource};
use async_trait::async_trait;
use rustez::{ConfigManager, ConfigPayload, LoadAction};
use rustnetconf::error::{NetconfError, RpcError};
use rustnetconf::types::ErrorTag;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Default budget for each cleanup phase (rollback, unlock, session close).
pub const DEFAULT_CLEANUP_TIMEOUT_SECS: u64 = 30;

/// Configured cleanup budget, in seconds. Set once at startup from the CLI.
///
/// An atomic rather than a constructor argument because this is a deployment
/// tuning knob, not per-call state: threading it through `DeviceManager` would
/// touch every call site to make one number configurable.
static CLEANUP_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(DEFAULT_CLEANUP_TIMEOUT_SECS);

/// Override the per-phase cleanup budget. Call once, before serving.
pub fn set_cleanup_timeout_secs(secs: u64) {
    CLEANUP_TIMEOUT_SECS.store(secs, Ordering::Relaxed);
}

pub(crate) fn cleanup_timeout() -> Duration {
    Duration::from_secs(CLEANUP_TIMEOUT_SECS.load(Ordering::Relaxed))
}

/// Number of per-phase cleanup budgets a single call can burn in series.
///
/// The longest chain is a failed change-set apply: the staged session close,
/// then the lock, fingerprint and unlock probes that establish whether anything
/// may be recorded (#312). The older rollback-then-unlock path spends two
/// of these; the bound has to cover the worst case, not the common one.
const CLEANUP_PHASES: u32 = 4;

/// Worst-case wall clock for one candidate transaction against `operation_timeout`.
///
/// A stalled device can burn the operation budget and then every cleanup phase
/// in series — the aggregate a client's idle timeout has to clear if it is to
/// hear the outcome rather than give up and report that the server "sent no
/// response" (#257).
#[must_use]
pub fn worst_case_duration(operation_timeout: Duration) -> Duration {
    operation_timeout + cleanup_timeout() * CLEANUP_PHASES
}

#[derive(Debug)]
pub(crate) enum CandidateMode {
    DryRun,
    CommitCheck,
    CommitWithComment(String),
    CommitConfirmed(u32),
    Discard,
}

#[derive(Debug)]
pub(crate) struct CandidateRequest {
    /// Exact MCP tool name, quoted in plane-guard refusals.
    pub(crate) tool: &'static str,
    /// `--allow-plane-owned-writes`: turns a plane-guard refusal into a warning.
    pub(crate) allow_plane_owned_writes: bool,
    pub(crate) payload: Option<ConfigPayload>,
    pub(crate) rollback_source: Option<u32>,
    pub(crate) mode: CandidateMode,
    /// Wire `action` for the `<load-configuration>` RPC when `payload` is
    /// set. Ignored when `rollback_source` is used instead — a rollback
    /// loads an archived config, not a caller-supplied payload, so it has no
    /// merge/replace/override choice to make.
    pub(crate) load_action: LoadAction,
}

/// Outcome of a commit-check. Distinguishes a genuine device rejection
/// (`Invalid`) from an inconclusive check that could not complete
/// (`CheckFailed`, e.g. the malformed multi-RE reply on chassis clusters that
/// rustnetconf cannot parse). Conflating them is a safety bug (#180).
#[derive(Debug)]
pub enum CheckOutcome {
    /// Configuration passed validation.
    Valid,
    /// Device rejected the configuration with a config-content error.
    Invalid(String),
    /// Check could not reach a verdict (parse failure, transport error, environmental RPC error).
    CheckFailed(String),
}

#[derive(Debug)]
pub(crate) enum CandidateResult {
    DryRun { diff: String },
    CommitCheck { diff: String, outcome: CheckOutcome },
    Committed { diff: String },
    CommitFailed { diff: String, error: String },
    Discarded,
}

#[async_trait]
pub(crate) trait CandidateBackend {
    async fn lock(&mut self) -> Result<(), JmcpError>;
    async fn load(&mut self, payload: ConfigPayload, action: LoadAction) -> Result<(), JmcpError>;
    async fn load_rollback(&mut self, version: u32) -> Result<(), JmcpError>;
    async fn diff(&mut self) -> Result<String, JmcpError>;
    async fn commit_check(&mut self) -> Result<(), JmcpError>;
    async fn commit_with_comment(&mut self, comment: &str) -> Result<(), JmcpError>;
    async fn commit_confirmed(&mut self, seconds: u32) -> Result<(), JmcpError>;
    async fn rollback(&mut self) -> Result<(), JmcpError>;
    async fn unlock(&mut self) -> Result<(), JmcpError>;
}

#[async_trait]
impl CandidateBackend for ConfigManager<'_> {
    async fn lock(&mut self) -> Result<(), JmcpError> {
        ConfigManager::lock(self).await.map_err(Into::into)
    }

    async fn load(&mut self, payload: ConfigPayload, action: LoadAction) -> Result<(), JmcpError> {
        ConfigManager::load_with_action(self, payload, action)
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    async fn load_rollback(&mut self, version: u32) -> Result<(), JmcpError> {
        ConfigManager::rollback(self, version)
            .await
            .map_err(Into::into)
    }

    async fn diff(&mut self) -> Result<String, JmcpError> {
        ConfigManager::diff(self)
            .await
            .map(|diff| diff.unwrap_or_default())
            .map_err(Into::into)
    }

    async fn commit_check(&mut self) -> Result<(), JmcpError> {
        ConfigManager::commit_check(self).await.map_err(Into::into)
    }

    async fn commit_with_comment(&mut self, comment: &str) -> Result<(), JmcpError> {
        ConfigManager::commit_with_comment(self, comment)
            .await
            .map_err(Into::into)
    }

    async fn commit_confirmed(&mut self, seconds: u32) -> Result<(), JmcpError> {
        ConfigManager::commit_confirmed(self, seconds)
            .await
            .map_err(Into::into)
    }

    async fn rollback(&mut self) -> Result<(), JmcpError> {
        ConfigManager::rollback(self, 0).await.map_err(Into::into)
    }

    async fn unlock(&mut self) -> Result<(), JmcpError> {
        ConfigManager::unlock(self).await.map_err(Into::into)
    }
}

struct Execution {
    result: Result<CandidateResult, JmcpError>,
    reusable: bool,
    /// Plane-guard warning from an allowed (flagged) protected change.
    warning: Option<String>,
}

#[derive(Default)]
struct CleanupFailures {
    rollback: Option<String>,
    unlock: Option<String>,
}

impl CleanupFailures {
    fn is_empty(&self) -> bool {
        self.rollback.is_none() && self.unlock.is_none()
    }
}

/// Open a device and run one complete candidate transaction. The session starts
/// tainted and is made reusable only after all required cleanup succeeds.
pub(crate) async fn run(
    dm: &DeviceManager,
    router: &str,
    request: CandidateRequest,
    timeout: Duration,
    ct: &CancellationToken,
) -> Result<(CandidateResult, Option<String>), JmcpError> {
    // Check for a prior cleanup failure and warn the caller (#260). Lock
    // acquisition failing later will prove whether the taint was real.
    if let Some(phases) = dm.check_cleanup_taint(router).await {
        tracing::warn!(
            router,
            phases,
            "a previous candidate transaction failed cleanup; \
             the device may still hold a configuration lock"
        );
    }

    // A declared authority wins; Mist is read-only, so refuse before connecting.
    let declared = dm.inventory().get(router)?.config_authority.clone();
    let mut pre_warning = None;
    if declared == JunosAuthority::Mist {
        pre_warning = plane_guard::check(
            request.tool,
            router,
            &declared,
            AuthoritySource::Declared,
            None,
            request.allow_plane_owned_writes,
        )?;
    }

    let deadline = Instant::now() + timeout;
    let mut dev = run_step(deadline, timeout, ct, dm.open(router)).await?;

    // Only an undeclared device is probed. This runs before the session is
    // tainted so a refusal hands an untouched session back to the pool.
    let (authority, source) = match run_step(deadline, timeout, ct, async {
        plane_guard::resolve_authority(&mut dev, &declared).await
    })
    .await
    {
        Ok(resolved) => resolved,
        Err(error) => {
            // A dropped or failed RPC leaves the session in an unknown state.
            dev.prevent_reuse();
            return Err(error);
        }
    };
    if authority == JunosAuthority::Mist {
        pre_warning = plane_guard::check(
            request.tool,
            router,
            &authority,
            source,
            None,
            request.allow_plane_owned_writes,
        )?;
    }
    dev.prevent_reuse();

    let execution = {
        let mut cfg = dev.config()?;
        execute(
            &mut cfg,
            router,
            (&authority, source),
            request,
            deadline,
            timeout,
            cleanup_timeout(),
            ct,
        )
        .await
    };

    if execution.reusable {
        // Cleanup succeeded and lock was acquired. The device is not locked,
        // so any prior taint was stale or resolved itself.
        dm.clear_cleanup_taint(router).await;
        dev.allow_reuse();
    } else {
        // close() takes ownership of the underlying client on its first poll,
        // so even a close-session timeout drops the transport and releases any
        // remote candidate lock before a later request opens a new session.
        match tokio::time::timeout(cleanup_timeout(), dev.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(router, error = %error, "failed to close tainted NETCONF session")
            }
            Err(_) => tracing::warn!(router, "timed out closing tainted NETCONF session"),
        }
    }

    // Record cleanup failure for the next caller if cleanup did not complete.
    // Extract the failure details from a CandidateCleanupFailed error.
    if let Err(JmcpError::CandidateCleanupFailed {
        rollback, unlock, ..
    }) = &execution.result
    {
        let mut phases = vec![];
        if rollback != "ok" {
            phases.push(format!("rollback={rollback}"));
        }
        if unlock != "ok" {
            phases.push(format!("unlock={unlock}"));
        }
        if !phases.is_empty() {
            dm.record_cleanup_taint(router, phases.join("; ")).await;
        }
    }

    let result = execution.result?;
    Ok((result, pre_warning.or(execution.warning)))
}

#[allow(clippy::too_many_arguments)]
async fn execute<B: CandidateBackend>(
    backend: &mut B,
    device: &str,
    authority: (&JunosAuthority, AuthoritySource),
    request: CandidateRequest,
    deadline: Instant,
    operation_timeout: Duration,
    cleanup_timeout: Duration,
    ct: &CancellationToken,
) -> Execution {
    // discard_candidate recovers a candidate left dirty. Junos <lock> of the
    // candidate fails with "configuration database modified" when uncommitted
    // changes exist — the exact state discard must clear — so discard must NOT
    // lock. It reverts the SHARED candidate directly with rollback 0
    // (equivalent to the CLI `configure; rollback 0; exit`) and opens no
    // private database, so the shared dirty changes are the ones cleared (#176).
    if matches!(request.mode, CandidateMode::Discard) {
        // Discarding pending edits on a plane-owned device is as much a write as
        // committing them, and without a lock it cannot be checked atomically.
        // Early returns here are not reusable: run() would read that as proof
        // cleanup succeeded and clear a recorded cleanup taint.
        let mut warning = None;
        if authority.0.is_plane_owned() {
            let diff = match run_step(deadline, operation_timeout, ct, backend.diff()).await {
                Ok(diff) => diff,
                Err(error) => {
                    return Execution {
                        result: Err(error),
                        reusable: false,
                        warning: None,
                    };
                }
            };
            if diff.trim().is_empty() {
                // Nothing pending: skip the rollback so there is no window to race.
                return Execution {
                    result: Ok(CandidateResult::Discarded),
                    reusable: false,
                    warning: None,
                };
            }
            match plane_guard::check_discard(
                request.tool,
                device,
                authority.0,
                authority.1,
                &diff,
                request.allow_plane_owned_writes,
            ) {
                Ok(found) => warning = found,
                Err(error) => {
                    return Execution {
                        result: Err(error),
                        reusable: false,
                        warning: None,
                    };
                }
            }
        }
        return match run_step(deadline, operation_timeout, ct, backend.rollback()).await {
            Ok(()) => Execution {
                result: Ok(CandidateResult::Discarded),
                reusable: true, // clean session: never locked, candidate reverted
                warning,
            },
            Err(error) => Execution {
                // Uncertain remote state (or dropped RPC): close the session.
                result: Err(error),
                reusable: false,
                warning: None,
            },
        };
    }

    let lock = run_step(deadline, operation_timeout, ct, backend.lock()).await;
    if let Err(primary) = lock {
        if matches!(primary, JmcpError::Cancelled | JmcpError::Timeout(_)) {
            // The lock RPC was dropped with an unknown remote outcome. Try the
            // full invariant, then close the uncertain protocol session.
            let cleanup = cleanup(backend, true, cleanup_timeout).await;
            return Execution {
                result: combine(Err(primary), cleanup, None),
                reusable: false,
                warning: None,
            };
        }
        return Execution {
            result: Err(primary),
            // Lock errors can include a lost response after the device took
            // the lock. Close this session instead of making that assumption.
            reusable: false,
            warning: None,
        };
    }

    let mut committed = false;
    let mut warning = None;
    let outcome = primary_operation(
        backend,
        device,
        authority,
        request,
        deadline,
        operation_timeout,
        ct,
        &mut committed,
        &mut warning,
    )
    .await;
    let reported_primary = match &outcome {
        Ok(CandidateResult::Committed { .. }) => Some("commit succeeded".into()),
        Ok(CandidateResult::CommitCheck {
            outcome: CheckOutcome::Invalid(error) | CheckOutcome::CheckFailed(error),
            ..
        })
        | Ok(CandidateResult::CommitFailed { error, .. }) => Some(error.clone()),
        _ => None,
    };
    let primary_rpc_was_dropped =
        matches!(&outcome, Err(JmcpError::Cancelled | JmcpError::Timeout(_)));
    let cleanup = cleanup(backend, !committed, cleanup_timeout).await;
    let reusable = cleanup.is_empty() && !primary_rpc_was_dropped;

    Execution {
        result: combine(outcome, cleanup, reported_primary),
        reusable,
        warning,
    }
}

#[allow(clippy::too_many_arguments)]
async fn primary_operation<B: CandidateBackend>(
    backend: &mut B,
    device: &str,
    (authority, source): (&JunosAuthority, AuthoritySource),
    request: CandidateRequest,
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
    committed: &mut bool,
    warning: &mut Option<String>,
) -> Result<CandidateResult, JmcpError> {
    // Load step: either a rollback archive or a config payload.
    if let Some(version) = request.rollback_source {
        run_step(
            deadline,
            operation_timeout,
            ct,
            backend.load_rollback(version),
        )
        .await?;
    } else {
        let action = request.load_action;
        let payload = request.payload.ok_or_else(|| {
            JmcpError::Validation("candidate transaction requires a configuration payload".into())
        })?;
        run_step(
            deadline,
            operation_timeout,
            ct,
            backend.load(payload, action),
        )
        .await?;
    }
    let diff = run_step(deadline, operation_timeout, ct, backend.diff()).await?;
    // An Err here skips every commit; execute()'s cleanup reverts and unlocks.
    *warning = plane_guard::check(
        request.tool,
        device,
        authority,
        source,
        Some(&diff),
        request.allow_plane_owned_writes,
    )?;

    match request.mode {
        CandidateMode::DryRun => Ok(CandidateResult::DryRun { diff }),
        CandidateMode::CommitCheck => {
            let outcome =
                match run_step(deadline, operation_timeout, ct, backend.commit_check()).await {
                    Ok(()) => CheckOutcome::Valid,
                    Err(error @ (JmcpError::Cancelled | JmcpError::Timeout(_))) => {
                        return Err(error);
                    }
                    Err(error) => classify_check_error(error),
                };
            Ok(CandidateResult::CommitCheck { diff, outcome })
        }
        CandidateMode::CommitWithComment(comment) => {
            ensure_active(deadline, operation_timeout, ct)?;
            // A sent commit must reach a known result. Cancellation and the
            // outer deadline are deliberately not allowed to drop this RPC.
            match backend.commit_with_comment(&comment).await {
                Ok(()) => {
                    *committed = true;
                    Ok(CandidateResult::Committed { diff })
                }
                Err(error) => Ok(CandidateResult::CommitFailed {
                    diff,
                    error: error.to_string(),
                }),
            }
        }
        CandidateMode::CommitConfirmed(seconds) => {
            ensure_active(deadline, operation_timeout, ct)?;
            match backend.commit_confirmed(seconds).await {
                Ok(()) => {
                    *committed = true;
                    Ok(CandidateResult::Committed { diff })
                }
                Err(error) => Ok(CandidateResult::CommitFailed {
                    diff,
                    error: error.to_string(),
                }),
            }
        }
        CandidateMode::Discard => {
            unreachable!("Discard is fully handled in execute() before primary_operation")
        }
    }
}

async fn cleanup<B: CandidateBackend>(
    backend: &mut B,
    rollback_required: bool,
    timeout: Duration,
) -> CleanupFailures {
    let rollback = if rollback_required {
        cleanup_step(timeout, backend.rollback()).await.err()
    } else {
        None
    };
    // Unlock is attempted even when rollback fails or times out.
    let unlock = cleanup_step(timeout, backend.unlock()).await.err();
    CleanupFailures { rollback, unlock }
}

async fn cleanup_step<F>(timeout: Duration, future: F) -> Result<(), String>
where
    F: Future<Output = Result<(), JmcpError>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => Err(format!("cleanup timed out after {timeout:?}")),
    }
}

fn combine(
    outcome: Result<CandidateResult, JmcpError>,
    cleanup: CleanupFailures,
    reported_primary: Option<String>,
) -> Result<CandidateResult, JmcpError> {
    if cleanup.is_empty() {
        return outcome;
    }

    let primary = match &outcome {
        Err(error) => error.to_string(),
        Ok(_) => reported_primary.unwrap_or_else(|| "none".into()),
    };
    Err(JmcpError::CandidateCleanupFailed {
        primary,
        rollback: cleanup.rollback.unwrap_or_else(|| "ok".into()),
        unlock: cleanup.unlock.unwrap_or_else(|| "ok".into()),
    })
}

fn ensure_active(
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
) -> Result<(), JmcpError> {
    if ct.is_cancelled() {
        return Err(JmcpError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(JmcpError::Timeout(operation_timeout));
    }
    Ok(())
}

async fn run_step<T, F>(
    deadline: Instant,
    operation_timeout: Duration,
    ct: &CancellationToken,
    future: F,
) -> Result<T, JmcpError>
where
    F: Future<Output = Result<T, JmcpError>>,
{
    ensure_active(deadline, operation_timeout, ct)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(JmcpError::Cancelled),
        result = tokio::time::timeout(remaining, future) => {
            result.map_err(|_| JmcpError::Timeout(operation_timeout))?
        }
    }
}

/// Classify a commit-check error. Only a device `<rpc-error>` carrying a
/// config-content error tag is `Invalid` (the config was genuinely rejected).
/// A parse/transport failure — including the unparseable multi-RE cluster
/// reply — or an environmental rpc-error (access/lock/resource denial,
/// unsupported op, unknown tag) is `CheckFailed`: the check could not reach a
/// verdict. Unknown → CheckFailed. Never report an inconclusive check as an
/// invalid config, and never report a genuine rejection as a validation pass
/// (#180).
pub(crate) fn classify_check_error(error: JmcpError) -> CheckOutcome {
    let JmcpError::Rustez(ref boxed) = error else {
        return CheckOutcome::CheckFailed(error.to_string());
    };
    let rustez::RustEzError::Netconf(NetconfError::Rpc(rpc)) = boxed.as_ref() else {
        return CheckOutcome::CheckFailed(error.to_string());
    };
    match rpc {
        // rustnetconf 0.16 boxed this payload into `RpcServerError` to keep the
        // error enums small; `tag` is unchanged, just one level in.
        RpcError::ServerError(server) if is_config_rejection(&server.tag) => {
            CheckOutcome::Invalid(error.to_string())
        }
        // Environmental rpc-errors, parse failures (incl. the multi-RE cluster
        // reply), timeouts, framing, etc. — the check did not reach a verdict.
        _ => CheckOutcome::CheckFailed(error.to_string()),
    }
}

/// True for NETCONF error tags that represent the device rejecting the
/// configuration CONTENT (a real commit-check "invalid" verdict), as opposed
/// to environmental/protocol failures.
fn is_config_rejection(tag: &ErrorTag) -> bool {
    matches!(
        tag,
        ErrorTag::OperationFailed
            | ErrorTag::InvalidValue
            | ErrorTag::MissingElement
            | ErrorTag::BadElement
            | ErrorTag::UnknownElement
            | ErrorTag::MissingAttribute
            | ErrorTag::BadAttribute
            | ErrorTag::UnknownAttribute
            | ErrorTag::DataMissing
            | ErrorTag::DataExists
    )
    // Everything else (AccessDenied, LockDenied, ResourceDenied,
    // OperationNotSupported, InUse, TooBig, MalformedMessage, RollbackFailed,
    // UnknownNamespace, Other) → not a config verdict → CheckFailed.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum Op {
        Lock,
        Load,
        Diff,
        Check,
        Commit,
        Rollback,
        Unlock,
    }

    #[derive(Default)]
    struct DeviceState {
        locked: bool,
        dirty: bool,
        events: Vec<Op>,
        last_rollback_version: Option<u32>,
        last_load_action: Option<LoadAction>,
    }

    struct FakeBackend {
        state: Arc<Mutex<DeviceState>>,
        failures: HashSet<Op>,
        hang: Option<Op>,
        diff: String,
    }

    impl FakeBackend {
        fn new(state: Arc<Mutex<DeviceState>>) -> Self {
            Self {
                state,
                failures: HashSet::new(),
                hang: None,
                diff: "fake diff".into(),
            }
        }

        fn with_diff(mut self, diff: &str) -> Self {
            self.diff = diff.into();
            self
        }

        fn failing(mut self, operations: &[Op]) -> Self {
            self.failures.extend(operations.iter().copied());
            self
        }

        fn hanging(mut self, operation: Op) -> Self {
            self.hang = Some(operation);
            self
        }

        async fn operation(&mut self, operation: Op) -> Result<(), JmcpError> {
            self.state.lock().unwrap().events.push(operation);
            if self.hang == Some(operation) {
                std::future::pending::<()>().await;
            }
            if self.failures.contains(&operation) {
                return Err(JmcpError::Validation(format!(
                    "injected {operation:?} failure"
                )));
            }
            Ok(())
        }

        fn close_tainted_session(&mut self) {
            let mut state = self.state.lock().unwrap();
            state.locked = false;
            state.dirty = false;
        }
    }

    #[async_trait]
    impl CandidateBackend for FakeBackend {
        async fn lock(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Lock).await?;
            let mut state = self.state.lock().unwrap();
            if state.locked {
                return Err(JmcpError::Validation("candidate already locked".into()));
            }
            state.locked = true;
            Ok(())
        }

        async fn load(
            &mut self,
            _payload: ConfigPayload,
            action: LoadAction,
        ) -> Result<(), JmcpError> {
            // Model a partial load: even a failed load can dirty candidate state.
            {
                let mut state = self.state.lock().unwrap();
                state.dirty = true;
                state.last_load_action = Some(action);
            }
            self.operation(Op::Load).await
        }

        async fn load_rollback(&mut self, version: u32) -> Result<(), JmcpError> {
            // Rollback also dirties the candidate (loads archived config).
            {
                let mut state = self.state.lock().unwrap();
                state.dirty = true;
                state.last_rollback_version = Some(version);
            }
            self.operation(Op::Load).await
        }

        async fn diff(&mut self) -> Result<String, JmcpError> {
            self.operation(Op::Diff).await?;
            Ok(self.diff.clone())
        }

        async fn commit_check(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Check).await
        }

        async fn commit_with_comment(&mut self, _comment: &str) -> Result<(), JmcpError> {
            self.operation(Op::Commit).await?;
            self.state.lock().unwrap().dirty = false;
            Ok(())
        }

        async fn commit_confirmed(&mut self, _seconds: u32) -> Result<(), JmcpError> {
            self.commit_with_comment("").await
        }

        async fn rollback(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Rollback).await?;
            self.state.lock().unwrap().dirty = false;
            Ok(())
        }

        async fn unlock(&mut self) -> Result<(), JmcpError> {
            self.operation(Op::Unlock).await?;
            self.state.lock().unwrap().locked = false;
            Ok(())
        }
    }

    fn commit_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            rollback_source: None,
            mode: CandidateMode::CommitWithComment("test".into()),
            load_action: LoadAction::Set,
            tool: "load_and_commit_config",
            allow_plane_owned_writes: false,
        }
    }

    fn check_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            rollback_source: None,
            mode: CandidateMode::CommitCheck,
            load_action: LoadAction::Set,
            tool: "load_and_commit_config",
            allow_plane_owned_writes: false,
        }
    }

    fn dry_run_request() -> CandidateRequest {
        CandidateRequest {
            payload: Some(ConfigPayload::Set("set system host-name test".into())),
            rollback_source: None,
            mode: CandidateMode::DryRun,
            load_action: LoadAction::Set,
            tool: "load_and_commit_config",
            allow_plane_owned_writes: false,
        }
    }

    fn discard_request() -> CandidateRequest {
        CandidateRequest {
            payload: None,
            rollback_source: None,
            mode: CandidateMode::Discard,
            load_action: LoadAction::Merge,
            tool: "load_and_commit_config",
            allow_plane_owned_writes: false,
        }
    }

    /// `CandidateRequest::load_action` must reach the backend's `load()` call
    /// unchanged — this is the one hop between a resolved `mode` and the wire
    /// `<load-configuration action=…>` attribute rustez sends.
    #[tokio::test]
    async fn requested_load_action_reaches_the_backend() {
        for action in [LoadAction::Merge, LoadAction::Replace, LoadAction::Override] {
            let state = Arc::new(Mutex::new(DeviceState::default()));
            let mut backend = FakeBackend::new(state.clone());
            let mut request = commit_request();
            request.load_action = action;
            let execution = run_fake(
                &mut backend,
                request,
                Duration::from_secs(1),
                Duration::from_millis(50),
                &CancellationToken::new(),
            )
            .await;
            assert!(execution.result.is_ok());
            assert_eq!(state.lock().unwrap().last_load_action, Some(action));
        }
    }

    async fn run_fake(
        backend: &mut FakeBackend,
        request: CandidateRequest,
        timeout: Duration,
        cleanup_timeout: Duration,
        ct: &CancellationToken,
    ) -> Execution {
        run_fake_as(
            backend,
            (&JunosAuthority::Local, AuthoritySource::Declared),
            request,
            timeout,
            cleanup_timeout,
            ct,
        )
        .await
    }

    async fn run_fake_as(
        backend: &mut FakeBackend,
        authority: (&JunosAuthority, AuthoritySource),
        request: CandidateRequest,
        timeout: Duration,
        cleanup_timeout: Duration,
        ct: &CancellationToken,
    ) -> Execution {
        execute(
            backend,
            "srx1",
            authority,
            request,
            Instant::now() + timeout,
            timeout,
            cleanup_timeout,
            ct,
        )
        .await
    }

    async fn assert_next_operation_can_lock(
        backend: &mut FakeBackend,
        execution: &Execution,
        state: Arc<Mutex<DeviceState>>,
    ) {
        if !execution.reusable {
            // Production does this by closing, rather than pooling, the tainted
            // PooledDevice. Closing a NETCONF session releases its lock.
            backend.close_tainted_session();
        }
        let mut next = FakeBackend::new(state);
        // Use dry_run as the probe: discard no longer locks, so it would not
        // verify that the lock is available. dry_run locks/unlocks like other
        // locking operations.
        let result = run_fake(
            &mut next,
            dry_run_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;
        assert!(result.result.is_ok(), "next operation failed to lock");
    }

    #[tokio::test]
    async fn load_and_diff_failures_rollback_unlock_and_allow_next_lock() {
        for failed in [Op::Load, Op::Diff] {
            let state = Arc::new(Mutex::new(DeviceState::default()));
            let mut backend = FakeBackend::new(state.clone()).failing(&[failed]);
            let execution = run_fake(
                &mut backend,
                commit_request(),
                Duration::from_secs(1),
                Duration::from_millis(50),
                &CancellationToken::new(),
            )
            .await;

            assert!(execution.result.is_err());
            assert!(execution.reusable);
            let events = state.lock().unwrap().events.clone();
            assert!(events.ends_with(&[Op::Rollback, Op::Unlock]));
            assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
        }
    }

    #[tokio::test]
    async fn check_failure_is_reported_after_cleanup_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Check]);
        let execution = run_fake(
            &mut backend,
            check_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        match &execution.result {
            Ok(CandidateResult::CommitCheck {
                outcome: CheckOutcome::CheckFailed(error),
                ..
            }) => {
                // The injected error ("injected Check failure") contains neither
                // "failed to parse RPC response" nor "server error", so
                // classify_check_error correctly returns CheckFailed (conservative
                // default, treating the injected failure as inconclusive).
                assert!(error.contains("injected Check failure"))
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(
            state
                .lock()
                .unwrap()
                .events
                .ends_with(&[Op::Rollback, Op::Unlock])
        );
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn commit_failure_preserves_primary_and_cleanup_failure() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Commit, Op::Rollback]);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("primary=validation error: injected Commit failure"));
        assert!(error.contains("rollback=validation error: injected Rollback failure"));
        assert!(error.contains("unlock=ok"));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn successful_commit_is_never_rolled_back_and_unlock_failure_is_an_error() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Unlock]);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("primary=commit succeeded"));
        assert!(error.contains("unlock=validation error: injected Unlock failure"));
        assert!(!state.lock().unwrap().events.contains(&Op::Rollback));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn rollback_timeout_still_attempts_unlock_and_taints_session() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Rollback);
        let execution = run_fake(
            &mut backend,
            dry_run_request(),
            Duration::from_secs(1),
            Duration::from_millis(10),
            &CancellationToken::new(),
        )
        .await;

        let error = execution.result.as_ref().unwrap_err().to_string();
        assert!(error.contains("rollback=cleanup timed out"));
        assert!(state.lock().unwrap().events.contains(&Op::Unlock));
        assert!(!execution.reusable);
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn primary_timeout_rolls_back_unlocks_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Diff);
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_millis(10),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        assert!(matches!(execution.result, Err(JmcpError::Timeout(_))));
        assert!(!execution.reusable);
        assert!(
            state
                .lock()
                .unwrap()
                .events
                .ends_with(&[Op::Rollback, Op::Unlock])
        );
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn cancellation_rolls_back_unlocks_and_allows_next_lock() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).hanging(Op::Diff);
        let ct = CancellationToken::new();
        let cancel = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let execution = run_fake(
            &mut backend,
            commit_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &ct,
        )
        .await;

        assert!(matches!(execution.result, Err(JmcpError::Cancelled)));
        assert!(!execution.reusable);
        assert!(
            state
                .lock()
                .unwrap()
                .events
                .ends_with(&[Op::Rollback, Op::Unlock])
        );
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn discard_reverts_dirty_candidate_without_locking() {
        let state = Arc::new(Mutex::new(DeviceState {
            dirty: true,
            ..Default::default()
        }));
        let mut backend = FakeBackend::new(state.clone());
        let execution = run_fake(
            &mut backend,
            discard_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        assert!(matches!(execution.result, Ok(CandidateResult::Discarded)));
        assert!(execution.reusable);
        let events = state.lock().unwrap().events.clone();
        assert_eq!(events, vec![Op::Rollback]);
        assert!(!events.contains(&Op::Lock));
        assert!(!events.contains(&Op::Unlock));
        assert!(!state.lock().unwrap().dirty);
    }

    async fn run_discard_as(
        authority: JunosAuthority,
        diff: &str,
        allow: bool,
    ) -> (Execution, Arc<Mutex<DeviceState>>) {
        let state = Arc::new(Mutex::new(DeviceState {
            dirty: true,
            ..Default::default()
        }));
        let mut backend = FakeBackend::new(state.clone()).with_diff(diff);
        let mut request = discard_request();
        request.allow_plane_owned_writes = allow;
        let execution = run_fake_as(
            &mut backend,
            (&authority, AuthoritySource::Declared),
            request,
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;
        (execution, state)
    }

    #[tokio::test]
    async fn sd_discard_of_pending_security_edits_is_refused_untouched() {
        let (execution, state) =
            run_discard_as(JunosAuthority::SecurityDirectorCloud, SECURITY_DIFF, false).await;
        assert!(matches!(
            execution.result,
            Err(JmcpError::PlaneManagedConfig { .. })
        ));
        assert!(
            !execution.reusable,
            "a refusal must not read as cleanup proof"
        );
        assert_eq!(state.lock().unwrap().events, vec![Op::Diff]);
        assert!(state.lock().unwrap().dirty, "pending edits must survive");
    }

    /// Discard cannot lock, so the diff could change before rollback runs:
    /// any pending change is refused, not just a protected one.
    #[tokio::test]
    async fn sd_discard_of_unprotected_pending_edits_is_refused_untouched() {
        let (execution, state) =
            run_discard_as(JunosAuthority::SecurityDirectorCloud, INTERFACE_DIFF, false).await;
        assert!(matches!(
            execution.result,
            Err(JmcpError::PlaneManagedConfig { .. })
        ));
        assert!(!execution.reusable);
        assert_eq!(state.lock().unwrap().events, vec![Op::Diff]);
        assert!(state.lock().unwrap().dirty);
    }

    #[tokio::test]
    async fn sd_discard_of_clean_candidate_skips_rollback() {
        let (execution, state) =
            run_discard_as(JunosAuthority::SecurityDirectorCloud, "", false).await;
        assert!(matches!(execution.result, Ok(CandidateResult::Discarded)));
        assert!(
            !execution.reusable,
            "no cleanup ran, so no taint is cleared"
        );
        assert_eq!(state.lock().unwrap().events, vec![Op::Diff]);
    }

    #[tokio::test]
    async fn sd_discard_of_unprotected_edits_with_flag_reverts_and_warns() {
        let (execution, state) =
            run_discard_as(JunosAuthority::SecurityDirectorCloud, INTERFACE_DIFF, true).await;
        assert!(matches!(execution.result, Ok(CandidateResult::Discarded)));
        assert!(
            execution.warning.is_some(),
            "the waived refusal must be visible"
        );
        assert_eq!(state.lock().unwrap().events, vec![Op::Diff, Op::Rollback]);
    }

    #[tokio::test]
    async fn sd_discard_of_security_edits_with_flag_reverts_and_warns() {
        let (execution, state) =
            run_discard_as(JunosAuthority::SecurityDirectorOnprem, SECURITY_DIFF, true).await;
        assert!(matches!(execution.result, Ok(CandidateResult::Discarded)));
        assert!(execution.warning.is_some());
        assert!(!state.lock().unwrap().dirty);
    }

    #[tokio::test]
    async fn discard_succeeds_even_when_lock_would_fail() {
        // Regression guard for #176: prove discard works when lock would fail
        // (dirty candidate causes "configuration database modified" from lock).
        let state = Arc::new(Mutex::new(DeviceState {
            dirty: true,
            ..Default::default()
        }));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Lock]);
        let execution = run_fake(
            &mut backend,
            discard_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        assert!(matches!(execution.result, Ok(CandidateResult::Discarded)));
        let events = state.lock().unwrap().events.clone();
        assert!(!events.contains(&Op::Lock), "discard must not call lock");
        assert!(!state.lock().unwrap().dirty);
    }

    #[tokio::test]
    async fn discard_rollback_failure_taints_session() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).failing(&[Op::Rollback]);
        let execution = run_fake(
            &mut backend,
            discard_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        assert!(execution.result.is_err());
        assert!(!execution.reusable);
    }

    fn rustez_rpc_error(rpc: RpcError) -> JmcpError {
        JmcpError::Rustez(Box::new(rustez::RustEzError::Netconf(NetconfError::Rpc(
            rpc,
        ))))
    }

    fn server_error(tag: ErrorTag, message: &str) -> JmcpError {
        rustez_rpc_error(RpcError::ServerError(Box::new(
            rustnetconf::error::RpcServerError {
                error_type: None,
                tag,
                severity: None,
                app_tag: None,
                path: None,
                message: message.into(),
                info: None,
            },
        )))
    }

    #[test]
    fn classify_parse_error_is_check_failed() {
        // The real multi-RE cluster failure type.
        let error = rustez_rpc_error(RpcError::ParseError(
            "XML parse error: ill-formed document: expected `</routing-engine>`, but `</nc:rpc-reply>` was found".into()
        ));
        match classify_check_error(error) {
            CheckOutcome::CheckFailed(msg) => {
                assert!(msg.contains("failed to parse RPC response"));
            }
            other => panic!("expected CheckFailed, got {other:?}"),
        }
    }

    #[test]
    fn classify_config_rejection_is_invalid() {
        let error = server_error(ErrorTag::OperationFailed, "syntax error");
        match classify_check_error(error) {
            CheckOutcome::Invalid(msg) => {
                assert!(msg.contains("syntax error"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn classify_environmental_server_error_is_check_failed() {
        // Regression guard: env errors (AccessDenied) are NOT config rejections.
        let error = server_error(ErrorTag::AccessDenied, "permission denied");
        match classify_check_error(error) {
            CheckOutcome::CheckFailed(msg) => {
                assert!(msg.contains("permission denied"));
            }
            other => panic!("expected CheckFailed (not Invalid), got {other:?}"),
        }
    }

    #[test]
    fn classify_non_rustez_error_is_check_failed() {
        let error = JmcpError::Validation("boom".into());
        match classify_check_error(error) {
            CheckOutcome::CheckFailed(msg) => {
                assert!(msg.contains("boom"));
            }
            other => panic!("expected CheckFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rollback_preview_loads_diffs_discards_and_is_reusable() {
        // Preview path (DryRun, rollback_source: Some(3)): loads rollback 3, diffs,
        // cleanup discards (rollback 0), unlocks. Session is reusable.
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone());
        let execution = run_fake(
            &mut backend,
            CandidateRequest {
                payload: None,
                rollback_source: Some(3),
                mode: CandidateMode::DryRun,
                load_action: LoadAction::Merge,
                tool: "rollback_config",
                allow_plane_owned_writes: false,
            },
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        // Result is DryRun with diff, session reusable.
        match &execution.result {
            Ok(CandidateResult::DryRun { diff }) => {
                assert_eq!(diff, "fake diff");
            }
            other => panic!("expected DryRun result, got {other:?}"),
        }
        assert!(execution.reusable);

        // Event sequence: Lock, Load (rollback 3), Diff, Rollback (cleanup), Unlock.
        let events = state.lock().unwrap().events.clone();
        assert_eq!(
            events,
            vec![Op::Lock, Op::Load, Op::Diff, Op::Rollback, Op::Unlock]
        );

        // Verify rollback version 3 was loaded.
        assert_eq!(state.lock().unwrap().last_rollback_version, Some(3));

        // Session is clean; next operation can lock.
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    #[tokio::test]
    async fn rollback_commit_loads_commits_no_cleanup_rollback() {
        // Commit path (CommitWithComment, rollback_source: Some(2)): loads rollback 2,
        // diffs, commits. NO cleanup rollback (committed=true). Unlock still happens.
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone());
        let execution = run_fake(
            &mut backend,
            CandidateRequest {
                payload: None,
                rollback_source: Some(2),
                mode: CandidateMode::CommitWithComment("rollback to 2".into()),
                load_action: LoadAction::Merge,
                tool: "rollback_config",
                allow_plane_owned_writes: false,
            },
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;

        // Result is Committed with diff, session reusable.
        match &execution.result {
            Ok(CandidateResult::Committed { diff }) => {
                assert_eq!(diff, "fake diff");
            }
            other => panic!("expected Committed result, got {other:?}"),
        }
        assert!(execution.reusable);

        // Event sequence: Lock, Load (rollback 2), Diff, Commit, Unlock.
        // NO Rollback in the sequence (committed=true means no cleanup rollback).
        let events = state.lock().unwrap().events.clone();
        assert_eq!(
            events,
            vec![Op::Lock, Op::Load, Op::Diff, Op::Commit, Op::Unlock]
        );
        assert!(
            !events.contains(&Op::Rollback),
            "successful commit must not rollback"
        );

        // Verify rollback version 2 was loaded.
        assert_eq!(state.lock().unwrap().last_rollback_version, Some(2));

        // Session is clean; next operation can lock.
        assert_next_operation_can_lock(&mut backend, &execution, state.clone()).await;
    }

    const SECURITY_DIFF: &str = "[edit security nat source]\n+   rule-set rs1;";
    const INTERFACE_DIFF: &str = "[edit interfaces ge-0/0/0]\n+   description x;";

    async fn run_commit_as(
        authority: JunosAuthority,
        diff: &str,
        allow: bool,
    ) -> (Execution, Arc<Mutex<DeviceState>>) {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).with_diff(diff);
        let mut request = commit_request();
        request.allow_plane_owned_writes = allow;
        let execution = run_fake_as(
            &mut backend,
            (&authority, AuthoritySource::Declared),
            request,
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;
        (execution, state)
    }

    #[tokio::test]
    async fn sd_security_diff_is_refused_reverted_and_never_committed() {
        let (execution, state) =
            run_commit_as(JunosAuthority::SecurityDirectorCloud, SECURITY_DIFF, false).await;
        assert!(matches!(
            execution.result,
            Err(JmcpError::PlaneManagedConfig { .. })
        ));
        assert!(execution.reusable, "cleanup succeeded, session is clean");
        let events = state.lock().unwrap().events.clone();
        assert!(!events.contains(&Op::Commit));
        assert!(events.ends_with(&[Op::Rollback, Op::Unlock]));
        assert!(!state.lock().unwrap().dirty);
    }

    #[tokio::test]
    async fn sd_non_security_diff_commits() {
        let (execution, state) =
            run_commit_as(JunosAuthority::SecurityDirectorCloud, INTERFACE_DIFF, false).await;
        assert!(matches!(
            execution.result,
            Ok(CandidateResult::Committed { .. })
        ));
        assert!(execution.warning.is_none());
        assert!(state.lock().unwrap().events.contains(&Op::Commit));
    }

    #[tokio::test]
    async fn sd_security_diff_with_flag_commits_and_warns() {
        let (execution, state) =
            run_commit_as(JunosAuthority::SecurityDirectorOnprem, SECURITY_DIFF, true).await;
        assert!(matches!(
            execution.result,
            Ok(CandidateResult::Committed { .. })
        ));
        assert!(execution.warning.as_deref().unwrap().contains("WARNING"));
        assert!(state.lock().unwrap().events.contains(&Op::Commit));
    }

    #[tokio::test]
    async fn local_security_diff_commits_without_warning() {
        let (execution, _) = run_commit_as(JunosAuthority::Local, SECURITY_DIFF, false).await;
        assert!(matches!(
            execution.result,
            Ok(CandidateResult::Committed { .. })
        ));
        assert!(execution.warning.is_none());
    }

    #[tokio::test]
    async fn sd_security_diff_is_refused_in_dry_run_too() {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let mut backend = FakeBackend::new(state.clone()).with_diff(SECURITY_DIFF);
        let execution = run_fake_as(
            &mut backend,
            (
                &JunosAuthority::SecurityDirectorCloud,
                AuthoritySource::Detected,
            ),
            dry_run_request(),
            Duration::from_secs(1),
            Duration::from_millis(50),
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(
            execution.result,
            Err(JmcpError::PlaneManagedConfig { .. })
        ));
    }
}

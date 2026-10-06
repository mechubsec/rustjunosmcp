//! Junos implementation of `mecmcp_changeset::DeviceTransaction`.
//!
//! This module wraps the existing device manager and rustez primitives to
//! provide the change-set lifecycle (fingerprint → stage → diff → validate →
//! commit) for Junos devices.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::build_config_payload;
use crate::tools::candidate_transaction::CheckOutcome;
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Junos-specific action: a config payload or a rollback archive reference.
// Security note for maintainers: `deny_unknown_fields` is load-bearing. Both
// fields are `Option`, so `{}` is structurally valid; without the attribute, a
// mistyped field name would be silently dropped, producing an empty approved
// change set that only fails at apply (#254).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JunosAction {
    /// Configuration payload to load. Exactly one of `payload` or
    /// `rollback_source` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ConfigPayloadSpec>,
    /// Rollback archive version (0..=49). Junos loads rollback N and diffs it.
    /// Exactly one of `payload` or `rollback_source` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_source: Option<u32>,
    /// Commit-0 attribution binding for a guarded plane-owned
    /// `rollback_source: 1` (MEC-1880, P5b TOCTOU binding, §5.5).
    ///
    /// **Reserved: server-computed only.** `create_junos_change_set` rejects
    /// any caller-supplied value outright before this field is ever trusted.
    /// It exists on the wire type only because the change-set plan is stored
    /// and re-read as this same type, and the approval digest must cover it —
    /// a caller allowed to set it directly could forge the server's own
    /// commit-0 classification and defeat the TOCTOU re-check this binding
    /// exists for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit0: Option<crate::commit_attribution::CommitZeroBinding>,
}

impl Default for JunosAction {
    /// All-`None` default, so existing test literals that predate `commit0`
    /// can opt in with `..Default::default()` instead of being rewritten one
    /// by one.
    fn default() -> Self {
        Self {
            payload: None,
            rollback_source: None,
            commit0: None,
        }
    }
}

impl JunosAction {
    /// Enforce the "exactly one of `payload` or `rollback_source`" invariant the
    /// field docs state.
    ///
    /// Serde cannot express it — both fields are `Option` — so it is checked
    /// here and called from `create_junos_change_set` before anything is
    /// persisted, digested, or approved. The equivalent check at apply time
    /// stays as defence in depth; this one makes it unreachable through the
    /// public API (#254).
    ///
    /// `index` is the caller's position in the `actions` array and appears in
    /// the message, since that is what the caller can act on.
    ///
    /// # Errors
    ///
    /// Returns a description of the violation when neither or both fields are
    /// set.
    pub fn validate_shape(&self, index: usize) -> Result<(), String> {
        match (&self.payload, self.rollback_source) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err(format!(
                "action {index} has neither `payload` nor `rollback_source`; \
                 exactly one is required. If you meant to load configuration, \
                 the field is `payload`, an object of the form \
                 {{\"text\": \"<config>\", \"format\": \"set\"|\"text\"|\"xml\"}}"
            )),
            (Some(_), Some(_)) => Err(format!(
                "action {index} sets both `payload` and `rollback_source`; \
                 exactly one is required"
            )),
        }
    }
}

/// Configuration text and format for loading into the Junos candidate.
// Security note for maintainers: `deny_unknown_fields` is load-bearing. A
// mistyped key would be silently dropped, producing a structurally valid but
// semantically wrong payload that passes staging and only fails at apply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigPayloadSpec {
    /// Configuration text to load into the Junos candidate database.
    pub text: String,
    /// Format: "set", "text", or "xml". Defaults to "set" if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Load mode: "merge" (default), "replace", or "override". `override`
    /// replaces the entire candidate configuration; it is permitted here
    /// (and only here) because a change set requires approval by a second
    /// principal — `create_junos_change_set` → `approve_junos_change_set` →
    /// `apply_junos_change_set` — before anything commits (MEC-12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// Opaque staged-transaction handle retaining the session and lock until commit or discard.
///
/// On a chassis cluster, `cfg.load()` auto-opens a *private* configuration
/// database that is destroyed when the session unlocks. To preserve the staged
/// candidate across validate and commit, this handle retains the session and its
/// lock until commit or discard. The session is marked non-reusable and will be
/// closed (not pooled) on drop unless `allow_reuse` is called after a successful
/// commit.
pub struct JunosStagedTransaction {
    /// Device name for the pool.
    #[allow(dead_code)] // Kept for potential future use; session carries the connection.
    router: String,
    /// Diff captured during load.
    diff: String,
    /// Private database session. Retained until commit/discard so validate and
    /// commit see the same candidate. The session is marked non-reusable; it
    /// will be closed (not pooled) on drop.
    ///
    /// Uses tokio::sync::Mutex for interior mutability because the trait signature
    /// passes `&Staged` (immutable), but we need mutable access to call `.config()`.
    /// tokio::sync::Mutex is used (not std::sync::Mutex) because the guard must
    /// be held across `.await` points.
    session: tokio::sync::Mutex<Option<crate::device_manager::PooledDevice>>,
}

/// A staged handle whose device session can be released on demand.
///
/// # Contract
///
/// `release` must leave the device with **no staged candidate and no lock held**
/// by this handle, and report whether it confirmed that. On Junos both fall out
/// of closing the session: rustnetconf's `CloseSequence::DiscardThenClose` sends
/// `<discard-changes/>` before `<close-session/>`, and Junos frees a candidate
/// lock when the session holding it closes.
///
/// Callers rely on that to settle a record without touching the device again,
/// so an implementation that cannot guarantee it must return `false` rather
/// than assume (#312).
#[async_trait]
pub trait ReleaseStaged {
    /// Release the session, returning `true` if the close completed.
    ///
    /// Never fails the caller: this is cleanup on a path already returning an
    /// error. `false` means the device state is unknown, not that anything else
    /// went wrong.
    async fn release(&self) -> bool;
}

#[async_trait]
impl ReleaseStaged for JunosStagedTransaction {
    async fn release(&self) -> bool {
        let Some(session) = self.session.lock().await.take() else {
            // Already released, or `stage()` never handed the session over.
            // Either way this handle holds nothing.
            return true;
        };

        // A session that committed cleanly released its lock in `commit` — by
        // closing, since `commit_with_comment` leaves the candidate flagged
        // dirty (#316) — so this handle owns nothing to clean up. Forcing a
        // close on a session that had unlocked and been pooled would send
        // `<discard-changes/>` against a candidate this operation no longer
        // owns, which on a standalone device can wipe edits another session made
        // after that unlock. This is the path where the device committed but the
        // coordinator's own state write then failed.
        if session.is_reusable() {
            drop(session);
            return true;
        }

        // Bounded by the same per-phase budget as rollback and unlock. The close
        // is three RPCs — close-configuration, discard-changes, close-session —
        // each carrying the device's own RPC timeout, which is measured in
        // hours. A black-holed peer would otherwise hold a handler that is
        // already returning an error for far longer than the cleanup budget.
        //
        // Awaiting rather than dropping is the point: `PooledDevice::drop` can
        // only *spawn* the close, so a dropped handle frees the lock at some
        // later moment the caller cannot observe.
        match tokio::time::timeout(
            crate::tools::candidate_transaction::cleanup_timeout(),
            session.close_now(),
        )
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!(
                    error = %error,
                    "failed to close the staged session; the candidate may still be staged \
                     and its configuration lock held"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    "timed out closing the staged session; the candidate may still be staged \
                     and its configuration lock held"
                );
                false
            }
        }
    }
}

/// Diff output: the text diff from Junos showing staged changes.
///
/// Captures the output of `show | compare` as reported by the device. Used by
/// the change-set diff primitive to show callers what will be committed.
#[derive(Debug, Clone, Serialize)]
pub struct JunosDiff {
    /// Text diff showing candidate vs committed configuration.
    pub diff: String,
}

/// Validation result from Junos `commit check`.
///
/// Reports whether the staged candidate passes Junos validation. A `valid: false`
/// result carries the device's rejection message. A check failure (timeout,
/// parse error, multi-RE cluster reply) is not a validation result and returns
/// an error instead.
#[derive(Debug, Clone, Serialize)]
pub struct JunosValidation {
    /// Whether the candidate configuration passed `commit check`.
    pub valid: bool,
    /// Junos validation error details. Set only when `valid` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Junos transaction context implementing the change-set lifecycle.
///
/// Implements [`DeviceTransaction`] by delegating to rustez primitives and the
/// device manager. Holds a locked session between `lock()` and `stage()` to close
/// the fingerprint-to-stage window (mecmcp#60, #80). The session is transferred to
/// the staged handle when staging completes, so validate and commit operate on the
/// same private candidate database (chassis cluster requirement).
pub struct JunosTransaction {
    device_manager: Arc<DeviceManager>,
    router: String,
    /// Session holding the candidate lock between `lock()` and `stage()`.
    ///
    /// A Junos candidate lock belongs to the NETCONF session that took it, so
    /// closing the session releases it. To hold the lock across the coordinator's
    /// fingerprint-read the transaction has to keep that session alive, which is
    /// why it lives here rather than as a local in `stage()` (mecmcp#60, #80).
    ///
    /// `stage()` *takes* the session out of here rather than borrowing it, so
    /// every existing cleanup path in that method still operates on an owned
    /// local and is unchanged.
    locked_session: tokio::sync::Mutex<Option<crate::device_manager::PooledDevice>>,
}

impl JunosTransaction {
    /// Create a new transaction for the given device.
    pub fn new(device_manager: Arc<DeviceManager>, router: String) -> Self {
        Self {
            device_manager,
            router,
            locked_session: tokio::sync::Mutex::new(None),
        }
    }
}

impl JunosTransaction {
    /// The atomicity Junos provides, as reported to
    /// [`DeviceTransaction::atomicity`].
    ///
    /// A named constant so it can be asserted without a device session:
    /// building a `JunosTransaction` needs a live NETCONF connection, and this
    /// declaration does not depend on one.
    pub const DECLARED_ATOMICITY: mecmcp_changeset::Atomicity =
        mecmcp_changeset::Atomicity::candidate_configuration();
}

#[async_trait]
impl DeviceTransaction for JunosTransaction {
    type Action = JunosAction;
    type Staged = JunosStagedTransaction;
    type Diff = JunosDiff;
    type Validation = JunosValidation;
    type Error = JmcpError;

    /// Junos stages into a candidate, `commit check`s it, and rolls back
    /// exactly, so all three guarantees hold.
    ///
    /// Declared rather than inherited. mecmcp 0.23.0's trait defaults to
    /// [`mecmcp_changeset::Atomicity::nothing_guaranteed`], the safe answer for an implementation
    /// that has not said -- but left inherited it would have an approval prompt
    /// tell an operator that a Junos change offers no atomic apply, no dry run
    /// and no guaranteed rollback, which understates the change control this
    /// server actually provides.
    fn atomicity(&self) -> mecmcp_changeset::Atomicity {
        Self::DECLARED_ATOMICITY
    }

    fn requires_config_lock(&self) -> bool {
        true
    }

    /// Take the Junos candidate lock and hold the session that owns it.
    ///
    /// The coordinator calls this before reading the fingerprint, so the check
    /// and the staging that follows are atomic against other sessions — an
    /// operator at the CLI or a second MCP process can no longer move the
    /// candidate in between (mecmcp#60).
    ///
    /// Idempotent: a second call while the lock is already held is a no-op, so a
    /// retry cannot strand a session.
    async fn lock(&self, _comment: &str) -> Result<(), Self::Error> {
        let mut held = self.locked_session.lock().await;
        if held.is_some() {
            return Ok(());
        }

        let mut dev = self.device_manager.open(&self.router).await?;
        // Non-reusable before locking, matching `stage()`: a session carrying a
        // lock must never go back to the pool for someone else to pick up.
        dev.prevent_reuse();

        let lock_result = {
            let mut cfg = dev.config()?;
            cfg.lock().await
        };

        if let Err(error) = lock_result {
            // Nothing was locked, so the session is clean and may be pooled.
            dev.allow_reuse();
            return Err(error.into());
        }

        *held = Some(dev);
        Ok(())
    }

    /// Release the candidate lock taken by [`lock`](Self::lock).
    async fn unlock(&self) -> Result<mecmcp_changeset::UnlockOutcome, Self::Error> {
        let Some(mut dev) = self.locked_session.lock().await.take() else {
            // Nothing retained here. Either the lock was never taken, or `stage()`
            // took the session and owns its lifecycle now. Junos releases a
            // candidate lock when its session closes, so no lock of ours is held
            // either way, and that is what the coordinator needs to know.
            return Ok(mecmcp_changeset::UnlockOutcome::Released);
        };

        // `release_lock` unlocks a clean session and closes a dirty one; either
        // way the device holds no lock of ours afterwards (#316).
        match dev.release_lock().await {
            // `Released` covers both: an acknowledged `<unlock>`, and a close
            // that ends the session Junos holds the lock against. What the
            // coordinator must not be told is that a lock is free when the
            // attempt failed — and that is the `Err` arm.
            Ok(_) => Ok(mecmcp_changeset::UnlockOutcome::Released),
            // The session is dropped without `allow_reuse`, so it closes rather
            // than returning to the pool — which releases the lock on the device
            // regardless. The error still propagates: the caller asked for a
            // confirmed release and did not get one.
            Err(error) => Err(error),
        }
    }

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        // Fetch the candidate database via <get-configuration database="candidate"/>.
        // Uses the rustez RPC executor to issue a raw NETCONF RPC with the
        // database attribute. The returned XML is normalised before hashing to
        // ensure determinism: Junos includes a changing `junos:changed-seconds`
        // timestamp attribute and can vary in whitespace.
        // Read through the locked session when one is held, so the fingerprint
        // the coordinator compares against is captured *inside* the lock. Reading
        // on a separate pooled session would leave the same gap the lock exists
        // to close: another session could move the candidate between this read
        // and staging.
        const CANDIDATE_RPC: &str = r#"<get-configuration database="candidate"/>"#;
        let mut held = self.locked_session.lock().await;
        let candidate_xml = match held.as_mut() {
            Some(session) => {
                let mut exec = session.rpc()?;
                exec.call_xml(CANDIDATE_RPC).await?
            }
            None => {
                let mut dev = self.device_manager.open(&self.router).await?;
                let mut exec = dev.rpc()?;
                exec.call_xml(CANDIDATE_RPC).await?
            }
        };
        drop(held);

        // Normalise: strip junos: namespace attributes (including the timestamp),
        // then apply line-based normalisation for deterministic hashing.
        let normalised = normalise_candidate_for_fingerprint(&candidate_xml);

        // SHA-256 hash the normalised text.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        // sha2 0.11 returns `hybrid_array::Array`, which no longer implements
        // `LowerHex`. Encode through the crate's existing hex helper so the
        // digest text is byte-for-byte what mecmcp-changeset already stores.
        let hash: [u8; 32] = hasher.finalize().into();

        // Return in the mecmcp_changeset digest format: "sha256:{lowercase-hex}".
        Ok(format!(
            "sha256:{}",
            crate::tools::transfer_file::hex32(&hash)
        ))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        // Defect #8: Validate exactly-one invariant (payload XOR rollback_source).
        for (i, action) in actions.iter().enumerate() {
            match (&action.payload, action.rollback_source) {
                (Some(_), Some(_)) => {
                    return Err(JmcpError::Validation(format!(
                        "action {} has both payload and rollback_source; exactly one is required",
                        i
                    )));
                }
                (None, None) => {
                    return Err(JmcpError::Validation(format!(
                        "action {} has neither payload nor rollback_source",
                        i
                    )));
                }
                _ => {} // exactly one is set; proceed
            }
        }

        // Resolve every action's payload/format/mode into a load instruction
        // before opening a session or taking the candidate lock. Doing that
        // resolution inside the load loop below meant a parse/resolve error on
        // action N returned early via `?`, skipping the revert-and-unlock
        // cleanup for actions 0..N already loaded into the locked candidate —
        // breaking the all-or-none staging contract (Percy review,
        // rustjunosmcp#425 F3). Resolving up front makes the load loop below
        // infallible except for the wire call itself, so every error path goes
        // through the existing cleanup.
        enum ResolvedAction {
            Rollback(u32),
            Load(rustez::ConfigPayload, rustez::LoadAction),
        }
        let resolved_actions = actions
            .iter()
            .map(|action| {
                if let Some(rollback) = action.rollback_source {
                    Ok(ResolvedAction::Rollback(rollback))
                } else if let Some(ref spec) = action.payload {
                    let format = spec.format.as_deref().unwrap_or("set");
                    let payload = build_config_payload(spec.text.clone(), Some(format))?;
                    let requested_mode = crate::helpers::parse_load_mode(spec.mode.as_deref())?;
                    let load_action = crate::helpers::resolve_load_action(format, requested_mode)?;
                    Ok(ResolvedAction::Load(payload, load_action))
                } else {
                    unreachable!("exactly-one validation already checked this")
                }
            })
            .collect::<Result<Vec<_>, JmcpError>>()?;

        // Open a session and lock the candidate. Load each action's payload or
        // rollback source. Capture the diff. The session is retained (not pooled)
        // until commit or discard so validate and commit see the same candidate.
        // Take the session `lock()` left behind, if there is one. Taking rather
        // than borrowing keeps `dev` an owned local, so every cleanup path below
        // is exactly as it was before the lock primitive existed (#80).
        let (mut dev, already_locked) = match self.locked_session.lock().await.take() {
            Some(session) => (session, true),
            None => {
                let mut dev = self.device_manager.open(&self.router).await?;

                // Defect #2: Mark session non-reusable before locking. It will be
                // restored to reusable only after all cleanup (rollback + unlock)
                // succeeds.
                dev.prevent_reuse();
                (dev, false)
            }
        };

        let mut cfg = dev.config()?;

        // Lock the candidate, unless `lock()` already did it on this session.
        if !already_locked && let Err(error) = cfg.lock().await {
            // Lock failed before any load. Session is clean; allow pooling.
            dev.allow_reuse();
            return Err(error.into());
        }

        // Load actions. Track success count for partial-failure revert.
        for (loaded, resolved) in resolved_actions.into_iter().enumerate() {
            // Re-check the rollback-depth guard here, inside the candidate
            // lock, rather than trusting the check `create_junos_change_set`
            // already did (MEC-1879, P5a item 6). A device can be re-tagged
            // plane-owned in `devices.json` between create and apply; reading
            // the inventory fresh on every staged action closes that window.
            if let ResolvedAction::Rollback(rollback) = &resolved {
                let authority = {
                    let inv = self.device_manager.inventory();
                    inv.get(&self.router)?.config_authority.clone()
                };

                let depth_check: Result<(), JmcpError> =
                    if !authority.is_plane_owned() || *rollback == 0 {
                        Ok(())
                    } else if *rollback == 1 {
                        // Re-read entry 0 fresh, inside the candidate lock, rather
                        // than trusting the plan's create-time snapshot (MEC-1880,
                        // §5.5 TOCTOU binding): a commit can land on the device
                        // between create and apply. The NETCONF candidate lock is
                        // device-side RPC state independent of this
                        // `ConfigManager` handle's lifetime (lock/unlock are
                        // explicit RPCs, not a `Drop` effect — it borrows `dev`
                        // but carries no `Drop` impl of its own), so ending its
                        // borrow here to free `dev` for a plain CLI read does
                        // not release the device-side lock.
                        let _ = cfg;
                        let log = dev.cli("show system commit").await;
                        let fresh_cfg = match dev.config() {
                            Ok(fresh) => fresh,
                            Err(error) => {
                                // No candidate-manager handle to revert or unlock
                                // through; the session is already non-reusable
                                // (`prevent_reuse` above) and stays that way.
                                // Failing hard here is fail-closed: we cannot
                                // reconstruct the shared cleanup path below
                                // without a `cfg` to call it on.
                                return Err(error.into());
                            }
                        };
                        cfg = fresh_cfg;

                        let fresh_entry = log
                            .ok()
                            .and_then(|log| crate::commit_attribution::parse_newest_entry(&log));
                        match (&fresh_entry, actions[loaded].commit0.as_ref()) {
                            (Some(fresh_entry), Some(binding)) if binding.matches(fresh_entry) => {
                                Ok(())
                            }
                            _ => Err(JmcpError::CommitLogMoved {
                                tool: "apply_junos_change_set",
                                device: self.router.clone(),
                            }),
                        }
                    } else {
                        crate::helpers::check_plane_owned_rollback_deep_depth(
                            "apply_junos_change_set",
                            &self.router,
                            &authority,
                            *rollback,
                        )
                    };

                if let Err(depth_error) = depth_check {
                    // Same cleanup contract as a load failure below, but the
                    // primary error is already a `JmcpError` built from this
                    // check rather than the wire-level load result.
                    let mut revert_err_opt = None;
                    let mut unlock_err_opt = None;

                    if loaded > 0
                        && let Err(revert_error) = cfg.rollback(0).await
                    {
                        tracing::error!(
                            router = %self.router,
                            loaded,
                            primary_error = %depth_error,
                            revert_error = %revert_error,
                            "failed to revert partial stage after apply-time plane-owned \
                             rollback refusal; session tainted"
                        );
                        revert_err_opt = Some(revert_error.to_string());
                    }

                    if let Err(unlock_error) = dev.release_lock().await {
                        tracing::error!(
                            router = %self.router,
                            primary_error = %depth_error,
                            unlock_error = %unlock_error,
                            "failed to release lock after apply-time plane-owned rollback \
                             refusal; session tainted"
                        );
                        unlock_err_opt = Some(unlock_error.to_string());
                    }

                    return match (&revert_err_opt, &unlock_err_opt) {
                        (Some(revert_err), Some(unlock_err)) => {
                            Err(JmcpError::CandidateCleanupFailed {
                                primary: depth_error.to_string(),
                                rollback: revert_err.clone(),
                                unlock: unlock_err.clone(),
                            })
                        }
                        (Some(revert_err), None) => Err(JmcpError::CandidateCleanupFailed {
                            primary: depth_error.to_string(),
                            rollback: revert_err.clone(),
                            unlock: "ok".into(),
                        }),
                        (None, Some(unlock_err)) => Err(JmcpError::CandidateCleanupFailed {
                            primary: depth_error.to_string(),
                            rollback: if loaded > 0 { "ok" } else { "skipped" }.into(),
                            unlock: unlock_err.clone(),
                        }),
                        (None, None) => Err(depth_error),
                    };
                }
            }

            let load_result = match resolved {
                ResolvedAction::Rollback(rollback) => cfg.rollback(rollback).await,
                ResolvedAction::Load(payload, load_action) => {
                    cfg.load_with_action(payload, load_action).await.map(|_| ())
                }
            };

            if let Err(error) = load_result {
                // Partial failure. Revert the candidate (rollback 0) and unlock.
                // Both must succeed before we allow the session back into the pool.
                // Finding 2 (P1): Cleanup failures must be visible in the returned
                // error, not just logged. A failed revert on a standalone device can
                // leave earlier actions sitting in the shared candidate, breaking the
                // all-or-none staging contract, and the caller sees nothing telling it
                // recovery is needed.
                let mut revert_err_opt = None;
                let mut unlock_err_opt = None;

                if loaded > 0
                    && let Err(revert_error) = cfg.rollback(0).await
                {
                    tracing::error!(
                        router = %self.router,
                        loaded,
                        primary_error = %error,
                        revert_error = %revert_error,
                        "failed to revert partial stage; session tainted"
                    );
                    revert_err_opt = Some(revert_error.to_string());
                }

                // The revert above dirtied the candidate, so this closes rather
                // than unlocks — under our own lock, never after it (#316).
                if let Err(unlock_error) = dev.release_lock().await {
                    tracing::error!(
                        router = %self.router,
                        primary_error = %error,
                        unlock_error = %unlock_error,
                        "failed to release lock after load failure; session tainted"
                    );
                    unlock_err_opt = Some(unlock_error.to_string());
                }

                // Return the cleanup-aware error if cleanup failed, otherwise the primary.
                return match (&revert_err_opt, &unlock_err_opt) {
                    (Some(revert_err), Some(unlock_err)) => {
                        Err(JmcpError::CandidateCleanupFailed {
                            primary: error.to_string(),
                            rollback: revert_err.clone(),
                            unlock: unlock_err.clone(),
                        })
                    }
                    (Some(revert_err), None) => Err(JmcpError::CandidateCleanupFailed {
                        primary: error.to_string(),
                        rollback: revert_err.clone(),
                        unlock: "ok".into(),
                    }),
                    (None, Some(unlock_err)) => Err(JmcpError::CandidateCleanupFailed {
                        primary: error.to_string(),
                        rollback: if loaded > 0 { "ok" } else { "skipped" }.into(),
                        unlock: unlock_err.clone(),
                    }),
                    (None, None) => Err(error.into()),
                };
            }
        }

        // Capture the diff.
        let diff = cfg.diff().await?.unwrap_or_default();

        // Defect #1: DO NOT unlock. Retain the session and lock so validate and
        // commit operate on the same private candidate database. On a chassis
        // cluster, unlocking closes the private database, and later operations
        // would open fresh sessions that can't see the staged candidate.
        //
        // The session will be dropped (and thus unlocked and closed) when the
        // caller drops the Staged handle, or when commit/rollback explicitly
        // unlocks and allows pooling.

        Ok(JunosStagedTransaction {
            router: self.router.clone(),
            diff,
            session: tokio::sync::Mutex::new(Some(dev)),
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // The diff was captured during stage. Return it.
        Ok(JunosDiff {
            diff: staged.diff.clone(),
        })
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        // Defect #1 fix: Use the retained session from stage, not a fresh one.
        // The staged session holds the lock and the private candidate database
        // (on chassis clusters). A fresh session cannot see the staged candidate.
        let mut session_guard = staged.session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            JmcpError::Validation("staged transaction has no session; already consumed?".into())
        })?;

        let mut cfg = session.config()?;

        match cfg.commit_check().await {
            Ok(()) => Ok(JunosValidation {
                valid: true,
                details: None,
            }),
            Err(error) => {
                // Classify the error. Only a device content rejection is "invalid".
                // Anything else (parse failure, multi-RE cluster reply, timeout) is
                // "check failed" — the check could not reach a verdict.
                let outcome =
                    crate::tools::candidate_transaction::classify_check_error(error.into());
                match outcome {
                    CheckOutcome::Valid => Ok(JunosValidation {
                        valid: true,
                        details: None,
                    }),
                    CheckOutcome::Invalid(details) => Ok(JunosValidation {
                        valid: false,
                        details: Some(details),
                    }),
                    CheckOutcome::CheckFailed(details) => Err(JmcpError::Validation(format!(
                        "commit-check could not reach a verdict: {}",
                        details
                    ))),
                }
            }
        }
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Finding 1 (P1): Reject confirm_timeout BEFORE staging to avoid leaving
        // the candidate dirty on refusal. The previous code refused after stage(),
        // which locked and loaded the shared candidate, then returned an error
        // without cleanup — leaving the staged changes for whatever commits next.
        // Reject an unusable confirm window before staging is touched, so a refusal
        // never leaves the candidate dirty for whatever commits next.
        let confirm_minutes = match options.confirm_timeout {
            Some(timeout) => Some(junos_confirm_minutes(timeout)?),
            None => None,
        };

        // Defect #1 fix: Use the staged session's lock and private candidate database.
        let mut session_guard = staged.session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            JmcpError::Validation("staged transaction has no session; already consumed?".into())
        })?;

        // Build the commit comment from the attribution.
        let comment = format_attribution(attribution);

        // Confirmed commit takes a different path: the Junos-native RPC rather
        // than the RFC form, because only the native one survives this session.
        if let Some(minutes) = confirm_minutes {
            return confirmed_commit_on_session(session, minutes, &comment).await;
        }

        let mut cfg = session.config()?;

        // Normal synchronous commit with comment.
        // Defect #3: Distinguish timeout/transport uncertainty from known rejection.
        match cfg.commit_with_comment(&comment).await {
            Ok(()) => {
                // Commit succeeded. Unlock and allow the session to be pooled.
                // If unlock fails, the commit already succeeded, but the lock state
                // is unknown — that's Indeterminate.
                // `commit_with_comment` leaves rustnetconf's candidate flag set,
                // so this closes the session under our lock rather than unlocking
                // and pooling an armed `<discard-changes/>` (#316).
                match session.release_lock().await {
                    // How the lock went is recorded, not glossed. An `<unlock>`
                    // was acknowledged by the device; a close was not — see
                    // `release_lock`. Neither is reported as `Indeterminate`,
                    // and deliberately: that state is non-terminal
                    // (`LifecycleState::terminal` is `Committed | Discarded`
                    // alone), so one per device blocks every later apply until
                    // an operator runs `state resolve`. The commit itself is
                    // device-acknowledged here; making every attributed commit
                    // need manual reconciliation to express a weaker fact about
                    // the lock would trade a small uncertainty for a certain
                    // outage. The uncertainty that does matter — a peer that
                    // stopped answering — arrives as the `Err` arm, because the
                    // close is bounded.
                    Ok(release) => Ok(CommitOutcome::Reconciled {
                        succeeded: true,
                        job_id: None,
                        details: Some(match release {
                            crate::device_manager::LockRelease::Confirmed => {
                                "commit succeeded".into()
                            }
                            crate::device_manager::LockRelease::ClosedUnverified => {
                                // Say what is known, not what is likely. The
                                // session was closed at our end; the device
                                // never acknowledged the release, and
                                // rustnetconf reports success either way.
                                "commit succeeded; session closed to release the candidate lock, \
                                 release not acknowledged by the device"
                                    .to_owned()
                            }
                        }),
                    }),
                    Err(release_error) => {
                        // Commit succeeded but the release failed or exceeded the
                        // cleanup budget. The lock state is unknown.
                        Ok(CommitOutcome::Indeterminate {
                            reason: format!(
                                "commit succeeded but releasing the candidate lock failed: {release_error}; lock state unknown"
                            ),
                        })
                    }
                }
            }
            Err(error) => {
                // Defect #3: Classify the error. A timeout or transport drop after
                // the commit RPC was sent means the outcome is unknown (device may
                // have committed). Only an explicit device rejection is Reconciled.
                if is_transport_uncertainty(&error) {
                    Ok(CommitOutcome::Indeterminate {
                        reason: format!("commit RPC timed out or transport dropped: {}", error),
                    })
                } else {
                    // Known rejection (syntax error, config invalid, etc.).
                    Ok(CommitOutcome::Reconciled {
                        succeeded: false,
                        job_id: None,
                        details: Some(error.to_string()),
                    })
                }
            }
        }
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::Archive(n) => {
                // Defense-in-depth (MEC-1879, H10): no caller reaches this
                // variant today, but refuse on a plane-owned device the same
                // way `stage()` and `create_junos_change_set` do, so the
                // guard applies uniformly however `rollback()` is reached.
                let authority = {
                    let inv = self.device_manager.inventory();
                    inv.get(&self.router)?.config_authority.clone()
                };
                crate::helpers::check_plane_owned_rollback_depth(
                    "rollback_archive",
                    &self.router,
                    &authority,
                    n,
                )?;

                // Defect #6: Archive rollback leaks the lock. After acquiring the lock,
                // an invalid or unavailable archive makes rollback(n) return without
                // unlocking, and a successful load followed by a known commit rejection
                // unlocks without reverting the rollback-loaded candidate.
                //
                // FIX: Route every post-lock exit through cleanup (revert + unlock).
                let mut dev = self.device_manager.open(&self.router).await?;
                dev.prevent_reuse(); // Taint until cleanup succeeds.
                let mut cfg = dev.config()?;

                if let Err(lock_error) = cfg.lock().await {
                    dev.allow_reuse(); // Lock never acquired; session is clean.
                    return Err(lock_error.into());
                }

                // Load rollback N. If this fails, the candidate may be dirty (partial
                // load) or the archive may be invalid. Either way, revert (rollback 0)
                // before unlocking.
                let load_result = cfg.rollback(n).await;
                if let Err(load_error) = load_result {
                    if let Err(revert_error) = cfg.rollback(0).await {
                        tracing::error!(
                            router = %self.router,
                            archive = n,
                            load_error = %load_error,
                            revert_error = %revert_error,
                            "failed to revert after archive load failure; session tainted"
                        );
                    }
                    // The revert dirtied the candidate, so this closes under our
                    // own lock instead of unlocking and discarding later (#316).
                    if let Err(unlock_error) = dev.release_lock().await {
                        tracing::error!(
                            router = %self.router,
                            unlock_error = %unlock_error,
                            "failed to release lock after archive load failure; session tainted"
                        );
                    }
                    return Err(load_error.into());
                }

                // Attempt to commit the rollback-loaded candidate.
                let commit_comment = format!("rollback to archive {}", n);
                let commit_result = cfg.commit_with_comment(&commit_comment).await;

                match commit_result {
                    Ok(()) => {
                        // Commit succeeded. The commit went through
                        // `commit_with_comment`, which leaves the candidate flagged
                        // dirty, so releasing closes the session under our lock
                        // rather than pooling an armed discard (#316).
                        if let Err(unlock_error) = dev.release_lock().await {
                            tracing::error!(
                                router = %self.router,
                                unlock_error = %unlock_error,
                                "lock release failed after successful archive rollback commit; session tainted"
                            );
                        }
                        Ok(RollbackOutcome {
                            succeeded: true,
                            details: Some(format!("rollback to archive {} committed", n)),
                        })
                    }
                    Err(commit_error) => {
                        // Commit failed. The candidate is dirty (has rollback N loaded).
                        // Revert (rollback 0) and unlock before returning.
                        if let Err(revert_error) = cfg.rollback(0).await {
                            tracing::error!(
                                router = %self.router,
                                commit_error = %commit_error,
                                revert_error = %revert_error,
                                "failed to revert after archive commit failure; session tainted"
                            );
                        }
                        // Same as the load-failure path: the revert dirtied the
                        // candidate, so release closes rather than unlocks (#316).
                        if let Err(unlock_error) = dev.release_lock().await {
                            tracing::error!(
                                router = %self.router,
                                unlock_error = %unlock_error,
                                "failed to release lock after archive commit failure; session tainted"
                            );
                        }
                        Ok(RollbackOutcome {
                            succeeded: false,
                            details: Some(commit_error.to_string()),
                        })
                    }
                }
            }
            RollbackRef::CandidateRevert => {
                // Defect #7: An uncertain candidate revert is reported as a known failure.
                // When rollback(0) times out or loses its response, the revert may have
                // succeeded, but this returns Ok with succeeded=false. The caller cannot
                // enter indeterminate recovery and may retry against a candidate that has
                // already changed.
                //
                // FIX: Propagate transport and RPC uncertainty as Err, and reserve
                // RollbackOutcome for outcomes actually known.
                let mut dev = self.device_manager.open(&self.router).await?;
                let mut cfg = dev.config()?;

                match cfg.rollback(0).await {
                    Ok(()) => Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some("candidate reverted (rollback 0)".into()),
                    }),
                    Err(error) => {
                        // Defect #7 fix: Classify the error. Timeout or transport drop
                        // means the outcome is unknown. Return Err so the caller knows
                        // reconciliation is required. Only a known rejection (e.g., the
                        // rollback RPC explicitly failed with a config error, which is
                        // rare for rollback 0) is a RollbackOutcome.
                        if is_transport_uncertainty(&error) {
                            Err(JmcpError::Validation(format!(
                                "candidate revert (rollback 0) outcome unknown: {}",
                                error
                            )))
                        } else {
                            Ok(RollbackOutcome {
                                succeeded: false,
                                details: Some(error.to_string()),
                            })
                        }
                    }
                }
            }
            RollbackRef::Custom(ref target) => Err(JmcpError::Validation(format!(
                "custom rollback target '{}' is not supported on Junos",
                target
            ))),
        }
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        // Issue a second <commit/> with a comment that references the confirmed
        // commit and applies the attribution. This is the NEW primitive that does
        // not currently exist: a plain commit (no candidate changes). We'll use
        // the existing commit_with_comment for now, which is safe because a
        // confirming commit against an empty candidate is a no-op with a logged
        // comment.
        let mut dev = self.device_manager.open(&self.router).await?;
        let mut cfg = dev.config()?;

        let comment = format!("Confirming commit: {}", format_attribution(attribution));

        let outcome = match cfg.commit_with_comment(&comment).await {
            Ok(()) => CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some("confirming commit succeeded".into()),
            },
            Err(error) => CommitOutcome::Reconciled {
                succeeded: false,
                job_id: None,
                details: Some(error.to_string()),
            },
        };

        // No lock is taken on this path, and `commit_with_comment` leaves the
        // candidate flagged dirty, so the session carries an armed
        // `<discard-changes/>`. Close it now rather than letting it sit in the
        // pool with that discard pending against a candidate anyone may write
        // (#316). A close failure does not change the commit's outcome.
        if let Err(close_error) = dev.close_in_place().await {
            tracing::warn!(
                router = %self.router,
                close_error = %close_error,
                "failed to close session after confirming commit"
            );
        }
        Ok(outcome)
    }
}

/// Normalise candidate configuration XML for deterministic fingerprinting.
///
/// Normalisation contract:
/// 1. Strip `junos:` namespace attributes (including `junos:changed-seconds`,
///    the timestamp that changes on every read, and `junos:style`).
/// 2. Trim each line, remove empty lines, sort lines.
///
/// The timestamp attribute `junos:changed-seconds` is Junos' way of marking
/// configuration recency. It changes on every `<get-configuration>` call, even
/// when the configuration itself is unchanged. Stripping it is essential for
/// fingerprint stability.
///
/// This does not parse the XML structure as a tree but is stable enough to
/// detect meaningful configuration changes while ignoring incidental whitespace
/// and the timestamp. A production implementation might use a proper XML
/// canonicalisation algorithm (e.g., C14N), but that requires an XML parser
/// and is overkill for this use case.
fn normalise_candidate_for_fingerprint(xml: &str) -> String {
    // Step 1: Strip junos: namespace attributes using the same primitive that
    // the SRX support-bundle redaction uses. This removes junos:changed-seconds,
    // junos:style, and any other junos: attributes that vary between reads.
    let stripped = simple_strip_junos_attrs(xml);

    // Step 2: Whitespace only. Indentation and blank lines carry no meaning in
    // this output, so trimming them is safe.
    //
    // Order is NOT normalised, deliberately. Junos evaluates security policies
    // and firewall filter terms in the order they appear, so a reordered policy
    // list is a genuinely different configuration that behaves differently.
    // Sorting the lines here would make such a change hash identically to the
    // original and report no drift — defeating the one thing this fingerprint
    // exists to detect.
    let lines: Vec<&str> = stripped
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    lines.join("\n")
}

/// Strip every `junos:attr="value"` occurrence in opening tags only.
///
/// Defect #5: The previous implementation used an unanchored substring search,
/// so configuration text containing a literal `junos:` (e.g.,
/// `<description>junos:foo</description>`) was treated as an attribute, causing
/// fingerprint collisions.
///
/// FIX: Only strip `junos:` when it appears in an opening tag context (after `<`
/// and before `>`). This is still a simplified parser (not a full XML tree), but
/// it correctly distinguishes attributes from element text.
fn simple_strip_junos_attrs(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;

    while let Some(open_tag_start) = rest.find('<') {
        // Copy everything before the opening `<`.
        out.push_str(&rest[..open_tag_start]);
        rest = &rest[open_tag_start..];

        // Find the closing `>` of this tag.
        let tag_end = match rest.find('>') {
            Some(pos) => pos,
            None => {
                // Malformed XML: no closing `>`. Copy the rest and bail.
                out.push_str(rest);
                return out;
            }
        };

        // Extract the tag content (everything between `<` and `>`).
        let tag_with_brackets = &rest[..=tag_end];
        let tag_content = &tag_with_brackets[1..tag_end]; // strip `<` and `>`

        // If this is a closing tag, comment, or CDATA, copy it as-is and continue.
        if tag_content.starts_with('/')
            || tag_content.starts_with('!')
            || tag_content.starts_with('?')
        {
            out.push_str(tag_with_brackets);
            rest = &rest[tag_end + 1..];
            continue;
        }

        // This is an opening tag. Strip `junos:` attributes from it.
        out.push('<');
        let stripped_tag_content = strip_junos_from_tag_content(tag_content);
        out.push_str(&stripped_tag_content);
        out.push('>');
        rest = &rest[tag_end + 1..];
    }

    // Copy any remaining content after the last tag.
    out.push_str(rest);
    out
}

/// Strip `junos:attr="value"` patterns from tag content (the text between `<` and `>`).
fn strip_junos_from_tag_content(tag: &str) -> String {
    let mut out = String::with_capacity(tag.len());
    let mut rest = tag;

    while let Some(pos) = rest.find("junos:") {
        // Copy everything before `junos:`.
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];

        // Find the end of the attribute (past the closing quote).
        let attr_end = find_attr_end(rest);
        rest = &rest[attr_end..];

        // Strip leading whitespace after the attribute.
        rest = rest.trim_start_matches(' ');
    }

    out.push_str(rest);
    out
}

/// Find the end position of an XML attribute starting at `s`.
///
/// Duplicated from `rust-junosmcp-srx-core/src/xml.rs` to avoid a cross-crate
/// dependency. Handles both quoted and unquoted attribute values.
fn find_attr_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    // Find the '=' sign.
    while i < len && bytes[i] != b'=' {
        i += 1;
    }
    if i >= len {
        return len;
    }
    i += 1; // past '='
    if i >= len {
        return len;
    }
    let quote = bytes[i];
    // Unquoted attribute value.
    if quote != b'"' && quote != b'\'' {
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
            i += 1;
        }
        return i;
    }
    // Quoted attribute value: find the closing quote.
    i += 1; // past opening quote
    while i < len && bytes[i] != quote {
        i += 1;
    }
    if i < len {
        i += 1; // past closing quote
    }
    i
}

/// Classify whether a rustez error indicates transport/timeout uncertainty.
///
/// Finding 3 (P2): Match on error VARIANTS, not substrings. A device returning
/// `<rpc-error>` with a message that happens to contain "timeout" (e.g., rejecting
/// a configuration statement *named* `timeout`) is a terminal ServerError — a
/// known rejection (Reconciled { succeeded: false }), not Indeterminate.
///
/// Returns `true` for errors that indicate the outcome is unknown (timeout,
/// connection drop, channel closed). Returns `false` for errors that indicate
/// a known rejection (explicit ServerError from the device).
///
/// **Evidence on error variant discrimination**: rustnetconf 0.13.x and rustez 0.13.x
/// provide the following enum structure:
///
/// - `RustEzError::Netconf(NetconfError)` wraps all NETCONF-layer errors.
/// - `NetconfError::Rpc(RpcError::ServerError(_))` is an explicit `<rpc-error>`
///   from the device — a known verdict, even if the message text contains "timeout".
/// - `NetconfError::Transport(_)` and `NetconfError::Framing(_)` are transport/framing
///   failures — the RPC outcome is unknown.
/// - `RpcError::ParseError(_)` can be a multi-RE cluster reply or a framing failure —
///   treat as uncertainty (safer default).
///
/// This distinction is PRESENT in the error variants and is RELIABLE: ServerError
/// means the device replied with an `<rpc-error>` element, which is a terminal
/// rejection. Transport/Framing mean the connection dropped or the message was
/// corrupt, which leaves the outcome unknown.
fn is_transport_uncertainty(error: &rustez::RustEzError) -> bool {
    use rustez::RustEzError;
    use rustnetconf::error::{NetconfError, RpcError};

    match error {
        // ServerError is an explicit <rpc-error> from the device. The device
        // rendered a verdict. This is a known rejection, NOT uncertainty.
        RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError(_))) => false,

        // The connection dropped after `<commit>` was sent and before its reply.
        // rustnetconf 0.14.3 raises this instead of a generic transport error
        // precisely so a caller can tell it apart: the device may hold the
        // change. This is the one error where guessing "rejected" is worst —
        // the apply would be recorded as failed and cleanup would run against a
        // device that already committed (#322).
        RustEzError::Netconf(NetconfError::Rpc(RpcError::CommitUnknown)) => true,

        // ParseError can be a framing failure, a multi-RE cluster reply that
        // won't parse, or a device rejection wrapped in unparseable XML. Without
        // more context, treat it as uncertainty (the safer default).
        RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(_))) => true,

        // Transport and framing errors (session closed, EOF, channel dropped).
        RustEzError::Netconf(NetconfError::Transport(_) | NetconfError::Framing(_)) => true,

        // Protocol errors (capability mismatch, session state) also indicate
        // uncertainty when they occur mid-commit.
        RustEzError::Netconf(NetconfError::Protocol(_)) => true,

        // SSH config errors, facts errors, config errors, XML parse errors — these
        // are usually pre-RPC failures, but if they occur mid-commit the outcome is
        // unknown. Treat as uncertainty (safer default).
        RustEzError::SshConfig(_) | RustEzError::Facts(_) | RustEzError::Config(_) => true,

        // XML parse errors can occur when a device returns malformed XML mid-commit.
        RustEzError::XmlParse(_) => true,

        // Backstop for any future variants or nested errors not explicitly matched.
        _ => {
            // Substring matching as a last resort. This catches timeout messages that
            // don't fit the above variants. Still check variants first to avoid
            // false positives (e.g., ServerError with "timeout" in the message).
            let err_str = error.to_string().to_ascii_lowercase();
            [
                "timeout",
                "timed out",
                "connection closed",
                "connection reset",
                "broken pipe",
                "unexpected eof",
                "channel closed",
                // The wording rustnetconf uses for a commit whose reply never
                // arrived, in case it reaches here as text rather than a variant.
                "connection lost",
                "commit status unknown",
            ]
            .iter()
            .any(|needle| err_str.contains(needle))
        }
    }
}

/// Convert a confirm timeout into the whole minutes Junos expects.
///
/// The trait expresses the window as a `Duration`, but the Junos native RPC's
/// `<confirm-timeout>` is in **minutes** — verified on vSRX 24.4R1.9, where a
/// value of 1 rolled the change back at roughly sixty seconds. Passing seconds
/// straight through would have asked for a 300-minute window when the caller
/// meant five minutes.
///
/// Sub-minute windows are refused rather than rounded up to one minute: the
/// caller would be told a deadline the device will not honour, and a confirmed
/// commit whose window is wrong is worse than no confirmed commit.
fn junos_confirm_minutes(timeout: std::time::Duration) -> Result<u32, JmcpError> {
    let seconds = timeout.as_secs();
    if seconds < 60 {
        return Err(JmcpError::Validation(format!(
            "confirm timeout must be at least 60 seconds; Junos schedules the rollback in whole \
             minutes and cannot honour {seconds}s"
        )));
    }
    if !seconds.is_multiple_of(60) {
        return Err(JmcpError::Validation(format!(
            "confirm timeout must be a whole number of minutes; Junos cannot honour {seconds}s"
        )));
    }
    u32::try_from(seconds / 60)
        .map_err(|_| JmcpError::Validation("confirm timeout is implausibly large".into()))
}

/// Build the Junos-native confirmed-commit RPC.
///
/// Deliberately not `rustez`'s `commit_confirmed`, which sends the RFC form
/// `<commit><confirmed/><confirm-timeout/></commit>`. Under
/// `:confirmed-commit:1.0` — the only version vSRX 24.4R1.9 advertises — that
/// form is bound to the issuing session and rolls back the moment the session
/// closes. Since this server pools NETCONF sessions and returns them after the
/// commit, the pool reaper would revert the change well before the deadline the
/// caller was given (#227).
///
/// The Junos-native `<commit-configuration>` has the CLI's `commit confirmed`
/// semantics instead: the pending rollback belongs to the device, not the
/// session. Verified against vSRX 24.4R1.9 — the change survived closing the
/// issuing session, auto-reverted at the deadline when left alone, and was held
/// permanently by a confirming commit issued from a *different* session.
fn build_confirmed_commit_xml(minutes: u32, comment: &str) -> String {
    format!(
        "<commit-configuration><confirmed/><confirm-timeout>{minutes}</confirm-timeout>\
         <log>{}</log></commit-configuration>",
        escape_xml_text(comment)
    )
}

/// Minimal XML text escaping for values interpolated into an RPC body.
fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Issue a confirmed commit on the staged session and report the deadline.
async fn confirmed_commit_on_session(
    session: &mut crate::device_manager::PooledDevice,
    minutes: u32,
    comment: &str,
) -> Result<CommitOutcome, JmcpError> {
    let xml = build_confirmed_commit_xml(minutes, comment);

    let response = {
        let mut exec = session.rpc()?;
        exec.call_xml(&xml).await
    };

    match response {
        Ok(_) => {
            // The rollback is the device's now, so the session is no longer
            // special and may return to the pool. This is the whole point of
            // using the native RPC: with the RFC form, pooling this session
            // would revert the change.
            session.allow_reuse();

            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0)
                + u64::from(minutes) * 60;

            Ok(CommitOutcome::AwaitingConfirmation {
                job_id: None,
                rollback_deadline_unix: deadline,
                details: Some(format!(
                    "confirmed commit issued; the device reverts in {minutes} minute(s) unless a \
                     confirming commit is received"
                )),
            })
        }
        Err(error) if is_transport_uncertainty(&error) => Ok(CommitOutcome::Indeterminate {
            reason: format!(
                "confirmed commit sent but the outcome is unknown: {error}; the device may be \
                 holding a pending rollback"
            ),
        }),
        Err(error) => Err(error.into()),
    }
}

/// How much of a change-set id reaches the device's commit comment.
///
/// Enough to correlate a commit with the server's change-set store — 16 hex
/// characters is 64 bits, against a store holding tens of records — without
/// spending a third of a bounded comment field on an identifier.
const CHANGE_SET_ID_COMMENT_PREFIX: usize = 16;

/// How much of an approver's name reaches the device's commit comment.
///
/// Junos accepts 512 characters of commit comment. This one already carries
/// two token names — the principal and the on-behalf-of — each of which may be
/// 128 characters, so a third unbounded name is what tips the worst case over.
/// Truncating is strictly better than the alternative: an over-long comment
/// fails the commit after the device is already staged.
///
/// 64 is far beyond any real token name; the fleet's approver is
/// "codex-approver", at 14.
const MAX_APPROVER_IN_COMMENT: usize = 64;

/// Format the attribution into a Junos commit comment.
fn format_attribution(attribution: &Attribution) -> String {
    let change_ref = attribution.change_ref.as_deref().unwrap_or("no-change-ref");
    let principal = &attribution.principal;
    let on_behalf_of = attribution.on_behalf_of.as_deref().unwrap_or("self");

    let actor_type_str = match attribution.actor_type {
        mecmcp_audit::ActorType::Human => "human",
        mecmcp_audit::ActorType::Agent => "agent",
        mecmcp_audit::ActorType::Unknown => "unknown",
    };

    // If it's an agent with identity, include provider and — only when the
    // caller actually asserted one — the model.
    //
    // `model_id` is always client-asserted: a token cannot vouch for which
    // model ran, so attribution built from a token entry leaves it empty by
    // design. Emitting `model=` unconditionally put a dangling, valueless key
    // on every commit this server made (mecmcp#75). Omit the segment rather
    // than record an empty claim.
    let agent_info = if let Some(ref agent) = attribution.agent {
        let model = if agent.model_id.is_empty() {
            String::new()
        } else {
            format!(" model={}", agent.model_id)
        };
        format!(" via {}-{}{}", agent.provider, agent.provider_tier, model)
    } else {
        String::new()
    };

    // The two-person evidence, where there is any (#307).
    //
    // Both segments follow the rule mecmcp#75 set for `model=`: omit rather
    // than write an empty claim. `approved-by=` with nothing after it reads,
    // to anyone scanning a commit log, like an approval that happened.
    //
    // `approver` is absent on a waived or single-operator apply, and that
    // absence is a fact about the change rather than a gap to fill.
    let approval_info = attribution
        .approver
        .as_deref()
        .map(|approver| {
            // Bounded because a commit comment is not. A token name may be 128
            // characters (`mecmcp_auth::MAX_TOKEN_NAME`), and this comment
            // already carries two of them — principal and on-behalf-of — so a
            // third unbounded name is what tips the worst case past what Junos
            // accepts. An over-long comment fails the commit at the last step,
            // after the device has already been staged, which is a far worse
            // outcome than a marked truncation. Real approver names are token
            // names like "codex-approver"; nothing near this bound is expected.
            if approver.len() > MAX_APPROVER_IN_COMMENT {
                let kept: String = approver.chars().take(MAX_APPROVER_IN_COMMENT).collect();
                format!(" approved-by={kept}...")
            } else {
                format!(" approved-by={approver}")
            }
        })
        .unwrap_or_default();

    // The id is truncated to a correlating prefix. A commit comment is a
    // bounded field shared with every other attribution field, and 64 hex
    // characters would spend over a third of it saying what 16 already says:
    // 64 bits is ample to find one change set in a store holding tens.
    let change_set_info = attribution
        .change_set_id
        .as_deref()
        .map(|id| {
            let prefix: String = id.chars().take(CHANGE_SET_ID_COMMENT_PREFIX).collect();
            format!(" change-set={prefix}")
        })
        .unwrap_or_default();

    format!(
        "{} by {} ({}) on-behalf-of={}{} request.id={}{}{}",
        change_ref,
        principal,
        actor_type_str,
        on_behalf_of,
        agent_info,
        attribution.request_id,
        approval_info,
        change_set_info
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transaction over an empty inventory. Every test using this asserts on
    /// behaviour that happens *before* a session is opened, so no device is
    /// contacted; `stage()` would fail at `device_manager.open()` if one of
    /// these ever got that far, which is itself the signal that the validation
    /// under test stopped working.
    fn offline_transaction() -> JunosTransaction {
        use crate::{device_manager::DeviceManager, inventory::Inventory};
        use std::sync::Arc;

        JunosTransaction::new(
            Arc::new(DeviceManager::new(Arc::new(Inventory::empty()))),
            "no-such-router".to_owned(),
        )
    }

    /// A transaction over a router that exists in inventory with the given
    /// `config_authority`, but is never actually dialled: every test using
    /// this asserts on the plane-owned rollback-depth guard, which (for
    /// `RollbackRef::Archive`) runs on the inventory lookup alone, before
    /// `device_manager.open()`. Reaching a real connection attempt is itself
    /// the signal that the guard stopped running first.
    fn plane_owned_transaction(authority: &str) -> JunosTransaction {
        use crate::{device_manager::DeviceManager, inventory::Inventory};
        use std::io::Write;
        use std::sync::Arc;

        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            format!(
                r#"{{"r1":{{"ip":"127.0.0.1","username":"u","auth":{{"type":"password","password":"x"}},"config_authority":"{authority}"}}}}"#,
            )
            .as_bytes(),
        )
        .unwrap();

        JunosTransaction::new(
            Arc::new(DeviceManager::new(Arc::new(
                Inventory::load(f.path()).unwrap(),
            ))),
            "r1".to_owned(),
        )
    }

    /// MEC-1879 H10: `RollbackRef::Archive` has no caller today, but refuses
    /// depth >= 1 on a plane-owned device anyway, so the guard applies
    /// uniformly however `rollback()` is reached.
    #[tokio::test]
    async fn rollback_archive_refuses_depth_one_on_plane_owned_device() {
        let txn = plane_owned_transaction("mist");
        let err = txn
            .rollback(RollbackRef::Archive(1))
            .await
            .expect_err("depth 1 on a plane-owned device must be refused");

        assert!(
            matches!(
                err,
                JmcpError::PlaneOwnedRollbackDepthRefused { depth: 1, .. }
            ),
            "expected a depth-refusal error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rollback_archive_refuses_deeper_depth_on_plane_owned_device() {
        let txn = plane_owned_transaction("security-director-onprem");
        let err = txn
            .rollback(RollbackRef::Archive(10))
            .await
            .expect_err("depth 10 on a plane-owned device must be refused");

        assert!(
            matches!(
                err,
                JmcpError::PlaneOwnedRollbackDepthRefused { depth: 10, .. }
            ),
            "expected a depth-refusal error, got {err:?}"
        );
    }

    fn action(payload: Option<&str>, rollback_source: Option<u32>) -> JunosAction {
        JunosAction {
            payload: payload.map(|text| ConfigPayloadSpec {
                text: text.to_owned(),
                format: Some("set".to_owned()),
                mode: None,
            }),
            rollback_source,
            ..Default::default()
        }
    }

    /// Like `action()`, but with an explicit `format` and `mode` for testing
    /// how `stage()` resolves them into a wire `LoadAction`.
    fn action_with_format_and_mode(text: &str, format: &str, mode: &str) -> JunosAction {
        JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: text.to_owned(),
                format: Some(format.to_owned()),
                mode: Some(mode.to_owned()),
            }),
            rollback_source: None,
            ..Default::default()
        }
    }

    /// `mode` is orthogonal to the payload/rollback_source XOR invariant
    /// `validate_shape` enforces — adding it must not change that check,
    /// including for `override`, the one mode this path (unlike
    /// `load_and_commit_config`) is allowed to carry.
    #[test]
    fn action_with_override_mode_still_passes_shape_validation() {
        let a = action_with_format_and_mode("system { host-name x; }", "text", "override");
        assert!(a.validate_shape(0).is_ok());
    }

    /// `ConfigPayloadSpec.mode` round-trips through JSON like `format` does —
    /// the field an approver's `create_junos_change_set` call actually sends.
    #[test]
    fn config_payload_spec_deserializes_mode() {
        let spec: ConfigPayloadSpec = serde_json::from_str(
            r#"{"text":"system { host-name x; }","format":"text","mode":"override"}"#,
        )
        .unwrap();
        assert_eq!(spec.mode.as_deref(), Some("override"));
    }

    #[test]
    fn config_payload_spec_mode_defaults_to_none() {
        let spec: ConfigPayloadSpec = serde_json::from_str(r#"{"text":"set x"}"#).unwrap();
        assert_eq!(spec.mode, None);
    }

    /// `payload` and `rollback_source` are mutually exclusive. Staging both
    /// would load a payload *and* a rollback archive into one candidate, so the
    /// resulting configuration is neither of the things the caller asked for.
    #[tokio::test]
    async fn stage_rejects_an_action_carrying_both_payload_and_rollback() {
        let error = offline_transaction()
            .stage(&[action(Some("set system host-name a"), Some(0))])
            .await
            .err()
            .expect("both fields set must be refused");

        let message = error.to_string();
        assert!(
            message.contains("both payload and rollback_source"),
            "the error should name the conflict, got: {message}"
        );
    }

    /// Neither field set has no meaning either, and it must be caught before a
    /// session is opened rather than surfacing as an `unreachable!` later.
    #[tokio::test]
    async fn stage_rejects_an_action_carrying_neither_payload_nor_rollback() {
        let error = offline_transaction()
            .stage(&[action(None, None)])
            .await
            .err()
            .expect("neither field set must be refused");

        let message = error.to_string();
        assert!(
            message.contains("neither payload nor rollback_source"),
            "the error should name the omission, got: {message}"
        );
    }

    /// The invariant is per action, not just the first one: a valid action must
    /// not mask an invalid one behind it.
    #[tokio::test]
    async fn stage_validates_every_action_not_only_the_first() {
        let error = offline_transaction()
            .stage(&[
                action(Some("set system host-name a"), None),
                action(Some("set system host-name b"), Some(0)),
            ])
            .await
            .err()
            .expect("the second action is invalid and must be caught");

        let message = error.to_string();
        assert!(
            message.contains("action 1"),
            "the error should identify which action failed, got: {message}"
        );
    }

    /// Percy review F3 (rustjunosmcp#425): an invalid format/mode combination
    /// on a later action used to be resolved inside the load loop, after the
    /// candidate was already locked in a live session — so the error from
    /// action 1 returned via `?` and skipped the revert-and-unlock cleanup for
    /// action 0, already loaded into the shared candidate. Resolving every
    /// action's mode up front, before a session is even opened, means this
    /// error surfaces without any device contact: `offline_transaction`'s
    /// router doesn't exist in the inventory, so reaching as far as
    /// `device_manager.open()` would fail with a different error (device
    /// lookup), not this one.
    #[tokio::test]
    async fn stage_resolves_every_action_mode_before_opening_a_session() {
        let error = offline_transaction()
            .stage(&[
                action(Some("set system host-name a"), None),
                action_with_format_and_mode("system { host-name b; }", "set", "override"),
            ])
            .await
            .err()
            .expect("format=set + mode=override on a later action must be refused");

        assert!(
            matches!(error, JmcpError::IncompatibleFormatMode { .. }),
            "expected the format/mode mismatch to surface directly, with no \
             device contact attempted, got: {error:?}"
        );
    }

    /// Junos must ask for the device lock, or the coordinator never calls
    /// `lock()` and the fingerprint-to-stage window stays open (mecmcp#60, #80).
    /// The default is `false`, so this is easy to lose silently in a refactor.
    #[test]
    fn junos_requires_the_device_config_lock() {
        assert!(
            offline_transaction().requires_config_lock(),
            "Junos must opt into the device lock"
        );
    }

    /// A fresh transaction holds no session, so `unlock()` reports the honest
    /// answer — no lock of ours is held — rather than erroring.
    #[tokio::test]
    async fn unlock_without_a_held_session_reports_released() {
        let outcome = offline_transaction().unlock().await.expect("unlock");
        assert_eq!(outcome, mecmcp_changeset::UnlockOutcome::Released);
    }

    /// Junos schedules the rollback in whole minutes. Passing the trait's
    /// seconds straight through would request a 300-minute window for a
    /// five-minute one — verified against vSRX 24.4R1.9, where
    /// `<confirm-timeout>1</confirm-timeout>` reverted at about sixty seconds.
    #[test]
    fn confirm_timeout_converts_seconds_to_whole_minutes() {
        use std::time::Duration;

        assert_eq!(junos_confirm_minutes(Duration::from_secs(60)).unwrap(), 1);
        assert_eq!(junos_confirm_minutes(Duration::from_secs(300)).unwrap(), 5);
    }

    /// A window Junos cannot honour is refused rather than rounded. Rounding up
    /// would hand the caller a deadline the device will not keep, and a
    /// confirmed commit with the wrong window is worse than none.
    #[test]
    fn confirm_timeout_refuses_windows_junos_cannot_honour() {
        use std::time::Duration;

        let err =
            junos_confirm_minutes(Duration::from_secs(30)).expect_err("sub-minute must be refused");
        assert!(err.to_string().contains("at least 60 seconds"), "{err}");

        let err = junos_confirm_minutes(Duration::from_secs(90))
            .expect_err("part-minute must be refused");
        assert!(err.to_string().contains("whole number of minutes"), "{err}");
    }

    /// The native `<commit-configuration>` RPC, not the RFC `<commit><confirmed/>`
    /// form. Only the native one survives the issuing session, which is what lets
    /// the session return to the pool (#227).
    #[test]
    fn confirmed_commit_uses_the_junos_native_rpc() {
        let xml = build_confirmed_commit_xml(5, "no-change-ref by tok (agent)");

        assert!(xml.starts_with("<commit-configuration>"), "{xml}");
        assert!(xml.contains("<confirmed/>"), "{xml}");
        assert!(
            xml.contains("<confirm-timeout>5</confirm-timeout>"),
            "{xml}"
        );
        assert!(
            !xml.contains("<commit>"),
            "must not emit the session-bound RFC form: {xml}"
        );
    }

    /// A comment reaches the device inside XML, so a stray angle bracket in the
    /// attribution must not be able to close the element early.
    #[test]
    fn confirmed_commit_escapes_the_comment() {
        let xml = build_confirmed_commit_xml(1, "evil </log><foo> & bar");

        assert!(!xml.contains("<foo>"), "unescaped markup leaked: {xml}");
        assert!(xml.contains("&lt;/log&gt;"), "{xml}");
        assert!(xml.contains("&amp; bar"), "{xml}");
    }

    fn agent_attribution(model_id: &str) -> Attribution {
        let mut attribution = Attribution::stdio();
        attribution.actor_type = mecmcp_audit::ActorType::Agent;
        attribution.on_behalf_of = Some("mharman".to_owned());
        attribution.agent = Some(mecmcp_audit::AgentIdentity {
            model_id: model_id.to_owned(),
            session_id: String::new(),
            client_name: None,
            provider: "anthropic".to_owned(),
            provider_tier: mecmcp_audit::Tier::Private,
            skills_used: Vec::new(),
        });
        attribution
    }

    /// A token cannot vouch for which model ran, so token-built attribution
    /// leaves `model_id` empty. The comment must then omit the segment rather
    /// than trail a valueless `model=` (mecmcp#75).
    #[test]
    fn commit_comment_omits_an_unasserted_model() {
        let comment = format_attribution(&agent_attribution(""));

        assert!(
            comment.contains("via anthropic-private"),
            "provider must still appear: {comment}"
        );
        assert!(
            !comment.contains("model="),
            "an empty model must not be recorded as a claim: {comment}"
        );
    }

    #[test]
    fn commit_comment_keeps_a_model_the_caller_asserted() {
        let comment = format_attribution(&agent_attribution("claude-opus-5"));

        assert!(
            comment.contains("via anthropic-private model=claude-opus-5"),
            "an asserted model must survive: {comment}"
        );
    }

    #[test]
    fn commit_comment_includes_request_id() {
        let comment = format_attribution(&agent_attribution(""));

        assert!(
            comment.contains("request.id="),
            "request ID must be present for provenance join: {comment}"
        );
    }

    #[test]
    fn commit_comment_request_id_matches_attribution() {
        use uuid::Uuid;

        let mut attribution = agent_attribution("");
        let expected_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        attribution.request_id = expected_id;

        let comment = format_attribution(&attribution);

        assert!(
            comment.contains(&format!("request.id={}", expected_id)),
            "request ID must match attribution's request_id: {comment}"
        );
    }

    #[test]
    fn normalise_candidate_trims_whitespace() {
        let xml = r#"
            <configuration>
                <system>
                    <host-name>r1</host-name>
                </system>
            </configuration>
        "#;
        let normalised = normalise_candidate_for_fingerprint(xml);
        assert!(normalised.contains("<configuration>"));
        assert!(normalised.contains("<host-name>r1</host-name>"));
        // Document order is preserved: the opening element still precedes what
        // it contains.
        let open = normalised.find("<configuration>").expect("root present");
        let inner = normalised.find("<host-name>").expect("child present");
        assert!(open < inner, "normalisation must not reorder the document");
    }

    #[test]
    fn normalise_candidate_detects_reordering() {
        // Junos evaluates security policies in the order they appear, so moving
        // one is a real configuration change. An earlier version of this
        // normalisation sorted the lines, which made a reordered policy list
        // hash identically to the original — the fingerprint would have reported
        // no drift on a change that alters what the device does.
        let original = r#"<configuration>
            <policy><name>permit-dns</name></policy>
            <policy><name>deny-all</name></policy>
        </configuration>"#;
        let reordered = r#"<configuration>
            <policy><name>deny-all</name></policy>
            <policy><name>permit-dns</name></policy>
        </configuration>"#;

        assert_ne!(
            normalise_candidate_for_fingerprint(original),
            normalise_candidate_for_fingerprint(reordered),
            "reordering policies must change the fingerprint"
        );
    }

    #[test]
    fn normalise_candidate_strips_junos_timestamp() {
        // Junos includes junos:changed-seconds on the root element, which changes
        // on every read. Fingerprinting must strip it for determinism.
        let xml1 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration junos:changed-seconds="1700000999">
            <system><host-name>r1</host-name></system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // The normalised forms must be identical because only the timestamp differs.
        assert_eq!(norm1, norm2, "timestamp-only change must hash identically");

        // Verify the timestamp was actually removed.
        assert!(
            !norm1.contains("junos:"),
            "junos: attributes must be stripped"
        );
    }

    #[test]
    fn normalise_candidate_detects_real_config_change() {
        let xml1 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r2</host-name></system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // A real configuration change (r1 → r2) must produce different fingerprints.
        assert_ne!(
            norm1, norm2,
            "real config change must produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_hash_format() {
        use sha2::{Digest, Sha256};

        // Fingerprint must return "sha256:{lowercase-hex}" format.
        let xml = r#"<configuration><system><host-name>test</host-name></system></configuration>"#;
        let normalised = normalise_candidate_for_fingerprint(xml);
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let fingerprint = format!("sha256:{}", crate::tools::transfer_file::hex32(&hash));

        // Verify the format.
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), 7 + 64); // "sha256:" + 64 hex chars
        assert!(fingerprint[7..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn format_attribution_includes_all_fields() {
        use mecmcp_audit::{ActorType, AgentIdentity, Principal, Tier};
        use uuid::Uuid;

        let request_id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let attribution = Attribution {
            principal: Principal::Token("alice".into()),
            actor_type: ActorType::Agent,
            agent: Some(AgentIdentity {
                model_id: "claude-sonnet-4-5".into(),
                session_id: "sess123".into(),
                client_name: None,
                provider: "anthropic".into(),
                provider_tier: Tier::Public,
                skills_used: vec![],
            }),
            on_behalf_of: Some("bob".into()),
            change_ref: Some("CHG0012345".into()),
            request_id,
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
            approver: None,
            change_set_id: None,
        };
        let formatted = format_attribution(&attribution);
        assert!(formatted.contains("CHG0012345"));
        assert!(formatted.contains("alice"));
        assert!(formatted.contains("anthropic"));
        assert!(formatted.contains("public"));
        assert!(formatted.contains("bob"));
        assert!(formatted.contains("agent"));
        assert!(
            formatted.contains(&format!("request.id={}", request_id)),
            "request_id must be present for provenance join: {formatted}"
        );
    }

    /// Build an attribution carrying the two-person evidence (#307).
    fn two_person_attribution(approver: Option<&str>, change_set_id: Option<&str>) -> Attribution {
        use mecmcp_audit::{ActorType, Principal};
        Attribution {
            principal: Principal::Token("claude-test".into()),
            actor_type: ActorType::Agent,
            agent: None,
            on_behalf_of: Some("mharman".into()),
            change_ref: None,
            request_id: uuid::Uuid::nil(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
            approver: approver.map(str::to_owned),
            change_set_id: change_set_id.map(str::to_owned),
        }
    }

    /// The defect: the device's commit log never named the second principal.
    ///
    /// Reading the firewall alone, a two-person apply was indistinguishable
    /// from a single-operator change.
    #[test]
    fn format_attribution_names_the_approver_and_change_set() {
        let attribution = two_person_attribution(
            Some("codex-approver"),
            Some("86324b20a3ecbfde732b981a8c69a664d44b176c29b5cdaf59e23e4ea96d4175"),
        );

        let formatted = format_attribution(&attribution);

        assert!(
            formatted.contains("approved-by=codex-approver"),
            "the approver must reach the device: {formatted}"
        );
        assert!(
            formatted.contains("change-set=86324b20a3ecbfde"),
            "the change set must reach the device: {formatted}"
        );
    }

    /// The id is truncated to a correlating prefix, not carried whole.
    ///
    /// A Junos commit comment is a bounded field shared with every other
    /// attribution field, and 64 hex characters would be over a third of it to
    /// say something 16 already says: 64 bits is ample to find one change set
    /// in a store that holds tens.
    #[test]
    fn change_set_id_is_truncated_to_a_correlating_prefix() {
        let full = "86324b20a3ecbfde732b981a8c69a664d44b176c29b5cdaf59e23e4ea96d4175";
        let formatted = format_attribution(&two_person_attribution(None, Some(full)));

        assert!(
            formatted.contains("change-set=86324b20a3ecbfde"),
            "expected the 16-character prefix: {formatted}"
        );
        assert!(
            !formatted.contains(full),
            "the full 64-character id must not be written: {formatted}"
        );
    }

    /// A waived or single-operator apply names no approver.
    ///
    /// Following the rule mecmcp#75 established for `model=`: omit the segment
    /// rather than write an empty claim. `approved-by=` with nothing after it
    /// reads, to anyone scanning a commit log, like an approval that happened.
    #[test]
    fn format_attribution_omits_an_absent_approver() {
        let formatted = format_attribution(&two_person_attribution(None, Some("86324b20a3ecbfde")));

        assert!(
            !formatted.contains("approved-by"),
            "a waived apply must not imply an approver: {formatted}"
        );
        assert!(
            formatted.contains("change-set=86324b20a3ecbfde"),
            "the change set is still named: {formatted}"
        );
    }

    /// An apply outside the change-set flow gains neither segment.
    #[test]
    fn format_attribution_omits_both_when_there_is_no_change_set() {
        let formatted = format_attribution(&two_person_attribution(None, None));

        assert!(!formatted.contains("approved-by"), "{formatted}");
        assert!(!formatted.contains("change-set"), "{formatted}");
        assert!(
            formatted.contains("by claude-test"),
            "the existing fields must survive: {formatted}"
        );
    }

    /// The comment must stay inside the Junos ceiling even at full stretch.
    ///
    /// Every variable field is a token name, capped at 128 characters by
    /// `mecmcp_auth::MAX_TOKEN_NAME`, and `change_ref` is caller-supplied. The
    /// worst realistic case must leave headroom under the 512-character limit
    /// Junos documents for a commit comment, or an apply fails at the very last
    /// step, after the device has already been staged.
    #[test]
    fn worst_case_comment_stays_within_the_junos_ceiling() {
        use mecmcp_audit::{ActorType, AgentIdentity, Principal, Tier};

        let long = "n".repeat(128);
        let attribution = Attribution {
            principal: Principal::Token(long.clone()),
            actor_type: ActorType::Agent,
            agent: Some(AgentIdentity {
                model_id: "claude-opus-5".into(),
                session_id: String::new(),
                client_name: None,
                provider: "anthropic".into(),
                provider_tier: Tier::Public,
                skills_used: vec![],
            }),
            on_behalf_of: Some(long.clone()),
            change_ref: Some("CHG0012345".into()),
            request_id: uuid::Uuid::nil(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
            approver: Some(long),
            change_set_id: Some("86324b20a3ecbfde732b981a8c69a664d44b176c29b5cdaf".into()),
        };

        let formatted = format_attribution(&attribution);

        assert!(
            formatted.len() <= 512,
            "commit comment is {} characters, over the 512 Junos allows: {formatted}",
            formatted.len()
        );
    }

    #[test]
    fn normalise_candidate_does_not_strip_junos_from_element_text() {
        // Defect #5 regression guard: A literal "junos:" in element text
        // (e.g., <description>junos:foo</description>) must NOT be treated as
        // an attribute. The previous unanchored substring search would strip
        // it, causing two genuinely different configs to hash identically.
        let xml1 = r#"<configuration>
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration>
            <system>
                <host-name>r1</host-name>
                <description>junos:style configuration</description>
            </system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // The second config has a description with literal "junos:" text.
        // This is a real difference and must produce different fingerprints.
        assert_ne!(
            norm1, norm2,
            "literal 'junos:' in element text must not cause fingerprint collision"
        );

        // Verify the description text was preserved (not stripped).
        assert!(
            norm2.contains("junos:style configuration"),
            "element text containing 'junos:' must be preserved"
        );
    }

    #[test]
    fn normalise_candidate_strips_junos_attrs_from_opening_tags() {
        // Defect #5 fix verification: junos: attributes in opening tags ARE
        // stripped, but element text containing "junos:" is preserved.
        let xml = r#"<configuration junos:changed-seconds="1700000000">
            <system junos:style="curly">
                <host-name>r1</host-name>
                <description>junos:style configuration</description>
            </system>
        </configuration>"#;

        let norm = normalise_candidate_for_fingerprint(xml);

        // Attributes junos:changed-seconds and junos:style must be stripped.
        assert!(
            !norm.contains("junos:changed-seconds"),
            "junos:changed-seconds attribute must be stripped"
        );
        assert!(
            !norm.contains("junos:style=\"curly\""),
            "junos:style attribute must be stripped"
        );

        // Element text "junos:style configuration" must be preserved.
        assert!(
            norm.contains("junos:style configuration"),
            "element text 'junos:style configuration' must be preserved"
        );
    }

    /// rustnetconf 0.14.3 reports a connection lost *after* `<commit>` was sent
    /// as its own variant rather than as a generic transport error. The device
    /// may have committed, so this is the single most important thing to call
    /// uncertain: classified as a known rejection, the apply is recorded as
    /// failed and cleanup runs against a device that may already hold the
    /// change (#322).
    #[test]
    fn a_lost_connection_after_commit_is_uncertainty_not_a_rejection() {
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::CommitUnknown));

        assert!(
            is_transport_uncertainty(&error),
            "CommitUnknown means the commit may have landed: {error}"
        );
    }

    #[test]
    fn is_transport_uncertainty_detects_timeout() {
        // The error string is what matters for classification, not the exact type.
        // Create a mock error with "timeout" in the message.
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        // Use a parse error with "timeout" in the message to test the classifier.
        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "operation timed out waiting for response".into(),
        )));
        assert!(
            is_transport_uncertainty(&error),
            "timeout must be classified as transport uncertainty"
        );

        // Test other uncertainty patterns.
        let error2 = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "connection closed unexpectedly".into(),
        )));
        assert!(
            is_transport_uncertainty(&error2),
            "connection closed must be classified as transport uncertainty"
        );
    }

    #[test]
    fn is_transport_uncertainty_does_not_match_rpc_errors() {
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};
        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError(Box::new(
            rustnetconf::error::RpcServerError {
                error_type: None,
                tag: rustnetconf::types::ErrorTag::OperationFailed,
                severity: None,
                app_tag: None,
                path: None,
                message: "syntax error".into(),
                info: None,
            },
        ))));
        assert!(
            !is_transport_uncertainty(&error),
            "RPC server error must NOT be classified as transport uncertainty"
        );
    }

    #[test]
    fn finding3_server_error_with_timeout_in_message_is_not_uncertain() {
        // Finding 3 (P2) regression guard: A ServerError (explicit <rpc-error>
        // from the device) whose message happens to contain "timeout" is still
        // a known rejection, not Indeterminate. The previous string-matching
        // classifier would treat this as uncertain.
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError(Box::new(
            rustnetconf::error::RpcServerError {
                error_type: None,
                tag: rustnetconf::types::ErrorTag::InvalidValue,
                severity: None,
                app_tag: None,
                path: None,
                message: "invalid value for 'timeout' parameter: must be 1..3600".into(),
                info: None,
            },
        ))));

        assert!(
            !is_transport_uncertainty(&error),
            "ServerError with 'timeout' in message must be classified as a known rejection"
        );
    }

    #[test]
    fn finding3_parse_error_is_uncertain() {
        // ParseError can be a framing failure or unparseable device reply.
        // Treat it as uncertainty (the safer default).
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "unexpected element".into(),
        )));

        assert!(
            is_transport_uncertainty(&error),
            "ParseError must be classified as uncertainty"
        );
    }

    #[test]
    fn finding3_transport_errors_are_uncertain() {
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, TransportError};

        let transport = RustEzError::Netconf(NetconfError::Transport(TransportError::Connect(
            "connection refused".into(),
        )));
        assert!(
            is_transport_uncertainty(&transport),
            "Transport error must be classified as uncertainty"
        );
    }

    // Three fixes in this round have NO automated test, and that is a gap rather
    // than an oversight:
    //
    //   - the confirmed-commit refusal happening before anything is staged,
    //   - a partial-stage cleanup failure surfacing in the returned error,
    //   - pooling being re-enabled after a clean commit.
    //
    // `JunosTransaction` is constructed from a `DeviceManager` and reaches the
    // device through a real `PooledDevice`, so there is no seam to inject a
    // failing backend the way `candidate_transaction.rs` does with `FakeBackend`.
    // Testing these means either a live device or giving this type the same
    // backend abstraction, which is a larger change than the fixes themselves and
    // is tracked separately.
    //
    // Recording it here so the absence is visible in the file rather than only in
    // a review comment.
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod atomicity_tests {
    use super::*;

    /// The declaration an approval prompt is keyed on.
    ///
    /// Inherited from the trait this would be `nothing_guaranteed()`, telling
    /// an operator that a Junos change offers no atomicity, no dry run and no
    /// rollback -- none of which is true of candidate staging with
    /// `commit check` and rollback.
    #[test]
    fn junos_declares_the_candidate_configuration_guarantees() {
        let atomicity = JunosTransaction::DECLARED_ATOMICITY;
        assert_eq!(
            atomicity,
            mecmcp_changeset::Atomicity::candidate_configuration(),
            "Junos commits a candidate configuration and must say so"
        );
        assert!(atomicity.atomic_apply, "a commit lands all staged changes");
        assert!(atomicity.dry_run_validation, "commit check validates first");
        assert!(atomicity.guaranteed_rollback, "rollback is exact");
    }
}

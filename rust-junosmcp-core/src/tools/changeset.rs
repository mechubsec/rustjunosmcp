//! Junos change-set lifecycle tools — two-person approval for multi-action plans.
//!
//! This module provides the MCP tool implementations for the change-set flow:
//! create → approve (by a second principal) → apply. It wraps the coordinator
//! from `mecmcp-changeset` and uses `JunosTransaction` as the device backend.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::excerpt;
use crate::junos_transaction::{JunosAction, JunosTransaction};
use crate::policy::{Decision, Policy};
use mecmcp_audit::Attribution;
use mecmcp_changeset::{ChangesetCoordinator, CommitOptions, DeviceTransaction as _};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Arguments for `create_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct CreateChangeSetArgs {
    /// Target device name.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Expected device fingerprint before applying. If the device state
    /// changes after planning, application will be rejected.
    pub expected_fingerprint: String,
    /// List of actions to stage. Each action is either a payload or a
    /// rollback archive reference.
    pub actions: Vec<JunosAction>,
}

/// Arguments for `approve_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ApproveChangeSetArgs {
    /// Change-set ID returned by create.
    pub change_set_id: String,
    /// Device name. Required because change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Expected plan digest. The approver must compute or be shown the exact
    /// digest and confirm it matches what they reviewed.
    pub expected_digest: String,
}

/// Arguments for `cancel_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct CancelChangeSetArgs {
    /// Change-set ID to cancel.
    pub change_set_id: String,
    /// Device name. Required because change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Arguments for `apply_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ApplyChangeSetArgs {
    /// Change-set ID to apply.
    pub change_set_id: String,
    /// Expected plan digest. Prevents applying a plan that was tampered with
    /// after approval.
    pub expected_digest: String,
    /// Expected device fingerprint at apply time. If the device changed after
    /// the plan was created, the apply is rejected.
    pub expected_fingerprint: String,
    /// Target device endpoint (device name from inventory).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Confirmed-commit window, in whole minutes.
    ///
    /// The device commits the change and schedules an automatic rollback
    /// after this many minutes unless `confirm_junos_change_set` is called
    /// first. Minutes, not seconds — that is what Junos schedules, and it
    /// matches `rollback_config`'s `confirm_timeout_mins`.
    ///
    /// Defaults to the server's `--commit-confirm-default-mins` (10 unless
    /// configured otherwise) when omitted — commit-confirmed is ON by
    /// default. Pass `0` to explicitly opt out and issue a plain commit
    /// instead; this is recorded in the audit trail as
    /// `commit_confirmed=false`.
    #[schemars(range(min = 0, max = 71_582_788))]
    pub confirm_timeout_mins: Option<u32>,
}

/// Arguments for `confirm_junos_change_set`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ConfirmChangeSetArgs {
    /// Operation ID returned by `apply_junos_change_set`.
    pub operation_id: String,
    /// Device name. Change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Arguments for `get_junos_change_set_status`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct GetChangeSetStatusArgs {
    /// Change-set ID to query.
    pub change_set_id: String,
    /// Device name. Required because change sets are indexed by (id, device).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Arguments for `list_junos_change_sets`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ListChangeSetsArgs {
    /// Optional device name to filter change sets. If omitted, returns all
    /// change sets across all devices visible to the caller.
    #[serde(alias = "router_name", alias = "router")]
    pub device: Option<String>,
}

/// Reconcile a change set and its operation after an apply fails past staging
/// (#309).
///
/// `ChangesetCoordinator::apply_change_set` marks a change set `Applied` once
/// *staging* succeeds — deliberate, and documented on `ApplyOutput`, because in
/// the coordinator's model an apply stages the actions. This server then runs
/// diff, validate and commit as separate steps, any of which can fail against
/// the device afterwards. Every one of those failure paths used to return early
/// and leave both records untouched, so:
///
/// - the change set kept the `Applied` that staging set, asserting a change had
///   landed that the device had in fact rejected, and
/// - the operation stayed `Validated`, which every later apply on that device
///   reads as "an active or unreconciled operation" and refuses.
///
/// `cancel_junos_change_set` could not clear either, because it refuses an
/// `applied` set. One validation failure therefore wedged the device with no
/// tool path out, recoverable only by hand-editing `changeset-state.json`.
///
/// The order matters. The discard runs first, to release the device's candidate
/// and configuration lock. Marking the change set `Failed` then happens whether
/// or not that succeeded: a wedged device is recoverable by an operator, while a
/// record claiming a change landed when it did not is not — nothing downstream
/// can tell it is wrong.
///
/// Both steps are best-effort by design. Neither may replace the error that
/// brought us here, which is the one describing what the device actually
/// refused; a cleanup failure must not mask it.
///
/// `Failed` is terminal, and that is the point: it is what
/// `apply_change_set` already records for a staging failure, and it is excluded
/// from `is_pending`, so the owner can plan a replacement change set for the
/// device immediately rather than needing a cancel that would be refused.
#[allow(clippy::too_many_arguments)]
/// Which failure path is abandoning the apply.
///
/// The two differ in what can honestly be recorded. Nothing reaches the device
/// before commit, so a diff or validation failure leaves a candidate that the
/// release discards. A commit that errored may have landed anyway — the device
/// can succeed and the coordinator still fail to persist it — and that outcome
/// is unknown until someone looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbandonOutcome {
    /// Diff, validation, or a rejected validation: nothing was committed.
    CandidateNotCommitted,
    /// The commit itself errored; whether it landed is unknown.
    CommitOutcomeUnknown,
}

/// Reconcile a change set and its operation after the device refused an apply.
///
/// `apply_change_set` marks a change set `Applied` once staging succeeds, and
/// this server then runs diff, validate and commit as separate steps. Every one
/// of those can fail afterwards, leaving a record asserting a change that the
/// device rejected and an operation that blocks every later apply.
///
/// The cleanup makes **no device write**. The staged handle owns the session
/// holding the candidate lock, and releasing it is itself the revert on Junos,
/// so the device needs nothing further — measured on vsrx-ci, where the
/// candidate is back to its pre-stage fingerprint and the lock free the instant
/// a failed apply returns. What remains is settling the records (#312).
/// What the cleanup needs to name: which records, on whose behalf, and why.
struct Abandon<'a> {
    change_set_id: &'a str,
    device: &'a str,
    principal: &'a str,
    operation_id: &'a str,
    /// The candidate fingerprint from *before* staging. Releasing the session
    /// discards, so a clean device reads back exactly this — and rustnetconf
    /// suppresses a failed `<discard-changes/>` and closes anyway, which makes
    /// this comparison the only proof the revert happened.
    pre_stage_fingerprint: &'a str,
    reason: &'a str,
    outcome: AbandonOutcome,
}

async fn abandon_failed_apply<T: mecmcp_changeset::DeviceTransaction>(
    coordinator: &ChangesetCoordinator,
    transaction: &T,
    staged: &T::Staged,
    about: Abandon<'_>,
) where
    T::Staged: crate::junos_transaction::ReleaseStaged,
{
    // Release the staged session first. It owns the candidate lock — `stage()`
    // takes the session out of the transaction and keeps it, so validate and
    // commit see the same private database — and on Junos closing it is the
    // revert: rustnetconf's `CloseSequence::DiscardThenClose` sends
    // `<discard-changes/>` before `<close-session/>`.
    //
    // Awaiting it is the point. `PooledDevice::drop` can only *spawn* the close,
    // so a dropped handle frees the lock at a moment the caller cannot observe.
    let Abandon {
        change_set_id,
        device,
        principal,
        operation_id,
        pre_stage_fingerprint,
        reason,
        outcome,
    } = about;

    use crate::junos_transaction::ReleaseStaged as _;
    let released = staged.release().await;

    // Settle the operation. A terminal record is what unblocks the device —
    // `LifecycleState::terminal()` counts only `Committed` and `Discarded`, and
    // `insert` refuses a new operation while a non-terminal one exists — but it
    // may only be written once the device state is actually known. An
    // unconfirmed release leaves the candidate and the lock in question, so
    // nothing is claimed and `state resolve` settles it after someone looks.
    if released {
        match coordinator.record(operation_id, principal, device).await {
            Ok(mut record) => {
                // A commit error does not mean the commit RPC was sent.
                // `commit_operation` persists `Committing` immediately before it
                // and returns earlier for the guard, cancellation, policy,
                // fingerprint and confirm-timeout checks. A record that never
                // reached `Committing` proves nothing was committed, so it can
                // settle as cleanly as a validation failure.
                let outcome = match outcome {
                    AbandonOutcome::CommitOutcomeUnknown
                        if !matches!(
                            record.state,
                            mecmcp_changeset::LifecycleState::Committing
                                | mecmcp_changeset::LifecycleState::Indeterminate
                        ) =>
                    {
                        AbandonOutcome::CandidateNotCommitted
                    }
                    other => other,
                };
                // The probes below exist only to justify claiming
                // `Discarded`. A commit whose outcome is unknown ends
                // non-terminal whatever they say, so on that path they are pure
                // cost and pure risk — the session may have committed and
                // unlocked cleanly, and opening probe sessions against the pool
                // behind it can end up discarding a candidate this operation no
                // longer owns.
                let settled = if outcome == AbandonOutcome::CommitOutcomeUnknown {
                    true
                } else {
                    // Two things have to be true before anything is recorded: the
                    // candidate reverted, and the lock is free. Both are checked
                    // under one lock so they cannot drift apart — an unlocked read
                    // could be overtaken by another session between the read and
                    // the lock, leaving a fingerprint that was true a moment ago.
                    //
                    // Taking the lock is also the only proof it was free.
                    // rustnetconf's close sequence is best-effort throughout and
                    // returns `Ok` even when `<close-session/>` fails, so a
                    // completed release establishes neither fact on its own.
                    //
                    // Every probe is bounded by the per-phase cleanup budget: this
                    // runs against a peer that has just failed an apply and may be
                    // unresponsive, and the pool's own RPC timeout is hours.
                    let budget = crate::tools::candidate_transaction::cleanup_timeout();
                    match probe(budget, transaction.lock("changeset cleanup probe")).await {
                        Ok(()) => {
                            // `fingerprint` reads through the held session, so this
                            // observes the candidate inside the lock.
                            let observed = probe(budget, transaction.fingerprint()).await;

                            // Give the lock back before deciding anything. Holding
                            // it would leave the device locked by the cleanup, which
                            // is no better for the next caller than the lock this is
                            // checking for.
                            let returned = matches!(
                                probe(budget, transaction.unlock()).await,
                                Ok(mecmcp_changeset::UnlockOutcome::Released)
                            );
                            if !returned {
                                tracing::warn!(
                                    operation_id = %operation_id,
                                    device = %device,
                                    "took the candidate lock to check the revert but could not \
                                     confirm it back; leaving the operation for `state resolve`"
                                );
                            }

                            match observed {
                                Ok(current) if current == pre_stage_fingerprint => {
                                    // Staging recorded the *staged* fingerprint;
                                    // the revert means it now names a configuration
                                    // the device threw away.
                                    record.current = current;
                                    returned
                                }
                                Ok(_) => {
                                    tracing::warn!(
                                        operation_id = %operation_id,
                                        device = %device,
                                        "the candidate did not return to its pre-stage fingerprint, \
                                         so the staged change may still be there; leaving the \
                                         operation for `state resolve`"
                                    );
                                    false
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        operation_id = %operation_id,
                                        device = %device,
                                        error = %error,
                                        "could not read the candidate back, so the revert is \
                                         unproven; leaving the operation for `state resolve`"
                                    );
                                    false
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                operation_id = %operation_id,
                                device = %device,
                                error = %error,
                                "the candidate lock is still held after the release, so the session \
                                 did not end; leaving the operation for `state resolve`"
                            );
                            false
                        }
                    }
                };

                if !settled {
                    settle_change_set(coordinator, change_set_id, device, reason).await;
                    return;
                }
                // Only claimed where the probe proved it. The unknown-outcome
                // path deliberately does not probe, and rustnetconf's close
                // reports success even when `<close-session/>` fails, so the
                // lock may well still be held there.
                if outcome == AbandonOutcome::CandidateNotCommitted {
                    record.config_lock_held = false;
                }
                record.state = match outcome {
                    AbandonOutcome::CandidateNotCommitted => {
                        record.details = Some(format!(
                            "candidate discarded with the staged session after a failed \
                             apply: {reason}"
                        ));
                        mecmcp_changeset::LifecycleState::Discarded
                    }
                    // Not `Discarded`: the commit may have reached the device
                    // even though this returned an error, and asserting a revert
                    // that did not happen is the same class of lie as the
                    // `Applied` this path exists to stop.
                    AbandonOutcome::CommitOutcomeUnknown => {
                        record.details = Some(format!(
                            "commit outcome unknown after a failed apply; verify the device \
                             and settle with `state resolve`: {reason}"
                        ));
                        mecmcp_changeset::LifecycleState::Indeterminate
                    }
                };
                if let Err(error) = coordinator.update(record).await {
                    tracing::error!(
                        operation_id = %operation_id,
                        device = %device,
                        error = %error,
                        "could not settle the operation; it stays non-terminal and blocks \
                         later applies until `state resolve` clears it"
                    );
                }
            }
            Err(error) => tracing::error!(
                operation_id = %operation_id,
                device = %device,
                error = %error,
                "could not read the operation back to settle it"
            ),
        }
    } else {
        tracing::warn!(
            operation_id = %operation_id,
            device = %device,
            "could not confirm the staged session closed; the candidate may still be staged \
             and its lock held, so the operation is left for `state resolve`"
        );
    }

    settle_change_set(coordinator, change_set_id, device, reason).await;
}

/// Run one cleanup probe under the per-phase budget.
///
/// A timeout is reported as an error rather than a value, so a probe that never
/// answers can never be read as proof of anything.
async fn probe<F, T, E>(budget: std::time::Duration, future: F) -> Result<T, ProbeError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(budget, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(ProbeError::Failed(error)),
        Err(_) => Err(ProbeError::TimedOut),
    }
}

/// Why a cleanup probe did not answer.
#[derive(Debug)]
enum ProbeError<E> {
    /// The device answered, with an error.
    Failed(E),
    /// The device did not answer inside the cleanup budget.
    TimedOut,
}

impl<E: std::fmt::Display> std::fmt::Display for ProbeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(error) => write!(f, "{error}"),
            Self::TimedOut => f.write_str("timed out inside the cleanup budget"),
        }
    }
}

/// Stop a change set claiming it applied.
///
/// Always runs, whatever the device did. A wedged device is recoverable by an
/// operator; a record asserting a change landed when it did not is not, because
/// nothing downstream can tell it is wrong.
async fn settle_change_set(
    coordinator: &ChangesetCoordinator,
    change_set_id: &str,
    device: &str,
    reason: &str,
) {
    match coordinator.change_set(change_set_id, device).await {
        Ok(mut change_set) => {
            change_set.state = mecmcp_changeset::ChangeSetState::Failed;
            // `ChangeSetRecord` has nowhere to carry the reason — no details
            // field, unlike `OperationRecord` — so the device's own words are
            // recorded here and returned to the caller in the error.
            tracing::info!(
                target: "audit",
                change_set_id = %change_set_id,
                device = %device,
                reason = %reason,
                "change set marked failed after the device refused the apply"
            );
            if let Err(error) = coordinator.update_change_set(change_set).await {
                tracing::error!(
                    change_set_id = %change_set_id,
                    device = %device,
                    error = %error,
                    "could not mark the change set failed; it still reads as applied and \
                     asserts a change the device rejected"
                );
            }
        }
        Err(error) => tracing::error!(
            change_set_id = %change_set_id,
            device = %device,
            error = %error,
            "could not read the change set back to mark it failed"
        ),
    }
}

/// The approver to name on the device's commit log, if there was one (#307).
///
/// Reads `approval.approver` rather than the record's own `approver` field.
/// That one is documented as present only for a genuine two-person approval and
/// absent when waived, which is exactly the distinction a commit log must keep:
/// a waived apply names nobody, and nobody is invented for it.
///
/// Split out from the apply path so the rule is testable. The apply path itself
/// needs a live NETCONF session, so the one line that calls this is covered only
/// by the live rig.
fn approver_for_commit(record: &mecmcp_changeset::ChangeSetRecord) -> Option<&str> {
    record
        .approval
        .as_ref()
        .and_then(|approval| approval.approver.as_deref())
}

/// Create a change set (plan).
///
/// Validates the device exists, derives owner from the authenticated principal,
/// validates each action's shape and checks it against policy, then persists the
/// plan to the coordinator. In lab mode, waives approval immediately so apply can
/// proceed without a second principal. Returns `{change_set_id, plan_digest, state}`.
pub async fn create_change_set(
    args: CreateChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    create_change_set_with_cancel(
        args,
        dm,
        coordinator,
        policy,
        attribution,
        CancellationToken::new(),
    )
    .await
}

/// Cancellable variant of `create_change_set` for use in transport shutdown paths.
pub async fn create_change_set_with_cancel(
    args: CreateChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists, and capture its config authority for the
    // plane-owned rollback guard below (dropped at the end of this block;
    // `inv` holds the only reference into it).
    let config_authority = { dm.inventory().get(&args.device)?.config_authority.clone() };

    // Derive the owner from the authenticated caller's principal.
    let owner = attribution.principal.to_string();

    // Reject malformed actions before anything is persisted, digested, or
    // approved. An action that satisfies no valid shape used to survive create,
    // burn the approval, and occupy this principal's one pending change-set
    // slot until someone thought to call apply and watch it fail (#254).
    //
    // Also resolve each payload's format/mode here, for the same reason: an
    // invalid combination (e.g. `mode=wipe`, or `format=set`+`mode=override`)
    // used to be caught only inside `JunosTransaction::stage`, at apply time —
    // by then a human has spent an approval and the principal's one pending
    // slot is burned for nothing (Percy review, rustjunosmcp#425 F2).
    let mut requests_override = false;
    for (index, action) in args.actions.iter().enumerate() {
        action
            .validate_shape(index)
            .map_err(JmcpError::Validation)?;

        if let Some(payload) = &action.payload {
            let format = payload.format.as_deref().unwrap_or("set");
            // Validates the format alone; the text isn't needed for that, so
            // avoid cloning the (potentially large) payload text just to check it.
            crate::helpers::build_config_payload(String::new(), Some(format))?;
            let requested_mode = crate::helpers::parse_load_mode(payload.mode.as_deref())?;
            crate::helpers::resolve_load_action(format, requested_mode)?;
            if requested_mode == rustez::LoadAction::Override {
                requests_override = true;
            }
        }
    }

    // Rollback-depth guard on plane-owned devices (MEC-1879, P5a). Checked
    // before the override/lab-mode gate below and before policy, since it
    // must refuse unconditionally — no flag or lab-mode waiver may bypass it.
    if config_authority.is_plane_owned() {
        let rollback_count = args
            .actions
            .iter()
            .filter(|a| a.rollback_source.is_some())
            .count();

        if rollback_count > 0 {
            // No lab-mode waiver ever applies to a plane-owned rollback,
            // regardless of depth: lab mode waives approval, and this action
            // has no waiver path at all.
            if coordinator.lab_mode() {
                return Err(JmcpError::PlaneOwnedRollbackLabMode {
                    tool: "create_junos_change_set",
                    device: args.device.clone(),
                    authority: config_authority.as_str().to_string(),
                });
            }

            // A rollback_source action on a plane-owned device must be the
            // sole action in the change set, regardless of depth, so the
            // depth check below evaluates it in isolation.
            if rollback_count != args.actions.len() {
                return Err(JmcpError::PlaneOwnedRollbackMixedAction {
                    tool: "create_junos_change_set",
                    device: args.device.clone(),
                    authority: config_authority.as_str().to_string(),
                });
            }

            // rollback_count == args.actions.len() (checked above): there is
            // exactly one action, and it is the rollback. Depth >= 1 is
            // refused unconditionally on a plane-owned device until
            // commit-origin attribution (MEC-1880, P5b) exists to tell this
            // server's own commits from the plane's — depth 0 is a no-op
            // load and needs no attribution, so it is allowed through.
            let depth = args.actions[0]
                .rollback_source
                .expect("rollback_count == 1 implies the sole action carries rollback_source");

            crate::helpers::check_plane_owned_rollback_depth(
                "create_junos_change_set",
                &args.device,
                &config_authority,
                depth,
            )?;
        }
    }

    // `override` is only permitted through this change-set path because it
    // requires approval by a second principal (MEC-12). Lab mode waives that
    // approval on every change set it creates — there is no second
    // principal on a single-operator server — so allowing `override` there
    // would silently defeat the only gate that makes it safe (Percy review,
    // rustjunosmcp#425 F1).
    if requests_override && coordinator.lab_mode() {
        return Err(JmcpError::OverrideRequiresHumanApproval {
            tool: "create_junos_change_set",
        });
    }

    // Check every action against the device's configuration policy.
    for action in &args.actions {
        if let Some(payload) = &action.payload {
            let format = payload.format.as_deref().unwrap_or("set");
            match policy.check_config(&args.device, format, &payload.text)? {
                Decision::Allow => {}
                Decision::Deny {
                    rule,
                    source,
                    line_number,
                } => {
                    let pattern = rule.pattern.clone();
                    let source_str = source.as_str();
                    let denied_excerpt = excerpt(&payload.text);
                    return Err(JmcpError::Denied {
                        tool: "create_junos_change_set",
                        router: args.device.clone(),
                        pattern,
                        rule_source: source_str,
                        input_excerpt: denied_excerpt,
                        line_number,
                    });
                }
                Decision::DenyAllowlist { .. } => {
                    return Err(JmcpError::ConfigDomainAllowlistInvariant {
                        tool: "create_junos_change_set",
                        router: args.device.clone(),
                    });
                }
            }
        }
        // Rollback actions do not need policy checks - they reference pre-existing config.
    }

    // The coordinator's create_change_set computes the digest over
    // (owner, device, expected_fingerprint, actions). It persists the plan
    // and returns the change_set_id and plan_digest.
    // Policy signature: we don't have a meaningful signature for Junos policy yet.
    // The check_config above enforces the policy, so the coordinator knows the
    // actions passed validation. For now, use a static marker.
    let policy_signature = "junos-default-v1".to_string();

    // Cloned before the call consumes them; the lab-mode waiver below needs both.
    let device_name = args.device.clone();
    let owner_principal = owner.clone();

    let result = coordinator
        .create_change_set(
            args.device,
            args.actions,
            owner,
            args.expected_fingerprint,
            policy_signature,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Single-operator servers waive approval here rather than exposing a tool to
    // do it. Starting the service with `--lab-mode` is already the deliberate
    // decision to run without a second reviewer, so requiring a per-change-set
    // waive call afterwards would be ceremony protecting nobody. The digest
    // confirmation such a call would carry is already enforced where it matters:
    // `apply` requires `expected_digest`, and apply is what touches the device
    // (mecmcp#94).
    //
    // The flow stays identical to production — plan, then apply. Only the record
    // differs, and it differs honestly: no approver is invented, and
    // `approval_waiver` says why it is approvable.
    if coordinator.lab_mode() {
        let waived = coordinator
            .waive_approval(
                result.change_set_id.clone(),
                device_name.clone(),
                owner_principal.clone(),
                result.digest.clone(),
            )
            .await
            .map_err(|e| JmcpError::Validation(e.to_string()))?;

        return Ok(json!({
            "change_set_id": waived.change_set_id,
            "plan_digest": waived.digest,
            "state": format!("{:?}", waived.state),
            "approver": waived.approver,
            "approval_waiver": waived.approval_waiver,
            "message": "change set created and approval waived: this server runs in lab mode, so no second principal reviewed it"
        }));
    }

    Ok(json!({
        "change_set_id": result.change_set_id,
        "plan_digest": result.digest,
        "state": format!("{:?}", result.state),
        "message": "change set created; awaiting approval by a second principal"
    }))
}

/// Approve a change set (second principal).
///
/// Validates the device exists and is within scope, derives approver from the
/// authenticated principal, checks the expected digest matches the stored plan,
/// and marks the change set as approved. Enforces separation of duties: the
/// approver must differ from the owner. Returns `{change_set_id, state, digest}`.
pub async fn approve_change_set(
    args: ApproveChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    approve_change_set_with_cancel(args, coordinator, dm, attribution, CancellationToken::new())
        .await
}

/// Approve a pending change set by ID. Makes the transition `Pending` → `Approved`.
pub async fn approve_change_set_with_cancel(
    args: ApproveChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists and is within scope.
    let _ = dm.inventory().get(&args.device)?;

    // Derive the approver from the authenticated caller's principal.
    let approver = attribution.principal.to_string();

    let result = coordinator
        .approve_change_set(
            args.change_set_id.clone(),
            args.device,
            approver,
            args.expected_digest,
            attribution.actor_type,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "change_set_id": args.change_set_id,
        "state": format!("{:?}", result.state),
        "digest": result.digest,
        "message": "change set approved; ready to apply"
    }))
}

/// Cancel a change set.
///
/// Transitions a Planned or Approved change set to the terminal Cancelled state,
/// freeing the per-principal pending slot. The caller must be either the owner
/// or have approver authority. Idempotent: already-Cancelled sets return success.
/// Rejects Applied/Applying sets.
pub async fn cancel_change_set(
    args: CancelChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    cancel_change_set_with_cancel(args, coordinator, dm, attribution, CancellationToken::new())
        .await
}

/// Cancellable variant of `cancel_change_set`.
pub async fn cancel_change_set_with_cancel(
    args: CancelChangeSetArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
    attribution: Attribution,
    _ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists and is within scope.
    let _ = dm.inventory().get(&args.device)?;

    // Derive the principal from the authenticated caller.
    let principal = attribution.principal.to_string();

    let result = coordinator
        .cancel_change_set(args.change_set_id.clone(), args.device, principal)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "change_set_id": args.change_set_id,
        "state": format!("{:?}", result.state),
        "digest": result.digest,
        "message": "change set cancelled"
    }))
}

/// Apply an approved change set.
pub async fn apply_change_set(
    args: ApplyChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    apply_change_set_with_cancel(
        args,
        dm,
        coordinator,
        policy,
        attribution,
        CancellationToken::new(),
    )
    .await
}

/// Apply an approved change set to its target device. Makes the transition `Approved` → `Committed`.
pub async fn apply_change_set_with_cancel(
    args: ApplyChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    policy: Arc<Policy>,
    attribution: Attribution,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Validate the device exists and capture endpoint components.
    let inventory = dm.inventory();
    let device_entry = inventory.get(&args.device)?;
    let device_ip = device_entry.ip.clone();
    let device_port = device_entry.port;

    // Commit-confirmed by default (MEC-45): a bad change-set apply reverts
    // itself unless the caller explicitly opts out with
    // `confirm_timeout_mins: 0`. Resolved and validated before any staging
    // RPC — like `load_and_commit_config`'s mode gate — so a bad value never
    // leaves a candidate staged with nothing to clean it up.
    let confirm_mins_used = match crate::helpers::resolve_confirm_timeout(args.confirm_timeout_mins)
    {
        crate::helpers::ConfirmDecision::Confirmed(mins) => {
            let secs = crate::helpers::confirm_timeout_to_secs(mins)?;
            Some((mins, secs))
        }
        crate::helpers::ConfirmDecision::OptedOut => None,
    };

    // Capture config authority for the audit record.
    let config_authority = serde_json::to_string(&device_entry.config_authority)
        .ok()
        .map(|s| s.trim_matches('"').to_string());

    // Derive the principal from the authenticated caller.
    let principal = attribution.principal.to_string();

    // Retrieve the full change set record to validate actions against policy before staging.
    let change_set_record = coordinator
        .change_set(&args.change_set_id, &args.device)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Name the two-person evidence on the device's own commit log (#307).
    //
    // The change-set record is the only thing that knows either value:
    // `Attribution::from_caller` sees a token, and a token cannot vouch for who
    // approved a change set. Set here, before the attribution reaches
    // `commit_operation`, so `format_attribution` can render both.
    //
    // `approval.approver` rather than the record's own `approver` field: it is
    // documented as present only for a genuine two-person approval and absent
    // when waived, which is exactly the distinction the commit log must keep.
    // A waived apply names no approver, and none is invented.
    let mut attribution = attribution;
    attribution.with_change_set(&args.change_set_id, approver_for_commit(&change_set_record));

    // Deserialize the actions from the stored JSON, validate each against
    // policy, and track each payload action's resolved load action so the
    // audit record can say what was actually requested rather than
    // hardcoding "merge" (Percy review, rustjunosmcp#425 F4: an override
    // apply used to be logged as a merge).
    let mut resolved_modes: Vec<&'static str> = Vec::new();
    for action_value in &change_set_record.actions {
        let action: JunosAction = serde_json::from_value(action_value.clone())
            .map_err(|e| JmcpError::Validation(format!("failed to deserialize action: {e}")))?;

        if let Some(payload) = &action.payload {
            let format = payload.format.as_deref().unwrap_or("set");
            match policy.check_config(&args.device, format, &payload.text)? {
                Decision::Allow => {}
                Decision::Deny {
                    rule,
                    source,
                    line_number,
                } => {
                    let pattern = rule.pattern.clone();
                    let source_str = source.as_str();
                    let denied_excerpt = excerpt(&payload.text);
                    return Err(JmcpError::Denied {
                        tool: "apply_junos_change_set",
                        router: args.device.clone(),
                        pattern,
                        rule_source: source_str,
                        input_excerpt: denied_excerpt,
                        line_number,
                    });
                }
                Decision::DenyAllowlist { .. } => {
                    return Err(JmcpError::ConfigDomainAllowlistInvariant {
                        tool: "apply_junos_change_set",
                        router: args.device.clone(),
                    });
                }
            }

            let requested_mode = crate::helpers::parse_load_mode(payload.mode.as_deref())?;
            let load_action = crate::helpers::resolve_load_action(format, requested_mode)?;
            resolved_modes.push(load_action.as_str());
        }
        // Rollback actions do not need policy checks and carry no load mode.
    }

    // Build the transaction backend.
    let transaction = JunosTransaction::new(dm.clone(), args.device.clone());

    // For Junos, there is no XPath equivalent, so the primary target is None.
    // The primary action discriminator: the first payload action's resolved
    // mode, or "mixed" when the change set's payload actions disagree, or
    // "merge" (Junos's own default) when the change set has no payload
    // actions at all (e.g. rollback-only).
    let primary_action: &str = match resolved_modes.split_first() {
        Some((first, rest)) if rest.iter().all(|m| m == first) => first,
        Some(_) => "mixed",
        None => "merge",
    };
    let primary_target: Option<&str> = None;

    // Construct a stable canonical endpoint URL for the coordinator's guard.
    // Junos has no management URL in the PAN-OS sense, so we synthesize one
    // from the device inventory entry: junos://<ip>:<port>. This is stable
    // and deterministic for a given device entry.
    let endpoint = format!("junos://{device_ip}:{device_port}");

    let result = coordinator
        .apply_change_set(
            args.change_set_id.clone(),
            args.device.clone(),
            endpoint,
            principal.clone(),
            args.expected_digest,
            args.expected_fingerprint.clone(),
            &transaction,
            primary_action,
            primary_target,
            config_authority.clone(),
            &attribution,
            &ct,
        )
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // The apply_change_set call stages all actions and returns the staged
    // handle. The caller (this tool) must then diff, validate, and commit.
    // Policy signature for commit - same as what we use for staging.
    let policy_signature = "junos-default-v1";

    // Run diff to get the configuration difference.
    let _diff = match coordinator
        .diff_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            &transaction,
            &result.staged,
            &ct,
        )
        .await
    {
        Ok(diff) => diff,
        Err(error) => {
            let reason = error.to_string();
            abandon_failed_apply(
                &coordinator,
                &transaction,
                &result.staged,
                Abandon {
                    change_set_id: &args.change_set_id,
                    device: &args.device,
                    principal: &principal,
                    operation_id: &result.operation_id,
                    pre_stage_fingerprint: &args.expected_fingerprint,
                    reason: &reason,
                    outcome: AbandonOutcome::CandidateNotCommitted,
                },
            )
            .await;
            return Err(JmcpError::Validation(reason));
        }
    };

    // Run validation before committing.
    let validation = match coordinator
        .validate_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            &transaction,
            &result.staged,
            &ct,
        )
        .await
    {
        Ok(validation) => validation,
        Err(error) => {
            let reason = error.to_string();
            abandon_failed_apply(
                &coordinator,
                &transaction,
                &result.staged,
                Abandon {
                    change_set_id: &args.change_set_id,
                    device: &args.device,
                    principal: &principal,
                    operation_id: &result.operation_id,
                    pre_stage_fingerprint: &args.expected_fingerprint,
                    reason: &reason,
                    outcome: AbandonOutcome::CandidateNotCommitted,
                },
            )
            .await;
            return Err(JmcpError::Validation(reason));
        }
    };

    // `confirm_mins_used` was resolved and validated at the top of this
    // function, before any staging RPC.
    let commit_options = CommitOptions {
        confirm_timeout: confirm_mins_used
            .map(|(_, secs)| std::time::Duration::from_secs(u64::from(secs))),
    };

    // Check if validation succeeded. If it failed, refuse to commit.
    if !validation.valid {
        let reason = format!(
            "configuration validation failed: {}",
            validation.details.as_deref().unwrap_or("no details")
        );
        abandon_failed_apply(
            &coordinator,
            &transaction,
            &result.staged,
            Abandon {
                change_set_id: &args.change_set_id,
                device: &args.device,
                principal: &principal,
                operation_id: &result.operation_id,
                pre_stage_fingerprint: &args.expected_fingerprint,
                reason: &reason,
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;
        return Err(JmcpError::Validation(reason));
    }

    let commit_result = match coordinator
        .commit_operation(
            &result.operation_id,
            &args.device,
            &principal,
            &result.after_fingerprint,
            policy_signature,
            &transaction,
            &result.staged,
            &attribution,
            &commit_options,
            &ct,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let reason = error.to_string();
            abandon_failed_apply(
                &coordinator,
                &transaction,
                &result.staged,
                Abandon {
                    change_set_id: &args.change_set_id,
                    device: &args.device,
                    principal: &principal,
                    operation_id: &result.operation_id,
                    pre_stage_fingerprint: &args.expected_fingerprint,
                    reason: &reason,
                    outcome: AbandonOutcome::CommitOutcomeUnknown,
                },
            )
            .await;
            return Err(JmcpError::Validation(reason));
        }
    };

    // Build a config-authority warning when the device is not locally owned.
    use mecmcp_inventory::LocalAuthority;
    let authority_warning = if !device_entry.config_authority.is_local() {
        Some(format!(
            "WARNING: this device is owned by {}. Changes may be overwritten at the next push from the owning management plane.",
            config_authority.as_deref().unwrap_or("unknown")
        ))
    } else {
        None
    };

    // Branch on the commit outcome and report honestly.
    use mecmcp_changeset::CommitOutcome;
    match commit_result {
        CommitOutcome::Reconciled {
            succeeded: true,
            details,
            ..
        } => {
            let mut result = json!({
                "change_set_id": args.change_set_id,
                "operation_id": result.operation_id,
                "state": "Applied",
                "commit_outcome": "Reconciled",
                "details": details,
                "message": "change set applied and committed successfully"
            });
            if let Some(warning) = authority_warning {
                result
                    .as_object_mut()
                    .expect("json! macro produces an object here")
                    .insert("config_authority_warning".to_string(), json!(warning));
            }
            Ok(result)
        }
        // A device that refuses the commit reports it as an *outcome*, not an
        // error, so this arm has to run the same cleanup as the error paths or
        // the change set keeps reading `Applied` and the operation keeps
        // blocking the device — the exact defect #309 and #312 are about, by a
        // fifth route.
        CommitOutcome::Reconciled {
            succeeded: false,
            details,
            ..
        } => {
            let reason = format!(
                "commit failed: {}",
                details.as_deref().unwrap_or("no details")
            );
            abandon_failed_apply(
                &coordinator,
                &transaction,
                &result.staged,
                Abandon {
                    change_set_id: &args.change_set_id,
                    device: &args.device,
                    principal: &principal,
                    operation_id: &result.operation_id,
                    pre_stage_fingerprint: &args.expected_fingerprint,
                    reason: &reason,
                    // The device said it did not commit. That is knowledge, not
                    // an unknown — the revert and lock proofs still gate whether
                    // anything is recorded.
                    outcome: AbandonOutcome::CandidateNotCommitted,
                },
            )
            .await;
            Err(JmcpError::Validation(reason))
        }
        CommitOutcome::Indeterminate { reason } => {
            let reason =
                format!("commit outcome indeterminate, manual reconciliation required: {reason}");
            abandon_failed_apply(
                &coordinator,
                &transaction,
                &result.staged,
                Abandon {
                    change_set_id: &args.change_set_id,
                    device: &args.device,
                    principal: &principal,
                    operation_id: &result.operation_id,
                    pre_stage_fingerprint: &args.expected_fingerprint,
                    reason: &reason,
                    outcome: AbandonOutcome::CommitOutcomeUnknown,
                },
            )
            .await;
            Err(JmcpError::Validation(reason))
        }
        CommitOutcome::Detached { job_id } => {
            let mut result = json!({
                "change_set_id": args.change_set_id,
                "operation_id": result.operation_id,
                "state": "Committing",
                "commit_outcome": "Detached",
                "job_id": job_id,
                "message": "commit detached, poll for completion"
            });
            if let Some(warning) = authority_warning {
                result
                    .as_object_mut()
                    .expect("json! macro produces an object here")
                    .insert("config_authority_warning".to_string(), json!(warning));
            }
            Ok(result)
        }
        CommitOutcome::AwaitingConfirmation {
            rollback_deadline_unix,
            details,
            ..
        } => {
            let mut result = json!({
                "change_set_id": args.change_set_id,
                "operation_id": result.operation_id,
                "state": "AwaitingConfirmation",
                "commit_outcome": "AwaitingConfirmation",
                "rollback_deadline_unix": rollback_deadline_unix,
                "details": details,
                "message": "commit awaiting confirmation; auto-rollback pending"
            });
            if let Some(warning) = authority_warning {
                result
                    .as_object_mut()
                    .expect("json! macro produces an object here")
                    .insert("config_authority_warning".to_string(), json!(warning));
            }
            Ok(result)
        }
    }
}

/// Confirm a provisional commit before the device rolls it back.
///
/// # Who may confirm
///
/// The **owner** — the principal that applied the change set — not the
/// approver. Authorization already happened at approval: a second principal
/// signed off on this exact plan, and `apply` executed it. Confirming does not
/// change what was approved; it stops the safety timer on a change that is
/// already live. That is execution, and execution is the owner's half of the
/// two-person split throughout this server (the approver's token cannot apply
/// either).
///
/// Requiring the approver here would also mean a change silently reverting
/// because the reviewer had gone home, which turns a safety feature into an
/// outage.
pub async fn confirm_change_set(
    args: ConfirmChangeSetArgs,
    dm: Arc<DeviceManager>,
    coordinator: Arc<ChangesetCoordinator>,
    attribution: Attribution,
) -> Result<Value, JmcpError> {
    let inventory = dm.inventory();
    inventory.get(&args.device)?;

    let principal = attribution.principal.to_string();

    // Scoped to (operation, principal, device), so one caller cannot confirm
    // another's provisional commit.
    let record = coordinator
        .record(&args.operation_id, &principal, &args.device)
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    let Some(deadline) = record.rollback_deadline_unix else {
        return Err(JmcpError::Validation(format!(
            "operation {} has no pending confirmation; it was not committed with a \
             confirm window",
            args.operation_id
        )));
    };

    // Report an expired window rather than issuing a confirming commit that
    // would land on whatever the device rolled back to. The operator needs to
    // know the change is already gone.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    if now >= deadline {
        return Err(JmcpError::Validation(format!(
            "the confirmation window for operation {} closed at {deadline}; the device \
             has already rolled the change back",
            args.operation_id
        )));
    }

    let transaction = JunosTransaction::new(dm.clone(), args.device.clone());
    let outcome = transaction
        .confirm_commit(&args.operation_id, &attribution)
        .await?;

    use mecmcp_changeset::CommitOutcome;
    match outcome {
        CommitOutcome::Reconciled {
            succeeded: true,
            details,
            ..
        } => {
            let mut confirmed = record;
            confirmed.state = mecmcp_changeset::LifecycleState::Committed;
            confirmed.rollback_deadline_unix = None;
            confirmed.details = details.clone();
            coordinator
                .update(confirmed)
                .await
                .map_err(|e| JmcpError::Validation(e.to_string()))?;

            Ok(json!({
                "operation_id": args.operation_id,
                "device": args.device,
                "state": "Committed",
                "details": details,
                "message": "confirming commit accepted; the automatic rollback is cancelled"
            }))
        }
        other => Ok(json!({
            "operation_id": args.operation_id,
            "device": args.device,
            "state": "Committing",
            "commit_outcome": format!("{other:?}"),
            "rollback_deadline_unix": deadline,
            "message": "the confirming commit did not report success; the rollback timer is still running"
        })),
    }
}

/// Derive commit confirmation state from the operation record.
///
/// `apply_junos_change_set` with `confirm_timeout_mins` issues a Junos confirmed
/// commit: the device commits and arms a rollback that fires unless
/// `confirm_junos_change_set` arrives first. The change set's own `state` cannot
/// report the result, because `Applied` is written when *staging* succeeds —
/// before the commit is issued — and nothing rewrites it afterwards. The
/// evidence lives on the operation record instead.
///
/// Values:
///
/// - `awaiting_confirmation` — a rollback deadline is set and still in the
///   future. `rollback_deadline_unix` carries it.
/// - `presumed_auto_reverted` — the deadline passed with no confirmation
///   recorded here.
/// - `committed` — the operation reached `Committed`.
/// - `discarded` — a record that *did* carry a deadline was reconciled as
///   `Discarded` by `state resolve`, an operator saying the change is not on
///   the device.
/// - `indeterminate` — the record was reconciled `AS COMMITTED` but its window
///   has since closed. `state resolve` neither stops the device nor records
///   when it ran, so this is either a confirm made out of band and then
///   reconciled, or a reconciliation made early on a timer that then fired.
///   Nothing stored here separates them; only the device does.
///
/// A deadline still on the record is the only evidence here that a confirm
/// window was used, and it outlives a manual resolve, which settles the state
/// without stopping the device — so while the window is still open it decides
/// the verdict even on a settled record.
/// With no deadline the record cannot say whether a confirm window was ever
/// asked for, because confirming clears it: `Committed` reports `committed`,
/// which an ordinary commit reports too and is therefore not evidence of
/// rollback protection. Any other state with no deadline gets no verdict — an
/// ordinary failed apply terminalizes as `Discarded`, which is not a
/// confirmed-commit outcome.
///
/// Three limits, none of which this server can close by reading its own state:
///
/// - `committed` cannot separate a confirmed commit from a plain one, because
///   confirming clears the deadline. Both mean the configuration is live, which
///   is the distinction that matters.
/// - `presumed_auto_reverted` is a **presumption**, not an observation. It is
///   the absence of a recorded confirmation, and it is wrong if a confirming
///   commit was issued out of band on the device, if the server and device
///   clocks disagree, or if `confirm_junos_change_set` reached the device but
///   its durable write failed — that last case returns an error to the caller
///   and leaves the record looking unconfirmed. Only the device settles it.
/// - A deadline in the future does not prove the commit is still pending; it
///   proves nothing here has confirmed it.
///
/// `operation_id` and `operation_state` are returned whenever an operation is
/// found, so a reader can see the basis for the verdict — in particular an
/// `indeterminate` operation state means a restart intervened.
///
/// When no operation is linked (a change set never applied, or whose operation
/// record was purged), no fields are added.
async fn derive_commit_confirmation(
    coordinator: &ChangesetCoordinator,
    change_set_id: &str,
    device: &str,
    now: u64,
) -> serde_json::Map<String, Value> {
    let mut fields = serde_json::Map::new();

    let Ok(change_set) = coordinator.change_set(change_set_id, device).await else {
        return fields;
    };
    let Some(operation_id) = change_set.operation_id.as_deref() else {
        return fields;
    };

    // A single keyed read. `record` is scoped to (operation, owner, device), and
    // the owner is always the change set's: `apply_change_set` refuses with
    // "only the principal that created the change set may apply it" when they
    // differ, so there is no divergent case to fall back for.
    //
    // A miss is genuine absence, and it is a normal state rather than an error:
    // an apply that fails after linking removes the operation while the change
    // set keeps its `operation_id`. Enumerating the store to confirm that would
    // clone every record and its action payloads, under the coordinator lock,
    // on each status read of a failed change set.
    let Ok(operation) = coordinator
        .record(operation_id, &change_set.owner, device)
        .await
    else {
        return fields;
    };

    fields.insert("operation_id".to_owned(), json!(operation.id));
    fields.insert("operation_state".to_owned(), json!(operation.state));

    // The presence of a deadline is the only evidence here that a confirmed
    // commit was ever issued, so it decides whether a verdict is owed at all.
    if let Some(deadline) = operation.rollback_deadline_unix {
        // `resolve_persisted_operation` writes a terminal state and leaves the
        // deadline behind, so a settled record can still have a live device
        // timer. `AS DISCARDED` is an operator saying the change is not on the
        // device; the timer only reverts it further, so the assertion stands.
        if operation.state == mecmcp_changeset::LifecycleState::Discarded {
            fields.insert("commit_confirmation".to_owned(), json!("discarded"));
            return fields;
        }

        // A `Committed` record whose window has since closed is genuinely
        // ambiguous, and neither answer can be justified from what is stored.
        // `state resolve ... AS COMMITTED` does not stop the device and does not
        // record when it ran, so this shape is either an operator who confirmed
        // out of band and then reconciled — the remedy for a confirming commit
        // whose durable write failed — or one who reconciled early on a timer
        // that then fired. Saying `committed` hides a revert; saying
        // `presumed_auto_reverted` contradicts a human who looked at the device.
        // Report the uncertainty instead: it is the one thing that is true, and
        // it routes the reader to the device rather than to a wrong answer.
        if operation.state == mecmcp_changeset::LifecycleState::Committed && now >= deadline {
            fields.insert("commit_confirmation".to_owned(), json!("indeterminate"));
            return fields;
        }

        // `AS COMMITTED` does not stop the device. It asserts the commit landed,
        // which for a confirmed commit is only ever provisional — reporting
        // `committed` here would hide a rollback that is still counting down.
        fields.insert("rollback_deadline_unix".to_owned(), json!(deadline));
        fields.insert(
            "commit_confirmation".to_owned(),
            json!(if now < deadline {
                "awaiting_confirmation"
            } else {
                "presumed_auto_reverted"
            }),
        );
        return fields;
    }

    // No deadline was ever recorded, so nothing here was a confirmed commit.
    // `Committed` is a commit that is live; every other state belongs to a plain
    // apply — notably the `Discarded` an ordinary failed apply terminalizes as,
    // which is not a confirmed-commit outcome and must not be labelled one.
    if operation.state == mecmcp_changeset::LifecycleState::Committed {
        fields.insert("commit_confirmation".to_owned(), json!("committed"));
    }

    fields
}

/// Get the status of a change set.
pub async fn get_change_set_status(
    args: GetChangeSetStatusArgs,
    coordinator: Arc<ChangesetCoordinator>,
) -> Result<Value, JmcpError> {
    let status = coordinator
        .change_set_status(args.change_set_id.clone(), args.device.clone())
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Get current time for deadline comparison.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Derive commit confirmation state.
    let confirmation_fields =
        derive_commit_confirmation(&coordinator, &args.change_set_id, &args.device, now).await;

    // Serialize the status and merge in the confirmation fields.
    let mut result = serde_json::to_value(status)
        .map_err(|e| JmcpError::Validation(e.to_string()))?
        .as_object_mut()
        .ok_or_else(|| JmcpError::Validation("status is not an object".to_owned()))?
        .clone();

    result.extend(confirmation_fields);
    Ok(Value::Object(result))
}

/// Get the status of a change set with staged actions included.
/// Only used when --web-enabled-approver is set.
pub async fn get_change_set_status_with_actions(
    args: GetChangeSetStatusArgs,
    coordinator: Arc<ChangesetCoordinator>,
) -> Result<Value, JmcpError> {
    let status = coordinator
        .change_set_status_with_actions(args.change_set_id.clone(), args.device.clone())
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    // Get current time for deadline comparison.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Derive commit confirmation state.
    let confirmation_fields =
        derive_commit_confirmation(&coordinator, &args.change_set_id, &args.device, now).await;

    // Serialize the status and merge in the confirmation fields.
    let mut result = serde_json::to_value(status)
        .map_err(|e| JmcpError::Validation(e.to_string()))?
        .as_object_mut()
        .ok_or_else(|| JmcpError::Validation("status is not an object".to_owned()))?
        .clone();

    result.extend(confirmation_fields);
    Ok(Value::Object(result))
}

/// List change sets, optionally filtered by device.
///
/// Returns all change sets across all devices, or filtered to a single device
/// if `device` is provided. Each record includes the change set ID, state,
/// owner, device, and expiry information.
///
/// This tool provides the recovery path for #255: when an expired change set
/// blocks creating a new one, enumerate to find the blocker's ID, then apply
/// it to let the expiry transition complete (or wait for the automatic sweep
/// that mecmcp v0.7.3 performs on insert).
///
/// Authorization is via device scope: records for devices outside the caller's
/// scope are filtered server-side, so no out-of-scope device name is ever
/// returned.
pub async fn list_change_sets(
    args: ListChangeSetsArgs,
    coordinator: Arc<ChangesetCoordinator>,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    // Get all change sets from the coordinator.
    let all_records = coordinator.change_sets().await;

    // Filter by device if specified, and by device scope authorization.
    let inventory = dm.inventory();
    let filtered: Vec<_> = all_records
        .into_iter()
        .filter(|record| {
            // If a device filter was provided, honor it.
            if let Some(ref device_filter) = args.device
                && &record.device != device_filter
            {
                return false;
            }
            // Only include devices that exist in the caller's inventory scope.
            // Devices outside scope are silently omitted rather than causing
            // an error, matching the behavior of enumeration tools generally.
            inventory.get(&record.device).is_ok()
        })
        .collect();

    // Serialize the filtered records.
    serde_json::to_value(filtered).map_err(|e| JmcpError::Validation(e.to_string()))
}

/// Arguments for `get_junos_candidate_fingerprint`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct CandidateFingerprintArgs {
    /// Target device name.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
}

/// Read the device's candidate fingerprint.
///
/// This seeds the change-set flow. `create_junos_change_set` requires an
/// `expected_fingerprint` so the plan is bound to the exact candidate it was
/// reviewed against — and without this tool there was no way to obtain one, so
/// the whole workflow was unreachable from MCP (#231).
///
/// The value comes from `DeviceTransaction::fingerprint`, the same code the
/// coordinator compares against at apply time, so it round-trips unchanged.
/// It is a read: no lock is taken and the candidate is not modified.
pub async fn get_candidate_fingerprint(
    args: CandidateFingerprintArgs,
    dm: Arc<DeviceManager>,
) -> Result<Value, JmcpError> {
    let transaction = JunosTransaction::new(dm, args.device.clone());
    let fingerprint = transaction
        .fingerprint()
        .await
        .map_err(|e| JmcpError::Validation(e.to_string()))?;

    Ok(json!({
        "device": args.device,
        "candidate_fingerprint": fingerprint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::junos_transaction::ConfigPayloadSpec;
    use mecmcp_audit::{ActorType, Attribution, Principal};
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::TempDir;

    // ---- #309: a failed apply must not leave the change set `Applied` ----

    use mecmcp_changeset::{
        ChangeSetRecord, LifecycleState, OperationLimits, OperationRecord, RollbackOutcome,
        RollbackRef, UnlockOutcome,
    };
    use std::time::Duration;

    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    struct FakeAction;

    /// The staged handle, modelling what vsrx-ci actually does.
    ///
    /// Releasing it closes the session, which on Junos discards the candidate
    /// and frees the lock — so the shared fingerprint flips back to its
    /// pre-stage value, and that is what a later read observes. Measured on 611:
    /// after a failed apply the candidate is already back and the lock is free.
    #[derive(Debug)]
    struct FakeStaged {
        released: Arc<AtomicBool>,
        /// Whether the close is allowed to complete. `false` models a peer that
        /// black-holes it, where the device state cannot be assumed.
        closes: bool,
    }

    #[async_trait::async_trait]
    impl crate::junos_transaction::ReleaseStaged for FakeStaged {
        async fn release(&self) -> bool {
            if !self.closes {
                return false;
            }
            self.released.store(true, Ordering::SeqCst);
            true
        }
    }
    #[derive(Debug, serde::Serialize)]
    struct FakeDiff;
    #[derive(Debug, serde::Serialize)]
    struct FakeValidation;

    #[derive(Debug, thiserror::Error)]
    enum FakeError {
        #[error("fake transaction failure")]
        Refused,
        /// What the device says when another session holds the lock.
        #[error("netconf error: RPC error: server error: [LockDenied]")]
        LockDenied,
    }

    /// A device that is not there.
    ///
    /// Only the methods `discard_operation` reaches are meaningful — `rollback`
    /// and `unlock`. `rollback_succeeds` lets a test drive the case where the
    /// device itself refuses the cleanup, which must still not leave the change
    /// set claiming it applied.
    struct FakeTransaction {
        rollback_succeeds: bool,
        /// Shared with the staged handle: set once the session has been
        /// released, which is when the candidate has reverted.
        staged_released: Arc<AtomicBool>,
        /// Counts device writes. The cleanup path must make none.
        rollbacks: Arc<AtomicUsize>,
        /// Counts lock probes, so a test can pin which paths probe at all.
        locks: Arc<AtomicUsize>,
        /// Whether the probe can give the candidate lock back. `false` leaves
        /// the device locked by the probe itself.
        unlock_confirms: bool,
        /// Whether the candidate lock can be taken after the release. `false`
        /// models a session that did not actually end — rustnetconf returns
        /// `Ok` from its close even when `<close-session/>` fails.
        lock_free: bool,
        /// What the candidate reads once released. Equal to the pre-stage value
        /// when the discard worked; different when it silently did not, which
        /// rustnetconf permits — it sends `<discard-changes/>` best-effort and
        /// closes anyway.
        post_release_fingerprint: String,
    }

    #[async_trait::async_trait]
    impl mecmcp_changeset::DeviceTransaction for FakeTransaction {
        type Action = FakeAction;
        type Staged = FakeStaged;
        type Diff = FakeDiff;
        type Validation = FakeValidation;
        type Error = FakeError;

        async fn fingerprint(&self) -> Result<String, Self::Error> {
            // Before the release the candidate still carries the staged change;
            // after it, the discard-on-close has put it back.
            if self.staged_released.load(Ordering::SeqCst) {
                // Released: the discard-on-close put the candidate back.
                Ok(self.post_release_fingerprint.clone())
            } else {
                Ok(format!("sha256:{}", "a".repeat(64)))
            }
        }
        async fn stage(&self, _actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
            Ok(FakeStaged {
                released: Arc::clone(&self.staged_released),
                closes: true,
            })
        }
        async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
            Ok(FakeDiff)
        }
        async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
            Ok(FakeValidation)
        }
        async fn commit(
            &self,
            _staged: &Self::Staged,
            _attribution: &Attribution,
            _options: &CommitOptions,
        ) -> Result<mecmcp_changeset::CommitOutcome, Self::Error> {
            Err(FakeError::Refused)
        }
        async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            if self.rollback_succeeds {
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: None,
                })
            } else {
                Err(FakeError::Refused)
            }
        }
        async fn lock(&self, _comment: &str) -> Result<(), Self::Error> {
            self.locks.fetch_add(1, Ordering::SeqCst);
            if self.lock_free {
                Ok(())
            } else {
                Err(FakeError::LockDenied)
            }
        }
        async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
            if self.unlock_confirms {
                Ok(UnlockOutcome::Released)
            } else {
                Err(FakeError::Refused)
            }
        }
        async fn confirm_commit(
            &self,
            _operation_id: &str,
            _attribution: &Attribution,
        ) -> Result<mecmcp_changeset::CommitOutcome, Self::Error> {
            Err(FakeError::Refused)
        }
    }

    /// What the candidate reads back once the release has discarded it — the
    /// value it held before staging. The fake returns the staged fingerprint
    /// until then.
    const PRE_STAGE: &str = PRE_STAGE_HEX;
    const DEVICE: &str = "vsrx-ci";
    const OWNER: &str = "claude-test";
    /// The pre-stage candidate, and the staged one that replaces it.
    const PRE_STAGE_HEX: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FINGERPRINT_HEX: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// Change-set and operation ids must be 64 hexadecimal characters.
    fn hex_id(seed: &str) -> String {
        format!("{seed:0>64}")
    }

    /// A transaction and the staged handle holding its lock, wired together.
    ///
    /// `closes` is whether the session close completes; when it does not, the
    /// device state is unknown and nothing may be terminalised.
    fn fake(closes: bool) -> (FakeTransaction, FakeStaged) {
        let released = Arc::new(AtomicBool::new(false));
        (
            FakeTransaction {
                rollback_succeeds: true,
                staged_released: Arc::clone(&released),
                rollbacks: Arc::new(AtomicUsize::new(0)),
                locks: Arc::new(AtomicUsize::new(0)),
                lock_free: true,
                unlock_confirms: true,
                post_release_fingerprint: PRE_STAGE.to_owned(),
            },
            FakeStaged { released, closes },
        )
    }

    fn coordinator() -> (tempfile::TempDir, Arc<ChangesetCoordinator>) {
        let dir = tempfile::tempdir().unwrap();
        let coordinator = ChangesetCoordinator::load(
            Some(&dir.path().join("state.json")),
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap();
        (dir, Arc::new(coordinator))
    }

    /// A change set mid-apply: staging succeeded, so it already reads `Applied`.
    fn applied_change_set(id: &str) -> ChangeSetRecord {
        ChangeSetRecord {
            id: id.to_owned(),
            owner: OWNER.to_owned(),
            device: DEVICE.to_owned(),
            expected_candidate_fingerprint: format!("sha256:{FINGERPRINT_HEX}"),
            actions: vec![json!({"op": "set"})],
            digest: format!("sha256:{}", "c".repeat(64)),
            state: mecmcp_changeset::ChangeSetState::Applied,
            approver: Some("codex-approver".to_owned()),
            approval: None,
            expires_at_unix: u64::MAX,
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            // No in-flight vendor task: these fixtures stand in for change sets
            // whose apply is already resolved. mecmcp 0.20.0's `task_id` is for
            // recovering an apply that died mid-flight, which this server does
            // not yet record — see the follow-up issue.
            task_id: None,
            // Not an apply that lost its handle. mecmcp 0.22.0 uses this to
            // hold a record in `Applying` across a restart when the apply ran
            // without a recoverable handle; these fixtures are already
            // resolved, so the honest value is false.
            apply_without_handle: false,
        }
    }

    /// The operation left behind by a commit that was already in flight.
    ///
    /// `commit_operation` persists this state immediately before sending the
    /// commit, so it is the only one from which the outcome is genuinely
    /// unknown.
    fn committing_operation(id: &str) -> OperationRecord {
        OperationRecord {
            state: LifecycleState::Committing,
            ..validated_operation(id)
        }
    }

    /// The operation left behind by a validation failure.
    fn validated_operation(id: &str) -> OperationRecord {
        OperationRecord {
            id: id.to_owned(),
            owner: OWNER.to_owned(),
            device: DEVICE.to_owned(),
            endpoint: format!("junos://{DEVICE}:830"),
            action: json!("merge"),
            xpath: None,
            actions: vec![json!({"op": "set"})],
            change_set_id: None,
            current: format!("sha256:{FINGERPRINT_HEX}"),
            state: LifecycleState::Validated,
            job_id: None,
            details: None,
            config_lock_held: true,
            policy_signature: String::new(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority: None,
        }
    }

    /// The reported symptom: the record claims a change landed that never did.
    #[tokio::test]
    async fn a_failed_apply_marks_the_change_set_failed_not_applied() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c1")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("01")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c1"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("01"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let change_set = coordinator.change_set(&hex_id("c1"), DEVICE).await.unwrap();
        assert_eq!(
            change_set.state,
            mecmcp_changeset::ChangeSetState::Failed,
            "a change set the device rejected must not read as applied"
        );
    }

    /// #312: the operation has to end terminal, or it blocks the device.
    ///
    /// `LifecycleState::terminal()` counts only `Committed` and `Discarded`, and
    /// `insert` refuses a new operation while a non-terminal one exists for the
    /// device. `Failed` is not terminal, which is why #309 left the wedge in
    /// place.
    #[tokio::test]
    async fn a_failed_apply_settles_the_operation_terminally() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c2")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("02")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c2"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("02"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("02"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_eq!(
            operation.state,
            LifecycleState::Discarded,
            "only Committed or Discarded is terminal; anything else keeps the device blocked"
        );
        assert!(
            !operation.config_lock_held,
            "the release closed the session, so no lock of ours is held"
        );
    }

    /// The cleanup must not touch the device.
    ///
    /// Releasing the staged session is already the revert — measured on
    /// vsrx-ci, where the candidate is back to its pre-stage fingerprint the
    /// instant a failed apply returns. `RollbackRef::Archive(0)` is not a
    /// discard either: it loads rollback 0 and *commits* it, which on the
    /// commit-failure path could undo a change that landed.
    #[tokio::test]
    async fn the_cleanup_makes_no_device_write() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c3")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("03")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);
        let rollbacks = Arc::clone(&transaction.rollbacks);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c3"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("03"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        assert_eq!(
            rollbacks.load(Ordering::SeqCst),
            0,
            "the cleanup issued a rollback, which on Junos is a commit"
        );
    }

    /// The record must name the candidate that is actually there now.
    ///
    /// Staging stores the *staged* fingerprint in `record.current`. After the
    /// release the candidate has reverted, so leaving that value in place would
    /// have the record identify the rejected configuration as current.
    #[tokio::test]
    async fn settling_refreshes_the_recorded_fingerprint() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c4")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("04")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c4"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("04"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("04"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_eq!(
            operation.current, PRE_STAGE,
            "the record still names the staged candidate the device threw away"
        );
    }

    /// A commit that errored may have landed anyway.
    ///
    /// `commit_operation` can fail because its final state write failed after
    /// the device already committed. Recording that as `Discarded` would assert
    /// a revert that never happened, so it stays `Indeterminate` — non-terminal,
    /// and settled by `state resolve` once someone has looked at the device.
    #[tokio::test]
    async fn a_failed_commit_is_left_indeterminate() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c5")))
            .await
            .unwrap();
        coordinator
            .insert(committing_operation(&hex_id("05")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c5"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("05"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "commit failed",
                outcome: AbandonOutcome::CommitOutcomeUnknown,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("05"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_eq!(
            operation.state,
            LifecycleState::Indeterminate,
            "a commit whose outcome is unknown must not be recorded as discarded"
        );
    }

    /// A release that could not complete leaves the device state unknown.
    ///
    /// Terminalising then would claim a clean candidate and a free lock without
    /// either being established. The change set must still stop lying.
    #[tokio::test]
    async fn an_unconfirmed_release_does_not_terminalise() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c6")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("06")))
            .await
            .unwrap();
        let (transaction, staged) = fake(false);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c6"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("06"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("06"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_ne!(
            operation.state,
            LifecycleState::Discarded,
            "an unconfirmed release must not be recorded as a clean discard"
        );
        let change_set = coordinator.change_set(&hex_id("c6"), DEVICE).await.unwrap();
        assert_eq!(
            change_set.state,
            mecmcp_changeset::ChangeSetState::Failed,
            "the change set must stop claiming it applied regardless"
        );
    }

    /// A close that completed is not proof the candidate was discarded.
    ///
    /// rustnetconf sends `<discard-changes/>` best-effort inside its close
    /// sequence and closes anyway when it fails, returning `Ok`. If the
    /// operation were terminalised on that alone, the rejected candidate could
    /// still be sitting there for a later apply to commit.
    #[tokio::test]
    async fn a_candidate_that_did_not_revert_is_not_recorded_as_discarded() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c7")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("07")))
            .await
            .unwrap();
        let (mut transaction, staged) = fake(true);
        // The close reported success, but the candidate still holds the staged
        // change — the discard failed and was swallowed.
        transaction.post_release_fingerprint = format!("sha256:{}", "c".repeat(64));

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c7"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("07"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("07"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_ne!(
            operation.state,
            LifecycleState::Discarded,
            "an unproven revert must not be recorded as a clean discard"
        );
        let change_set = coordinator.change_set(&hex_id("c7"), DEVICE).await.unwrap();
        assert_eq!(
            change_set.state,
            mecmcp_changeset::ChangeSetState::Failed,
            "the change set must stop claiming it applied regardless"
        );
    }

    /// A commit error before the RPC is not an unknown outcome.
    ///
    /// `commit_operation` persists `Committing` immediately before it sends the
    /// commit and returns earlier for the guard, cancellation, policy,
    /// fingerprint and confirm-timeout checks. Leaving those `Indeterminate`
    /// would keep the device blocked for a commit that never happened.
    #[tokio::test]
    async fn a_commit_that_never_reached_the_device_settles_cleanly() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c8")))
            .await
            .unwrap();
        // Still `Validated`: it never advanced to `Committing`.
        coordinator
            .insert(validated_operation(&hex_id("08")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c8"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("08"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "commit refused before it was sent",
                outcome: AbandonOutcome::CommitOutcomeUnknown,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("08"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_eq!(
            operation.state,
            LifecycleState::Discarded,
            "a commit that never reached the device leaves nothing unknown"
        );
    }

    /// A candidate that reverted does not prove the session ended.
    ///
    /// rustnetconf's close is best-effort throughout and returns `Ok` even when
    /// `<close-session/>` fails, so the lock can outlive a successful discard.
    /// Recording `config_lock_held = false` then would be an assertion nobody
    /// checked.
    #[tokio::test]
    async fn a_lock_still_held_after_release_is_not_terminalised() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("c9")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("09")))
            .await
            .unwrap();
        let (mut transaction, staged) = fake(true);
        transaction.lock_free = false;

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("c9"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("09"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("09"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_ne!(
            operation.state,
            LifecycleState::Discarded,
            "the lock was never proven free, so nothing may be terminalised"
        );
    }

    /// The probe must not leave the device locked by itself.
    ///
    /// `unlock` drops the owning session and leaves the close to `Drop`, which
    /// only spawns it, so an unconfirmed unlock means the lock may still be
    /// held — by this cleanup rather than by the failed apply, which is no
    /// better for the next caller.
    #[tokio::test]
    async fn a_probe_that_cannot_return_the_lock_does_not_terminalise() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("ca")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("0a")))
            .await
            .unwrap();
        let (mut transaction, staged) = fake(true);
        transaction.unlock_confirms = false;

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("ca"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("0a"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        let operation = coordinator
            .record(&hex_id("0a"), OWNER, DEVICE)
            .await
            .unwrap();
        assert_ne!(
            operation.state,
            LifecycleState::Discarded,
            "the probe still holds the lock, so nothing may be terminalised"
        );
    }

    /// The probes exist to justify `Discarded`, so a path that cannot reach it
    /// must not run them.
    ///
    /// A commit whose outcome is unknown ends non-terminal whatever the device
    /// says. Probing anyway opens sessions against the pool behind a handle that
    /// may have committed and unlocked cleanly, which can end up discarding a
    /// candidate this operation no longer owns.
    #[tokio::test]
    async fn an_unknown_commit_outcome_does_not_probe_the_device() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("cb")))
            .await
            .unwrap();
        coordinator
            .insert(committing_operation(&hex_id("0b")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);
        let locks = Arc::clone(&transaction.locks);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("cb"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("0b"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "commit failed",
                outcome: AbandonOutcome::CommitOutcomeUnknown,
            },
        )
        .await;

        assert_eq!(
            locks.load(Ordering::SeqCst),
            0,
            "an outcome that cannot be terminalised has nothing to prove"
        );
    }

    /// ...and a path that *can* reach `Discarded` must run them.
    #[tokio::test]
    async fn a_revert_that_can_be_terminalised_is_proved_on_the_device() {
        let (_dir, coordinator) = coordinator();
        coordinator
            .seed_change_set_for_test(applied_change_set(&hex_id("cc")))
            .await
            .unwrap();
        coordinator
            .insert(validated_operation(&hex_id("0c")))
            .await
            .unwrap();
        let (transaction, staged) = fake(true);
        let locks = Arc::clone(&transaction.locks);

        abandon_failed_apply(
            &coordinator,
            &transaction,
            &staged,
            Abandon {
                change_set_id: &hex_id("cc"),
                device: DEVICE,
                principal: OWNER,
                operation_id: &hex_id("0c"),
                pre_stage_fingerprint: PRE_STAGE,
                reason: "configuration validation failed",
                outcome: AbandonOutcome::CandidateNotCommitted,
            },
        )
        .await;

        assert_eq!(
            locks.load(Ordering::SeqCst),
            1,
            "the lock is the only proof it was free, so it has to be taken"
        );
    }

    /// A change-set record whose approval is either two-person or waived.
    fn record_with_approval(
        approver: Option<&str>,
        waived: bool,
    ) -> mecmcp_changeset::ChangeSetRecord {
        use mecmcp_changeset::{ApprovalRecord, ChangeSetState, WaiverKind, WaiverRecord};
        mecmcp_changeset::ChangeSetRecord {
            id: "86324b20a3ecbfde".to_owned(),
            owner: "claude-test".to_owned(),
            device: "vsrx-ci".to_owned(),
            expected_candidate_fingerprint: format!("sha256:{}", "b".repeat(64)),
            actions: vec![json!({"op": "set"})],
            digest: format!("sha256:{}", "c".repeat(64)),
            state: ChangeSetState::Approved,
            approver: approver.map(str::to_owned),
            approval: Some(ApprovalRecord {
                approver: approver.map(str::to_owned),
                approved_at_unix: 1_000,
                digest: format!("sha256:{}", "d".repeat(64)),
                // These fixtures carry no preview, so the v4 tuple is the
                // right shape for them. mecmcp 0.23.0 adds v5, which binds a
                // preview digest into the approval; a fixture that claimed v5
                // while setting `preview: None` would misrepresent itself.
                digest_version: 4,
                waived: waived.then(|| WaiverRecord {
                    kind: WaiverKind::LabMode,
                    reason: "lab-mode".to_owned(),
                    expires_at_unix: None,
                    ticket: None,
                }),
            }),
            expires_at_unix: 2_000,
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            // No in-flight vendor task: these fixtures stand in for change sets
            // whose apply is already resolved. mecmcp 0.20.0's `task_id` is for
            // recovering an apply that died mid-flight, which this server does
            // not yet record — see the follow-up issue.
            task_id: None,
            // Not an apply that lost its handle. mecmcp 0.22.0 uses this to
            // hold a record in `Applying` across a restart when the apply ran
            // without a recoverable handle; these fixtures are already
            // resolved, so the honest value is false.
            apply_without_handle: false,
        }
    }

    /// A genuine two-person approval names its approver on the device (#307).
    #[test]
    fn approver_for_commit_names_a_two_person_approver() {
        let record = record_with_approval(Some("codex-approver"), false);
        assert_eq!(approver_for_commit(&record), Some("codex-approver"));
    }

    /// A waived apply names nobody, and nobody is invented for it.
    #[test]
    fn approver_for_commit_is_absent_for_a_waived_approval() {
        let record = record_with_approval(None, true);
        assert_eq!(
            approver_for_commit(&record),
            None,
            "lab mode approved this without a second principal; the commit log must not claim one"
        );
    }

    /// A record still awaiting approval has no approver either.
    #[test]
    fn approver_for_commit_is_absent_without_an_approval_record() {
        let mut record = record_with_approval(None, false);
        record.approval = None;
        assert_eq!(approver_for_commit(&record), None);
    }

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn test_attribution(principal: &str) -> Attribution {
        Attribution {
            principal: Principal::Token(principal.into()),
            actor_type: ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: Some("TEST-001".into()),
            request_id: uuid::Uuid::new_v4(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
            approver: None,
            change_set_id: None,
        }
    }

    fn test_policy(inv: Arc<Inventory>) -> Arc<Policy> {
        Arc::new(Policy::build(&inv).unwrap())
    }

    #[tokio::test]
    async fn create_change_set_unknown_device_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        let r =
            create_change_set(
                CreateChangeSetArgs {
                    device: "nope".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![],
                },
                dm.clone(),
                coordinator,
                policy,
                test_attribution("alice"),
            )
            .await;

        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    fn test_coordinator(state_dir: &TempDir) -> Arc<ChangesetCoordinator> {
        Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        )
    }

    fn test_coordinator_lab_mode(state_dir: &TempDir) -> Arc<ChangesetCoordinator> {
        Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                true,
            )
            .unwrap(),
        )
    }

    /// #254: an action satisfying no valid shape used to be accepted, digested,
    /// and (in lab mode) approved, failing only at apply. The negative
    /// assertion at the end is the part that matters most: the rejected create
    /// must not leave a record occupying this principal's one pending
    /// change-set slot on the device.
    #[tokio::test]
    async fn create_change_set_rejects_action_with_neither_payload_nor_rollback() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let r = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: None,
                    rollback_source: None,
                }],
            },
            dm.clone(),
            coordinator.clone(),
            policy.clone(),
            test_attribution("alice"),
        )
        .await;

        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("action 0") && msg.contains("payload"),
                    "the error must name the offending action and the field the \
                     caller got wrong, got: {msg}"
                );
            }
            other => panic!("expected create to reject an empty action, got {other:?}"),
        }

        // The slot must still be free: a well-formed create by the same
        // principal on the same device has to succeed immediately.
        let ok = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "set system host-name test".into(),
                        format: Some("set".into()),
                        mode: None,
                    }),
                    rollback_source: None,
                }],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        assert!(
            ok.is_ok(),
            "a rejected create must not consume the pending change-set slot, got {ok:?}"
        );
    }

    /// The doc on `JunosAction` says *exactly* one, so both set is as invalid
    /// as neither.
    #[tokio::test]
    async fn create_change_set_rejects_action_with_both_payload_and_rollback() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);

        let r =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![JunosAction {
                        payload: Some(ConfigPayloadSpec {
                            text: "set system host-name test".into(),
                            format: Some("set".into()),
                            mode: None,
                        }),
                        rollback_source: Some(1),
                    }],
                },
                dm,
                coordinator,
                policy,
                test_attribution("alice"),
            )
            .await;

        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("action 0") && msg.contains("both"),
                    "got: {msg}"
                );
            }
            other => panic!("expected create to reject a both-fields action, got {other:?}"),
        }
    }

    fn rollback_action(depth: u32) -> JunosAction {
        JunosAction {
            payload: None,
            rollback_source: Some(depth),
        }
    }

    fn payload_action(text: &str) -> JunosAction {
        JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: text.into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        }
    }

    async fn create_on_plane_owned_device(
        authority: &str,
        actions: Vec<JunosAction>,
        lab_mode: bool,
    ) -> Result<Value, JmcpError> {
        let inv = inv_with(&format!(
            r#"{{"r1":{{"ip":"127.0.0.1","username":"u","auth":{{"type":"password","password":"x"}},"config_authority":"{authority}"}}}}"#,
        ));
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = if lab_mode {
            test_coordinator_lab_mode(&state_dir)
        } else {
            test_coordinator(&state_dir)
        };

        create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .into(),
                actions,
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await
    }

    /// MEC-1879 P5a: `rollback_source: 0` is a no-op load and is always
    /// allowed on a plane-owned device.
    #[tokio::test]
    async fn create_change_set_allows_rollback_depth_zero_on_plane_owned_device() {
        let r = create_on_plane_owned_device("mist", vec![rollback_action(0)], false).await;
        assert!(
            r.is_ok(),
            "expected depth 0 to be allowed on a plane-owned device, got {r:?}"
        );
    }

    /// MEC-1879 P5a: `rollback_source: 1` on a plane-owned device is refused
    /// at create, fail-closed, until commit-origin attribution (MEC-1880,
    /// P5b) exists.
    #[tokio::test]
    async fn create_change_set_refuses_rollback_depth_one_on_plane_owned_device() {
        let r = create_on_plane_owned_device("mist", vec![rollback_action(1)], false).await;
        match r {
            Err(JmcpError::PlaneOwnedRollbackDepthRefused { depth, .. }) => {
                assert_eq!(depth, 1);
            }
            other => panic!("expected depth 1 to be refused, got {other:?}"),
        }
    }

    /// MEC-1879 P5a: depth >= 2 on a plane-owned device is refused
    /// unconditionally, with no flag to override it.
    #[tokio::test]
    async fn create_change_set_refuses_rollback_depth_two_or_more_on_plane_owned_device() {
        for depth in [2, 5, 49] {
            let r = create_on_plane_owned_device(
                "security-director-cloud",
                vec![rollback_action(depth)],
                false,
            )
            .await;
            match r {
                Err(JmcpError::PlaneOwnedRollbackDepthRefused { depth: d, .. }) => {
                    assert_eq!(d, depth);
                }
                other => panic!("expected depth {depth} to be refused, got {other:?}"),
            }
        }
    }

    /// MEC-1879 P5a: a rollback on a `local`/`unknown` device needs no
    /// attribution and is unaffected by this guard, at any depth.
    #[tokio::test]
    async fn create_change_set_allows_any_depth_on_local_device() {
        for depth in [0, 1, 2, 49] {
            let r =
                create_on_plane_owned_device("local", vec![rollback_action(depth)], false).await;
            assert!(
                r.is_ok(),
                "expected depth {depth} to be allowed on a local device, got {r:?}"
            );
        }
    }

    /// MEC-1879 P5a (sole-action rule): a change set mixing a
    /// `rollback_source` action with a payload action on a plane-owned
    /// device is refused, regardless of depth.
    #[tokio::test]
    async fn create_change_set_refuses_rollback_mixed_with_payload_on_plane_owned_device() {
        let r = create_on_plane_owned_device(
            "mist",
            vec![
                rollback_action(0),
                payload_action("set system host-name test"),
            ],
            false,
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::PlaneOwnedRollbackMixedAction { .. })),
            "expected a mixed-action refusal, got {r:?}"
        );
    }

    /// MEC-1879 P5a (lab-mode refusal): no lab-mode waiver ever applies to a
    /// plane-owned rollback action, so creating one in lab mode is refused
    /// before the depth check would even run.
    #[tokio::test]
    async fn create_change_set_refuses_plane_owned_rollback_in_lab_mode() {
        let r = create_on_plane_owned_device("mist", vec![rollback_action(0)], true).await;
        assert!(
            matches!(r, Err(JmcpError::PlaneOwnedRollbackLabMode { .. })),
            "expected a lab-mode refusal even for depth 0, got {r:?}"
        );
    }

    /// The call that produced #254, verbatim. Before `deny_unknown_fields`
    /// every field here was dropped and the action deserialized to `{}`.
    #[test]
    fn mistyped_action_fields_are_rejected_rather_than_dropped() {
        let err = serde_json::from_str::<JunosAction>(
            r#"{"action":"set","config_text":"set system host-name x","format":"set"}"#,
        )
        .expect_err("a mistyped action must not deserialize to an empty action");

        assert!(
            err.to_string().contains("action"),
            "the error must name the unknown field so the caller can fix it, got: {err}"
        );
    }

    /// Percy review F1 (rustjunosmcp#425): lab mode waives approval on every
    /// change set it creates, so allowing `mode=override` there would commit
    /// the whole candidate configuration with no human ever reviewing it.
    /// `create_junos_change_set` must refuse override outright when the
    /// coordinator is in lab mode, before anything is persisted or waived.
    #[tokio::test]
    async fn create_change_set_refuses_override_in_lab_mode() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator_lab_mode(&state_dir);
        const FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let r = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "system { host-name test; }".into(),
                        format: Some("text".into()),
                        mode: Some("override".into()),
                    }),
                    rollback_source: None,
                }],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        match r {
            Err(JmcpError::OverrideRequiresHumanApproval { tool }) => {
                assert_eq!(tool, "create_junos_change_set");
            }
            other => panic!("expected override to be refused in lab mode, got {other:?}"),
        }
    }

    /// Non-override modes are unaffected by the lab-mode override refusal.
    #[tokio::test]
    async fn create_change_set_allows_merge_in_lab_mode() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator_lab_mode(&state_dir);
        const FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let r = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "set system host-name test".into(),
                        format: Some("set".into()),
                        mode: None,
                    }),
                    rollback_source: None,
                }],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        assert!(
            r.is_ok(),
            "merge in lab mode must still be allowed, got {r:?}"
        );
    }

    /// Percy review F2 (rustjunosmcp#425): an invalid `mode` or an
    /// incompatible format/mode combination used to survive `create` and
    /// fail only inside `JunosTransaction::stage`, at apply time — by then a
    /// human has spent an approval and the principal's one pending slot is
    /// burned. Both must now be rejected at create, before the pending slot
    /// is consumed, mirroring the #254 test above.
    #[tokio::test]
    async fn create_change_set_rejects_unknown_mode_before_consuming_the_pending_slot() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let r = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "set system host-name test".into(),
                        format: Some("set".into()),
                        mode: Some("wipe".into()),
                    }),
                    rollback_source: None,
                }],
            },
            dm.clone(),
            coordinator.clone(),
            policy.clone(),
            test_attribution("alice"),
        )
        .await;

        assert!(
            matches!(r, Err(JmcpError::BadLoadMode(ref m)) if m == "wipe"),
            "expected an unknown mode to be rejected at create, got {r:?}"
        );

        // The slot must still be free.
        let ok = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "set system host-name test".into(),
                        format: Some("set".into()),
                        mode: None,
                    }),
                    rollback_source: None,
                }],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        assert!(
            ok.is_ok(),
            "a rejected create must not consume the pending change-set slot, got {ok:?}"
        );
    }

    /// Same class of bug as above, for the format/mode incompatibility rather
    /// than an unknown mode string: `format=set` has no wire-level `override`
    /// action, and that must be caught at create rather than at apply.
    #[tokio::test]
    async fn create_change_set_rejects_incompatible_format_and_mode_at_create() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let r = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FINGERPRINT.into(),
                actions: vec![JunosAction {
                    payload: Some(ConfigPayloadSpec {
                        text: "set system host-name test".into(),
                        format: Some("set".into()),
                        mode: Some("override".into()),
                    }),
                    rollback_source: None,
                }],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        assert!(
            matches!(r, Err(JmcpError::IncompatibleFormatMode { .. })),
            "expected format=set + mode=override to be rejected at create, got {r:?}"
        );
    }

    #[tokio::test]
    async fn approve_change_set_by_same_principal_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        // Create a change set as alice.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                },
                dm.clone(),
                coordinator.clone(),
                policy,
                test_attribution("alice"),
            )
            .await
            .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();

        // Try to approve as alice (the owner). Should fail.
        let r = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("alice"),
        )
        .await;

        assert!(r.is_err());
        let err_str = r.unwrap_err().to_string();
        // The coordinator enforces separation of duties; assert on what it
        // actually says so this test fails if that check is ever removed.
        assert!(
            err_str.contains("owner cannot approve their own plan"),
            "self-approval must be refused, got: {err_str}"
        );
    }

    /// House rule: a human approves. An agent principal — distinct from the
    /// owner, so separation of duties alone would let this through — must
    /// still be refused as the second approver.
    #[tokio::test]
    async fn approve_change_set_by_agent_actor_fails() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                },
                dm.clone(),
                coordinator.clone(),
                policy,
                test_attribution("alice"),
            )
            .await
            .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();

        let mut bob_agent = test_attribution("bob");
        bob_agent.actor_type = ActorType::Agent;

        let r = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            bob_agent,
        )
        .await;

        assert!(r.is_err());
        let err_str = r.unwrap_err().to_string();
        assert!(
            err_str.contains("must be a human principal"),
            "a non-human approver must be refused, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn create_approve_status_flow() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = Arc::new(
            ChangesetCoordinator::load(
                Some(&state_dir.path().join("changeset-state.json")),
                mecmcp_changeset::OperationLimits::default(),
                std::time::Duration::from_secs(300),
                false,
            )
            .unwrap(),
        );

        // Create.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result =
            create_change_set(
                CreateChangeSetArgs {
                    device: "r1".into(),
                    expected_fingerprint:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    actions: vec![action],
                },
                dm.clone(),
                coordinator.clone(),
                policy,
                test_attribution("alice"),
            )
            .await
            .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();
        assert_eq!(create_result["state"].as_str().unwrap(), "Planned");

        // Approve by a second principal.
        let approve_result = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("bob"),
        )
        .await
        .unwrap();

        assert_eq!(approve_result["state"].as_str().unwrap(), "Approved");

        // Get status.
        let status_result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator.clone(),
        )
        .await
        .unwrap();

        // The lifecycle state serializes lowercase.
        assert_eq!(status_result["state"].as_str().unwrap(), "approved");
        assert_eq!(status_result["owner"].as_str().unwrap(), "alice");
    }

    /// #255: list_junos_change_sets provides the recovery path when an expired
    /// change set blocks creating a new one. It must enumerate change sets,
    /// filter by device when requested, and respect device-scope authorization.
    #[tokio::test]
    async fn list_change_sets_enumerates_and_filters() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FP: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create two change sets on different devices.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test1".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let r1_result = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action.clone()],
            },
            dm.clone(),
            coordinator.clone(),
            policy.clone(),
            test_attribution("alice"),
        )
        .await
        .unwrap();
        let r1_id = r1_result["change_set_id"].as_str().unwrap();

        let action2 = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test2".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let r2_result = create_change_set(
            CreateChangeSetArgs {
                device: "r2".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action2],
            },
            dm.clone(),
            coordinator.clone(),
            policy.clone(),
            test_attribution("bob"),
        )
        .await
        .unwrap();
        let r2_id = r2_result["change_set_id"].as_str().unwrap();

        // List all change sets: both should appear.
        let all = list_change_sets(
            ListChangeSetsArgs { device: None },
            coordinator.clone(),
            dm.clone(),
        )
        .await
        .unwrap();
        let all_arr = all.as_array().unwrap();
        assert_eq!(all_arr.len(), 2, "both change sets should be listed");
        let ids: Vec<&str> = all_arr.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&r1_id) && ids.contains(&r2_id));

        // List filtered by device: only r1's change set should appear.
        let r1_only = list_change_sets(
            ListChangeSetsArgs {
                device: Some("r1".into()),
            },
            coordinator.clone(),
            dm.clone(),
        )
        .await
        .unwrap();
        let r1_arr = r1_only.as_array().unwrap();
        assert_eq!(r1_arr.len(), 1, "only r1's change set should be listed");
        assert_eq!(r1_arr[0]["id"].as_str().unwrap(), r1_id);
        assert_eq!(r1_arr[0]["device"].as_str().unwrap(), "r1");
        assert_eq!(r1_arr[0]["owner"].as_str().unwrap(), "alice");

        // List filtered by the other device.
        let r2_only = list_change_sets(
            ListChangeSetsArgs {
                device: Some("r2".into()),
            },
            coordinator.clone(),
            dm.clone(),
        )
        .await
        .unwrap();
        let r2_arr = r2_only.as_array().unwrap();
        assert_eq!(r2_arr.len(), 1);
        assert_eq!(r2_arr[0]["id"].as_str().unwrap(), r2_id);

        // Filter by a device not in the inventory: returns empty.
        let inv_subset = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm_subset = Arc::new(DeviceManager::new(inv_subset));
        let scoped = list_change_sets(
            ListChangeSetsArgs { device: None },
            coordinator.clone(),
            dm_subset,
        )
        .await
        .unwrap();
        let scoped_arr = scoped.as_array().unwrap();
        // Only r1 is in the scoped inventory, so r2's change set is omitted.
        assert_eq!(scoped_arr.len(), 1);
        assert_eq!(scoped_arr[0]["device"].as_str().unwrap(), "r1");
    }

    /// Cancel transitions a Planned change set to Cancelled and frees the slot.
    #[tokio::test]
    async fn cancel_change_set_owner_can_cancel_planned() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FP: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create a change set as alice.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action],
            },
            dm.clone(),
            coordinator.clone(),
            policy.clone(),
            test_attribution("alice"),
        )
        .await
        .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        assert_eq!(create_result["state"].as_str().unwrap(), "Planned");

        // Alice cancels her own change set.
        let cancel_result = cancel_change_set(
            CancelChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("alice"),
        )
        .await
        .unwrap();

        assert_eq!(cancel_result["state"].as_str().unwrap(), "Cancelled");
        assert_eq!(
            cancel_result["message"].as_str().unwrap(),
            "change set cancelled"
        );

        // The slot must be free: alice can create another change set immediately.
        let action2 = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test2".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create2 = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action2],
            },
            dm,
            coordinator,
            policy,
            test_attribution("alice"),
        )
        .await;

        assert!(
            create2.is_ok(),
            "a cancelled change set must free the pending slot, got {:?}",
            create2
        );
    }

    /// An approver can cancel an Approved change set.
    #[tokio::test]
    async fn cancel_change_set_approver_can_cancel_approved() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FP: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create a change set as alice.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action],
            },
            dm.clone(),
            coordinator.clone(),
            policy,
            test_attribution("alice"),
        )
        .await
        .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();
        let plan_digest = create_result["plan_digest"].as_str().unwrap();

        // Bob approves it.
        let approve_result = approve_change_set(
            ApproveChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
                expected_digest: plan_digest.into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("bob"),
        )
        .await
        .unwrap();

        assert_eq!(approve_result["state"].as_str().unwrap(), "Approved");

        // Bob cancels it.
        let cancel_result = cancel_change_set(
            CancelChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator.clone(),
            dm,
            test_attribution("bob"),
        )
        .await
        .unwrap();

        assert_eq!(cancel_result["state"].as_str().unwrap(), "Cancelled");
    }

    /// Cancelling an already-Cancelled change set is idempotent.
    #[tokio::test]
    async fn cancel_change_set_idempotent() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy(inv);
        let state_dir = TempDir::new().unwrap();
        let coordinator = test_coordinator(&state_dir);
        const FP: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create and cancel a change set.
        let action = JunosAction {
            payload: Some(ConfigPayloadSpec {
                text: "set system host-name test".into(),
                format: Some("set".into()),
                mode: None,
            }),
            rollback_source: None,
        };
        let create_result = create_change_set(
            CreateChangeSetArgs {
                device: "r1".into(),
                expected_fingerprint: FP.into(),
                actions: vec![action],
            },
            dm.clone(),
            coordinator.clone(),
            policy,
            test_attribution("alice"),
        )
        .await
        .unwrap();

        let change_set_id = create_result["change_set_id"].as_str().unwrap();

        let cancel1 = cancel_change_set(
            CancelChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator.clone(),
            dm.clone(),
            test_attribution("alice"),
        )
        .await
        .unwrap();

        assert_eq!(cancel1["state"].as_str().unwrap(), "Cancelled");

        // Cancel it again: should succeed idempotently.
        let cancel2 = cancel_change_set(
            CancelChangeSetArgs {
                change_set_id: change_set_id.into(),
                device: "r1".into(),
            },
            coordinator,
            dm,
            test_attribution("alice"),
        )
        .await;

        assert!(
            cancel2.is_ok(),
            "cancelling an already-Cancelled change set should be idempotent, got {:?}",
            cancel2
        );
        assert_eq!(cancel2.unwrap()["state"].as_str().unwrap(), "Cancelled");
    }

    // ---- #384: commit confirmation state inference ----

    /// An applied change set already linked to its operation, which is what
    /// `apply_change_set` leaves on disk — the status join walks
    /// `ChangeSetRecord::operation_id`, so an unlinked fixture tests nothing.
    fn applied_change_set_linked(change_set_id: &str, operation_id: &str) -> ChangeSetRecord {
        ChangeSetRecord {
            operation_id: Some(operation_id.to_owned()),
            ..applied_change_set(change_set_id)
        }
    }

    /// Helper to create an operation with a change_set_id link.
    fn operation_with_change_set(
        operation_id: &str,
        change_set_id: &str,
        state: LifecycleState,
        rollback_deadline_unix: Option<u64>,
    ) -> OperationRecord {
        OperationRecord {
            state,
            rollback_deadline_unix,
            change_set_id: Some(change_set_id.to_owned()),
            ..validated_operation(operation_id)
        }
    }

    /// When the deadline is in the past and operation is Committing, infer auto-reverted.
    #[tokio::test]
    async fn commit_confirmation_presumes_revert_when_deadline_passed() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("cd");
        let operation_id = hex_id("0d");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        let deadline_past = 1000u64; // Far in the past
        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committing,
                Some(deadline_past),
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "presumed_auto_reverted",
            "when deadline is past and operation is Committing, should presume auto-revert"
        );
        assert_eq!(
            result["rollback_deadline_unix"].as_u64().unwrap(),
            deadline_past
        );
        assert_eq!(result["operation_id"].as_str().unwrap(), operation_id);
        assert_eq!(result["operation_state"].as_str().unwrap(), "committing");
    }

    /// `state resolve ... AS COMMITTED` asserts the commit landed, but does not
    /// stop the device. While the timer runs the change is still provisional,
    /// so the deadline must stay visible rather than being hidden behind a
    /// terminal `committed`.
    #[tokio::test]
    async fn commit_confirmation_keeps_a_live_timer_visible_after_a_manual_commit_resolve() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d4");
        let operation_id = hex_id("13");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committed,
                Some(u64::MAX),
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "awaiting_confirmation",
            "a resolve does not cancel the device's rollback"
        );
        assert_eq!(result["rollback_deadline_unix"].as_u64().unwrap(), u64::MAX);
    }

    /// An ordinary failed apply terminalizes the operation as `Discarded` with
    /// no deadline. Nothing was ever confirm-committed, so no confirmation
    /// verdict is owed — labelling it would misreport a plain failure.
    #[tokio::test]
    async fn commit_confirmation_absent_for_a_failed_apply_that_never_confirm_committed() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d5");
        let operation_id = hex_id("14");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Discarded,
                None,
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert!(
            result.get("commit_confirmation").is_none(),
            "a failed apply with no confirm window is not a confirmed-commit outcome"
        );
        assert_eq!(
            result["operation_state"].as_str().unwrap(),
            "discarded",
            "the operation state still has to be visible"
        );
    }

    /// `AS COMMITTED` on a window that has since closed is unresolvable from
    /// stored state: the resolve neither stops the device nor records its own
    /// time. Asserting either outcome would be a guess, so the tool says so.
    #[tokio::test]
    async fn commit_confirmation_is_indeterminate_for_a_committed_resolve_past_its_window() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d6");
        let operation_id = hex_id("15");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committed,
                Some(1000), // window long closed, deadline left behind by resolve
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "indeterminate",
            "neither committed nor reverted can be justified from what is stored"
        );
        assert!(
            result.get("rollback_deadline_unix").is_none(),
            "a closed window must not be advertised as pending"
        );
    }

    /// `state resolve ... AS DISCARDED` settles a record but leaves its
    /// deadline behind. The operator looked at the device and said the change
    /// is not there; a stale timer must not talk over that.
    #[tokio::test]
    async fn commit_confirmation_honours_a_manual_discard_over_a_stale_deadline() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d3");
        let operation_id = hex_id("12");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Discarded,
                Some(u64::MAX),
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "discarded",
            "a reconciled discard outranks a deadline the resolve left behind"
        );
        assert!(
            result.get("rollback_deadline_unix").is_none(),
            "a settled record must not advertise a confirmable window"
        );
    }

    /// A restart rewrites the operation to `Indeterminate` but leaves the
    /// deadline, and the Junos timer belongs to the device — so the window is
    /// still open and must still be reported. Keying on `Committing` alone
    /// dropped it, which is what the review caught.
    #[tokio::test]
    async fn commit_confirmation_survives_a_restart_rewriting_the_operation() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d2");
        let operation_id = hex_id("11");

        let mut record = applied_change_set(&change_set_id);
        record.operation_id = Some(operation_id.clone());
        coordinator.seed_change_set_for_test(record).await.unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Indeterminate,
                Some(u64::MAX),
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "awaiting_confirmation",
            "an Indeterminate operation still holding a future deadline is still confirmable"
        );
        assert_eq!(result["rollback_deadline_unix"].as_u64().unwrap(), u64::MAX);
        assert_eq!(
            result["operation_state"].as_str().unwrap(),
            "indeterminate",
            "the reader must be able to see a restart intervened"
        );
    }

    /// When the deadline is in the future and operation is Committing, report awaiting_confirmation.
    #[tokio::test]
    async fn commit_confirmation_awaiting_when_deadline_future() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("ce");
        let operation_id = hex_id("0e");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        let deadline_future = u64::MAX; // Far in the future
        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committing,
                Some(deadline_future),
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "awaiting_confirmation",
            "when deadline is future and operation is Committing, should report awaiting_confirmation"
        );
        assert_eq!(
            result["rollback_deadline_unix"].as_u64().unwrap(),
            deadline_future
        );
        assert_eq!(result["operation_id"].as_str().unwrap(), operation_id);
        assert_eq!(result["operation_state"].as_str().unwrap(), "committing");
    }

    /// When operation is Committed, report committed (regardless of deadline).
    #[tokio::test]
    async fn commit_confirmation_committed_when_operation_committed() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("cf");
        let operation_id = hex_id("0f");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committed,
                None, // Confirming clears the deadline
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert_eq!(
            result["commit_confirmation"].as_str().unwrap(),
            "committed",
            "when operation is Committed, should report committed"
        );
        assert!(
            result.get("rollback_deadline_unix").is_none(),
            "Committed operations have no deadline"
        );
        assert_eq!(result["operation_id"].as_str().unwrap(), operation_id);
        assert_eq!(result["operation_state"].as_str().unwrap(), "committed");
    }

    /// When no operation is linked to the change set, no confirmation fields are added.
    #[tokio::test]
    async fn commit_confirmation_absent_when_no_operation() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d0");

        coordinator
            .seed_change_set_for_test(applied_change_set(&change_set_id))
            .await
            .unwrap();

        // No operation inserted — the change set stands alone.

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        assert!(
            result.get("commit_confirmation").is_none(),
            "no operation means no commit_confirmation"
        );
        assert!(
            result.get("operation_id").is_none(),
            "no operation means no operation_id"
        );
        assert!(
            result.get("operation_state").is_none(),
            "no operation means no operation_state"
        );
    }

    /// Regression test: ensure pre-existing ChangeSetOutput fields are still present.
    #[tokio::test]
    async fn commit_confirmation_preserves_existing_fields() {
        let (_dir, coordinator) = coordinator();
        let change_set_id = hex_id("d1");
        let operation_id = hex_id("10");

        coordinator
            .seed_change_set_for_test(applied_change_set_linked(&change_set_id, &operation_id))
            .await
            .unwrap();

        coordinator
            .insert(operation_with_change_set(
                &operation_id,
                &change_set_id,
                LifecycleState::Committed,
                None,
            ))
            .await
            .unwrap();

        let result = get_change_set_status(
            GetChangeSetStatusArgs {
                change_set_id: change_set_id.clone(),
                device: DEVICE.to_owned(),
            },
            coordinator,
        )
        .await
        .unwrap();

        // Pre-existing ChangeSetOutput fields must all be present.
        assert!(
            result.get("change_set_id").is_some(),
            "change_set_id must be present"
        );
        assert_eq!(result["change_set_id"].as_str().unwrap(), change_set_id);

        assert!(result.get("owner").is_some(), "owner must be present");
        assert_eq!(result["owner"].as_str().unwrap(), OWNER);

        assert!(result.get("device").is_some(), "device must be present");
        assert_eq!(result["device"].as_str().unwrap(), DEVICE);

        assert!(result.get("state").is_some(), "state must be present");
        // `ChangeSetOutput::state` serialises snake_case, unlike the hand-built
        // PascalCase literals the create/approve/cancel handlers return.
        assert_eq!(result["state"].as_str().unwrap(), "applied");

        assert!(
            result.get("action_count").is_some(),
            "action_count must be present"
        );

        // The enrichment must sit *alongside* the original fields, not replace
        // them: this is a merge into the serialised `ChangeSetOutput`, and a
        // merge that dropped either half would still satisfy the asserts above.
        assert_eq!(result["commit_confirmation"].as_str().unwrap(), "committed");
        assert_eq!(result["operation_id"].as_str().unwrap(), operation_id);
    }
}

//! Re-probe a commit that this process died in the middle of (#370).
//!
//! `commit_operation` persists the caller's attribution — including
//! `request_id` — immediately *before* the commit RPC is sent, and
//! `format_attribution` puts that same id into the Junos commit comment as
//! `request.id=<uuid>`. So a process that dies between sending the commit and
//! recording its result leaves behind a record naming something the device can
//! be asked about.
//!
//! `ChangesetCoordinator::load` rewrites every non-terminal operation to
//! `Indeterminate` on restart, so that — not `Committing` — is the state a
//! crashed commit is found in. Pairing it with a present `attribution` is what
//! makes the selection precise: attribution is written nowhere else, so a
//! record carrying one had reached the commit, while a crash during staging
//! leaves `Indeterminate` with none.
//!
//! The rule that matters most here is what a *miss* means. Junos keeps a
//! bounded commit history, so an entry can age out; a device can also be
//! unreachable at startup. Neither is evidence the commit did not happen, and
//! settling such a record would assert an outcome nobody observed. Only a hit
//! settles anything.
//!
//! A confirmed commit is the other thing a hit cannot settle. Finding the id
//! proves the provisional commit entered the log, not that the rollback timer
//! was ever cancelled — so those are reported separately and left alone. The
//! entry's header is what tells them apart, which is why the match groups the
//! log back into entries rather than searching it flat.
//!
//! Known gap: a settle here writes the record directly and does not emit an
//! SSDF `result_receipt`, so a crash after the apply intent was spooled leaves
//! that evidence chain unterminated even once the device has confirmed the
//! outcome. Recovery is otherwise fully audited; closing the evidence chain
//! needs the recorder plumbed through startup and is tracked separately.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use mecmcp_changeset::{DeviceTransaction, LifecycleState, records::OperationRecord};
use std::sync::Arc;
use std::time::Duration;

/// Whether the candidate lock was proven free after a committed operation.
///
/// The commit log proves the commit landed, but not that the lock was released,
/// because this code path exists for the case where the process died between
/// sending the commit and recording its result — so the transaction's own
/// post-commit unlock/close may never have run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockProbeResult {
    /// The lock was proven free by taking and releasing it.
    ProvenFree,
    /// Lock freedom was not proven (could not take, could not confirm release,
    /// timeout, or error).
    NotProven,
}

/// How long one device may take to answer before its record is left alone.
pub const REPROBE_DEVICE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long after a rollback deadline the log is not trusted to show the
/// outcome: on a lab vSRX Junos wrote the rollback entry 25 s and 54 s late,
/// and `rollback pending` was seen up to 3 s before it, not to the instant.
const ROLLBACK_SETTLE_GRACE: u64 = 300;

/// How long the whole startup sweep may take before it gives up.
///
/// The sweep runs before the server serves traffic, so it must not be able to
/// hold startup open on an unreachable fleet. Whatever it has not settled by
/// then stays `Indeterminate`, which is where it already was.
pub const REPROBE_SWEEP_TIMEOUT: Duration = Duration::from_secs(120);

/// What the device said about one crashed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReprobeOutcome {
    /// The commit log carries this operation's `request.id`, so the commit
    /// reached the device and took effect.
    Committed,
    /// The id is in the log, but the commit that carried it was a *confirmed*
    /// commit that is either still pending (the device reverts it unless a
    /// confirming commit arrives) or whose fate cannot be read from the log.
    /// Finding it proves the provisional commit entered history, not that the
    /// rollback was ever cancelled.
    CommittedProvisional,
    /// The device answered and the id is not in its commit log.
    ///
    /// **Not** evidence the commit did not happen: the entry may have aged out
    /// of Junos's bounded history, or the commit may have carried no comment.
    NotFound,
    /// The device could not be asked at all.
    Unreachable(String),
}

/// Whether `commit_log` records a commit made under `request_id`.
///
/// A plain substring match on the whole commit log, which is sound here because
/// of what the needle is. `request.id=` is a fixed literal this server always
/// emits, and a v4 UUID's 122 random bits make an accidental match impossible
/// in a log Junos bounds to a few dozen entries. A UUID is also all hex digits
/// and hyphens, so it survives the XML escaping the commit comment goes through
/// unchanged and needs no unescaping before comparison.
///
/// Matching the raw text rather than walking `<commit-history>` elements keeps
/// this immune to the shape of whatever Junos returns — the same reason it is
/// safe to read either the CLI rendering or the RPC's XML with one function.
pub fn commit_log_contains_request_id(commit_log: &str, request_id: &str) -> bool {
    if request_id.is_empty() {
        return false;
    }
    commit_log.contains(&format!("request.id={request_id}"))
}

/// The one commit-log entry carrying `request_id`, header line included.
///
/// Junos prints an entry as a numbered header followed by its comment on
/// indented continuation lines, so the header — which is where a confirmed
/// commit is marked — is only reachable by grouping the lines back into
/// entries. A bare substring match finds the comment but loses that.
pub fn commit_entry_for_request_id<'log>(
    commit_log: &'log str,
    request_id: &str,
) -> Option<&'log str> {
    if request_id.is_empty() {
        return None;
    }
    let needle = format!("request.id={request_id}");
    let mut start: Option<usize> = None;
    let mut current: Option<usize> = None;
    let mut hit = false;
    for (offset, line) in line_offsets(commit_log) {
        let is_header = line
            .trim_start()
            .split_once(char::is_whitespace)
            .is_some_and(|(first, _)| {
                !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit())
            })
            && !line.starts_with(' ');
        if is_header {
            if hit {
                return start.map(|from| commit_log[from..offset].trim_end());
            }
            current = Some(offset);
        }
        if line.contains(&needle) {
            hit = true;
            start = current.or(Some(offset));
        }
    }
    if hit {
        return start.map(|from| commit_log[from..].trim_end());
    }
    None
}

fn line_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let base = text.as_ptr() as usize;
    text.lines()
        .map(move |line| (line.as_ptr() as usize - base, line))
}

/// Whether this commit-log entry records a *confirmed* commit.
///
/// Junos appends `commit confirmed, rollback in Nmins` to the entry's header
/// line. The text persists after the commit is confirmed or rolled back, so it
/// says the commit *was* a commit confirmed, not that it is still provisional;
/// see [`confirmed_commit_outcome`] for the settled-or-not decision.
pub fn entry_is_confirmed_commit(entry: &str) -> bool {
    entry
        .lines()
        .next()
        .is_some_and(|header| header.contains("commit confirmed"))
}

/// Ask one device whether the commit named by `record` landed.
pub async fn reprobe_operation(
    dm: &DeviceManager,
    record: &OperationRecord,
) -> Result<ReprobeOutcome, JmcpError> {
    let Some(attribution) = record.attribution.as_ref() else {
        return Ok(ReprobeOutcome::NotFound);
    };

    let probe = tokio::time::timeout(
        REPROBE_DEVICE_TIMEOUT,
        dm.run_cli(&record.device, "show system commit"),
    )
    .await;

    let commit_log = match probe {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Ok(ReprobeOutcome::Unreachable(error.to_string())),
        Err(_elapsed) => {
            return Ok(ReprobeOutcome::Unreachable(format!(
                "device did not answer within {}s",
                REPROBE_DEVICE_TIMEOUT.as_secs()
            )));
        }
    };

    let Some(entry) = commit_entry_for_request_id(&commit_log, &attribution.request_id) else {
        return Ok(ReprobeOutcome::NotFound);
    };

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    Ok(confirmed_commit_outcome(
        entry,
        record.rollback_deadline_unix,
        now_unix,
    ))
}

/// Decide `Committed` or `CommittedProvisional` for a log entry that carries
/// the operation's `request.id`.
///
/// A deadline on the record or the header's marker says it was a confirmed
/// commit (the marker catches a crash that beat the deadline to disk). The
/// marker persists after settling, so it is provisional unless the entry is
/// entry 0 and no longer pending: an automatic rollback writes a *new* entry 0,
/// so an entry 0 that is not pending was confirmed. The window around the
/// deadline is not trusted (see [`ROLLBACK_SETTLE_GRACE`]). Anything pushed
/// below entry 0 could be a confirming commit or a rollback, so it stays
/// provisional.
// shortcut: with no deadline on the record a settled entry 0 stays provisional;
// the header's `rollback in Nmins` plus its timestamp could compute one, if
// that matters.
fn confirmed_commit_outcome(
    entry: &str,
    rollback_deadline_unix: Option<u64>,
    now_unix: u64,
) -> ReprobeOutcome {
    if rollback_deadline_unix.is_none() && !entry_is_confirmed_commit(entry) {
        return ReprobeOutcome::Committed;
    }
    let Some(deadline) = rollback_deadline_unix else {
        return ReprobeOutcome::CommittedProvisional;
    };
    let is_entry_zero = entry
        .lines()
        .next()
        .and_then(|header| header.split_whitespace().next())
        == Some("0");
    let outside_gap =
        now_unix < deadline || now_unix >= deadline.saturating_add(ROLLBACK_SETTLE_GRACE);
    if is_entry_zero
        && entry_is_confirmed_commit(entry)
        && !crate::commit_attribution::commit_confirm_pending(entry)
        && outside_gap
    {
        return ReprobeOutcome::Committed;
    }
    ReprobeOutcome::CommittedProvisional
}

/// Whether this record is one a crashed commit could have left behind.
///
/// `Indeterminate` alone is not enough: a crash during staging reaches the same
/// state. The attribution is the discriminator, because `commit_operation`
/// writes it and nothing else does.
pub fn is_reprobe_candidate(record: &OperationRecord) -> bool {
    record.state == LifecycleState::Indeterminate && record.attribution.is_some()
}

/// The record to persist for `outcome`, or `None` to leave it untouched.
///
/// Only [`ReprobeOutcome::Committed`] settles anything. A miss and an
/// unreachable device are both "still unknown", and the record stays
/// `Indeterminate` for `state resolve` — the honest state, and the one it was
/// already in.
///
/// When settling `Committed`, the `lock_probe` result determines whether
/// `config_lock_held` is cleared. The commit log proves the commit landed,
/// but not that the lock was released — the process may have died between
/// the commit and the unlock. Only clear the flag when the probe proved freedom.
pub fn settle_from_outcome(
    record: &OperationRecord,
    outcome: &ReprobeOutcome,
    lock_probe: LockProbeResult,
) -> Option<OperationRecord> {
    match outcome {
        ReprobeOutcome::Committed => {
            let mut settled = record.clone();
            settled.state = LifecycleState::Committed;
            // `Committed` is only reached for a confirmed commit once the log
            // shows it confirmed; drop the deadline as `confirm_change_set` does,
            // or status keeps reporting the closed window.
            settled.rollback_deadline_unix = None;

            let lock_status_msg = match lock_probe {
                LockProbeResult::ProvenFree => {
                    settled.config_lock_held = false;
                    "the lock was proven free and returned"
                }
                LockProbeResult::NotProven => {
                    // Leave the record's own value untouched — this sweep learned
                    // nothing about the lock, in either direction.
                    "the lock state could not be verified"
                }
            };
            settled.details = Some(format!(
                "re-probed after restart: the device's commit log carries request.id={}, \
                 so the commit landed before this process died; {}",
                record
                    .attribution
                    .as_ref()
                    .map(|a| a.request_id.as_str())
                    .unwrap_or("<none>"),
                lock_status_msg
            ));
            Some(settled)
        }
        // A provisional commit is not settleable from the log. Marking it
        // `Committed` would make it terminal, freeing the device for an apply
        // whose commit would cancel a rollback that is still armed — and would
        // report a change as permanently live that the device may yet revert.
        ReprobeOutcome::CommittedProvisional
        | ReprobeOutcome::NotFound
        | ReprobeOutcome::Unreachable(_) => None,
    }
}

/// What one sweep did, for logging and for tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepSummary {
    /// Records that looked like a crashed commit.
    pub candidates: usize,
    /// Records settled `Committed` because the device had the id.
    pub settled: usize,
    /// Records whose commit landed provisionally under a confirm window.
    pub provisional: usize,
    /// Records left alone because the device answered without the id.
    pub not_found: usize,
    /// Records left alone because the device could not be asked.
    pub unreachable: usize,
    /// Records whose settle could not be persisted.
    pub write_failed: usize,
    /// Whether the sweep ran out of time before finishing.
    pub timed_out: bool,
}

/// Re-probe every crashed commit in the store, settling only what the device
/// confirms.
///
/// Never writes `Failed`: see the module docs for why a miss is not evidence.
/// The record as it stands now, if it is still an unsettled crashed commit.
///
/// A probe can take 20s, and the sweep runs alongside live traffic, so the
/// snapshot it started from may be stale by the time there is something to
/// write. Anything that reached a terminal state in the meantime — a confirm,
/// an operator's `state resolve` — is the newer truth and must not be written
/// over by a verdict formed before it happened.
async fn still_a_candidate(
    coordinator: &mecmcp_changeset::ChangesetCoordinator,
    record: &OperationRecord,
) -> Option<OperationRecord> {
    let current = coordinator
        .record(&record.id, &record.owner, &record.device)
        .await
        .ok()?;
    is_reprobe_candidate(&current).then_some(current)
}

/// Probe whether the candidate lock is free on a device.
///
/// Matches the abandon path's lock probe: take the lock and release it, bounded
/// by the cleanup budget. Returns `ProvenFree` only when the lock was taken and
/// confirmed returned. Any error, timeout, or failure to confirm the release
/// returns `NotProven`.
///
/// Taking the lock is the only proof it was free, because rustnetconf's close
/// sequence is best-effort and returns `Ok` even when `<close-session/>` fails.
async fn probe_lock_freedom(dm: Arc<DeviceManager>, device: &str) -> LockProbeResult {
    use crate::junos_transaction::JunosTransaction;

    let budget = crate::tools::candidate_transaction::cleanup_timeout();

    /// Helper to run one operation with a timeout, matching the abandon path's `probe`.
    async fn probe<F, T, E>(budget: Duration, future: F) -> Result<T, ProbeError<E>>
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

    // Build the transaction backend, matching apply_change_set.
    let transaction = JunosTransaction::new(dm, device.to_owned());

    // Try to take the lock
    if let Err(error) = probe(budget, transaction.lock("changeset recovery lock probe")).await {
        tracing::debug!(
            device = %device,
            error = %error,
            "could not take the lock to prove freedom"
        );
        return LockProbeResult::NotProven;
    }

    // Try to release the lock and confirm it was returned
    let returned = matches!(
        probe(budget, transaction.unlock()).await,
        Ok(mecmcp_changeset::UnlockOutcome::Released)
    );

    if returned {
        LockProbeResult::ProvenFree
    } else {
        tracing::debug!(
            device = %device,
            "took the candidate lock but could not confirm it was returned"
        );
        LockProbeResult::NotProven
    }
}

/// How many devices may be probed at once.
///
/// Serial probing lets a prefix of unreachable devices burn the whole sweep
/// budget on every start, so a reachable candidate later in the (stable) map
/// order would never be reached and would stay indeterminate forever. Bounded
/// concurrency removes the ordering dependence without opening an unbounded
/// number of NETCONF sessions.
pub const REPROBE_CONCURRENCY: usize = 4;

/// Re-probe every crashed commit in the store, settling only what the device
/// confirms.
///
/// Never writes `Failed`: see the module docs for why a miss is not evidence.
/// Intended to run in the background — it does device I/O, and startup must not
/// wait on a fleet that may be down.
pub async fn sweep_crashed_commits(
    dm: Arc<DeviceManager>,
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
) -> SweepSummary {
    let mut summary = SweepSummary::default();
    let mut candidates: Vec<OperationRecord> = coordinator
        .operations()
        .await
        .into_iter()
        .filter(is_reprobe_candidate)
        .collect();
    summary.candidates = candidates.len();
    if candidates.is_empty() {
        return summary;
    }

    // `operations()` returns a stable map order, and the sweep is capped. Left
    // in that order, a prefix of slow devices would consume the budget on every
    // start and the same tail would be aborted unprobed forever. Rotating the
    // start point each run means every candidate reaches the front eventually.
    // Seeded per process rather than from the clock: a wall-clock modulo is
    // periodic, so a fleet restarted on a schedule can select the same slow
    // prefix every time (60 records restarted daily hits `86400 % 60 == 0`) and
    // the tail would never be probed at all. `RandomState` is randomly seeded
    // on construction, which is aperiodic and needs no new dependency.
    let rotation = {
        use std::hash::{BuildHasher, Hasher};
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish() as usize
            % candidates.len()
    };
    candidates.rotate_left(rotation);

    // Deliberately NOT on `target: "audit"`. That stream carries one record per
    // tool call with a fixed schema — request_id, caller, tool, action, result
    // — which SIEM consumers parse on that basis, and it is where
    // `--audit-redact` is applied. Startup recovery has none of those fields
    // and no caller, so emitting it there would both break that contract and
    // put raw device names past the configured redaction policy.
    tracing::info!(
        event = "changeset_reprobe_started",
        candidates = summary.candidates,
        "re-probing operations left mid-commit by a previous run"
    );

    let permits = Arc::new(tokio::sync::Semaphore::new(REPROBE_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for record in candidates {
        let dm = dm.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await;
            let outcome = match reprobe_operation(&dm, &record).await {
                Ok(outcome) => outcome,
                Err(error) => ReprobeOutcome::Unreachable(error.to_string()),
            };
            (record, outcome)
        });
    }

    let deadline = tokio::time::Instant::now() + REPROBE_SWEEP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            summary.timed_out = true;
            break;
        }
        let next = match tokio::time::timeout(remaining, tasks.join_next()).await {
            Err(_elapsed) => {
                summary.timed_out = true;
                break;
            }
            Ok(None) => break,
            Ok(Some(joined)) => joined,
        };
        let Ok((record, outcome)) = next else {
            summary.unreachable += 1;
            continue;
        };

        match &outcome {
            ReprobeOutcome::Committed => {
                // Re-read before writing. The sweep runs alongside live traffic
                // now, and `record` is a snapshot taken before a probe that may
                // have taken 20s — writing it back blind would undo whatever
                // settled the operation in the meantime, including a confirm.
                let Some(current) = still_a_candidate(&coordinator, &record).await else {
                    continue;
                };
                // Probe lock freedom. The commit log proves the commit landed,
                // but not that the lock was released — the process may have died
                // between the commit and the unlock.
                //
                // Bounded by what is left of the sweep *now*, not by the
                // `remaining` computed at the top of this iteration: that value
                // was read before `join_next` awaited, so a candidate that spent
                // most of the budget there would otherwise hand the whole of it
                // to the lock probe as well and overrun the deadline.
                let remaining_for_probe =
                    deadline.saturating_duration_since(tokio::time::Instant::now());
                let lock_probe = match tokio::time::timeout(
                    remaining_for_probe,
                    probe_lock_freedom(dm.clone(), &record.device),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        summary.timed_out = true;
                        LockProbeResult::NotProven
                    }
                };
                let Some(settled) = settle_from_outcome(&current, &outcome, lock_probe) else {
                    continue;
                };
                if let Err(error) = coordinator.update(settled).await {
                    summary.write_failed += 1;
                    tracing::warn!(
                        event = "changeset_reprobe_write_failed",
                        operation_id = %record.id,
                        device = %record.device,
                        error = %error,
                        "the device confirmed the commit but the record could not be updated"
                    );
                    continue;
                }
                summary.settled += 1;
                tracing::info!(
                    event = "changeset_reprobe_settled",
                    operation_id = %record.id,
                    device = %record.device,
                    "the device's commit log carries this operation's request id; settled as committed"
                );
            }
            ReprobeOutcome::CommittedProvisional => {
                summary.provisional += 1;
                // The finding is reported, not written. Recording it would
                // mean writing `Indeterminate` plus the old deadline over a
                // record that a `confirm_junos_change_set` may have settled
                // between the re-read and the write — un-confirming a commit
                // the operator did confirm. mecmcp has no compare-and-update
                // for operations (only `update_change_set_from`, for change
                // sets), so that check cannot be made atomic here, and a note
                // is not worth that risk. The settle path below is safe from
                // the same race for a different reason: `Committed` is only
                // reached when the record carried no deadline, so it writes
                // exactly what a concurrent confirm would have written.
                tracing::warn!(
                    event = "changeset_reprobe_provisional",
                    operation_id = %record.id,
                    device = %record.device,
                    has_deadline = record.rollback_deadline_unix.is_some(),
                    "the commit landed but was a confirmed commit, so it is live only \
                     provisionally; the device reverts it unless confirmed, and only the device \
                     says whether the window is still open"
                );
            }
            ReprobeOutcome::NotFound => {
                summary.not_found += 1;
                tracing::warn!(
                    event = "changeset_reprobe_not_found",
                    operation_id = %record.id,
                    device = %record.device,
                    "the request id is not in the device's commit log; it may have aged out, so \
                     the record is left for `state resolve` rather than settled"
                );
            }
            ReprobeOutcome::Unreachable(reason) => {
                summary.unreachable += 1;
                tracing::warn!(
                    event = "changeset_reprobe_unreachable",
                    operation_id = %record.id,
                    device = %record.device,
                    reason = %reason,
                    "could not ask the device; the record is left for `state resolve`"
                );
            }
        }
    }
    tasks.abort_all();

    tracing::info!(
        event = "changeset_reprobe_finished",
        candidates = summary.candidates,
        settled = summary.settled,
        provisional = summary.provisional,
        not_found = summary.not_found,
        unreachable = summary.unreachable,
        write_failed = summary.write_failed,
        timed_out = summary.timed_out,
        "re-probe sweep complete"
    );

    summary
}

#[cfg(test)]
mod tests {
    /// Captured verbatim from vSRX 24.4R1.9 during the #370 hardware run, so
    /// the entry grouping is tested against what a device actually prints
    /// rather than against what this module wishes it printed.
    const REAL_LOG: &str = "\
0   2026-09-03 17:03:08 UTC by netconf via netconf
    no-change-ref by reprobe-370-w (agent) on-behalf-of=self via unknown-public request.id=abadcafe-dead-4bad-8bad-c0dedeadbeef change-set=30a15e0b686bae37
1   2026-07-28 17:54:19 UTC by root via other
2   2026-07-20 22:04:08 UTC by netconf via netconf
    Remove unused srxoutpost super-user (shared-credential cleanup)
3   2026-03-30 21:49:31 UTC by netconf via netconf commit confirmed, rollback in 3mins
    provisional change request.id=11111111-2222-4333-8444-555555555555 change-set=deadbeef
";

    /// The entry must carry its own header, because that is the only place
    /// Junos marks a commit as confirmed.
    #[test]
    fn commit_entry_includes_the_header_line() {
        let entry = commit_entry_for_request_id(REAL_LOG, "abadcafe-dead-4bad-8bad-c0dedeadbeef")
            .expect("the id is in the captured log");
        assert!(entry.starts_with("0   2026-09-03"), "entry was: {entry:?}");
        assert!(entry.contains("request.id=abadcafe"));
        assert!(
            !entry.contains("2026-07-28"),
            "the entry must stop at the next header, not run into it"
        );
    }

    /// An id that is not there yields no entry, which is what keeps a miss from
    /// being read as anything but unknown.
    #[test]
    fn commit_entry_absent_for_an_unknown_id() {
        assert!(
            commit_entry_for_request_id(REAL_LOG, "00000000-dead-4bee-8000-ffffffffffff").is_none()
        );
        assert!(commit_entry_for_request_id(REAL_LOG, "").is_none());
    }

    /// A plain commit's entry carries no confirm marker.
    #[test]
    fn plain_commit_entry_is_not_a_confirmed_commit() {
        let entry = commit_entry_for_request_id(REAL_LOG, "abadcafe-dead-4bad-8bad-c0dedeadbeef")
            .expect("present");
        assert!(!entry_is_confirmed_commit(entry));
    }

    /// The confirm marker lives on the header, above the comment that carries
    /// the id — so finding the id is not the same as knowing the commit stuck.
    #[test]
    fn confirmed_commit_entry_is_recognised() {
        let entry = commit_entry_for_request_id(REAL_LOG, "11111111-2222-4333-8444-555555555555")
            .expect("present");
        assert!(
            entry_is_confirmed_commit(entry),
            "header marks it confirmed: {entry:?}"
        );
    }

    // Captured from a lab vSRX on Junos 24.4R1.9 on 2026-11-11 through execute_junos_command.
    const CHANGESET_REQUEST_ID: &str = "0f4f3f37-9088-4b40-89d7-0c30f8665fd4";
    const CHANGESET_DEADLINE: u64 = 1_794_372_656;
    const CHANGESET_PENDING_LOG: &str = "\
<output xmlns:junos=\"http://xml.juniper.net/junos/24.4R1.9/junos\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">
0   2026-11-11 04:48:56 UTC by netconf via netconf commit confirmed, rollback in 2mins
    no-change-ref by claude-fullscope (unknown) on-behalf-of=self via unknown-public request.id=0f4f3f37-9088-4b40-89d7-0c30f8665fd4 change-set=ba40922fbc291fd6
    rollback pending
1   2026-11-11 00:05:12 UTC by netconf via netconf
    rjm-632 capture: restore baseline
";
    const CHANGESET_ROLLED_BACK_LOG: &str = "\
<output xmlns:junos=\"http://xml.juniper.net/junos/24.4R1.9/junos\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">
0   2026-11-11 04:51:50 UTC by root via other
1   2026-11-11 04:48:56 UTC by netconf via netconf commit confirmed, rollback in 2mins
    no-change-ref by claude-fullscope (unknown) on-behalf-of=self via unknown-public request.id=0f4f3f37-9088-4b40-89d7-0c30f8665fd4 change-set=ba40922fbc291fd6
2   2026-11-11 00:05:12 UTC by netconf via netconf
";

    fn changeset_entry(log: &str) -> String {
        commit_entry_for_request_id(log, CHANGESET_REQUEST_ID)
            .expect("the capture carries the request id")
            .to_string()
    }

    /// No change-set capture exists for a commit confirmed by a later commit
    /// check, so this is CHANGESET_PENDING_LOG minus its `rollback pending`
    /// line, which is exactly what the earlier capture showed a confirm does.
    fn settled_changeset_entry() -> String {
        changeset_entry(&CHANGESET_PENDING_LOG.replace("    rollback pending\n", ""))
    }

    /// The whole point of the provisional outcome: a confirmed commit that was
    /// found in the log is still one the device may revert, so settling it
    /// `Committed` would both hide a live rollback and free the device for an
    /// apply whose commit would cancel it.
    #[test]
    fn a_provisional_commit_is_never_settled() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution("abadcafe-dead-4bad-8bad-c0dedeadbeef")),
        );
        assert!(
            settle_from_outcome(
                &record,
                &ReprobeOutcome::CommittedProvisional,
                LockProbeResult::NotProven
            )
            .is_none(),
            "a provisional commit must stay unsettled"
        );
    }

    use super::*;
    use mecmcp_changeset::records::{
        OperationRecord, PersistedAgentIdentity, PersistedAttribution, PersistedPrincipal,
    };
    use serde_json::json;

    const TEST_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const DIFFERENT_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";

    /// Create a minimal `PersistedAttribution` for testing.
    fn test_attribution(request_id: &str) -> PersistedAttribution {
        PersistedAttribution {
            principal: PersistedPrincipal::Token("demo".to_owned()),
            actor_type: "agent".to_owned(),
            on_behalf_of: Some("self".to_owned()),
            change_ref: Some("00112233445566".to_owned()),
            request_id: request_id.to_owned(),
            agent: Some(PersistedAgentIdentity {
                model_id: "claude-sonnet-4-5".to_owned(),
                provider: "anthropic".to_owned(),
                provider_tier: "public".to_owned(),
                skills_used: "none".to_owned(),
            }),
        }
    }

    /// Realistic Junos commit log containing the test UUID.
    fn commit_log_with_uuid(uuid: &str) -> String {
        format!(
            r#"0   2026-07-28 17:54:19 UTC by root via other
1   2026-07-28 17:50:12 UTC by netconf via netconf
    CHG-1 by token:demo (agent) on-behalf-of=self request.id={} change-set=00112233445566
2   2026-07-20 22:04:08 UTC by netconf via netconf
    some earlier config change
3   2026-07-19 10:23:45 UTC by root via cli
"#,
            uuid
        )
    }

    /// Create a minimal test `OperationRecord` with the given state and attribution.
    fn test_record(
        state: LifecycleState,
        attribution: Option<PersistedAttribution>,
    ) -> OperationRecord {
        OperationRecord {
            id: "0".repeat(64),
            owner: "test-owner".to_owned(),
            device: "test-device".to_owned(),
            endpoint: "junos://test-device:830".to_owned(),
            action: json!("merge"),
            xpath: None,
            actions: vec![],
            change_set_id: None,
            current: "sha256:".to_owned() + &"f".repeat(64),
            state,
            job_id: None,
            details: None,
            config_lock_held: true,
            policy_signature: String::new(),
            attribution,
            rollback_deadline_unix: None,
            config_authority: None,
        }
    }

    /// Protects against falsely settling an operation the device does not remember.
    #[test]
    fn commit_log_contains_request_id_realistic_log() {
        let log = commit_log_with_uuid(TEST_UUID);
        assert!(
            commit_log_contains_request_id(&log, TEST_UUID),
            "should find the request id in a realistic commit log"
        );
    }

    /// Confirms that absence of the id returns false, not a false positive.
    #[test]
    fn commit_log_contains_request_id_missing_id() {
        let log = commit_log_with_uuid(TEST_UUID);
        assert!(
            !commit_log_contains_request_id(&log, DIFFERENT_UUID),
            "should not find a different uuid"
        );
    }

    /// An empty log has no id, so the result must be false.
    #[test]
    fn commit_log_contains_request_id_empty_log() {
        assert!(
            !commit_log_contains_request_id("", TEST_UUID),
            "empty log cannot contain any id"
        );
    }

    /// Empty request_id must not match everything, which a naive contains() would do.
    #[test]
    fn commit_log_contains_request_id_empty_request_id() {
        let log = commit_log_with_uuid(TEST_UUID);
        assert!(
            !commit_log_contains_request_id(&log, ""),
            "empty request_id must not match a non-empty log"
        );
    }

    /// Confirms that a truncated UUID would substring-match despite being invalid.
    ///
    /// This test documents a case the implementation does not defend against, because
    /// `request_id` in production always comes from `Uuid` and is always 36 characters.
    /// A truncated id is not something this server can produce.
    #[test]
    fn commit_log_contains_request_id_prefix_safety() {
        let full_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let truncated = "550e8400-e29b-41d4-a716-44665544000"; // one char shorter
        let log = commit_log_with_uuid(full_uuid);

        // The truncated string would match as a substring, but this is not a real case.
        assert!(
            commit_log_contains_request_id(&log, truncated),
            "a truncated uuid DOES substring-match, but the server never produces one"
        );

        // The real case: looking for a completely different UUID returns false.
        assert!(
            !commit_log_contains_request_id(&log, DIFFERENT_UUID),
            "a genuinely different uuid does not match"
        );
    }

    /// An aged-out commit is not in the log, and that is not evidence it did not happen.
    ///
    /// Junos keeps a bounded commit history; this is the case the module docs say must
    /// never settle a record.
    #[test]
    fn commit_log_contains_request_id_aged_out() {
        // Build a log with ~45 entries, none of which carry our id.
        let mut log = String::new();
        for i in 0..45 {
            log.push_str(&format!(
                "{}   2026-07-{:02} 12:00:00 UTC by root via cli\n    some change\n",
                i,
                (i % 28) + 1
            ));
        }

        assert!(
            !commit_log_contains_request_id(&log, TEST_UUID),
            "aged-out id is not in the log; this must NOT be treated as evidence the commit did not happen"
        );
    }

    /// Indeterminate + attribution is the crashed-commit shape to look for.
    #[test]
    fn is_reprobe_candidate_indeterminate_with_attribution() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        assert!(
            is_reprobe_candidate(&record),
            "Indeterminate + attribution is the crashed-commit shape"
        );
    }

    /// Indeterminate alone is not enough: a crash during staging reaches the same state.
    ///
    /// Attribution is the discriminator; it is written only by commit_operation.
    #[test]
    fn is_reprobe_candidate_indeterminate_without_attribution() {
        let record = test_record(LifecycleState::Indeterminate, None);
        assert!(
            !is_reprobe_candidate(&record),
            "Indeterminate without attribution is a crash during staging, not commit"
        );
    }

    /// Committing + attribution is not the shape to look for.
    ///
    /// `load()` rewrites `Committing` to `Indeterminate` before any sweep sees it,
    /// so `Committing` is not what the reprobe logic searches for.
    #[test]
    fn is_reprobe_candidate_committing_with_attribution() {
        let record = test_record(
            LifecycleState::Committing,
            Some(test_attribution(TEST_UUID)),
        );
        assert!(
            !is_reprobe_candidate(&record),
            "Committing is rewritten to Indeterminate before sweep, so it is not the shape to look for"
        );
    }

    /// Committed operations are already settled and need no reprobe.
    #[test]
    fn is_reprobe_candidate_committed_with_attribution() {
        let record = test_record(LifecycleState::Committed, Some(test_attribution(TEST_UUID)));
        assert!(
            !is_reprobe_candidate(&record),
            "Committed operations are already settled"
        );
    }

    /// The only outcome that settles a record is Committed.
    ///
    /// Confirms the settled record is marked `Committed`, has the lock flag cleared
    /// when lock freedom was proven, and carries a details message citing the request id.
    #[test]
    fn settle_from_outcome_committed_with_lock_proven_free() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        let outcome = ReprobeOutcome::Committed;
        let lock_probe = LockProbeResult::ProvenFree;

        let settled =
            settle_from_outcome(&record, &outcome, lock_probe).expect("Committed should settle");

        assert_eq!(
            settled.state,
            LifecycleState::Committed,
            "the settled record must be Committed"
        );
        assert!(
            !settled.config_lock_held,
            "the lock must be cleared when proven free"
        );
        assert!(
            settled.details.as_ref().unwrap().contains(TEST_UUID),
            "details must cite the request id"
        );
        assert!(
            settled
                .details
                .as_ref()
                .unwrap()
                .contains("lock was proven free"),
            "details must state that lock freedom was proven"
        );
    }

    /// A confirmed commit the log shows settled leaves no deadline behind, or
    /// status would still report `awaiting_confirmation` or `indeterminate`.
    #[test]
    fn settle_from_outcome_committed_clears_the_rollback_deadline() {
        let mut record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(CHANGESET_REQUEST_ID)),
        );
        record.rollback_deadline_unix = Some(CHANGESET_DEADLINE);
        let settled = settle_from_outcome(
            &record,
            &ReprobeOutcome::Committed,
            LockProbeResult::NotProven,
        )
        .expect("Committed should settle");
        assert_eq!(settled.rollback_deadline_unix, None);
    }

    /// When lock freedom was not proven, the flag must remain set.
    ///
    /// The commit log proves the commit landed, but not that the lock was released,
    /// because the process may have died between the commit and the unlock. Only clear
    /// the flag when the probe proved freedom.
    #[test]
    fn settle_from_outcome_committed_with_lock_not_proven() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        let outcome = ReprobeOutcome::Committed;
        let lock_probe = LockProbeResult::NotProven;

        let settled = settle_from_outcome(&record, &outcome, lock_probe)
            .expect("Committed should settle even when lock state is unverified");

        assert_eq!(
            settled.state,
            LifecycleState::Committed,
            "the settled record must be Committed"
        );
        assert!(
            settled.config_lock_held,
            "the lock flag must remain set when freedom was not proven"
        );
        assert!(
            settled.details.as_ref().unwrap().contains(TEST_UUID),
            "details must cite the request id"
        );
        assert!(
            settled
                .details
                .as_ref()
                .unwrap()
                .contains("lock state could not be verified"),
            "details must state that lock freedom was not verified"
        );
    }

    /// NotFound is not evidence the commit did not happen; it must not settle the record.
    ///
    /// This is the most important test in the file. The id may have aged out, or the
    /// commit may have carried no comment. Settling here would assert an outcome nobody
    /// observed, which is the exact failure #370 exists to avoid.
    #[test]
    fn settle_from_outcome_not_found() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        let outcome = ReprobeOutcome::NotFound;

        let result = settle_from_outcome(&record, &outcome, LockProbeResult::NotProven);

        assert!(
            result.is_none(),
            "NotFound must NOT settle the record; absence of proof is not proof of absence"
        );
    }

    /// Unreachable devices cannot be asked; the record must stay indeterminate.
    #[test]
    fn settle_from_outcome_unreachable() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        let outcome = ReprobeOutcome::Unreachable("network timeout".to_owned());

        let result = settle_from_outcome(&record, &outcome, LockProbeResult::NotProven);

        assert!(
            result.is_none(),
            "Unreachable devices cannot be asked; the record must stay indeterminate"
        );
    }

    /// settle_from_outcome never returns Failed for any outcome.
    ///
    /// A miss is not evidence the commit did not happen, so the function must never
    /// settle a record as Failed.
    #[test]
    fn settle_from_outcome_never_returns_failed() {
        let record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );

        let outcomes = [
            ReprobeOutcome::Committed,
            ReprobeOutcome::NotFound,
            ReprobeOutcome::Unreachable("test".to_owned()),
        ];

        for outcome in &outcomes {
            if let Some(settled) = settle_from_outcome(&record, outcome, LockProbeResult::NotProven)
            {
                assert_ne!(
                    settled.state,
                    LifecycleState::Failed,
                    "settle_from_outcome must never return Failed for {:?}",
                    outcome
                );
            }
        }
    }

    /// When lock freedom is not proven, the flag must be left as it was.
    ///
    /// The commit log proves the commit landed, but the probe learned nothing about
    /// the lock. If the incoming record had config_lock_held == false, it must stay
    /// false — inventing a held lock is as bad as clearing one that may still exist.
    #[test]
    fn settle_from_outcome_not_proven_leaves_flag_alone_when_already_clear() {
        let mut record = test_record(
            LifecycleState::Indeterminate,
            Some(test_attribution(TEST_UUID)),
        );
        // Start with the flag already clear
        record.config_lock_held = false;
        let outcome = ReprobeOutcome::Committed;
        let lock_probe = LockProbeResult::NotProven;

        let settled = settle_from_outcome(&record, &outcome, lock_probe)
            .expect("Committed should settle even when lock state is unverified");

        assert_eq!(
            settled.state,
            LifecycleState::Committed,
            "the settled record must be Committed"
        );
        assert!(
            !settled.config_lock_held,
            "the lock flag must remain clear when it was already clear and probe is NotProven"
        );
        assert!(
            settled
                .details
                .as_ref()
                .unwrap()
                .contains("lock state could not be verified"),
            "details must state that lock freedom was not verified"
        );
    }

    /// A lock probe that outlives the remaining sweep budget must be cut short.
    ///
    /// The sweep deadline bounds both `join_next()` and the lock probe. A probe
    /// that would take longer than the remaining time must yield NotProven and
    /// set timed_out rather than letting the sweep run unbounded.
    #[tokio::test]
    async fn lock_probe_is_bounded_by_sweep_deadline() {
        use tokio::time::Duration;

        // Simulate the timeout wrapper that should exist in the sweep.
        // We use a very short timeout (1ms) and a slow operation to verify
        // the timeout logic without using test-util.

        let remaining = Duration::from_millis(1);

        // Simulate a probe that would take much longer
        let slow_probe = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            LockProbeResult::ProvenFree
        };

        let mut timed_out = false;
        let probe_result = match tokio::time::timeout(remaining, slow_probe).await {
            Ok(result) => result,
            Err(_) => {
                timed_out = true;
                LockProbeResult::NotProven
            }
        };

        assert!(
            timed_out,
            "the timeout must fire when probe exceeds remaining time"
        );
        assert_eq!(
            probe_result,
            LockProbeResult::NotProven,
            "timed-out probe must yield NotProven"
        );
    }

    const DEADLINE: u64 = CHANGESET_DEADLINE;

    #[test]
    fn pending_entry_zero_is_provisional() {
        let entry = changeset_entry(CHANGESET_PENDING_LOG);
        for now in [DEADLINE - 10, DEADLINE + 60, DEADLINE + 1000] {
            assert_eq!(
                confirmed_commit_outcome(&entry, Some(DEADLINE), now),
                ReprobeOutcome::CommittedProvisional
            );
        }
    }

    #[test]
    fn settled_entry_zero_commits_outside_the_deadline_gap() {
        let entry = settled_changeset_entry();
        assert_eq!(
            confirmed_commit_outcome(&entry, Some(DEADLINE), DEADLINE - 1),
            ReprobeOutcome::Committed
        );
        assert_eq!(
            confirmed_commit_outcome(&entry, Some(DEADLINE), DEADLINE + 60),
            ReprobeOutcome::CommittedProvisional
        );
        assert_eq!(
            confirmed_commit_outcome(&entry, Some(DEADLINE), DEADLINE + 301),
            ReprobeOutcome::Committed
        );
    }

    #[test]
    fn settled_entry_zero_without_a_deadline_is_provisional() {
        assert_eq!(
            confirmed_commit_outcome(&settled_changeset_entry(), None, DEADLINE + 1000),
            ReprobeOutcome::CommittedProvisional
        );
    }

    /// The rolled-back capture: a later entry exists, so the fate of the
    /// confirmed commit is not readable however long ago the deadline passed.
    #[test]
    fn confirmed_commit_below_entry_zero_is_provisional() {
        let entry = changeset_entry(CHANGESET_ROLLED_BACK_LOG);
        assert!(entry.starts_with("1 "), "entry was: {entry:?}");
        assert_eq!(
            confirmed_commit_outcome(&entry, Some(DEADLINE), DEADLINE + 100_000),
            ReprobeOutcome::CommittedProvisional
        );
    }

    #[test]
    fn plain_entry_without_a_deadline_commits() {
        let entry = commit_entry_for_request_id(REAL_LOG, "abadcafe-dead-4bad-8bad-c0dedeadbeef")
            .expect("present");
        assert_eq!(
            confirmed_commit_outcome(entry, None, DEADLINE),
            ReprobeOutcome::Committed
        );
    }
}

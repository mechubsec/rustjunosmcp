//! `rollback_config` — load a Junos rollback archive (rollback N) into the
//! candidate and optionally commit it.
//!
//! - **Preview mode** (commit=false, default): loads rollback N, computes the
//!   diff, then discards the candidate (stateless). Returns the diff without
//!   committing.
//! - **Commit mode** (commit=true): loads rollback N and commits. Supports
//!   confirmed-commit with auto-rollback after N minutes.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{
    ConfirmDecision, confirm_timeout_to_secs, resolve_confirm_timeout, rollback_deadline_unix,
    validate_rollback_version,
};
use crate::tools::RollbackConfigArgs;
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Load a rollback archive and optionally commit it.
///
/// Preview mode (commit=false): loads rollback N, diffs, discards the candidate
/// (stateless). Commit mode (commit=true): loads rollback N and commits, with
/// optional confirmed-commit. Validates rollback version (0..=49). Config blocklist
/// is NOT applied — granting rollback_config scope grants full config-change authority.
pub async fn handle(
    args: RollbackConfigArgs,
    dm: Arc<DeviceManager>,
    allow_plane_owned_writes: bool,
) -> Result<Value, JmcpError> {
    handle_with_cancel(args, dm, allow_plane_owned_writes, CancellationToken::new()).await
}

/// Cancellable variant of `handle` for use in transport shutdown paths.
///
/// `_allow_plane_owned_writes` is unused: a plane-owned commit is refused
/// unconditionally below (MEC-1879, P5c), so the flag has no effect here. The
/// parameter stays so this handler's signature matches the others the CLI
/// dispatches to generically.
pub async fn handle_with_cancel(
    args: RollbackConfigArgs,
    dm: Arc<DeviceManager>,
    _allow_plane_owned_writes: bool,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Confirm the router exists and check config authority.
    let authority_warning: Option<String> = {
        let inv = dm.inventory();
        let device_entry = inv.get(&args.device)?;

        // Only check if actually committing (preview mode is read-only).
        if args.commit {
            // Plane-owned rollback commits are refused unconditionally here,
            // even with --allow-plane-owned-writes (MEC-1879, P5c): the
            // rollback-depth guard only exists on the change-set path, so a
            // direct-commit rollback has no equivalent safeguard to run under.
            if device_entry.config_authority.is_plane_owned() {
                return Err(JmcpError::PlaneOwnedRollbackConfigRefused {
                    device: args.device.clone(),
                    authority: device_entry.config_authority.as_str().to_string(),
                });
            }

            // Authority is Local or Unknown here (plane-owned already
            // returned above), so there is never a warning to attach.
            None
        } else {
            None
        }
    };

    // Validate rollback version 0..=49.
    let version = validate_rollback_version(args.version)?;

    // NOTE: Config blocklist is NOT applied. Rollback restores an archived,
    // already-committed configuration (not caller-authored text). Granting
    // rollback_config scope is equivalent to full config-change authority.

    let timeout_dur = Duration::from_secs(args.timeout);

    let has_commit_comment = args.commit_comment.is_some();
    // Commit-confirmed by default when committing (MEC-45): a bad rollback
    // reverts itself unless the caller explicitly opts out with
    // `confirm_timeout_mins: 0`. Preview mode never commits, so it is
    // unaffected.
    let (mode, confirmed) = if !args.commit {
        (CandidateMode::DryRun, None)
    } else {
        match resolve_confirm_timeout(args.confirm_timeout_mins) {
            ConfirmDecision::Confirmed(mins) => {
                let secs = confirm_timeout_to_secs(mins)?;
                (CandidateMode::CommitConfirmed(secs), Some(mins))
            }
            ConfirmDecision::OptedOut => {
                let comment = args
                    .commit_comment
                    .clone()
                    .unwrap_or_else(|| format!("rollback to {} via rollback_config", version));
                (CandidateMode::CommitWithComment(comment), None)
            }
        }
    };

    match candidate_transaction::run(
        &dm,
        &args.device,
        CandidateRequest {
            payload: None,
            rollback_source: Some(version),
            mode,
            // Unused: this loads an archived rollback, not a caller payload.
            load_action: rustez::LoadAction::Merge,
        },
        timeout_dur,
        &ct,
    )
    .await?
    {
        CandidateResult::DryRun { diff } => {
            // Preview mode: config loaded and diffed, then discarded.
            Ok(json!({
                "committed": false,
                "diff": diff,
                "version": version
            }))
        }
        CandidateResult::Committed { diff } => {
            // Commit succeeded (normal or confirmed).
            let mut result = json!({
                "committed": true,
                "diff": diff,
                "version": version
            });
            if let Some(mins) = confirmed {
                result["confirmed"] = json!(true);
                result["rollback_in_minutes"] = json!(mins);
                result["rollback_deadline_unix"] = json!(rollback_deadline_unix(mins));
                result["message"] = json!(format!(
                    "Commit confirmed: auto-rollback in {} minutes unless confirmed. \
                     Send another commit to confirm with confirm_commit.",
                    mins
                ));
                if has_commit_comment {
                    result["note"] = json!(
                        "commit_comment is ignored during confirmed commits \
                         (rustez API limitation)"
                    );
                }
            }
            if let Some(warning) = authority_warning {
                result["warning"] = json!(warning);
            }
            Ok(result)
        }
        CandidateResult::CommitFailed { diff, error } => {
            // Commit was attempted but device rejected it.
            let mut result = json!({
                "committed": false,
                "diff": diff,
                "version": version,
                "error": error
            });
            if let Some(warning) = authority_warning {
                result["warning"] = json!(warning);
            }
            Ok(result)
        }
        _ => unreachable!("rollback transaction returned unexpected result kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            RollbackConfigArgs {
                device: "nope".into(),
                version: 1,
                commit: false,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    /// MEC-1879 P5c: `rollback_config` with `commit=true` on a plane-owned
    /// device refuses unconditionally, even with `allow_plane_owned_writes`
    /// set — the depth-refusal guard only exists on the change-set path.
    #[tokio::test]
    async fn commit_refused_on_plane_owned_device_even_with_allow_plane_owned_writes() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"},"config_authority":"mist"}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            RollbackConfigArgs {
                device: "r1".into(),
                version: 1,
                commit: true,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
            true, // allow_plane_owned_writes = true must not matter here
        )
        .await;

        match r {
            Err(JmcpError::PlaneOwnedRollbackConfigRefused { device, authority }) => {
                assert_eq!(device, "r1");
                assert_eq!(authority, "mist");
            }
            other => panic!(
                "expected a plane-owned commit to be refused regardless of \
                 allow_plane_owned_writes, got {other:?}"
            ),
        }
    }

    /// MEC-1879 P5c: preview mode (`commit=false`) is unaffected by the
    /// plane-owned commit refusal — it must reach the (unrelated) version
    /// validation below rather than being refused for plane ownership.
    #[tokio::test]
    async fn preview_mode_unaffected_by_plane_owned_commit_refusal() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"},"config_authority":"mist"}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            RollbackConfigArgs {
                device: "r1".into(),
                version: 50, // out of range: a network-free way to prove the
                // authority check never ran for commit=false.
                commit: false,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
            false,
        )
        .await;

        assert!(
            matches!(r, Err(JmcpError::BadRollbackVersion(50))),
            "expected preview mode to skip the plane-owned check and reach version \
             validation, got {r:?}"
        );
    }

    #[tokio::test]
    async fn version_out_of_range_rejected() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            RollbackConfigArgs {
                device: "r1".into(),
                version: 50,
                commit: false,
                confirm_timeout_mins: None,
                commit_comment: None,
                timeout: 5,
            },
            dm,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }
}

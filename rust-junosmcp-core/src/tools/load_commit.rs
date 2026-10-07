//! `load_and_commit_config` — lock candidate, load, diff, commit (with comment),
//! unlock. Rollback on commit failure. Returns `{success, diff, error?}`.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{
    ConfirmDecision, build_config_payload, confirm_timeout_to_secs, excerpt, parse_load_mode,
    refuse_override_outside_changeset, resolve_confirm_timeout, resolve_load_action,
    rollback_deadline_unix, validate_input_length,
};
use crate::policy::{Decision, Policy};
use crate::tools::LoadCommitArgs;
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Load configuration and commit it to the device.
///
/// Locks the candidate, loads the provided config (validating format and checking
/// policy), diffs, and commits with the provided comment. Supports confirmed-commit
/// with auto-rollback. Rolls back the candidate on commit failure. Returns
/// `{success, diff, error?, confirmed?, rollback_in_minutes?}`.
pub async fn handle(
    args: LoadCommitArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    allow_plane_owned_writes: bool,
) -> Result<Value, JmcpError> {
    handle_with_cancel(
        args,
        dm,
        policy,
        allow_plane_owned_writes,
        CancellationToken::new(),
    )
    .await
}

/// Cancellable variant of `handle` for use in transport shutdown paths.
pub async fn handle_with_cancel(
    args: LoadCommitArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    allow_plane_owned_writes: bool,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    validate_input_length("config_text", &args.config_text)?;

    // Confirm the router exists and check config authority before policy check.
    let authority_warning = {
        let inv = dm.inventory();
        let device_entry = inv.get(&args.device)?;

        // Check config_authority: refuse if plane-owned and not explicitly allowed.
        crate::helpers::check_plane_owned_operation(
            "load_and_commit_config",
            &args.device,
            &device_entry.config_authority,
            allow_plane_owned_writes,
        )?
    };

    // The format gate is part of the policy check; downstream
    // build_config_payload still validates the value separately.
    match policy.check_config(&args.device, &args.config_format, &args.config_text)? {
        Decision::Allow => {}
        Decision::Deny {
            rule,
            source,
            line_number,
        } => {
            let pattern = rule.pattern.clone();
            let source_str = source.as_str();
            let denied_excerpt = excerpt(&args.config_text);
            tracing::warn!(
                tool = "load_and_commit_config",
                router = %args.device,
                matched_rule = %pattern,
                rule_source = %source_str,
                line_number = ?line_number,
                input_excerpt = %denied_excerpt,
                "blocklist denied request",
            );
            return Err(JmcpError::Denied {
                tool: "load_and_commit_config",
                router: args.device.clone(),
                pattern,
                rule_source: source_str,
                input_excerpt: denied_excerpt,
                line_number,
            });
        }
        Decision::DenyAllowlist { .. } => {
            return Err(JmcpError::ConfigDomainAllowlistInvariant {
                tool: "load_and_commit_config",
                router: args.device.clone(),
            });
        }
    }

    // `mode` is validated and gated before any payload is built or RPC is
    // sent: `override` is the highest blast-radius operation this server
    // exposes, and this tool commits directly with no second-principal
    // review, so it is refused outright rather than forwarded to the device.
    let load_mode = parse_load_mode(Some(&args.mode))?;
    refuse_override_outside_changeset("load_and_commit_config", load_mode)?;
    let load_action = resolve_load_action(&args.config_format, load_mode)?;

    let payload = build_config_payload(args.config_text, Some(&args.config_format))?;

    let timeout_dur = Duration::from_secs(args.timeout);
    // Commit-confirmed by default (MEC-45): a bad load that cuts management
    // access reverts itself unless the caller explicitly opts out with
    // `confirm_timeout_mins: 0`.
    let (mode, confirmed) = match resolve_confirm_timeout(args.confirm_timeout_mins) {
        ConfirmDecision::Confirmed(mins) => {
            let secs = confirm_timeout_to_secs(mins)?;
            (CandidateMode::CommitConfirmed(secs), Some(mins))
        }
        ConfirmDecision::OptedOut => (
            CandidateMode::CommitWithComment(args.commit_comment.clone()),
            None,
        ),
    };
    let result = candidate_transaction::run(
        &dm,
        &args.device,
        CandidateRequest {
            payload: Some(payload),
            rollback_source: None,
            mode,
            load_action,
        },
        timeout_dur,
        &ct,
    )
    .await?;

    match result {
        CandidateResult::Committed { diff } => {
            let mut obj = json!({ "success": true, "diff": diff });
            if let Some(mins) = confirmed {
                obj["confirmed"] = json!(true);
                obj["rollback_in_minutes"] = json!(mins);
                obj["rollback_deadline_unix"] = json!(rollback_deadline_unix(mins));
                obj["message"] = json!(format!(
                    "Commit confirmed: auto-rollback in {} minutes unless confirmed. \
                     Send another commit to confirm with confirm_commit.",
                    mins
                ));
                if !args.commit_comment.is_empty() {
                    obj["note"] = json!(
                        "commit_comment is not applied during confirmed commits \
                         (rustez API limitation)"
                    );
                }
            }
            if let Some(warning) = authority_warning {
                obj["warning"] = json!(warning);
            }
            Ok(obj)
        }
        CandidateResult::CommitFailed { diff, error } => {
            let mut obj = json!({ "success": false, "diff": diff, "error": error });
            if let Some(warning) = authority_warning {
                obj["warning"] = json!(warning);
            }
            Ok(obj)
        }
        _ => unreachable!("load/commit transaction returned the wrong result kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
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
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "nope".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                mode: "merge".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn invalid_format_rejected_before_connect() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "x".into(),
                config_format: "yaml".into(),
                mode: "merge".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[tokio::test]
    async fn non_set_format_with_rules_present_returns_format_error() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "<x/>".into(),
                config_format: "xml".into(),
                mode: "merge".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        match r {
            Err(JmcpError::ConfigFormatNotAllowedWithRules { format }) => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn denied_payload_short_circuits_before_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "set foo\ndelete protocols bgp".into(),
                config_format: "set".into(),
                mode: "merge".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        match r {
            Err(JmcpError::Denied {
                tool,
                line_number,
                pattern,
                ..
            }) => {
                assert_eq!(tool, "load_and_commit_config");
                assert_eq!(line_number, Some(2));
                assert_eq!(pattern, "delete *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// `override` is the highest blast-radius operation this server exposes.
    /// `load_and_commit_config` commits in the same call with no
    /// second-principal review, so it must refuse `override` outright —
    /// before any device connection, exactly like the format/blocklist
    /// gates above.
    #[tokio::test]
    async fn override_mode_is_refused_without_a_change_set() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "system { host-name test; }".into(),
                config_format: "text".into(),
                mode: "override".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        match r {
            Err(JmcpError::OverrideRequiresChangeSet { tool }) => {
                assert_eq!(tool, "load_and_commit_config");
            }
            other => panic!("expected OverrideRequiresChangeSet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn replace_mode_is_accepted_unlike_override() {
        // `replace` is not gated the way `override` is: it does not reach
        // OverrideRequiresChangeSet. It fails later trying to reach the
        // device (a non-routable address on a closed port), proving the
        // gate did not fire for `replace`.
        let inv = inv_with(
            r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "system { host-name test; }".into(),
                config_format: "text".into(),
                mode: "replace".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 1,
            },
            dm,
            pol,
            false,
        )
        .await;
        assert!(!matches!(
            r,
            Err(JmcpError::OverrideRequiresChangeSet { .. })
        ));
    }

    #[tokio::test]
    async fn unknown_mode_is_rejected_before_connect() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                mode: "wipe".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadLoadMode(ref s)) if s == "wipe"));
    }

    /// Junos has no wire-level `override` action for a `configuration-set`
    /// payload. This combination must be rejected before any RPC is sent —
    /// and it also happens to be moot, since `override` alone is already
    /// refused by `refuse_override_outside_changeset` for this tool; this
    /// test pins that the format/mode incompatibility check exists
    /// independently (exercised directly for `set`+`override` via
    /// `helpers::resolve_load_action` unit tests) and does not silently fall
    /// back to `merge`.
    #[tokio::test]
    async fn set_format_with_override_mode_is_refused() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            LoadCommitArgs {
                device: "r1".into(),
                config_text: "set system foo".into(),
                config_format: "set".into(),
                mode: "override".into(),
                commit_comment: "test".into(),
                confirm_timeout_mins: None,
                timeout: 5,
            },
            dm,
            pol,
            false,
        )
        .await;
        // OverrideRequiresChangeSet fires first (tool-level gate), before the
        // format/mode compatibility check ever runs.
        match r {
            Err(JmcpError::OverrideRequiresChangeSet { tool }) => {
                assert_eq!(tool, "load_and_commit_config");
            }
            other => panic!("expected OverrideRequiresChangeSet, got {other:?}"),
        }
    }
}

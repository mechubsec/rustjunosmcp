//! `execute_junos_command` — run an operational CLI command on one device.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{validate_input_length, validate_output_caps};
use crate::policy::{Policy, enforce_decision};
use crate::tools::ExecuteCommandArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Run an operational CLI command via NETCONF and return the text output.
///
/// Validates input length, checks the command against the device's policy
/// blocklist, then opens a pooled NETCONF session and executes the command.
/// Supports optional output caps (`max_lines`, `max_bytes`, `tail`) and
/// respects the caller's timeout. Short-circuits before connecting if the
/// device is unknown or the command is denied.
pub async fn handle(
    args: ExecuteCommandArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_input_length("command", &args.command)?;
    validate_output_caps(args.max_lines, args.max_bytes)?;
    // Fail fast on unknown devices so the policy check has a valid target.
    let _ = dm.inventory().get(&args.device)?;

    enforce_decision(
        policy.check_command(&args.device, &args.command),
        "execute_junos_command",
        &args.device,
        &args.command,
    )?;

    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, dm.run_cli(&args.device, &args.command))
        .await
        .map_err(|_| JmcpError::Timeout(timeout))??;
    let processed = crate::output::process_output(
        &args.command,
        result,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!(processed))
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
            ExecuteCommandArgs {
                device: "nope".into(),
                command: "show version".into(),
                timeout: 5,
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn denied_command_short_circuits_before_connect() {
        // ip:port is intentionally unreachable; the test asserts we never
        // reach the connect path by looking at the error variant — connect
        // failure would be a Rustez/Timeout error, not Denied.
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                device: "r1".into(),
                command: "request system reboot".into(),
                timeout: 1,
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            pol,
        )
        .await;
        match r {
            Err(JmcpError::Denied {
                tool,
                router,
                pattern,
                ..
            }) => {
                assert_eq!(tool, "execute_junos_command");
                assert_eq!(router, "r1");
                assert_eq!(pattern, "request system *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// MEC-93 acceptance: a command refused by the allowlist engine surfaces
    /// as `JmcpError::DeniedAllowlist` out of `handle()`, with `audit_kind()`
    /// returning the specific reason code — this is what `server.rs` feeds
    /// to `AuditScope::fail_kind`, so proving this proves the refusal lands
    /// in audit output.
    #[tokio::test]
    async fn allowlist_denied_command_surfaces_deniedallowlist_with_reason() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"mode":"allowlist","allow":["show version"]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecuteCommandArgs {
                device: "r1".into(),
                command: "sh ver".into(),
                timeout: 1,
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            pol,
        )
        .await;
        match &r {
            Err(
                e @ JmcpError::DeniedAllowlist {
                    tool,
                    router,
                    reason,
                    ..
                },
            ) => {
                assert_eq!(*tool, "execute_junos_command");
                assert_eq!(router, "r1");
                assert_eq!(*reason, "not_allowlisted");
                assert_eq!(e.audit_kind(), "not_allowlisted");
            }
            other => panic!("expected DeniedAllowlist, got {other:?}"),
        }
    }
}

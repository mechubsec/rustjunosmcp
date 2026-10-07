//! `execute_junos_pfe_command` — single PFE call against an explicit FPC target.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{validate_input_length, validate_output_caps};
use crate::policy::{Policy, enforce_decision};
use crate::tools::ExecutePfeArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Execute a PFE command on a specific FPC via the NETCONF CLI wrapper.
///
/// Wraps the provided `pfe_command` in `request pfe execute target <fpc_target> command "..."`,
/// validates inputs (rejects literal quotes and invalid FPC target chars),
/// checks the command against the device's PFE policy blocklist, opens a
/// pooled session, and returns the output. Short-circuits before connecting
/// if validation or policy fails.
pub async fn handle(
    args: ExecutePfeArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_input_length("pfe_command", &args.pfe_command)?;
    validate_output_caps(args.max_lines, args.max_bytes)?;
    // Reject quote-injection inputs before we build the wrapper.
    if args.pfe_command.contains('"') {
        return Err(JmcpError::BadPfeCommand(
            "literal '\"' is not allowed (would break the wrapper command)".into(),
        ));
    }

    // Validate fpc_target format: must match fpc0, fpc1, etc.
    if !args
        .fpc_target
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(JmcpError::BadPfeCommand(
            "fpc_target contains invalid characters".into(),
        ));
    }

    // Fail fast on unknown routers so the policy check has a valid target.
    let _ = dm.inventory().get(&args.device)?;

    enforce_decision(
        policy.check_pfe_command(&args.device, &args.pfe_command),
        "execute_junos_pfe_command",
        &args.device,
        &args.pfe_command,
    )?;

    let timeout = Duration::from_secs(args.timeout);
    let fpc_target = args.fpc_target.clone();
    let wrapper = format!(
        "request pfe execute target {} command \"{}\"",
        args.fpc_target, args.pfe_command
    );
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.device).await?;
        let output = dev.cli(&wrapper).await?;
        Ok::<_, JmcpError>(output)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    let output = crate::output::process_output(
        &args.pfe_command,
        result,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!({
        "fpc_target": fpc_target,
        "output": output,
    }))
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
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                device: "nope".into(),
                fpc_target: "fpc0".into(),
                pfe_command: "show jnh 0 stats".into(),
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
    async fn denied_pfe_command_short_circuits_before_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"pfe_commands":[{"action":"deny","pattern":"set *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                device: "r1".into(),
                fpc_target: "fpc0".into(),
                pfe_command: "set jnh 0 debug".into(),
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
                assert_eq!(tool, "execute_junos_pfe_command");
                assert_eq!(router, "r1");
                assert_eq!(pattern, "set *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_invalid_fpc_target() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                device: "r1".into(),
                fpc_target: "fpc0; rm -rf /".into(),
                pfe_command: "show jnh 0 stats".into(),
                timeout: 5,
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadPfeCommand(_))));
    }

    #[tokio::test]
    async fn rejects_pfe_command_with_literal_quote() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            ExecutePfeArgs {
                device: "r1".into(),
                fpc_target: "fpc0".into(),
                pfe_command: r#"show "evil""#.into(),
                timeout: 5,
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            pol,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadPfeCommand(_))));
    }
}

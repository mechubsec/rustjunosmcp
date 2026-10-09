//! `junos_config_diff` — compare running config against rollback N (0..=49).

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{strip_config_xml_wrapper, validate_rollback_version};
use crate::tools::ConfigDiffArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Return an enriched, actionable error message when a config-diff failure
/// looks like an on-box config-parse error (the committed config won't parse
/// for the device's current mode). Returns `None` for unrelated errors.
fn parse_error_hint(err_text: &str) -> Option<String> {
    let lower = err_text.to_ascii_lowercase();
    if lower.contains("juniper.conf") || lower.contains("parse error") {
        Some(format!(
            "{err_text} (the on-box configuration failed to parse for the current mode — \
             common right after a chassis-cluster enable/disable. Fix or load a valid \
             config on the device, then retry junos_config_diff.)"
        ))
    } else {
        None
    }
}

/// Compare running config against a rollback archive (rollback 0..=49).
///
/// Opens a pooled session, runs `show configuration | compare rollback <version>`,
/// strips the XML wrapper, and returns the diff text. Validates rollback version
/// range (0..=49). On failure, checks for on-box config parse errors (common
/// after chassis-cluster mode changes) and enriches the error message with recovery
/// hints.
pub async fn handle(args: ConfigDiffArgs, dm: Arc<DeviceManager>) -> Result<Value, JmcpError> {
    let version = validate_rollback_version(args.version)?;
    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.device).await?;
        let cmd = format!("show configuration | compare rollback {version}");
        match dev.cli(&cmd).await {
            Ok(diff) => Ok::<_, JmcpError>(diff),
            Err(e) => {
                let text = e.to_string();
                match parse_error_hint(&text) {
                    Some(hint) => Err(JmcpError::ConfigParseHint(hint)),
                    None => Err(JmcpError::from(e)),
                }
            }
        }
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;
    // The diff is line-oriented Junos config syntax (unified `compare
    // rollback` output), so it may carry the same secret-shaped values
    // (`$9$...`, pre-shared-key, SNMP community, PEM key body, URL-userinfo
    // password, ...) a full `show configuration` would. Redact it before it
    // reaches the caller with the cross-vendor `mecmcp_redact::redact_text`
    // denylist first and the Junos-specific closed key vocabulary layered
    // on top — see `get_config::redact_config_output`'s doc comment
    // (MEC-2519/MEC-2558) for why neither pass alone is sufficient.
    let stripped = strip_config_xml_wrapper(&result);
    Ok(json!(mecmcp_redact::junos::redact_log_text(
        &mecmcp_redact::redact_text(&stripped)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm() -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        )
        .unwrap();
        Arc::new(DeviceManager::new(Arc::new(
            Inventory::load(f.path()).unwrap(),
        )))
    }

    #[tokio::test]
    async fn accepts_version_zero() {
        let r = handle(
            ConfigDiffArgs {
                device: "r1".into(),
                version: 0,
                timeout: 5,
            },
            dm(),
        )
        .await;
        // version 0 is now valid, so the error will be transport/timeout, NOT BadRollbackVersion
        assert!(!matches!(r, Err(JmcpError::BadRollbackVersion(_))));
    }

    #[tokio::test]
    async fn rejects_version_50_before_connecting() {
        let r = handle(
            ConfigDiffArgs {
                device: "r1".into(),
                version: 50,
                timeout: 5,
            },
            dm(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }

    #[test]
    fn parse_error_hint_matches_config_parse_failure() {
        let raw = "netconf error: RPC error: server error: [OperationFailed] \
                   /config/juniper.conf:256:(12) fpc value outside range 0..3 for '7/0/0' in 'ge-7/0/0'";
        let hint = parse_error_hint(raw).expect("should produce a hint");
        assert!(hint.contains(raw), "hint must preserve the raw error");
        assert!(
            hint.to_ascii_lowercase().contains("failed to parse"),
            "hint must explain: {hint}"
        );
        assert!(
            hint.contains("junos_config_diff"),
            "hint should tell the caller what to retry"
        );
    }

    #[test]
    fn parse_error_hint_matches_parse_error_phrase() {
        assert!(parse_error_hint("syntax error\nparse error at line 3").is_some());
    }

    #[test]
    fn parse_error_hint_ignores_unrelated_errors() {
        assert!(parse_error_hint("connection refused").is_none());
        assert!(parse_error_hint("netconf error: timed out").is_none());
    }
}

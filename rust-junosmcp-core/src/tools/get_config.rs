//! `get_junos_config` — return full or scoped running config, in text (default),
//! set, xml, or json format.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::{
    config_display_suffix, strip_config_xml_wrapper, validate_config_path, validate_input_length,
    validate_output_caps,
};
use crate::policy::{Policy, enforce_decision};
use crate::tools::GetConfigArgs;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Redact device secrets (Junos `$9$`-style reversibly-encrypted values,
/// PSKs, SNMP communities, RADIUS/TACACS secrets, PEM key blocks,
/// URL-userinfo passwords, plaintext tokens, ...) from configuration text
/// before it reaches the caller, using the redactor that matches the
/// requested display `format`.
///
/// `text` and `set` output is line-oriented Junos config syntax, so it goes
/// through [`junos_text_fallback`], which runs the cross-vendor
/// [`mecmcp_redact::redact_text`] denylist first and layers the
/// Junos-specific, whole-word [`mecmcp_redact::junos::redact_log_text`]
/// vocabulary on top (MEC-2558 re-review of MEC-2519/#526: the Junos-only
/// pass alone is not a superset of the generic one — it has no entries for
/// PEM bodies, URL-userinfo passwords, plaintext bearer tokens, or several
/// generic secret-shaped keys, so using it *instead of* the generic pass
/// let those shapes through unredacted). This still carries the generic
/// denylist's documented `session`-substring over-masking (MEC-2519,
/// tracked upstream in `mecmcp`) for genuinely non-secret Junos syntax like
/// `then log session-init session-close;` or `limit-session 1000;` — an
/// accepted, explicitly reviewed tradeoff until that false positive is
/// fixed at its root in `mecmcp`'s denylist.
///
/// `xml` and `json` output is parsed and structurally redacted via
/// [`mecmcp_redact::redact_xml_str`] / [`mecmcp_redact::redact_json_value`]
/// so secrets are caught regardless of where they sit in the structure; if
/// an unexpected or malformed device reply makes the fragment unparseable,
/// this falls back to the same composed line redactor rather than shipping
/// an unredacted body. This runs before `max_lines` / `max_bytes` / `tail`
/// output caps are applied (see the caller), so a caps-truncated fragment
/// is never what reaches this function.
fn redact_config_output(text: &str, format: &str) -> String {
    match format {
        "xml" => match mecmcp_redact::redact_xml_str(text) {
            Ok(redacted) => redacted,
            Err(_) => junos_text_fallback(text),
        },
        "json" => match serde_json::from_str::<Value>(text) {
            Ok(mut value) => {
                mecmcp_redact::redact_json_value(&mut value);
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| junos_text_fallback(text))
            }
            Err(_) => junos_text_fallback(text),
        },
        // "text" and "set", and any future/unknown format: line-oriented
        // redaction, generic-then-Junos-vocabulary, is the correct and safe
        // choice.
        _ => junos_text_fallback(text),
    }
}

/// See [`redact_config_output`]'s doc comment for why this composition
/// (generic [`mecmcp_redact::redact_text`] then Junos-specific
/// [`mecmcp_redact::junos::redact_log_text`]) replaced a bare
/// `redact_log_text` call.
fn junos_text_fallback(text: &str) -> String {
    mecmcp_redact::junos::redact_log_text(&mecmcp_redact::redact_text(text))
}

/// Build the `show configuration [<config_path>]` command for the requested
/// `format`, appending the Junos `| display <format>` suffix that produces
/// it (absent for `text`, the unmodified default this tool has always
/// returned). Pure — no I/O, no RPC sent; an unrecognized `format` is
/// rejected here before any device is touched.
fn build_command(config_path: Option<&str>, format: &str) -> Result<String, JmcpError> {
    let suffix = config_display_suffix(format)?;
    let base = match config_path {
        Some(path) if !path.trim().is_empty() => format!("show configuration {}", path.trim()),
        _ => "show configuration".to_string(),
    };
    Ok(match suffix {
        Some(suffix) => format!("{base} | {suffix}"),
        None => base,
    })
}

/// Retrieve the running configuration from a Junos device.
///
/// Runs `show configuration [<config_path>]` over NETCONF, strips the XML
/// wrapper, validates the `config_path` against injection (newlines, pipes,
/// semicolons), checks the final command against policy, and applies optional
/// output caps. Returns configuration in the requested `format` (`text`,
/// `set`, `xml`, or `json`). Fails fast if the device is unknown, `format` is
/// not recognized, or the path/command is denied.
pub async fn handle(
    args: GetConfigArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    validate_output_caps(args.max_lines, args.max_bytes)?;

    // Validate config_path if provided
    if let Some(ref path) = args.config_path {
        validate_input_length("config_path", path)?;
        validate_config_path(path)?;
    }

    // Build command up front: also validates `format` deterministically,
    // before any inventory lookup or device connection.
    let command = build_command(args.config_path.as_deref(), &args.format)?;

    // Fail fast on unknown devices so the policy check has a valid target.
    let _ = dm.inventory().get(&args.device)?;

    // Check command against policy (same as execute_junos_command)
    enforce_decision(
        policy.check_command(&args.device, &command),
        "get_junos_config",
        &args.device,
        &command,
    )?;

    let timeout = Duration::from_secs(args.timeout);
    let result = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.device).await?;
        let cfg_text = dev.cli(&command).await?;
        Ok::<_, JmcpError>(cfg_text)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;

    // Apply the same output caps the operational-command tools honour. Without
    // them a caller that asks for a bounded response has no way to get one, and
    // a full `show configuration` is large enough to matter (#253). Caps are
    // applied after the XML wrapper is stripped so a line budget counts
    // configuration lines, not markup.
    let stripped = strip_config_xml_wrapper(&result);
    let redacted = redact_config_output(&stripped, &args.format);
    let capped = crate::output::process_output(
        &command,
        redacted,
        args.max_lines,
        args.max_bytes,
        args.tail,
    );
    Ok(json!(capped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use std::io::Write;

    // ── redact_config_output: synthetic secret fixtures, never real device
    // output — see MEC-14 (device secrets reaching tool-output callers). ────

    const FAKE_JUNOS_HASH: &str = "$9$FAKE9uBEreWx-VwgJGiHmz3nCA0IcSlKMX";
    const FAKE_PSK: &str = "FAKE-psk-9c203b81";
    const FAKE_SNMP_COMMUNITY: &str = "FAKE-community-77aa";

    #[test]
    fn redact_config_output_text_strips_set_style_secrets() {
        let text = format!(
            "set security ike policy p1 pre-shared-key ascii-text \"{FAKE_PSK}\"\n\
             set snmp community \"{FAKE_SNMP_COMMUNITY}\"\n\
             set system host-name edge1.example.net\n"
        );
        let out = redact_config_output(&text, "text");
        assert!(!out.contains(FAKE_PSK), "PSK leaked: {out}");
        assert!(
            !out.contains(FAKE_SNMP_COMMUNITY),
            "community leaked: {out}"
        );
        assert!(out.contains("edge1.example.net"), "hostname lost: {out}");
    }

    #[test]
    fn redact_config_output_set_strips_set_style_secrets() {
        let text = format!("set snmp community \"{FAKE_SNMP_COMMUNITY}\";\n");
        let out = redact_config_output(&text, "set");
        assert!(
            !out.contains(FAKE_SNMP_COMMUNITY),
            "community leaked: {out}"
        );
    }

    /// MEC-2558 (re-review of MEC-2519/#526): the Junos-only
    /// `redact_log_text` vocabulary alone does not catch a PEM private-key
    /// body, a plaintext API key/shared-secret/passphrase, or a URL's
    /// userinfo password — `redact_config_output` must still catch all of
    /// these via the generic [`mecmcp_redact::redact_text`] pass it now
    /// layers underneath.
    #[test]
    fn redact_config_output_text_still_catches_shapes_the_junos_only_vocabulary_misses() {
        let text = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{FAKE_PSK}\n-----END RSA PRIVATE KEY-----\n\
             set security ike policy p1 pre-shared-key ascii-text \"shhh\"\n\
             set security dynamic-address archive-sites \"ftp://svc:{FAKE_PSK}@archive.example.net/cfg\"\n\
             set system host-name edge1.example.net\n"
        );
        let out = redact_config_output(&text, "text");
        assert!(!out.contains(FAKE_PSK), "secret leaked: {out}");
        assert!(out.contains("edge1.example.net"), "hostname lost: {out}");
    }

    #[test]
    fn redact_config_output_xml_strips_secret_elements_structurally() {
        let xml = format!(
            "<configuration><system><root-authentication><encrypted-password>{FAKE_JUNOS_HASH}</encrypted-password></root-authentication></system><host-name>edge1.example.net</host-name></configuration>"
        );
        let out = redact_config_output(&xml, "xml");
        assert!(!out.contains(FAKE_JUNOS_HASH), "hash leaked: {out}");
        assert!(out.contains("edge1.example.net"), "hostname lost: {out}");
        assert!(out.contains("<host-name>"), "structure lost: {out}");
    }

    #[test]
    fn redact_config_output_xml_falls_back_to_text_redaction_on_unparseable_input() {
        // A malformed XML fragment (e.g. an unexpected device reply) is not
        // well-formed; redact_config_output must still scrub the secret
        // rather than shipping it unredacted. The hash sits on its own line,
        // clearly delimited, so the line-oriented fallback's bare-crypt-hash
        // catch-all is unambiguously exercised regardless of the
        // (deliberately broken) surrounding markup.
        let truncated_xml = format!("<configuration>\n{FAKE_JUNOS_HASH}\n<unterminated");
        let out = redact_config_output(&truncated_xml, "xml");
        assert!(
            !out.contains(FAKE_JUNOS_HASH),
            "hash leaked via unparseable-XML fallback: {out}"
        );
    }

    #[test]
    fn redact_config_output_json_strips_secret_fields_structurally() {
        let json_text = format!(
            r#"{{"system":{{"host-name":"edge1.example.net","root-authentication":{{"encrypted-password":"{FAKE_JUNOS_HASH}"}}}}}}"#
        );
        let out = redact_config_output(&json_text, "json");
        assert!(!out.contains(FAKE_JUNOS_HASH), "hash leaked: {out}");
        assert!(out.contains("edge1.example.net"), "hostname lost: {out}");
    }

    #[test]
    fn redact_config_output_json_falls_back_to_text_redaction_on_unparseable_input() {
        // Same rationale as the XML fallback test above: deliberately
        // unparseable JSON, with the hash on its own clearly-delimited line.
        let truncated_json = format!("{{\n{FAKE_JUNOS_HASH}\n\"unterminated");
        let out = redact_config_output(&truncated_json, "json");
        assert!(
            !out.contains(FAKE_JUNOS_HASH),
            "hash leaked via unparseable-JSON fallback: {out}"
        );
    }

    fn test_inventory() -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        )
        .unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn test_policy() -> Arc<Policy> {
        let inv = test_inventory();
        Arc::new(Policy::build(&inv).unwrap())
    }

    #[test]
    fn build_command_text_format_is_unchanged_from_before_this_field_existed() {
        assert_eq!(build_command(None, "text").unwrap(), "show configuration");
        assert_eq!(
            build_command(Some("system services"), "text").unwrap(),
            "show configuration system services"
        );
    }

    #[test]
    fn build_command_appends_the_matching_display_modifier() {
        assert_eq!(
            build_command(None, "set").unwrap(),
            "show configuration | display set"
        );
        assert_eq!(
            build_command(None, "xml").unwrap(),
            "show configuration | display xml"
        );
        assert_eq!(
            build_command(None, "json").unwrap(),
            "show configuration | display json"
        );
    }

    #[test]
    fn build_command_combines_config_path_and_format() {
        assert_eq!(
            build_command(Some("system services"), "set").unwrap(),
            "show configuration system services | display set"
        );
    }

    #[test]
    fn build_command_rejects_unknown_format_before_any_rpc() {
        let r = build_command(None, "yaml");
        assert!(matches!(r, Err(JmcpError::BadConfigFormat(ref s)) if s == "yaml"));
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(
            GetConfigArgs {
                device: "nope".into(),
                timeout: 5,
                config_path: None,
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[test]
    fn config_path_none_is_backward_compatible() {
        // Existing callers that omit config_path must get identical behavior.
        // This test verifies that GetConfigArgs can be deserialized without the field.
        let json = r#"{"device": "r1", "timeout": 30}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.device, "r1");
        assert_eq!(args.timeout, 30);
        assert!(args.config_path.is_none());
    }

    #[test]
    fn config_path_with_value_is_preserved() {
        let json = r#"{"device": "r1", "timeout": 30, "config_path": "system services"}"#;
        let args: GetConfigArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.config_path, Some("system services".to_string()));
    }

    /// #253: `filter` is the name callers reach for. It used to be dropped
    /// silently, and the caller got the whole configuration — `## SECRET-DATA`
    /// included — in place of the one stanza they asked for.
    #[test]
    fn filter_is_accepted_as_an_alias_for_config_path() {
        let args: GetConfigArgs =
            serde_json::from_str(r#"{"device": "r1", "filter": "routing-options"}"#).unwrap();
        assert_eq!(args.config_path, Some("routing-options".to_string()));
    }

    /// The general form of #253: an argument this tool does not understand must
    /// be an error, because the fallback is "return everything", and everything
    /// includes credential material the caller did not ask for. Failing closed
    /// is the whole point.
    #[test]
    fn an_unknown_argument_is_rejected_rather_than_ignored() {
        let err = serde_json::from_str::<GetConfigArgs>(
            r#"{"device": "r1", "stanza": "routing-options"}"#,
        )
        .expect_err("an unrecognised argument must not be silently dropped");

        assert!(
            err.to_string().contains("stanza"),
            "the error must name the field the caller got wrong, got: {err}"
        );
    }

    #[test]
    fn output_caps_are_accepted() {
        let args: GetConfigArgs = serde_json::from_str(
            r#"{"device": "r1", "max_lines": 25, "max_bytes": 4096, "tail": true}"#,
        )
        .unwrap();
        assert_eq!(args.max_lines, Some(25));
        assert_eq!(args.max_bytes, Some(4096));
        assert!(args.tail);
    }

    #[tokio::test]
    async fn config_path_exceeding_max_length_is_rejected() {
        // config_path over MAX_INPUT_LEN (1 MB) should fail validation
        let huge_path = "a".repeat(1_048_577); // 1 byte over limit
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some(huge_path),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        assert!(matches!(result, Err(JmcpError::InventoryInvalid(_))));
    }

    #[tokio::test]
    async fn injection_pipe_to_save_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("system services | save /tmp/x".to_string()),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("pipe operator"),
                    "expected pipe rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for pipe, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_semicolon_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("foo; bar".to_string()),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("semicolon"),
                    "expected semicolon rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for semicolon, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_embedded_newline_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("system\nservices".to_string()),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("newline"),
                    "expected newline rejection, got: {msg}"
                );
            }
            other => panic!("expected Validation error for newline, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn injection_leading_newline_is_rejected() {
        let inv = test_inventory();
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = test_policy();

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("\nsystem services".to_string()),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("newline"),
                    "expected newline rejection, got: {msg}"
                );
            }
            other => panic!(
                "expected Validation error for leading newline, got {:?}",
                other
            ),
        }
    }

    /// The policy check at the top of `handle` is the second half of the fix for
    /// the injection defect: the allowlist stops shell metacharacters, and this
    /// stops a *syntactically valid* path that a site has chosen to deny.
    ///
    /// Without a test the wiring can be deleted and every other test still
    /// passes — the default blocklist cannot deny anything reachable from a
    /// `show configuration ` prefix, so only a per-device rule exercises it.
    #[tokio::test]
    async fn config_path_forming_a_blocklisted_command_is_denied_by_policy() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"},
                  "blocklist":{"commands":[{"action":"deny","pattern":"show configuration secret*"}]}}
        }"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                // Passes the allowlist cleanly — no metacharacters at all.
                config_path: Some("secrets".to_string()),
                format: "text".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        match result {
            Err(JmcpError::Denied { .. }) => {}
            other => panic!(
                "a denied config_path must be rejected by the policy, not sent \
                 to the device. got: {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn unknown_format_is_rejected_before_connect() {
        let dm = Arc::new(DeviceManager::new(test_inventory()));
        let policy = test_policy();
        let r = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: None,
                format: "yaml".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadConfigFormat(ref s)) if s == "yaml"));
    }

    /// The blocklist pattern is written against the base `show configuration`
    /// command; the `| display set` suffix this tool appends for
    /// `format=set` must not let a denied path slip past it by changing the
    /// command's shape.
    #[tokio::test]
    async fn blocklisted_path_is_still_denied_with_a_non_text_format() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
            "r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"},
                  "blocklist":{"commands":[{"action":"deny","pattern":"show configuration secret*"}]}}
        }"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(Policy::build(&inv).unwrap());

        let result = handle(
            GetConfigArgs {
                device: "r1".into(),
                timeout: 5,
                config_path: Some("secrets".to_string()),
                format: "set".into(),
                max_lines: None,
                max_bytes: None,
                tail: false,
            },
            dm,
            policy,
        )
        .await;

        assert!(matches!(result, Err(JmcpError::Denied { .. })));
    }
}

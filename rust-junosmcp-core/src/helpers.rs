//! Pure helper functions, easily unit-testable without device contact.

use crate::error::JmcpError;
use rustez::{ConfigPayload, LoadAction};

/// Map the optional `config_format` string from the MCP tool input to
/// a `rustez::ConfigPayload` constructor closure. Default = "set".
pub fn build_config_payload(text: String, fmt: Option<&str>) -> Result<ConfigPayload, JmcpError> {
    match fmt.unwrap_or("set") {
        "set" => Ok(ConfigPayload::Set(text)),
        "text" => Ok(ConfigPayload::Text(text)),
        "xml" => Ok(ConfigPayload::Xml(text)),
        other => Err(JmcpError::BadFormat(other.into())),
    }
}

/// Map the optional load `mode` string from the MCP tool input to a
/// `rustez::LoadAction`. Default = "merge". Only `merge`, `replace`, and
/// `override` are caller-facing; `set` and `update` are internal wire
/// concepts selected by `config_format`, not exposed as a `mode` value.
pub fn parse_load_mode(mode: Option<&str>) -> Result<LoadAction, JmcpError> {
    match mode.unwrap_or("merge") {
        "merge" => Ok(LoadAction::Merge),
        "replace" => Ok(LoadAction::Replace),
        "override" => Ok(LoadAction::Override),
        other => Err(JmcpError::BadLoadMode(other.into())),
    }
}

/// Resolve the wire `action` for a `<load-configuration>` RPC from the
/// requested `config_format` and `mode`, rejecting combinations Junos cannot
/// perform before any RPC is sent.
///
/// Junos requires `action="set"` for a `configuration-set` (set-command list)
/// payload — there is no separate wire-level replace/override action for a
/// set-style load, because set commands are inherently incremental
/// (add/delete statements the caller already controls). `merge` and
/// `replace` are therefore both accepted for `config_format="set"` and both
/// resolve to the one valid wire action; `override` has no set-format
/// equivalent (there is nothing to "wholesale replace" a set-command list
/// with) and is rejected here rather than sent to the device.
///
/// `text` and `xml` support the full `merge`/`replace`/`override` range
/// unchanged.
pub fn resolve_load_action(format: &str, mode: LoadAction) -> Result<LoadAction, JmcpError> {
    match (format, mode) {
        ("set", LoadAction::Override) => Err(JmcpError::IncompatibleFormatMode {
            format: format.into(),
            mode: "override".into(),
        }),
        ("set", _) => Ok(LoadAction::Set),
        (_, mode) => Ok(mode),
    }
}

/// Refuse `mode=override` on any load path that commits directly with no
/// second-principal review.
///
/// `override` replaces the whole candidate configuration — the highest
/// blast-radius operation this server exposes — so it is only permitted
/// through `create_junos_change_set` → `approve_junos_change_set` →
/// `apply_junos_change_set`, which requires a human approver distinct from
/// the creator before anything commits (MEC-12). `load_and_commit_config`
/// and `render_and_apply_j2_template` commit in the same call with no such
/// gate and must refuse it outright.
pub fn refuse_override_outside_changeset(
    tool: &'static str,
    mode: LoadAction,
) -> Result<(), JmcpError> {
    if mode == LoadAction::Override {
        return Err(JmcpError::OverrideRequiresChangeSet { tool });
    }
    Ok(())
}

/// Map the `get_junos_config` `format` argument to the Junos CLI `| display`
/// suffix that produces it. Default ("text") needs no suffix — that is the
/// unmodified `show configuration` output this tool has always returned.
///
/// This reuses Junos's own `| display set|xml|json` pipe modifiers rather
/// than adding a new NETCONF-level format path: `execute_junos_command`
/// already passes these through untouched to the device (see
/// `output::apply_pipe_modifiers`), so the device — not this server — does
/// the actual rendering, the same way it does for the existing `text` format.
pub fn config_display_suffix(format: &str) -> Result<Option<&'static str>, JmcpError> {
    match format {
        "text" => Ok(None),
        "set" => Ok(Some("display set")),
        "xml" => Ok(Some("display xml")),
        "json" => Ok(Some("display json")),
        other => Err(JmcpError::BadConfigFormat(other.into())),
    }
}

/// Truncate `s` to at most 120 chars on a char boundary.
pub fn excerpt(s: &str) -> String {
    if s.len() <= 120 {
        return s.to_string();
    }
    let mut end = 120;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Strip `<configuration-information>` / `<configuration-output>` XML wrapper
/// tags that Junos adds around CLI output delivered over NETCONF.
pub fn strip_config_xml_wrapper(raw: &str) -> String {
    if let Some(start) = raw.find("<configuration-output>") {
        let content_start = start + "<configuration-output>".len();
        if let Some(end) = raw[content_start..].find("</configuration-output>") {
            return raw[content_start..content_start + end].trim().to_string();
        }
    }
    raw.trim().to_string()
}

/// Maximum allowed length for user-supplied text fields (1 MB).
///
/// Command strings, configuration payloads, and other text inputs exceeding
/// this limit are rejected with [`JmcpError::InventoryInvalid`]. Prevents
/// unbounded memory allocation from malicious or malformed inputs.
pub const MAX_INPUT_LEN: usize = 1_048_576;

/// Reject text fields that exceed the maximum allowed length.
pub fn validate_input_length(field_name: &str, value: &str) -> Result<(), JmcpError> {
    if value.len() > MAX_INPUT_LEN {
        return Err(JmcpError::InventoryInvalid(format!(
            "{field_name} exceeds maximum length of {} bytes",
            MAX_INPUT_LEN
        )));
    }
    Ok(())
}

/// Validate an LLM-provided rollback version to the Junos-supported range 0..=49.
/// 0 = candidate vs committed (what is staged now); N>=1 = committed vs Nth-previous.
pub fn validate_rollback_version(v: i64) -> Result<u32, JmcpError> {
    if (0..=49).contains(&v) {
        Ok(v as u32)
    } else {
        Err(JmcpError::BadRollbackVersion(v))
    }
}

/// Convert confirmed-commit timeout from minutes to seconds, validating RFC 6241
/// constraints: must be >= 1 minute, and the result must fit in u32 (no overflow).
pub fn confirm_timeout_to_secs(mins: u32) -> Result<u32, JmcpError> {
    if mins == 0 {
        return Err(JmcpError::Validation(
            "confirm_timeout_mins must be >= 1".into(),
        ));
    }
    mins.checked_mul(60).ok_or_else(|| {
        JmcpError::Validation(
            "confirm_timeout_mins too large (overflow when converting to seconds)".into(),
        )
    })
}

/// Server-wide default confirm-commit window, in whole minutes, applied when a
/// caller omits `confirm_timeout_mins`. Set once at startup from
/// `--commit-confirm-default-mins` (MEC-45).
///
/// A deployment tuning knob, not per-call state — same rationale as
/// `candidate_transaction::CLEANUP_TIMEOUT_SECS`: threading it through every
/// tool's argument struct and call chain would touch every commit path to
/// make one number configurable.
static COMMIT_CONFIRM_DEFAULT_MINS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(10);

/// Override the server-wide default confirm-commit window. Call once, before
/// serving, with a value already validated by [`confirm_timeout_to_secs`].
pub fn set_commit_confirm_default_mins(mins: u32) {
    COMMIT_CONFIRM_DEFAULT_MINS.store(mins, std::sync::atomic::Ordering::Relaxed);
}

/// The configured server-wide default confirm-commit window, in minutes.
pub fn commit_confirm_default_mins() -> u32 {
    COMMIT_CONFIRM_DEFAULT_MINS.load(std::sync::atomic::Ordering::Relaxed)
}

/// How a caller's `confirm_timeout_mins` combines with the server-wide
/// default for one commit call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmDecision {
    /// Issue a confirmed commit with this many minutes (the server default,
    /// or an explicit per-call override).
    Confirmed(u32),
    /// The caller explicitly opted out with `confirm_timeout_mins: 0`: issue
    /// a plain commit with no auto-rollback window.
    OptedOut,
}

/// Resolve a caller-supplied `confirm_timeout_mins` against the server-wide
/// default.
///
/// `None` (the field omitted) defaults ON: the server-configured window
/// applies. `Some(0)` is the documented explicit opt-out for a plain
/// (unconfirmed) commit — chosen over a separate `commit_confirmed: false`
/// flag so there is exactly one knob to read, and `0` is already outside the
/// `>= 1` range a real window accepts. `Some(n)` for `n >= 1` overrides the
/// default with the caller's value (MEC-45).
pub fn resolve_confirm_timeout(caller_mins: Option<u32>) -> ConfirmDecision {
    match caller_mins {
        None => ConfirmDecision::Confirmed(commit_confirm_default_mins()),
        Some(0) => ConfirmDecision::OptedOut,
        Some(mins) => ConfirmDecision::Confirmed(mins),
    }
}

/// Unix timestamp of the auto-rollback deadline for a confirmed commit issued
/// right now with a window of `mins` minutes. Saturates rather than panics on
/// a clock earlier than the epoch or an overflowing addition — the caller
/// gets a usable (if degenerate) deadline instead of a crashed tool call.
pub fn rollback_deadline_unix(mins: u32) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    now.saturating_add(u64::from(mins).saturating_mul(60))
}

/// Validate a Junos configuration path for `get_junos_config` to prevent command injection.
/// Junos config paths are hierarchy words: alphanumerics, hyphens, underscores, dots, slashes,
/// colons, and single spaces between tokens. Rejects pipe operators, semicolons, newlines,
/// quotes, and other shell metacharacters.
pub fn validate_config_path(path: &str) -> Result<(), JmcpError> {
    // Reject empty or whitespace-only paths
    if path.trim().is_empty() {
        return Err(JmcpError::Validation(
            "config_path cannot be empty or whitespace-only".into(),
        ));
    }

    // Check for injection characters BEFORE trimming
    let dangerous_chars = [
        ('|', "pipe operator"),
        (';', "semicolon"),
        ('\n', "newline"),
        ('\r', "carriage return"),
        ('"', "double quote"),
        ('\'', "single quote"),
        ('`', "backtick"),
        ('$', "dollar sign"),
        ('&', "ampersand"),
        ('>', "redirect"),
        ('<', "redirect"),
        ('\\', "backslash"),
        ('(', "parenthesis"),
        (')', "parenthesis"),
        ('{', "brace"),
        ('}', "brace"),
        ('[', "bracket"),
        (']', "bracket"),
        ('*', "wildcard"),
        ('?', "wildcard"),
        ('!', "exclamation"),
        ('#', "hash"),
    ];

    for (ch, name) in &dangerous_chars {
        if path.contains(*ch) {
            return Err(JmcpError::Validation(format!(
                "config_path contains forbidden character: {} ({})",
                name, ch
            )));
        }
    }

    // Valid characters: alphanumerics, hyphen, underscore, dot, slash, colon, space
    // We already rejected dangerous chars above, so this is a positive allowlist
    for ch in path.chars() {
        if !ch.is_alphanumeric()
            && ch != '-'
            && ch != '_'
            && ch != '.'
            && ch != '/'
            && ch != ':'
            && ch != ' '
        {
            return Err(JmcpError::Validation(format!(
                "config_path contains invalid character: '{}' (only alphanumerics, hyphens, underscores, dots, slashes, colons, and spaces are allowed)",
                ch
            )));
        }
    }

    // Reject multiple consecutive spaces (could be an attempt to hide commands)
    if path.contains("  ") {
        return Err(JmcpError::Validation(
            "config_path contains consecutive spaces".into(),
        ));
    }

    Ok(())
}

/// Smallest `max_bytes` a caller may request.
///
/// The truncation marker has to fit inside the budget for `max_bytes` to be the
/// hard cap it is advertised as, and the marker is around 40 bytes at its
/// longest. Rather than silently overshoot a budget too small to hold it — or
/// return a marker with no content and call that a success — a request below
/// this floor is refused with an error that says what the floor is.
pub const MIN_MAX_BYTES: u32 = 64;

/// Reject output caps too small to be honoured exactly.
///
/// `max_lines` of 0 is meaningless rather than merely small: it asks for no
/// output at all, which no response can distinguish from a device that returned
/// nothing.
///
/// # Errors
///
/// Returns [`JmcpError::Validation`] naming the offending field and its floor.
pub fn validate_output_caps(
    max_lines: Option<u32>,
    max_bytes: Option<u32>,
) -> Result<(), JmcpError> {
    if max_lines == Some(0) {
        return Err(JmcpError::Validation(
            "max_lines must be at least 1; a cap of 0 asks for no output at all".into(),
        ));
    }
    if let Some(bytes) = max_bytes
        && bytes < MIN_MAX_BYTES
    {
        return Err(JmcpError::Validation(format!(
            "max_bytes must be at least {MIN_MAX_BYTES}; a smaller budget cannot \
             hold the truncation marker, so the cap could not be honoured exactly"
        )));
    }
    Ok(())
}

/// Check if a destructive operation should be allowed on a plane-owned device.
///
/// Returns `Ok(Some(warning))` if the operation is allowed with a warning,
/// `Ok(None)` if allowed without warning (local/unknown authority),
/// or `Err(JmcpError::PlaneOwnedDevice)` if refused.
///
/// # Arguments
///
/// * `tool_name` - Name of the tool for error messages (e.g., "load_and_commit_config")
/// * `device_name` - Name of the device being operated on
/// * `authority` - Configuration authority from the device entry
/// * `allow_plane_owned_writes` - Whether to allow (with warning) or refuse
///
/// # Errors
///
/// Returns [`JmcpError::PlaneOwnedDevice`] when the device is plane-owned and
/// `allow_plane_owned_writes` is false.
pub fn check_plane_owned_operation(
    tool_name: &str,
    device_name: &str,
    authority: &crate::config_authority::JunosAuthority,
    allow_plane_owned_writes: bool,
) -> Result<Option<String>, JmcpError> {
    use crate::config_authority::JunosAuthority;

    match authority {
        JunosAuthority::Local | JunosAuthority::Unknown => {
            // Local or unknown authority: allow without warning
            Ok(None)
        }
        _ => {
            // Plane-owned device
            let authority_str = serde_json::to_string(authority)
                .ok()
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| "unknown".to_string());

            if allow_plane_owned_writes {
                // Allow with warning
                Ok(Some(format!(
                    "WARNING: this device is owned by {}. Changes may be overwritten \
                     at the next push from the owning management plane.",
                    authority_str
                )))
            } else {
                // Refuse
                Err(JmcpError::PlaneOwnedDevice {
                    tool: tool_name.to_string(),
                    device: device_name.to_string(),
                    authority: authority_str,
                })
            }
        }
    }
}

/// Refuse a rollback to depth `depth` on a plane-owned device.
///
/// The single deterministic function the rollback-depth guard is built from
/// (MEC-1879, P5a): every call site — `create_junos_change_set`,
/// `JunosTransaction::stage`'s apply-time re-check, and the `RollbackRef::Archive`
/// defense-in-depth path — calls this instead of repeating the depth logic, so
/// the rule can only be changed in one place.
///
/// `depth` 0 is a no-op load (revert candidate to running config) and is
/// always allowed. Any `depth >= 1` on a plane-owned device is refused
/// unconditionally: depth 1 because commit-origin attribution (MEC-1880, P5b)
/// does not exist yet to tell the server's own commits from the plane's, and
/// depth 2+ because of the same risk at greater blast radius. No flag
/// overrides this.
///
/// # Errors
///
/// Returns [`JmcpError::PlaneOwnedRollbackDepthRefused`] when the device is
/// plane-owned and `depth >= 1`.
pub fn check_plane_owned_rollback_depth(
    tool_name: &'static str,
    device_name: &str,
    authority: &crate::config_authority::JunosAuthority,
    depth: u32,
) -> Result<(), JmcpError> {
    if depth >= 1 && authority.is_plane_owned() {
        return Err(JmcpError::PlaneOwnedRollbackDepthRefused {
            tool: tool_name,
            device: device_name.to_string(),
            authority: authority.as_str().to_string(),
            depth,
        });
    }
    Ok(())
}

/// Write a test fixture with mode 0600.
///
/// The inventory is read through a hardened reader (mecmcp 0.3.8+) that refuses
/// a group- or world-accessible file, and `std::fs::write` yields whatever the
/// umask allows — 0644 on a default setup. Fixtures must therefore restrict
/// themselves the way a real deployment does.
#[cfg(test)]
pub(crate) fn write_restricted_fixture(path: impl AsRef<std::path::Path>, contents: &str) {
    let path = path.as_ref();
    std::fs::write(path, contents).expect("write fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict fixture permissions");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_owned_rollback_depth_zero_is_always_allowed() {
        use crate::config_authority::JunosAuthority;
        for authority in [
            JunosAuthority::Local,
            JunosAuthority::Unknown,
            JunosAuthority::Mist,
            JunosAuthority::SecurityDirectorCloud,
            JunosAuthority::SecurityDirectorOnprem,
        ] {
            assert!(
                check_plane_owned_rollback_depth("t", "r1", &authority, 0).is_ok(),
                "depth 0 must be allowed for {authority:?}"
            );
        }
    }

    #[test]
    fn plane_owned_rollback_depth_one_is_refused_pre_p5b() {
        use crate::config_authority::JunosAuthority;
        let r = check_plane_owned_rollback_depth("t", "r1", &JunosAuthority::Mist, 1);
        match r {
            Err(JmcpError::PlaneOwnedRollbackDepthRefused { depth, .. }) => {
                assert_eq!(depth, 1);
            }
            other => {
                panic!("expected depth 1 to be refused on a plane-owned device, got {other:?}")
            }
        }
    }

    #[test]
    fn plane_owned_rollback_depth_two_or_more_is_refused() {
        use crate::config_authority::JunosAuthority;
        for depth in [2, 5, 49] {
            let r = check_plane_owned_rollback_depth(
                "t",
                "r1",
                &JunosAuthority::SecurityDirectorCloud,
                depth,
            );
            assert!(
                matches!(r, Err(JmcpError::PlaneOwnedRollbackDepthRefused { depth: d, .. }) if d == depth),
                "expected depth {depth} to be refused, got {r:?}"
            );
        }
    }

    #[test]
    fn local_and_unknown_authority_allow_any_depth() {
        use crate::config_authority::JunosAuthority;
        for authority in [JunosAuthority::Local, JunosAuthority::Unknown] {
            for depth in [0, 1, 2, 49] {
                assert!(
                    check_plane_owned_rollback_depth("t", "r1", &authority, depth).is_ok(),
                    "depth {depth} must be allowed for {authority:?}"
                );
            }
        }
    }

    #[test]
    fn build_config_payload_defaults_to_set() {
        let p = build_config_payload("set system foo".into(), None).unwrap();
        assert!(matches!(p, ConfigPayload::Set(ref s) if s == "set system foo"));
    }

    #[test]
    fn build_config_payload_accepts_text() {
        let p = build_config_payload("system { foo; }".into(), Some("text")).unwrap();
        assert!(matches!(p, ConfigPayload::Text(_)));
    }

    #[test]
    fn build_config_payload_accepts_xml() {
        let p = build_config_payload("<foo/>".into(), Some("xml")).unwrap();
        assert!(matches!(p, ConfigPayload::Xml(_)));
    }

    #[test]
    fn build_config_payload_rejects_unknown() {
        let r = build_config_payload("x".into(), Some("yaml"));
        assert!(matches!(r, Err(JmcpError::BadFormat(ref s)) if s == "yaml"));
    }

    #[test]
    fn parse_load_mode_defaults_to_merge() {
        assert_eq!(parse_load_mode(None).unwrap(), LoadAction::Merge);
    }

    #[test]
    fn parse_load_mode_accepts_all_three_values() {
        assert_eq!(parse_load_mode(Some("merge")).unwrap(), LoadAction::Merge);
        assert_eq!(
            parse_load_mode(Some("replace")).unwrap(),
            LoadAction::Replace
        );
        assert_eq!(
            parse_load_mode(Some("override")).unwrap(),
            LoadAction::Override
        );
    }

    #[test]
    fn parse_load_mode_rejects_wire_level_actions_not_exposed_to_callers() {
        // `set` and `update` are internal LoadAction variants selected by
        // config_format, not accepted as a `mode` value.
        for bad in ["set", "update", "wipe", ""] {
            let r = parse_load_mode(Some(bad));
            assert!(
                matches!(r, Err(JmcpError::BadLoadMode(ref s)) if s == bad),
                "expected BadLoadMode for {bad:?}, got {r:?}"
            );
        }
    }

    #[test]
    fn resolve_load_action_passes_through_for_text_and_xml() {
        for format in ["text", "xml"] {
            for mode in [LoadAction::Merge, LoadAction::Replace, LoadAction::Override] {
                assert_eq!(resolve_load_action(format, mode).unwrap(), mode);
            }
        }
    }

    #[test]
    fn resolve_load_action_normalizes_set_merge_and_replace_to_the_set_action() {
        assert_eq!(
            resolve_load_action("set", LoadAction::Merge).unwrap(),
            LoadAction::Set
        );
        assert_eq!(
            resolve_load_action("set", LoadAction::Replace).unwrap(),
            LoadAction::Set
        );
    }

    /// Junos has no wire-level "override" action for a configuration-set
    /// payload; this combination must be rejected before any RPC is sent.
    #[test]
    fn resolve_load_action_rejects_set_format_with_override_mode() {
        let r = resolve_load_action("set", LoadAction::Override);
        match r {
            Err(JmcpError::IncompatibleFormatMode { format, mode }) => {
                assert_eq!(format, "set");
                assert_eq!(mode, "override");
            }
            other => panic!("expected IncompatibleFormatMode, got {other:?}"),
        }
    }

    #[test]
    fn refuse_override_outside_changeset_allows_merge_and_replace() {
        assert!(
            refuse_override_outside_changeset("load_and_commit_config", LoadAction::Merge).is_ok()
        );
        assert!(
            refuse_override_outside_changeset("load_and_commit_config", LoadAction::Replace)
                .is_ok()
        );
    }

    #[test]
    fn refuse_override_outside_changeset_rejects_override() {
        let r = refuse_override_outside_changeset("load_and_commit_config", LoadAction::Override);
        match r {
            Err(JmcpError::OverrideRequiresChangeSet { tool }) => {
                assert_eq!(tool, "load_and_commit_config");
            }
            other => panic!("expected OverrideRequiresChangeSet, got {other:?}"),
        }
    }

    #[test]
    fn config_display_suffix_text_needs_no_suffix() {
        assert_eq!(config_display_suffix("text").unwrap(), None);
    }

    #[test]
    fn config_display_suffix_maps_set_xml_json() {
        assert_eq!(config_display_suffix("set").unwrap(), Some("display set"));
        assert_eq!(config_display_suffix("xml").unwrap(), Some("display xml"));
        assert_eq!(config_display_suffix("json").unwrap(), Some("display json"));
    }

    #[test]
    fn config_display_suffix_rejects_unknown() {
        let r = config_display_suffix("yaml");
        assert!(matches!(r, Err(JmcpError::BadConfigFormat(ref s)) if s == "yaml"));
    }

    #[test]
    fn rollback_version_accepts_1_through_49() {
        assert_eq!(validate_rollback_version(1).unwrap(), 1);
        assert_eq!(validate_rollback_version(49).unwrap(), 49);
    }

    #[test]
    fn rollback_version_accepts_zero() {
        assert_eq!(validate_rollback_version(0).unwrap(), 0);
    }

    #[test]
    fn rollback_version_rejects_50() {
        let r = validate_rollback_version(50);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(50))));
    }

    #[test]
    fn rollback_version_rejects_negative() {
        let r = validate_rollback_version(-3);
        assert!(matches!(r, Err(JmcpError::BadRollbackVersion(-3))));
    }

    #[test]
    fn excerpt_short_string_unchanged() {
        let s = "show version";
        assert_eq!(excerpt(s), s);
    }

    #[test]
    fn excerpt_truncates_at_120_char_boundary() {
        let s = "a".repeat(200);
        let result = excerpt(&s);
        assert_eq!(result.len(), 120);
    }

    #[test]
    fn strip_config_xml_wrapper_extracts_content() {
        let raw = "<configuration-information><configuration-output>  system { host-name r1; }  </configuration-output></configuration-information>";
        assert_eq!(strip_config_xml_wrapper(raw), "system { host-name r1; }");
    }

    #[test]
    fn strip_config_xml_wrapper_passthrough_when_no_tag() {
        let raw = "  system { host-name r1; }  ";
        assert_eq!(strip_config_xml_wrapper(raw), "system { host-name r1; }");
    }

    #[test]
    fn confirm_timeout_to_secs_converts_minutes() {
        assert_eq!(confirm_timeout_to_secs(1).unwrap(), 60);
        assert_eq!(confirm_timeout_to_secs(10).unwrap(), 600);
        assert_eq!(confirm_timeout_to_secs(120).unwrap(), 7200);
    }

    #[test]
    fn confirm_timeout_to_secs_rejects_zero() {
        let r = confirm_timeout_to_secs(0);
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("must be >= 1"), "error: {msg}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_accepts_valid_paths() {
        assert!(validate_config_path("system services").is_ok());
        assert!(validate_config_path("security policies").is_ok());
        assert!(validate_config_path("interfaces ge-0/0/0").is_ok());
        assert!(validate_config_path("protocols bgp group peer:1").is_ok());
        assert!(validate_config_path("system.services").is_ok());
    }

    #[test]
    fn validate_config_path_rejects_pipe() {
        let r = validate_config_path("system services | save /tmp/x");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("pipe operator"), "error: {msg}");
            }
            other => panic!("expected Validation error for pipe, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_rejects_semicolon() {
        let r = validate_config_path("foo; bar");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("semicolon"), "error: {msg}");
            }
            other => panic!("expected Validation error for semicolon, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_rejects_newline() {
        let r = validate_config_path("system\nservices");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("newline"), "error: {msg}");
            }
            other => panic!("expected Validation error for newline, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_rejects_leading_newline() {
        let r = validate_config_path("\nsystem services");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("newline"), "error: {msg}");
            }
            other => panic!("expected Validation error for leading newline, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_rejects_quotes() {
        assert!(matches!(
            validate_config_path("system \"services\""),
            Err(JmcpError::Validation(_))
        ));
        assert!(matches!(
            validate_config_path("system 'services'"),
            Err(JmcpError::Validation(_))
        ));
    }

    #[test]
    fn validate_config_path_rejects_backtick() {
        let r = validate_config_path("system `cmd`");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("backtick"), "error: {msg}");
            }
            other => panic!("expected Validation error for backtick, got {other:?}"),
        }
    }

    #[test]
    fn validate_config_path_rejects_empty() {
        let r = validate_config_path("");
        assert!(matches!(r, Err(JmcpError::Validation(_))));
        let r = validate_config_path("   ");
        assert!(matches!(r, Err(JmcpError::Validation(_))));
    }

    #[test]
    fn validate_config_path_rejects_consecutive_spaces() {
        let r = validate_config_path("system  services");
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("consecutive spaces"), "error: {msg}");
            }
            other => panic!("expected Validation error for consecutive spaces, got {other:?}"),
        }
    }

    #[test]
    fn confirm_timeout_to_secs_rejects_overflow() {
        // u32::MAX / 60 = 71582788; anything above that overflows when * 60.
        let r = confirm_timeout_to_secs(u32::MAX / 60 + 1);
        match r {
            Err(JmcpError::Validation(msg)) => {
                assert!(
                    msg.contains("too large") || msg.contains("overflow"),
                    "error: {msg}"
                );
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    // MEC-45: commit-confirmed default-on. `COMMIT_CONFIRM_DEFAULT_MINS` is a
    // single process-wide atomic, and cargo test runs tests in parallel
    // threads by default, so any test that changes it must hold this mutex
    // for the duration of the change-assert-restore sequence — otherwise two
    // such tests interleave and one observes the other's temporary value.
    static DEFAULT_MINS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn resolve_confirm_timeout_omitted_uses_the_server_default() {
        let _guard = DEFAULT_MINS_TEST_LOCK.lock().unwrap();
        let original = commit_confirm_default_mins();
        set_commit_confirm_default_mins(15);
        assert_eq!(
            resolve_confirm_timeout(None),
            ConfirmDecision::Confirmed(15)
        );
        set_commit_confirm_default_mins(original);
    }

    #[test]
    fn resolve_confirm_timeout_zero_is_the_documented_opt_out() {
        assert_eq!(resolve_confirm_timeout(Some(0)), ConfirmDecision::OptedOut);
    }

    #[test]
    fn resolve_confirm_timeout_explicit_value_overrides_the_default() {
        let _guard = DEFAULT_MINS_TEST_LOCK.lock().unwrap();
        let original = commit_confirm_default_mins();
        set_commit_confirm_default_mins(15);
        assert_eq!(
            resolve_confirm_timeout(Some(5)),
            ConfirmDecision::Confirmed(5)
        );
        set_commit_confirm_default_mins(original);
    }

    #[test]
    fn rollback_deadline_unix_is_now_plus_the_window() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deadline = rollback_deadline_unix(10);
        assert!(deadline >= before + 600);
        assert!(deadline < before + 600 + 5, "deadline should be ~now+600s");
    }

    #[test]
    fn rollback_deadline_unix_does_not_panic_on_max_mins() {
        // u32::MAX minutes in seconds (~2.6e11) is nowhere near u64::MAX
        // (~1.8e19), so the saturating arithmetic never actually saturates
        // for any valid `mins`. This test exists to prove the calculation
        // stays panic-free (no overflow-checked add/mul) even at the type's
        // extreme, not that saturation is reachable.
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deadline = rollback_deadline_unix(u32::MAX);
        let expected_window = u64::from(u32::MAX) * 60;
        assert!(deadline >= before + expected_window);
        assert!(deadline < before + expected_window + 5);
        assert!(deadline < u64::MAX);
    }
}

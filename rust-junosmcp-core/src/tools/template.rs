//! `render_and_apply_j2_template` — Jinja2 render with optional commit.
//!
//! As of v0.5.2 (RJMCP-SEC-002), `vars_content` is parsed as JSON only.
//! YAML support was removed because `serde_yml` / `libyml` are unmaintained
//! and carry unfixed soundness advisories (RUSTSEC-2025-0067/-0068) that
//! were reachable from untrusted MCP input. Both `template_content` and
//! `vars_content` are now bounded at 64 KiB to limit parser/renderer cost.

use crate::error::JmcpError;
use minijinja::{Environment, UndefinedBehavior};
use serde_json::Value;
use std::time::Duration;

/// Hard ceiling on `template_content` and `vars_content` byte length. Any
/// real-world Junos config payload sits well below this; the cap exists to
/// bound parser / renderer cost against a hostile token holder.
pub(crate) const MAX_TEMPLATE_BYTES: usize = 65_536;

/// Parse `vars_content` strictly as a JSON object. YAML is no longer
/// accepted (see RJMCP-SEC-002). Input is rejected if it exceeds
/// `MAX_TEMPLATE_BYTES` or does not deserialize to a top-level object.
pub(crate) fn parse_vars(input: &str) -> Result<Value, JmcpError> {
    if input.len() > MAX_TEMPLATE_BYTES {
        return Err(JmcpError::TemplateVars(format!(
            "vars_content exceeds {MAX_TEMPLATE_BYTES}-byte limit ({} bytes)",
            input.len()
        )));
    }
    let parsed = serde_json::from_str::<Value>(input)
        .map_err(|e| JmcpError::TemplateVars(format!("JSON parse failed: {e}")))?;
    if !parsed.is_object() {
        return Err(JmcpError::TemplateVars(
            "vars_content must deserialize to a top-level JSON object".into(),
        ));
    }
    Ok(parsed)
}

/// Render `template_content` with `vars` (a JSON object). Strict-undefined:
/// missing variables surface as `JmcpError::TemplateRender`, not silently as "".
/// Input over `MAX_TEMPLATE_BYTES` is rejected to bound renderer cost.
pub(crate) fn render(template_content: &str, vars: &Value) -> Result<String, JmcpError> {
    if template_content.len() > MAX_TEMPLATE_BYTES {
        return Err(JmcpError::TemplateSyntax(format!(
            "template_content exceeds {MAX_TEMPLATE_BYTES}-byte limit ({} bytes)",
            template_content.len()
        )));
    }
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    let tmpl = env
        .template_from_str(template_content)
        .map_err(|e| JmcpError::TemplateSyntax(format!("{e}")))?;
    tmpl.render(vars)
        .map_err(|e| JmcpError::TemplateRender(format!("{e}")))
}

/// Auto-detect Junos config format from the rendered string.
/// Returns "xml" if the first non-whitespace char is `<`, "set" if any line
/// starts with `set ` or `delete `, otherwise "text".
pub(crate) fn detect_format(rendered: &str) -> &'static str {
    let trimmed = rendered.trim_start();
    if trimmed.starts_with('<') {
        return "xml";
    }
    for line in rendered.lines() {
        let line = line.trim_start();
        if line.starts_with("set ") || line.starts_with("delete ") {
            return "set";
        }
    }
    "text"
}

use crate::device_manager::DeviceManager;
use crate::helpers::{
    ConfirmDecision, build_config_payload, confirm_timeout_to_secs, parse_load_mode,
    refuse_override_outside_changeset, resolve_confirm_timeout, resolve_load_action,
    rollback_deadline_unix,
};
use crate::policy::Policy;
use crate::tools::TemplateArgs;
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Resolve the device-selector args to a single canonical Vec<String>.
/// Rejects both-supplied; rejects empty `device_names`; allows neither
/// (returns an empty list — apply path will be a no-op).
fn resolve_devices(args: &TemplateArgs) -> Result<Vec<String>, JmcpError> {
    match (&args.device_name, &args.device_names) {
        (Some(_), Some(_)) => Err(JmcpError::Validation(
            "specify exactly one of `device_name` or `device_names`".into(),
        )),
        (Some(one), None) => Ok(vec![one.clone()]),
        (None, Some(many)) if many.is_empty() => Err(JmcpError::Validation(
            "`device_names` cannot be empty".into(),
        )),
        (None, Some(many)) => Ok(many.clone()),
        (None, None) => Ok(Vec::new()),
    }
}

/// Render a Jinja2 template and apply it to one or more devices.
pub async fn handle(
    args: TemplateArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<serde_json::Value, JmcpError> {
    handle_with_cancel(args, dm, policy, CancellationToken::new()).await
}

/// Cancellable variant of `handle` for use in transport shutdown paths.
pub async fn handle_with_cancel(
    args: TemplateArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    ct: CancellationToken,
) -> Result<serde_json::Value, JmcpError> {
    let devices = resolve_devices(&args)?;

    // Pre-flight: verify every named device exists. Mirrors the batch tool.
    for d in &devices {
        let _ = dm.inventory().get(d)?;
    }

    let vars = parse_vars(&args.vars_content)?;
    let rendered = render(&args.template_content, &vars)?;
    let format = match args.config_format.as_deref() {
        Some(f) if f == "set" || f == "text" || f == "xml" => f.to_string(),
        Some(other) => return Err(JmcpError::BadFormat(other.to_string())),
        None => detect_format(&rendered).to_string(),
    };

    // `mode` is validated and gated before any payload is built or RPC is
    // sent: `override` is the highest blast-radius operation this server
    // exposes, and this tool commits directly with no second-principal
    // review, so it is refused outright rather than forwarded to the device.
    let load_mode = parse_load_mode(Some(&args.mode))?;
    refuse_override_outside_changeset("render_and_apply_j2_template", load_mode)?;
    let load_action = resolve_load_action(&format, load_mode)?;

    // Format gate: if any selected device has effective config rules,
    // the rendered format must be `set`. Same restriction as
    // load_and_commit_config.
    if format != "set" {
        for d in &devices {
            if policy.has_config_rules_for(d) {
                return Err(JmcpError::TemplateFormatMismatch { format });
            }
        }
    }

    if !args.apply_config {
        let mut rows = Vec::with_capacity(devices.len().max(1));
        if devices.is_empty() {
            rows.push(json!({
                "router": null,
                "rendered_template": rendered,
                "config_format": format,
            }));
        } else {
            for d in devices {
                rows.push(json!({
                    "router": d,
                    "rendered_template": rendered,
                    "config_format": format,
                }));
            }
        }
        return Ok(json!({ "results": rows, "applied": false }));
    }

    // Apply path: per-device blocklist on the rendered output, then commit.
    let payload = build_config_payload(rendered.clone(), Some(&format))?;
    let mut rows: Vec<serde_json::Value> = Vec::with_capacity(devices.len());
    for d in &devices {
        match policy.check_config(d, &format, &rendered)? {
            crate::policy::Decision::Allow => {}
            crate::policy::Decision::Deny {
                rule,
                source,
                line_number,
            } => {
                let pattern = rule.pattern.clone();
                let source_str = source.as_str();
                tracing::warn!(
                    tool = "render_and_apply_j2_template",
                    router = %d,
                    matched_rule = %pattern,
                    rule_source = %source_str,
                    line_number = ?line_number,
                    "blocklist denied request",
                );
                rows.push(json!({
                    "router": d,
                    "rendered_template": rendered,
                    "config_format": format,
                    "error": format!("blocklist denied: pattern `{pattern}` from {source_str}"),
                }));
                continue;
            }
            crate::policy::Decision::DenyAllowlist { .. } => {
                tracing::warn!(
                    tool = "render_and_apply_j2_template",
                    router = %d,
                    "policy invariant violated: check_config returned DenyAllowlist",
                );
                rows.push(json!({
                    "router": d,
                    "rendered_template": rendered,
                    "config_format": format,
                    "error": "policy invariant violated: config domain returned DenyAllowlist",
                }));
                continue;
            }
        }

        let row = match commit_one(
            d,
            (payload.clone(), load_action),
            &args.commit_comment,
            args.dry_run,
            args.confirm_timeout_mins,
            &dm,
            Duration::from_secs(args.timeout),
            &ct,
        )
        .await
        {
            Err(JmcpError::Cancelled) => return Err(JmcpError::Cancelled),
            Ok(CommitOneOutcome::DryRun { diff }) => json!({
                "router": d,
                "rendered_template": rendered,
                "config_format": format,
                "diff": diff,
            }),
            Ok(CommitOneOutcome::Committed { echo, confirmed }) => {
                let mut row = json!({
                    "router": d,
                    "rendered_template": rendered,
                    "config_format": format,
                    // Note: rustez's commit() does not return a server-issued
                    // commit identifier, so we surface the supplied
                    // commit_comment instead. Field name reflects what is
                    // actually returned.
                    "commit_comment": echo,
                });
                if let Some(mins) = confirmed {
                    row["confirmed"] = json!(true);
                    row["rollback_in_minutes"] = json!(mins);
                    row["rollback_deadline_unix"] = json!(rollback_deadline_unix(mins));
                    row["message"] = json!(format!(
                        "Commit confirmed: auto-rollback in {} minutes unless confirmed. \
                         Send another commit to confirm with confirm_commit.",
                        mins
                    ));
                }
                row
            }
            Err(e) => json!({
                "router": d,
                "rendered_template": rendered,
                "config_format": format,
                "error": e.to_string(),
            }),
        };
        rows.push(row);
    }
    Ok(json!({ "results": rows, "applied": !args.dry_run }))
}

/// Outcome of [`commit_one`]: either a dry-run diff, or a successful commit
/// echo plus the confirm-commit window actually used (`None` when the caller
/// opted out with `confirm_timeout_mins: 0`).
enum CommitOneOutcome {
    DryRun {
        diff: String,
    },
    Committed {
        echo: String,
        confirmed: Option<u32>,
    },
}

/// Commit (or dry-run) a rendered config payload to one device.
///
/// Commit-confirmed by default (MEC-45): a bad template apply reverts itself
/// unless the caller explicitly opts out with `confirm_timeout_mins: 0`.
/// rustez does not return a server-issued commit identifier, so the apply-mode
/// echo is the comment that was used, not a device-assigned commit ID.
#[allow(clippy::too_many_arguments)]
async fn commit_one(
    device_name: &str,
    (payload, load_action): (rustez::ConfigPayload, rustez::LoadAction),
    commit_comment: &str,
    dry_run: bool,
    confirm_timeout_mins: Option<u32>,
    dm: &Arc<DeviceManager>,
    timeout: Duration,
    ct: &CancellationToken,
) -> Result<CommitOneOutcome, JmcpError> {
    let commit_comment = commit_comment.to_string();
    let (mode, confirmed) = if dry_run {
        (CandidateMode::DryRun, None)
    } else {
        match resolve_confirm_timeout(confirm_timeout_mins) {
            ConfirmDecision::Confirmed(mins) => {
                let secs = confirm_timeout_to_secs(mins)?;
                (CandidateMode::CommitConfirmed(secs), Some(mins))
            }
            ConfirmDecision::OptedOut => (
                CandidateMode::CommitWithComment(commit_comment.clone()),
                None,
            ),
        }
    };
    match candidate_transaction::run(
        dm,
        device_name,
        CandidateRequest {
            payload: Some(payload),
            rollback_source: None,
            mode,
            load_action,
        },
        timeout,
        ct,
    )
    .await?
    {
        CandidateResult::DryRun { diff } => Ok(CommitOneOutcome::DryRun { diff }),
        CandidateResult::Committed { .. } => Ok(CommitOneOutcome::Committed {
            echo: commit_comment,
            confirmed,
        }),
        CandidateResult::CommitFailed { error, .. } => Err(JmcpError::Validation(error)),
        _ => unreachable!("template transaction returned the wrong result kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_parses_json_object() {
        let v = parse_vars(r#"{"name":"r1","port":22}"#).unwrap();
        assert_eq!(v["name"], "r1");
        assert_eq!(v["port"], 22);
    }

    #[test]
    fn vars_handles_leading_whitespace_before_json() {
        let v = parse_vars("   \n   {\"x\":1}").unwrap();
        assert_eq!(v["x"], 1);
    }

    #[test]
    fn vars_rejects_json_array() {
        let r = parse_vars("[1,2,3]");
        match r {
            Err(JmcpError::TemplateVars(s)) => assert!(s.contains("top-level JSON object")),
            other => panic!("expected TemplateVars rejection, got {other:?}"),
        }
    }

    /// RJMCP-SEC-002: YAML is no longer accepted. Previously a `vars_content`
    /// that did not start with `{` was routed to `serde_yml`, which is
    /// unsound/unmaintained (RUSTSEC-2025-0067/-0068). Now it must be a JSON
    /// parse failure.
    #[test]
    fn vars_rejects_yaml_input_with_clear_json_error() {
        let r = parse_vars("name: r1\nport: 22\n");
        match r {
            Err(JmcpError::TemplateVars(s)) => assert!(
                s.contains("JSON parse failed"),
                "error must steer caller toward JSON: {s}"
            ),
            other => panic!("expected TemplateVars rejection, got {other:?}"),
        }
    }

    #[test]
    fn vars_rejects_non_object_scalar() {
        let r = parse_vars("\"just a string\"");
        match r {
            Err(JmcpError::TemplateVars(s)) => assert!(s.contains("top-level JSON object")),
            other => panic!("expected TemplateVars rejection, got {other:?}"),
        }
    }

    /// 64 KiB cap is enforced before parsing — confirm both ends of the
    /// boundary.
    #[test]
    fn vars_accepts_input_at_size_limit() {
        // Build a JSON object whose total byte length lands exactly on the cap.
        // Shape: `{"k":"<padding>"}` — outer wrapping is 8 chars, so padding
        // fills the remaining (MAX - 8) bytes.
        let padding = "a".repeat(MAX_TEMPLATE_BYTES - 8);
        let input = format!("{{\"k\":\"{padding}\"}}");
        assert_eq!(input.len(), MAX_TEMPLATE_BYTES);
        let v = parse_vars(&input).unwrap();
        assert!(v["k"].is_string());
    }

    #[test]
    fn vars_rejects_input_over_size_limit() {
        let oversize = "a".repeat(MAX_TEMPLATE_BYTES + 1);
        let r = parse_vars(&oversize);
        match r {
            Err(JmcpError::TemplateVars(s)) => assert!(
                s.contains("exceeds") && s.contains("limit"),
                "error must mention the size limit: {s}"
            ),
            other => panic!("expected size-cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_template_over_size_limit() {
        let oversize = "x".repeat(MAX_TEMPLATE_BYTES + 1);
        let r = render(&oversize, &parse_vars("{}").unwrap());
        match r {
            Err(JmcpError::TemplateSyntax(s)) => assert!(
                s.contains("exceeds") && s.contains("limit"),
                "error must mention the size limit: {s}"
            ),
            other => panic!("expected size-cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn render_substitutes_simple_var() {
        let out = render(
            "set system host-name {{ name }}",
            &parse_vars(r#"{"name":"r1"}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "set system host-name r1");
    }

    #[test]
    fn render_strict_undefined_fails_with_var_name() {
        let r = render(
            "set system host-name {{ missing }}",
            &parse_vars("{}").unwrap(),
        );
        match r {
            Err(JmcpError::TemplateRender(s)) => assert!(s.contains("undefined")),
            other => panic!("expected TemplateRender, got {other:?}"),
        }
    }

    #[test]
    fn render_minijinja_filters_work() {
        let out = render(
            "{{ name | upper }}-{{ ports | length }}",
            &parse_vars(r#"{"name":"r1","ports":[1,2,3,4]}"#).unwrap(),
        )
        .unwrap();
        assert_eq!(out, "R1-4");
    }

    #[test]
    fn render_template_syntax_error_surfaces() {
        let r = render("{{ unterminated", &parse_vars("{}").unwrap());
        assert!(matches!(r, Err(JmcpError::TemplateSyntax(_))));
    }

    #[test]
    fn format_autodetect_xml_for_leading_lt() {
        assert_eq!(detect_format("<configuration>...</configuration>"), "xml");
        assert_eq!(detect_format("\n  <foo/>"), "xml");
    }

    #[test]
    fn format_autodetect_set_for_set_lines() {
        assert_eq!(detect_format("set system host-name r1"), "set");
        assert_eq!(detect_format("delete protocols bgp"), "set");
        // Mixed input, but `set ` line wins:
        assert_eq!(detect_format("set foo\n# comment\nbar"), "set");
    }

    #[test]
    fn format_autodetect_text_otherwise() {
        assert_eq!(detect_format("system {\n  host-name r1;\n}"), "text");
        assert_eq!(detect_format(""), "text");
    }

    use crate::device_manager::DeviceManager;
    use crate::inventory::Inventory;
    use crate::policy::Policy;
    use crate::tools::TemplateArgs;
    use std::io::Write;
    use std::sync::Arc;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    fn args_render_only(devices: Vec<&str>) -> TemplateArgs {
        TemplateArgs {
            template_content: "set system host-name {{ name }}".into(),
            vars_content: r#"{"name":"r1"}"#.into(),
            device_name: None,
            device_names: Some(devices.iter().map(|s| s.to_string()).collect()),
            apply_config: false,
            commit_comment: "test".into(),
            dry_run: false,
            config_format: None,
            mode: "merge".into(),
            confirm_timeout_mins: None,
            timeout: 5,
        }
    }

    #[tokio::test]
    async fn render_only_returns_rendered_string_per_router() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(args_render_only(vec!["r1"]), dm, pol).await.unwrap();
        let rows = r["results"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["router"], "r1");
        assert_eq!(rows[0]["rendered_template"], "set system host-name r1");
        assert!(rows[0].get("commit_comment").is_none());
        assert!(rows[0].get("error").is_none());
    }

    #[tokio::test]
    async fn render_only_unknown_router_returns_error_row() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let r = handle(args_render_only(vec!["nope"]), dm, pol).await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn render_only_rejects_both_device_name_and_names() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_render_only(vec!["r1"]);
        a.device_name = Some("r1".into());
        let r = handle(a, dm, pol).await;
        assert!(matches!(r, Err(JmcpError::Validation(_))));
    }

    fn args_apply(devices: Vec<&str>, dry_run: bool) -> TemplateArgs {
        let mut a = args_render_only(devices);
        a.apply_config = true;
        a.dry_run = dry_run;
        a
    }

    #[tokio::test]
    async fn apply_blocklist_rejects_rendered_payload_pre_connect() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_apply(vec!["r1"], false);
        a.template_content = "set foo\ndelete protocols bgp".into();
        a.vars_content = "{}".into();
        let r = handle(a, dm, pol).await.unwrap();
        let rows = r["results"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["error"].as_str().unwrap().contains("delete *"));
    }

    #[tokio::test]
    async fn apply_text_format_with_rules_returns_format_mismatch() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_apply(vec!["r1"], false);
        a.template_content = "system { host-name r1; }".into();
        a.vars_content = "{}".into();
        a.config_format = Some("text".into());
        let r = handle(a, dm, pol).await;
        assert!(
            matches!(r, Err(JmcpError::TemplateFormatMismatch { ref format }) if format == "text")
        );
    }

    /// `render_and_apply_j2_template` commits in the same call with no
    /// second-principal review, so — like `load_and_commit_config` —
    /// `override` must be refused outright rather than forwarded to a
    /// device. Checked even in render-only mode: the tool never accepts
    /// `mode=override` at all, not just at apply time.
    #[tokio::test]
    async fn override_mode_is_refused_without_a_change_set() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_render_only(vec!["r1"]);
        a.mode = "override".into();
        let r = handle(a, dm, pol).await;
        match r {
            Err(JmcpError::OverrideRequiresChangeSet { tool }) => {
                assert_eq!(tool, "render_and_apply_j2_template");
            }
            other => panic!("expected OverrideRequiresChangeSet, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_mode_is_rejected() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let mut a = args_render_only(vec!["r1"]);
        a.mode = "wipe".into();
        let r = handle(a, dm, pol).await;
        assert!(matches!(r, Err(JmcpError::BadLoadMode(ref s)) if s == "wipe"));
    }
}

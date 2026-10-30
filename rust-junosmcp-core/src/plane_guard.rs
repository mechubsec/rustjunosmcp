//! Plane guard: refuse config writes that a management plane owns.
//!
//! An SRX managed by Juniper Security Director (Cloud or On-Prem) owns its
//! `security` tree plus top-level `applications` and `schedulers`; a
//! Mist-managed SRX owns its whole configuration. This module holds the pure
//! logic: detecting the managing plane from `system services outbound-ssh`,
//! finding protected hierarchies in a `show | compare` diff, and deciding
//! whether a write is refused, warned about, or allowed. It performs no I/O.

use crate::config_authority::JunosAuthority;
use crate::error::JmcpError;
use std::collections::HashSet;

/// Top-level hierarchies Security Director owns on a managed SRX.
const PROTECTED: [&str; 3] = ["security", "applications", "schedulers"];

/// Containers whose first child is a name and whose body is a full config tree.
const WRAPPERS: [&str; 3] = ["groups", "logical-systems", "tenants"];

/// Most protected paths quoted in one refusal or warning.
const MAX_RENDERED_PATHS: usize = 10;

/// How the managing plane was established, quoted in refusals and warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySource {
    /// The operator set `config_authority` in `devices.json`.
    Declared,
    /// Inferred from the device's `system services outbound-ssh` stanza.
    Detected,
}

impl AuthoritySource {
    /// Human-readable provenance for error and warning text.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Declared => "declared in devices.json config_authority",
            Self::Detected => "detected from system services outbound-ssh",
        }
    }
}

/// Infer the managing plane from `show configuration system services outbound-ssh`.
///
/// Accepts curly-brace text (relative to `outbound-ssh`) or `| display set`
/// lines. Inactive or protected clients still count: refusing too much is the
/// safe error. Precedence is Mist, then Security Director Cloud, then
/// Security Director On-Prem (`EMS-` client), else `Unknown`.
pub fn detect_authority(outbound_ssh: &str) -> JunosAuthority {
    let mut has_mist = false;
    let mut has_sd_cloud = false;
    let mut has_ems_client = false;
    for line in outbound_ssh.lines() {
        // Annotations are free text: `/* old client mist */` must not lock a device.
        let trimmed = line.trim_start();
        if trimmed.starts_with("/*") || trimmed.starts_with('*') || trimmed.starts_with('#') {
            continue;
        }
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("sdcloud.juniperclouds.net") {
            has_sd_cloud = true;
        }
        let mut tokens = line.split_whitespace();
        if !tokens.any(|token| token == "client") {
            continue;
        }
        let Some(raw_name) = tokens.next() else {
            continue;
        };
        let name = raw_name.trim_end_matches('{').to_ascii_lowercase();
        if name == "mist" {
            has_mist = true;
        }
        if name.starts_with("ems-") {
            has_ems_client = true;
        }
    }
    if has_mist {
        return JunosAuthority::Mist;
    }
    if has_sd_cloud {
        return JunosAuthority::SecurityDirectorCloud;
    }
    if has_ems_client {
        return JunosAuthority::SecurityDirectorOnprem;
    }
    JunosAuthority::Unknown
}

/// Decide whether `path` (full hierarchy of a changed line) hits a protected
/// hierarchy, returning the value-free string to record.
fn classify(path: &[String]) -> Option<String> {
    let mut start = 0;
    while path
        .get(start)
        .is_some_and(|token| WRAPPERS.contains(&token.as_str()))
    {
        if path.len() < start + 2 {
            return None; // bare wrapper container
        }
        start += 2;
    }
    let keyword = path.get(start)?;
    let mut recorded: Vec<&str> = path[..start].iter().map(String::as_str).collect();
    recorded.push(keyword);
    // shortcut: conservative, over-refuses top-level apply-groups; --allow-plane-owned-writes overrides
    if keyword == "apply-groups" || keyword == "apply-groups-except" {
        return Some(recorded.join(" "));
    }
    if !PROTECTED.contains(&keyword.as_str()) {
        return None;
    }
    // At most one child token: deeper tokens can be leaf values such as secrets.
    if let Some(child) = path.get(start + 1) {
        recorded.push(child);
    }
    Some(recorded.join(" "))
}

/// Push the hit for `path` (if any) onto `hits`, keeping first-seen order.
fn record(hits: &mut Vec<String>, seen: &mut HashSet<String>, path: &[String]) {
    let Some(hit) = classify(path) else {
        return;
    };
    if seen.insert(hit.clone()) {
        hits.push(hit);
    }
}

/// Join `paths` for a message, capped so a diff touching thousands of groups
/// cannot produce an unbounded error or warning.
fn render_paths(paths: &[String]) -> String {
    if paths.len() <= MAX_RENDERED_PATHS {
        return paths.join(", ");
    }
    format!(
        "{} and {} more",
        paths[..MAX_RENDERED_PATHS].join(", "),
        paths.len() - MAX_RENDERED_PATHS
    )
}

/// List protected hierarchies touched by a Junos `show | compare` text diff.
///
/// Returns value-free strings such as `security nat` or
/// `logical-systems LS1 security ike`, deduplicated in first-seen order.
/// Leaf values are never included, since they may be secrets.
pub fn protected_paths(diff: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut header_path: Vec<String> = Vec::new();
    let mut stack: Vec<Vec<String>> = Vec::new();
    for line in diff.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[edit") && trimmed.ends_with(']') {
            header_path = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            stack.clear();
            record(&mut hits, &mut seen, &header_path);
            continue;
        }
        let is_changed = line.starts_with(['+', '-', '!']);
        let mut rest = if is_changed { &line[1..] } else { line }.trim();
        if rest.is_empty()
            || rest.starts_with("/*")
            || rest.starts_with('*')
            || rest.starts_with('#')
        {
            continue;
        }
        while let Some(stripped) = rest
            .strip_prefix("inactive:")
            .or_else(|| rest.strip_prefix("protect:"))
        {
            rest = stripped.trim_start();
        }
        if rest == "}" {
            stack.pop();
            continue;
        }
        let opens_block = rest.ends_with('{');
        let statement = rest.trim_end_matches('{').trim_end_matches(';');
        let tokens: Vec<String> = statement.split_whitespace().map(str::to_owned).collect();
        let mut full_path = header_path.clone();
        full_path.extend(stack.iter().flatten().cloned());
        full_path.extend(tokens.iter().cloned());
        if is_changed {
            record(&mut hits, &mut seen, &full_path);
        }
        if opens_block {
            stack.push(tokens);
        }
    }
    hits
}

/// Decide whether a config write on a plane-managed device is allowed.
///
/// Returns `Ok(None)` when nothing is wrong, `Ok(Some(warning))` when the
/// write is allowed only because `allow_plane_owned_writes` is set, and
/// `Err(PlaneManagedConfig)` when refused. Mist is read-only, so its `diff`
/// is ignored. For Security Director a `diff` of `None` means the candidate
/// does not exist yet; the caller re-checks once it does.
pub fn check(
    tool: &'static str,
    device: &str,
    authority: &JunosAuthority,
    source: AuthoritySource,
    diff: Option<&str>,
    allow_plane_owned_writes: bool,
) -> Result<Option<String>, JmcpError> {
    let source_text = source.as_str();
    let paths = match authority {
        JunosAuthority::Local | JunosAuthority::Unknown => return Ok(None),
        JunosAuthority::Mist => {
            if allow_plane_owned_writes {
                return Ok(Some(format!(
                    "WARNING: '{device}' is managed by Juniper Mist ({source_text}). \
                     This change will be overwritten and erased by the next Mist push."
                )));
            }
            return Err(refuse(
                tool,
                device,
                authority,
                format!(
                    "this SRX is managed by Juniper Mist ({source_text}) and is read-only through this server. \
                 Make configuration changes with rustmistmcp (plan_mist_change, then approve_mist_change_set \
                 and apply_mist_change_set), the Mist API, or ask the user to make them in the Mist portal. \
                 If Mist does not configure this device, set its config_authority in devices.json."
                ),
            ));
        }
        JunosAuthority::SecurityDirectorCloud | JunosAuthority::SecurityDirectorOnprem => {
            let Some(diff_text) = diff else {
                return Ok(None);
            };
            let paths = protected_paths(diff_text);
            if paths.is_empty() {
                return Ok(None);
            }
            render_paths(&paths)
        }
    };
    let (plane, remedy) = if matches!(authority, JunosAuthority::SecurityDirectorCloud) {
        (
            "Security Director Cloud",
            "in Security Director Cloud: use rustsdcmcp (prepare_sdc_firewall_rule_write, \
             prepare_sdc_nat_write or prepare_sdc_object_write, then prepare_sdc_policy_deploy), \
             the SDC API, or ask the user to make the change in the Security Director Cloud GUI",
        )
    } else {
        (
            "Security Director On-Prem",
            "through the Security Director API, or ask the user to make the change in the \
             Security Director GUI",
        )
    };
    if allow_plane_owned_writes {
        return Ok(Some(format!(
            "WARNING: '{device}' is managed by {plane} ({source_text}) and this change touches {paths}. \
             This may cause you to have to delete and re-import your security and NAT policy."
        )));
    }
    Err(refuse(
        tool,
        device,
        authority,
        format!(
            "this change touches {paths}, which {plane} manages on this SRX ({source_text}). \
             Make security policy, NAT, address/application object and scheduler changes {remedy}. \
             Interface, routing and system changes are still allowed here; resubmit them without the \
             security, applications and schedulers changes."
        ),
    ))
}

/// Build the refusal error for `authority`.
fn refuse(
    tool: &'static str,
    device: &str,
    authority: &JunosAuthority,
    detail: String,
) -> JmcpError {
    JmcpError::PlaneManagedConfig {
        tool,
        device: device.to_owned(),
        authority: authority.as_str().to_owned(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDC_STANZA: &str = "client EMS-srx.sdcloud.juniperclouds.net {\n    device-id abc;\n    services netconf;\n    srx.sdcloud.juniperclouds.net port 7804;\n}\n";

    #[test]
    fn detects_mist_curly() {
        let text = "client mist {\n    device-id x;\n    services netconf;\n    oc-term.mistsys.net port 2200;\n}\n";
        assert_eq!(detect_authority(text), JunosAuthority::Mist);
    }

    #[test]
    fn detects_mist_display_set() {
        let text = "set system services outbound-ssh client mist device-id x\n";
        assert_eq!(detect_authority(text), JunosAuthority::Mist);
    }

    #[test]
    fn detects_sd_cloud() {
        assert_eq!(
            detect_authority(SDC_STANZA),
            JunosAuthority::SecurityDirectorCloud
        );
    }

    #[test]
    fn detects_sd_onprem() {
        let text = "client EMS-sdon {\n    device-id y;\n    services netconf;\n    10.1.2.3 port 7804;\n}\n";
        assert_eq!(
            detect_authority(text),
            JunosAuthority::SecurityDirectorOnprem
        );
    }

    #[test]
    fn detects_unknown() {
        assert_eq!(detect_authority(""), JunosAuthority::Unknown);
        let text = "client noc-collector {\n    10.9.9.9 port 22;\n}\n";
        assert_eq!(detect_authority(text), JunosAuthority::Unknown);
    }

    #[test]
    fn inactive_mist_client_still_counts() {
        assert_eq!(
            detect_authority("inactive: client mist {\n}\n"),
            JunosAuthority::Mist
        );
    }

    #[test]
    fn mist_beats_sd_cloud() {
        let text = format!("client mist {{\n}}\n{SDC_STANZA}");
        assert_eq!(detect_authority(&text), JunosAuthority::Mist);
    }

    #[test]
    fn annotations_do_not_detect() {
        let text = "/* old client mist, retired sdcloud.juniperclouds.net endpoint */\n\
                    client noc-collector {\n    10.0.0.9 port 2200;\n}\n";
        assert_eq!(detect_authority(text), JunosAuthority::Unknown);
    }

    fn hits(diff: &str) -> Vec<String> {
        protected_paths(diff)
    }

    #[test]
    fn header_under_security_hits() {
        let diff =
            "[edit security policies from-zone trust to-zone untrust]\n+    policy p1 {\n+    }\n";
        assert_eq!(hits(diff), vec!["security policies"]);
    }

    #[test]
    fn nested_security_from_root_hits() {
        let diff = "[edit]\n+  security {\n+      nat {\n+          source {\n+          }\n+      }\n+  }\n";
        assert_eq!(hits(diff), vec!["security", "security nat"]);
    }

    #[test]
    fn groups_wrapper_is_recorded() {
        assert_eq!(
            hits("[edit groups G security nat]\n+   source;\n"),
            vec!["groups G security nat"]
        );
    }

    #[test]
    fn logical_system_security_hits() {
        assert_eq!(
            hits("[edit logical-systems LS1 security]\n+   zones;\n"),
            vec![
                "logical-systems LS1 security",
                "logical-systems LS1 security zones"
            ]
        );
        let nested = "[edit logical-systems]\n+  LS1 {\n+      security {\n+          zones;\n+      }\n+  }\n";
        assert_eq!(
            hits(nested),
            vec![
                "logical-systems LS1 security",
                "logical-systems LS1 security zones"
            ]
        );
    }

    #[test]
    fn applications_and_schedulers_hit() {
        assert_eq!(
            hits("[edit applications]\n+   application a;\n"),
            vec!["applications", "applications application"]
        );
        assert_eq!(
            hits("[edit schedulers]\n+   scheduler s;\n"),
            vec!["schedulers", "schedulers scheduler"]
        );
    }

    #[test]
    fn inactive_security_hits() {
        assert_eq!(
            hits("[edit]\n!  inactive: security {\n!  }\n"),
            vec!["security"]
        );
    }

    #[test]
    fn top_level_apply_groups_hits() {
        assert_eq!(hits("[edit]\n+  apply-groups SEC;\n"), vec!["apply-groups"]);
    }

    #[test]
    fn unprotected_diffs_do_not_hit() {
        let cases = [
            "[edit interfaces ge-0/0/0 unit 0 family inet]\n-       address 10.0.0.2/24;\n+       address 10.0.0.1/24;\n",
            "[edit system services]\n+   ssh;\n",
            "[edit class-of-service schedulers]\n+   be;\n",
            "[edit]\n+  class-of-service {\n+      schedulers {\n+          be;\n+      }\n+  }\n",
            "[edit interfaces]\n+  apply-groups X;\n",
            "[edit]\n+  security-profile foo;\n",
            "[edit logical-systems]\n+   LS1;\n",
        ];
        for diff in cases {
            assert!(hits(diff).is_empty(), "unexpected hit for {diff:?}");
        }
    }

    #[test]
    fn leaf_values_are_never_recorded() {
        let diff = "[edit security ike policy P]\n+    pre-shared-key ascii-text \"$9$abc\"; ## SECRET-DATA\n"; // gitleaks:allow
        let found = hits(diff);
        assert_eq!(found, vec!["security ike"]);
        let joined = found.join(" ");
        assert!(!joined.contains("$9$") && !joined.contains("pre-shared-key"));
    }

    #[test]
    fn hits_are_deduplicated() {
        let diff = "[edit security nat]\n+   a;\n[edit security nat]\n+   b;\n";
        assert_eq!(hits(diff), vec!["security nat"]);
    }

    #[test]
    fn empty_diff_has_no_hits() {
        assert!(hits("").is_empty());
    }

    const SECURITY_DIFF: &str = "[edit security nat source]\n+    rule-set rs1 {\n+    }\n";
    const INTERFACE_DIFF: &str = "[edit interfaces ge-0/0/0]\n+   description x;\n";

    fn run(
        authority: &JunosAuthority,
        source: AuthoritySource,
        diff: Option<&str>,
        allow: bool,
    ) -> Result<Option<String>, JmcpError> {
        check(
            "load_and_commit_config",
            "srx1",
            authority,
            source,
            diff,
            allow,
        )
    }

    #[test]
    fn local_and_unknown_always_pass() {
        for authority in [JunosAuthority::Local, JunosAuthority::Unknown] {
            let result = run(
                &authority,
                AuthoritySource::Declared,
                Some(SECURITY_DIFF),
                false,
            );
            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    fn mist_refused_without_flag() {
        let err = run(
            &JunosAuthority::Mist,
            AuthoritySource::Declared,
            None,
            false,
        )
        .unwrap_err();
        assert_eq!(err.audit_kind(), "blocked");
        assert!(err.to_string().contains("plan_mist_change"));
    }

    #[test]
    fn mist_warns_with_flag() {
        let warning = run(&JunosAuthority::Mist, AuthoritySource::Declared, None, true)
            .unwrap()
            .unwrap();
        assert!(warning.contains("overwritten and erased"));
    }

    #[test]
    fn sd_cloud_refuses_security_diff() {
        let err = run(
            &JunosAuthority::SecurityDirectorCloud,
            AuthoritySource::Declared,
            Some(SECURITY_DIFF),
            false,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("prepare_sdc_nat_write"));
        assert!(text.contains("security nat"));
    }

    #[test]
    fn sd_allows_unprotected_or_missing_diff() {
        for diff in [Some(INTERFACE_DIFF), None] {
            let result = run(
                &JunosAuthority::SecurityDirectorCloud,
                AuthoritySource::Declared,
                diff,
                false,
            );
            assert!(matches!(result, Ok(None)));
        }
    }

    #[test]
    fn sd_warns_with_flag() {
        let warning = run(
            &JunosAuthority::SecurityDirectorCloud,
            AuthoritySource::Declared,
            Some(SECURITY_DIFF),
            true,
        )
        .unwrap()
        .unwrap();
        assert!(warning.contains("delete and re-import"));
    }

    #[test]
    fn rendered_paths_are_capped() {
        let diff: String = (0..25)
            .map(|index| format!("[edit groups G{index} security nat]\n+    pool p;\n"))
            .collect();
        assert_eq!(hits(&diff).len(), 25);
        let err = run(
            &JunosAuthority::SecurityDirectorCloud,
            AuthoritySource::Declared,
            Some(&diff),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("groups G9 security nat and 15 more"));
        assert!(!err.contains("groups G10 "));
    }

    #[test]
    fn onprem_names_its_own_plane() {
        let text = run(
            &JunosAuthority::SecurityDirectorOnprem,
            AuthoritySource::Declared,
            Some(SECURITY_DIFF),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(text.contains("Security Director On-Prem"));
        assert!(!text.contains("rustsdcmcp"));
    }

    #[test]
    fn detected_source_appears_in_text() {
        let text = run(
            &JunosAuthority::SecurityDirectorCloud,
            AuthoritySource::Detected,
            Some(SECURITY_DIFF),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(text.contains("detected from system services outbound-ssh"));
    }
}

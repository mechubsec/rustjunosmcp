//! Junos command/config policy — thin shim over `mecmcp-policy` (MEC-93).
//!
//! Two authorization models are available for the `commands` and
//! `pfe_commands` domains, chosen once for the whole compiled [`Policy`] via
//! [`mecmcp_policy::CommandMode`]:
//!
//! - **Allowlist (fail-closed, default).** A command is refused unless it is
//!   a whole-token prefix of a configured `allow` entry. Abbreviations are
//!   refused, never expanded. See [`mecmcp_policy::CommandMode::Allowlist`]
//!   for the exact matching rules.
//! - **Blocklist (fail-open, legacy/opt-in).** The pre-MEC-92 behaviour: a
//!   command is refused only if it matches a `deny` glob rule.
//!
//! The `config` domain (used by `load_and_commit_config` et al.) is
//! unaffected by the mode and is always a fail-open deny-pattern blocklist.
//!
//! # Why one `mecmcp_policy::Policy` per device
//!
//! `mecmcp_policy::CommandAllowlist` is a single value per `Policy` instance
//! — `check_command`/`check_pfe_command` under `CommandMode::Allowlist` do
//! not consult the `device` argument at all. To honour the spec's
//! requirement that per-router `allow`/`allowed_pipes` merge with defaults
//! the same way deny rules do, this module compiles one
//! `mecmcp_policy::Policy<Action>` **per device**, each sharing the same
//! `CommandMode` but carrying a device-tailored allowlist (defaults' `allow`
//! ∪ that device's own `allow`, same for `allowed_pipes`; `pfe_allow` and
//! `pfe_allowed_pipes` merge the same way, independently, for the
//! `pfe_commands` domain). Building one global `Policy` whose allowlist was
//! the union of every device's entries was considered and rejected: it
//! would let a command scoped as extra-allowed on device B silently also
//! work on device A, which is a real security regression, not a
//! convenience.
//!
//! The `pfe_commands` domain has its own `pfe_allow`/`pfe_allowed_pipes`
//! config keys (MEC-1303), independent from `commands`' `allow`/
//! `allowed_pipes` — a command allowlisted for `execute_junos_command` is
//! not implicitly allowlisted for `execute_junos_pfe_command` or vice
//! versa. A config with neither key set still fails closed under
//! `CommandMode::Allowlist` (empty allowlist), which was the behavior
//! before this config key existed and remains correct: fail-closed is the
//! safe default for an unconfigured domain.
//!
//! # Deny rules are a carve-out on top of the allowlist (MEC-1096 F1)
//!
//! `mecmcp_policy::Policy::check_command`/`check_pfe_command` never consult
//! the `commands`/`pfe_commands` blocklist once the mode is `Allowlist` — an
//! operator who writes `allow: ["request system"]` plus a
//! `commands: [{deny, "request system reboot*"}]` carve-out would otherwise
//! see the deny silently ignored (a wider hole than no carve-out at all: the
//! operator believes the destructive command is fenced off). `Policy::
//! check_command`/`check_pfe_command` in this module close that gap: an
//! `Allow` from the library's allowlist is re-checked against that device's
//! effective deny rules, which demotes it to `Deny` on a match. See
//! `Policy::check_command`.

use crate::error::JmcpError;
use crate::helpers::excerpt;
use crate::inventory::{Action, CommandModeConfig, RuleSpec};
use std::collections::HashMap;

// Re-export the upstream rule engine primitives and types callers match on.
pub use mecmcp_policy::{
    AllowlistDenyReason, CommandMode, CompiledRule, Decision, RuleSource, count_literal_chars,
    normalize_input,
};

/// Compile a list of `RuleSpec`s into `CompiledRule`s, attaching the given
/// `source` and a scope label used in compile-time error messages.
fn compile_rules(
    rules: &[RuleSpec],
    scope: &str,
    source: RuleSource,
) -> Result<Vec<CompiledRule<Action>>, JmcpError> {
    let pairs: Vec<(Action, String)> = rules
        .iter()
        .map(|r| (r.action, r.pattern.clone()))
        .collect();

    mecmcp_policy::compile_rules(&pairs, scope, source, |scope, pattern, err| {
        JmcpError::BlocklistRuleInvalid {
            scope,
            pattern,
            source: err,
        }
    })
}

/// Compile a list of raw `allow`/`allowed_pipes` strings into
/// `AllowlistEntry`s, attaching `scope` for error messages.
fn compile_allowlist(
    entries: &[String],
    scope: &str,
) -> Result<Vec<mecmcp_policy::AllowlistEntry>, JmcpError> {
    mecmcp_policy::compile_allowlist_entries(entries, scope, |scope, entry, kind| {
        let reason = match kind {
            mecmcp_policy::AllowlistEntryErrorKind::GlobMetachar(c) => format!(
                "contains glob metacharacter '{c}' (allowlist entries are literal \
                 whitespace-token prefixes, never globs)"
            ),
            mecmcp_policy::AllowlistEntryErrorKind::Empty => {
                "is empty or all-whitespace".to_string()
            }
        };
        JmcpError::AllowlistEntryInvalid {
            scope,
            entry,
            reason,
        }
    })
}

/// Compile one domain's defaults ⊕ (optional) single device's rules into a
/// `DomainRules<Action>`. `device` is `Some((name, rules))` for the device
/// this `DomainRules` is being built for; an empty per-device rule list does
/// not get inserted, matching the "empty per-device blocklist should not
/// inflate rule counts" behaviour from before MEC-93.
fn compile_domain_rules(
    defaults: &[RuleSpec],
    device: Option<(&str, &[RuleSpec])>,
    scope_prefix: &str,
) -> Result<mecmcp_policy::DomainRules<Action>, JmcpError> {
    let mut domain = mecmcp_policy::DomainRules {
        defaults: compile_rules(
            defaults,
            &format!("_blocklist_defaults.{scope_prefix}"),
            RuleSource::Defaults,
        )?,
        ..Default::default()
    };
    if let Some((name, rules)) = device
        && !rules.is_empty()
    {
        let compiled = compile_rules(
            rules,
            &format!("device '{name}'.blocklist.{scope_prefix}"),
            RuleSource::Device,
        )?;
        if !compiled.is_empty() {
            domain.device_specific.insert(name.to_string(), compiled);
        }
    }
    Ok(domain)
}

/// Compiled, per-device command/config policy. Built once at startup from
/// the parsed inventory. Internally one [`mecmcp_policy::Policy`] per known
/// device (see module docs for why), plus a defaults-only fallback used for
/// any device name not present at build time.
#[derive(Debug)]
pub struct Policy {
    per_device: HashMap<String, mecmcp_policy::Policy<Action>>,
    /// Defaults-only policy, consulted for a device name that wasn't in the
    /// inventory at build time. Defensive: callers already validate the
    /// device exists (`inventory().get()`) before consulting policy, so this
    /// path should not normally be hit.
    default_policy: mecmcp_policy::Policy<Action>,
    command_mode: CommandMode,
    default_commands_count: usize,
    default_config_count: usize,
    default_pfe_commands_count: usize,
    devices_with_rules: usize,
}

impl Policy {
    /// Compile every glob/allowlist entry in the inventory. Returns the
    /// first compile error encountered, scoped to its source location.
    ///
    /// Also decides the effective [`CommandMode`] (spec item 3, "migration"):
    ///
    /// - `_blocklist_defaults.mode` explicitly set → use it.
    /// - Unset, but `_blocklist_defaults` has any non-empty `commands`,
    ///   `config`, or `pfe_commands` rule list → this is a legacy
    ///   deny-only config; select [`CommandMode::Blocklist`] and log one
    ///   `tracing::warn!` explaining that blocklist mode is fail-open, with
    ///   a pointer to the README migration docs.
    /// - Otherwise (no `_blocklist_defaults` at all, an empty one, or `mode`
    ///   absent with no rules) → [`CommandMode::Allowlist`] (also just
    ///   `CommandMode::default()`).
    pub fn build(inv: &crate::Inventory) -> Result<Self, JmcpError> {
        let defaults = inv.blocklist_defaults();
        let default_commands_specs: &[RuleSpec] =
            defaults.map(|d| d.commands.as_slice()).unwrap_or(&[]);
        let default_config_specs: &[RuleSpec] =
            defaults.map(|d| d.config.as_slice()).unwrap_or(&[]);
        let default_pfe_specs: &[RuleSpec] =
            defaults.map(|d| d.pfe_commands.as_slice()).unwrap_or(&[]);
        let default_allow: &[String] = defaults.map(|d| d.allow.as_slice()).unwrap_or(&[]);
        let default_pipes: &[String] = defaults.map(|d| d.allowed_pipes.as_slice()).unwrap_or(&[]);
        let default_pfe_allow: &[String] = defaults.map(|d| d.pfe_allow.as_slice()).unwrap_or(&[]);
        let default_pfe_pipes: &[String] = defaults
            .map(|d| d.pfe_allowed_pipes.as_slice())
            .unwrap_or(&[]);

        let command_mode = match defaults.and_then(|d| d.mode) {
            Some(CommandModeConfig::Allowlist) => CommandMode::Allowlist,
            Some(CommandModeConfig::Blocklist) => CommandMode::Blocklist,
            None => {
                // "Has deny rules" spans the whole config file, not just
                // `_blocklist_defaults` — a config with no defaults section
                // but a device-level `blocklist.commands` deny rule is still
                // an existing deny-rule config that must keep working
                // fail-open, not suddenly start refusing everything under
                // the new fail-closed default.
                let any_device_has_rules = inv.names().iter().any(|name| {
                    inv.get(name).is_ok_and(|entry| {
                        entry.blocklist.as_ref().is_some_and(|b| {
                            !b.commands.is_empty()
                                || !b.config.is_empty()
                                || !b.pfe_commands.is_empty()
                        })
                    })
                });
                let legacy_deny_only = !default_commands_specs.is_empty()
                    || !default_config_specs.is_empty()
                    || !default_pfe_specs.is_empty()
                    || any_device_has_rules;
                if legacy_deny_only {
                    tracing::warn!(
                        "_blocklist_defaults has deny rules but no explicit `mode` key; \
                         loading as legacy blocklist mode. Blocklist mode is fail-open \
                         (anything not explicitly denied is allowed) and is being phased \
                         out in favor of the fail-closed allowlist mode, which is now the \
                         default for configs that set no rules at all. See README.md, \
                         sections 'Allowlist mode (default)' and 'Blocklist mode (legacy, \
                         opt-in)', for how to migrate to an explicit `mode: allowlist` with \
                         an `allow` list."
                    );
                    CommandMode::Blocklist
                } else {
                    CommandMode::Allowlist
                }
            }
        };

        let mut per_device = HashMap::new();
        let mut devices_with_rules = 0usize;

        for name in inv.names() {
            let entry = inv.get(&name)?;
            let device_bl = entry.blocklist.as_ref();
            let has_own_rules = device_bl.is_some_and(|b| {
                !b.commands.is_empty() || !b.config.is_empty() || !b.pfe_commands.is_empty()
            });
            if has_own_rules {
                devices_with_rules += 1;
            }

            let commands_rules = compile_domain_rules(
                default_commands_specs,
                device_bl.map(|b| (name.as_str(), b.commands.as_slice())),
                "commands",
            )?;
            let config_rules = compile_domain_rules(
                default_config_specs,
                device_bl.map(|b| (name.as_str(), b.config.as_slice())),
                "config",
            )?;
            let pfe_rules = compile_domain_rules(
                default_pfe_specs,
                device_bl.map(|b| (name.as_str(), b.pfe_commands.as_slice())),
                "pfe_commands",
            )?;

            let merged_allow: Vec<String> = default_allow
                .iter()
                .cloned()
                .chain(device_bl.map(|b| b.allow.clone()).unwrap_or_default())
                .collect();
            let merged_pipes: Vec<String> = default_pipes
                .iter()
                .cloned()
                .chain(
                    device_bl
                        .map(|b| b.allowed_pipes.clone())
                        .unwrap_or_default(),
                )
                .collect();
            let allow_entries =
                compile_allowlist(&merged_allow, &format!("device '{name}'.allow"))?;
            let pipe_entries =
                compile_allowlist(&merged_pipes, &format!("device '{name}'.allowed_pipes"))?;

            let merged_pfe_allow: Vec<String> = default_pfe_allow
                .iter()
                .cloned()
                .chain(device_bl.map(|b| b.pfe_allow.clone()).unwrap_or_default())
                .collect();
            let merged_pfe_pipes: Vec<String> = default_pfe_pipes
                .iter()
                .cloned()
                .chain(
                    device_bl
                        .map(|b| b.pfe_allowed_pipes.clone())
                        .unwrap_or_default(),
                )
                .collect();
            let pfe_allow_entries =
                compile_allowlist(&merged_pfe_allow, &format!("device '{name}'.pfe_allow"))?;
            let pfe_pipe_entries = compile_allowlist(
                &merged_pfe_pipes,
                &format!("device '{name}'.pfe_allowed_pipes"),
            )?;

            let commands_domain = mecmcp_policy::CommandDomain {
                blocklist: commands_rules,
                allowlist: mecmcp_policy::CommandAllowlist {
                    entries: allow_entries,
                    allowed_pipes: pipe_entries,
                },
            };
            let pfe_domain = mecmcp_policy::CommandDomain {
                blocklist: pfe_rules,
                allowlist: mecmcp_policy::CommandAllowlist {
                    entries: pfe_allow_entries,
                    allowed_pipes: pfe_pipe_entries,
                },
            };

            let lib_policy =
                mecmcp_policy::Policy::new(command_mode, commands_domain, config_rules, pfe_domain);
            per_device.insert(name.clone(), lib_policy);
        }

        let default_commands_rules =
            compile_domain_rules(default_commands_specs, None, "commands")?;
        let default_config_rules = compile_domain_rules(default_config_specs, None, "config")?;
        let default_pfe_rules = compile_domain_rules(default_pfe_specs, None, "pfe_commands")?;
        let default_allow_entries = compile_allowlist(default_allow, "_blocklist_defaults.allow")?;
        let default_pipe_entries =
            compile_allowlist(default_pipes, "_blocklist_defaults.allowed_pipes")?;
        let default_pfe_allow_entries =
            compile_allowlist(default_pfe_allow, "_blocklist_defaults.pfe_allow")?;
        let default_pfe_pipe_entries =
            compile_allowlist(default_pfe_pipes, "_blocklist_defaults.pfe_allowed_pipes")?;
        let default_policy = mecmcp_policy::Policy::new(
            command_mode,
            mecmcp_policy::CommandDomain {
                blocklist: default_commands_rules,
                allowlist: mecmcp_policy::CommandAllowlist {
                    entries: default_allow_entries,
                    allowed_pipes: default_pipe_entries,
                },
            },
            default_config_rules,
            mecmcp_policy::CommandDomain {
                blocklist: default_pfe_rules,
                allowlist: mecmcp_policy::CommandAllowlist {
                    entries: default_pfe_allow_entries,
                    allowed_pipes: default_pfe_pipe_entries,
                },
            },
        );

        Ok(Self {
            per_device,
            default_policy,
            command_mode,
            default_commands_count: default_commands_specs.len(),
            default_config_count: default_config_specs.len(),
            default_pfe_commands_count: default_pfe_specs.len(),
            devices_with_rules,
        })
    }

    fn policy_for(&self, router: &str) -> &mecmcp_policy::Policy<Action> {
        self.per_device.get(router).unwrap_or(&self.default_policy)
    }

    /// The effective [`CommandMode`] this policy was built with.
    pub fn command_mode(&self) -> CommandMode {
        self.command_mode
    }

    /// Decide whether `command` is allowed on `router`.
    ///
    /// Under [`CommandMode::Allowlist`], an `Allow` from the library's
    /// prefix-match allowlist is still subject to this device's `commands`
    /// deny rules as a carve-out (see module docs / MEC-1096 F1): an
    /// operator who writes `allow: ["request system"]` plus a
    /// `commands: [{deny, "request system reboot*"}]` carve-out expects the
    /// deny to win, but `mecmcp_policy::Policy::check_command` never
    /// consults the blocklist once the mode is `Allowlist`.
    pub fn check_command<'a>(&'a self, router: &str, command: &str) -> Decision<'a, Action> {
        let policy = self.policy_for(router);
        if let Some(decision) = self.deny_disallowed_character(command) {
            return decision;
        }
        let decision = policy.check_command(router, command, Action::Deny);
        self.apply_allowlist_deny_carveout(policy, router, command, decision, |p, d| {
            p.command_rules_for(d)
        })
    }

    /// Decide whether `pfe_command` is allowed on `router`. Independent from
    /// `check_command`. See `check_command`'s docs for the allowlist deny
    /// carve-out.
    pub fn check_pfe_command<'a>(
        &'a self,
        router: &str,
        pfe_command: &str,
    ) -> Decision<'a, Action> {
        let policy = self.policy_for(router);
        if let Some(decision) = self.deny_disallowed_character(pfe_command) {
            return decision;
        }
        let decision = policy.check_pfe_command(router, pfe_command, Action::Deny);
        self.apply_allowlist_deny_carveout(policy, router, pfe_command, decision, |p, d| {
            p.pfe_command_rules_for(d)
        })
    }

    /// Under [`CommandMode::Allowlist`], refuse a command outright unless
    /// every character is printable ASCII or the literal ASCII space
    /// (`' '`) used as the token separator (MEC-1337). Returns `None`
    /// outside [`CommandMode::Allowlist`] and when `raw` is already
    /// entirely printable ASCII plus space.
    fn deny_disallowed_character<'a>(&'a self, raw: &str) -> Option<Decision<'a, Action>> {
        if self.command_mode != CommandMode::Allowlist {
            return None;
        }
        if !raw.chars().any(|c| c != ' ' && !c.is_ascii_graphic()) {
            return None;
        }
        Some(Decision::DenyAllowlist {
            mode: CommandMode::Allowlist,
            reason: AllowlistDenyReason::ForbiddenMetachar,
            normalized: normalize_input(raw),
        })
    }

    /// Under [`CommandMode::Allowlist`], demote an `Allow` decision to
    /// `Deny` if a `commands`/`pfe_commands` deny rule (picked by
    /// `rules_for`) also matches. A no-op under [`CommandMode::Blocklist`]
    /// (the library already consulted those same rules to produce
    /// `decision`) or when `decision` is already a denial.
    fn apply_allowlist_deny_carveout<'a>(
        &'a self,
        policy: &'a mecmcp_policy::Policy<Action>,
        router: &str,
        raw_input: &str,
        decision: Decision<'a, Action>,
        rules_for: impl FnOnce(&'a mecmcp_policy::Policy<Action>, &str) -> Vec<&'a CompiledRule<Action>>,
    ) -> Decision<'a, Action> {
        if self.command_mode != CommandMode::Allowlist || !decision.is_allowed() {
            return decision;
        }
        let rules = rules_for(policy, router);
        let normalized = normalize_input(raw_input);
        match mecmcp_policy::evaluate(&rules, &normalized) {
            Some(rule) if rule.action == Action::Deny => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => decision,
        }
    }

    /// Decide whether `config_text` is allowed on `router` for the given
    /// `config_format`. Returns `Err` if `config_format != "set"` and the
    /// device has any effective config rules. Always a fail-open blocklist;
    /// never returns `Decision::DenyAllowlist`.
    pub fn check_config<'a>(
        &'a self,
        router: &str,
        config_format: &str,
        config_text: &str,
    ) -> Result<Decision<'a, Action>, JmcpError> {
        self.policy_for(router).check_config(
            router,
            config_format,
            config_text,
            Action::Deny,
            "set",
            |format| JmcpError::ConfigFormatNotAllowedWithRules { format },
        )
    }

    /// True if the per-router effective config rule list is non-empty.
    pub fn has_config_rules_for(&self, router: &str) -> bool {
        self.policy_for(router).has_config_rules_for(router)
    }

    /// Counts for the startup info log.
    pub fn rule_counts(&self) -> PolicyCounts {
        PolicyCounts {
            default_commands: self.default_commands_count,
            default_config: self.default_config_count,
            default_pfe_commands: self.default_pfe_commands_count,
            devices_with_rules: self.devices_with_rules,
        }
    }
}

/// Turn a commands/pfe_commands-domain [`Decision`] into `Ok(())` or an
/// audit-ready [`JmcpError`], warn-logging the refusal either way. Shared by
/// every `execute_junos_command`-shaped call site so the three-variant
/// `Decision` match lives in exactly one place — see the module docs on
/// `mecmcp_policy::Decision` for why matching only `Deny` (and treating
/// `DenyAllowlist` as an implicit allow) is a live vulnerability.
pub fn enforce_decision(
    decision: Decision<'_, Action>,
    tool: &'static str,
    router: &str,
    raw_input: &str,
) -> Result<(), JmcpError> {
    match decision {
        Decision::Allow => Ok(()),
        Decision::Deny { rule, source, .. } => {
            let pattern = rule.pattern.clone();
            let source_str = source.as_str();
            tracing::warn!(
                tool,
                router = %router,
                matched_rule = %pattern,
                rule_source = %source_str,
                input_excerpt = %excerpt(raw_input),
                "blocklist denied request",
            );
            Err(JmcpError::Denied {
                tool,
                router: router.to_string(),
                pattern,
                rule_source: source_str,
                input_excerpt: excerpt(raw_input),
                line_number: None,
            })
        }
        Decision::DenyAllowlist {
            reason, normalized, ..
        } => {
            let reason_str = reason.as_str();
            tracing::warn!(
                tool,
                router = %router,
                reason = %reason_str,
                normalized = %normalized,
                "allowlist denied request",
            );
            Err(JmcpError::DeniedAllowlist {
                tool,
                router: router.to_string(),
                reason: reason_str,
                input_excerpt: excerpt(&normalized),
            })
        }
    }
}

/// Summary numbers for startup logging.
///
/// Reports how many rules are active from defaults and how many devices have
/// device-specific overrides. Used to log policy coverage at server boot.
#[derive(Debug, Clone, Copy)]
pub struct PolicyCounts {
    /// Number of default command rules active across all devices.
    pub default_commands: usize,
    /// Number of default config rules active across all devices.
    pub default_config: usize,
    /// Number of default PFE command rules active across all devices.
    pub default_pfe_commands: usize,
    /// Number of devices that have at least one device-specific rule.
    pub devices_with_rules: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn spec(action: Action, pattern: &str) -> RuleSpec {
        RuleSpec {
            action,
            pattern: pattern.into(),
        }
    }

    #[test]
    fn count_literals_handles_wildcards_and_classes() {
        assert_eq!(count_literal_chars("request system reboot"), 21);
        assert_eq!(count_literal_chars("request system *"), 15);
        assert_eq!(count_literal_chars("*"), 0);
        assert_eq!(count_literal_chars("?abc"), 3);
        assert_eq!(count_literal_chars("ab[cd]ef"), 4); // class doesn't count
        assert_eq!(count_literal_chars(r"\*literal"), 8); // escaped * counts as literal
    }

    #[test]
    fn compile_rules_succeeds_on_valid_globs() {
        let r = vec![
            spec(Action::Deny, "request system *"),
            spec(Action::Allow, "show version"),
        ];
        let compiled = compile_rules(&r, "test", RuleSource::Defaults).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].specificity, (15, 16));
        assert_eq!(compiled[0].source, RuleSource::Defaults);
    }

    #[test]
    fn compile_rules_errors_with_scope_on_bad_glob() {
        let r = vec![spec(Action::Deny, "[unterminated")];
        let err =
            compile_rules(&r, "_blocklist_defaults.commands", RuleSource::Defaults).unwrap_err();
        match err {
            JmcpError::BlocklistRuleInvalid { scope, pattern, .. } => {
                assert_eq!(scope, "_blocklist_defaults.commands");
                assert_eq!(pattern, "[unterminated");
            }
            _ => panic!("expected BlocklistRuleInvalid, got {err:?}"),
        }
    }

    #[test]
    fn compile_allowlist_rejects_glob_star() {
        let err = compile_allowlist(&["show *".to_string()], "scope").unwrap_err();
        match err {
            JmcpError::AllowlistEntryInvalid { scope, entry, .. } => {
                assert_eq!(scope, "scope");
                assert_eq!(entry, "show *");
            }
            _ => panic!("expected AllowlistEntryInvalid, got {err:?}"),
        }
    }

    use crate::Inventory;
    use std::io::Write;

    fn inv_from(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    fn build_policy(json: &str) -> Policy {
        Policy::build(&inv_from(json)).unwrap()
    }

    // --- Legacy migration: deny-only config, no `mode` key -> Blocklist + warn ---

    #[derive(Clone, Default)]
    struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for VecWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn legacy_deny_only_config_selects_blocklist_and_warns() {
        let buf = VecWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();

        let inv = inv_from(
            r#"{
                "_blocklist_defaults": {
                    "commands": [{"action":"deny","pattern":"request system *"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let policy = tracing::subscriber::with_default(subscriber, || Policy::build(&inv).unwrap());

        assert_eq!(policy.command_mode(), CommandMode::Blocklist);
        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            logged.contains("legacy blocklist mode"),
            "expected a migration WARN, got: {logged}"
        );
    }

    #[test]
    fn no_blocklist_defaults_selects_allowlist_and_refuses_everything() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        assert_eq!(p.command_mode(), CommandMode::Allowlist);
        assert!(
            !p.check_command("r1", "request system reboot").is_allowed(),
            "empty allowlist must refuse a destructive command"
        );
        assert!(
            !p.check_command("r1", "show version").is_allowed(),
            "empty allowlist must refuse even a benign read"
        );
    }

    #[test]
    fn explicit_mode_allowlist_with_allow_list_permits_exact_prefix_only() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "allow": ["show version"]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(p.check_command("r1", "show version").is_allowed());
        match p.check_command("r1", "sh ver") {
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            } => {}
            other => {
                panic!("expected DenyAllowlist(NotAllowlisted) for abbreviation, got {other:?}")
            }
        }
    }

    #[test]
    fn allowlist_mode_deny_rule_carves_out_of_a_broader_allow_prefix() {
        // MEC-1096 F1: mecmcp_policy::Policy::check_command never consults
        // the blocklist under CommandMode::Allowlist, so a broad `allow`
        // prefix plus an explicit deny carve-out used to silently allow the
        // denied command. Verify the carve-out now wins.
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "allow": ["request system"],
                    "commands": [{"action":"deny","pattern":"request system reboot*"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            p.check_command("r1", "request system software validate")
                .is_allowed(),
            "commands allowed by the prefix but not denied must still be allowed"
        );
        match p.check_command("r1", "request system reboot") {
            Decision::Deny { rule, .. } => assert_eq!(rule.pattern, "request system reboot*"),
            other => panic!("expected Deny (carve-out), got {other:?}"),
        }
    }

    // --- MEC-1303: pfe_commands gets its own allow/allowed_pipes keys ---

    #[test]
    fn no_blocklist_defaults_selects_allowlist_and_refuses_all_pfe_commands() {
        // Pre-fix baseline (MEC-1303): a fresh config with no policy section
        // at all defaults to CommandMode::Allowlist (MEC-93) and, since
        // `pfe_allow` defaults to empty, refuses every PFE command. This is
        // the documented fail-closed regression the issue describes — still
        // correct behavior for an unconfigured domain, just worth pinning so
        // a future change that accidentally widens the default is caught.
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        assert_eq!(p.command_mode(), CommandMode::Allowlist);
        assert!(
            !p.check_pfe_command("r1", "show cos").is_allowed(),
            "empty pfe_allow must refuse even a benign PFE read"
        );
    }

    #[test]
    fn pfe_allow_permits_listed_command_and_refuses_unlisted_with_audit_reason() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "pfe_allow": ["show cos"]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            p.check_pfe_command("r1", "show cos classifier")
                .is_allowed()
        );
        match p.check_pfe_command("r1", "show route") {
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            } => {}
            other => panic!("expected DenyAllowlist(NotAllowlisted), got {other:?}"),
        }
        let decision = p.check_pfe_command("r1", "show route");
        let err = enforce_decision(decision, "execute_junos_pfe_command", "r1", "show route")
            .unwrap_err();
        match err {
            JmcpError::DeniedAllowlist { reason, .. } => assert_eq!(reason, "not_allowlisted"),
            other => panic!("expected DeniedAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn pfe_allow_and_commands_allow_are_independent_domains() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "allow": ["show version"],
                    "pfe_allow": ["show cos"]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            !p.check_pfe_command("r1", "show version").is_allowed(),
            "commands allow must not leak into the pfe_commands domain"
        );
        assert!(
            !p.check_command("r1", "show cos").is_allowed(),
            "pfe_allow must not leak into the commands domain"
        );
    }

    #[test]
    fn per_device_pfe_allow_merges_with_defaults() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","pfe_allow":["show cos"]},
                "r1":{
                    "ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"},
                    "blocklist": {"pfe_allow": ["show route forwarding-table"]}
                },
                "r2":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(p.check_pfe_command("r1", "show cos").is_allowed());
        assert!(
            p.check_pfe_command("r1", "show route forwarding-table")
                .is_allowed()
        );
        assert!(p.check_pfe_command("r2", "show cos").is_allowed());
        assert!(
            !p.check_pfe_command("r2", "show route forwarding-table")
                .is_allowed(),
            "device-scoped pfe_allow must not leak to other devices"
        );
    }

    #[test]
    fn pfe_allowed_pipes_gates_piped_pfe_commands() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "pfe_allow": ["show cos"],
                    "pfe_allowed_pipes": ["match foo"]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            p.check_pfe_command("r1", "show cos | match foo")
                .is_allowed()
        );
        assert!(
            !p.check_pfe_command("r1", "show cos | match bar")
                .is_allowed(),
            "pipe stage not in pfe_allowed_pipes must be refused"
        );
    }

    #[test]
    fn per_device_allow_merges_with_defaults() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","allow":["show version"]},
                "r1":{
                    "ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"},
                    "blocklist": {"allow": ["show interfaces"]}
                },
                "r2":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        // r1 gets both the default and its own addition.
        assert!(p.check_command("r1", "show version").is_allowed());
        assert!(
            p.check_command("r1", "show interfaces ge-0/0/0")
                .is_allowed()
        );
        // r2 only gets the default; the device-scoped addition must not leak.
        assert!(p.check_command("r2", "show version").is_allowed());
        assert!(
            !p.check_command("r2", "show interfaces ge-0/0/0")
                .is_allowed()
        );
    }

    #[test]
    fn per_device_mode_is_rejected_at_load_time() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{
                "r1":{
                    "ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"},
                    "blocklist": {"mode":"blocklist"}
                }
            }"#,
        )
        .unwrap();
        let err = Inventory::load(f.path()).unwrap_err();
        assert!(
            matches!(err, JmcpError::InventoryInvalid(ref s) if s.contains("blocklist.mode")),
            "got {err:?}"
        );
    }

    #[test]
    fn build_merges_defaults_and_device_blocklist_rules() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "blocklist",
                    "commands": [{"action":"deny","pattern":"request system *"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [{"action":"allow","pattern":"request system reboot"}]
                    }
                }
            }"#,
        );
        assert!(p.check_command("r1", "request system reboot").is_allowed());
        assert!(!p.check_command("r1", "request system halt").is_allowed());
    }

    #[test]
    fn whitespace_is_normalized_in_blocklist_mode() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "blocklist",
                    "commands":[{"action":"deny","pattern":"request system reboot"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            !p.check_command("r1", "  request   system\treboot  ")
                .is_allowed()
        );
    }

    #[test]
    fn config_no_rules_allows_any_format() {
        let p = build_policy(
            r#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let r = p.check_config("r1", "xml", "<configuration/>").unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn config_non_set_format_with_rules_present_errors() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let err = p.check_config("r1", "xml", "<x/>").unwrap_err();
        match err {
            JmcpError::ConfigFormatNotAllowedWithRules { format } => {
                assert_eq!(format, "xml");
            }
            other => panic!("expected ConfigFormatNotAllowedWithRules, got {other:?}"),
        }
    }

    #[test]
    fn config_per_line_match_rejects_first_offending_line() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"config":[{"action":"deny","pattern":"delete *"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let payload =
            "set interfaces ge-0/0/0 description ok\ndelete protocols bgp\nset system host-name r1";
        match p.check_config("r1", "set", payload).unwrap() {
            Decision::Deny {
                line_number, rule, ..
            } => {
                assert_eq!(line_number, Some(2));
                assert_eq!(rule.pattern, "delete *");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn config_domain_is_allowlist_mode_agnostic() {
        // config rules are a blocklist regardless of the commands/pfe_commands
        // CommandMode — an allowlist-mode policy must still enforce them.
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "allowlist",
                    "allow": ["show version"],
                    "config":[{"action":"deny","pattern":"delete *"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let r = p.check_config("r1", "set", "delete protocols bgp").unwrap();
        assert!(matches!(r, Decision::Deny { .. }));
    }

    #[test]
    fn build_collects_pfe_commands_from_defaults_and_device_in_blocklist_mode() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "blocklist",
                    "pfe_commands": [{"action":"deny","pattern":"set *"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "pfe_commands": [{"action":"allow","pattern":"set debug *"}]
                    }
                }
            }"#,
        );
        assert!(p.check_pfe_command("r1", "set debug foo").is_allowed());
        assert!(!p.check_pfe_command("r1", "set other").is_allowed());
    }

    #[test]
    fn rule_counts_reports_defaults_and_devices_with_rules() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "blocklist",
                    "commands": [{"action":"deny","pattern":"x"}]
                },
                "r1":{
                    "ip":"1.1.1.1","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {}
                }
            }"#,
        );
        let counts = p.rule_counts();
        assert_eq!(counts.default_commands, 1);
        assert_eq!(counts.default_config, 0);
        assert_eq!(
            counts.devices_with_rules, 0,
            "r1 has empty blocklist; should not count"
        );
    }

    #[test]
    fn unknown_device_falls_back_to_defaults_only_policy() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","allow":["show version"]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        // "ghost" was never in the inventory; must fall back to defaults, not panic.
        assert!(p.check_command("ghost", "show version").is_allowed());
    }

    // --- enforce_decision ---

    #[test]
    fn enforce_decision_allow_is_ok() {
        assert!(enforce_decision(Decision::Allow, "t", "r1", "show version").is_ok());
    }

    #[test]
    fn enforce_decision_deny_allowlist_carries_reason_and_normalized_excerpt() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","allow":["show version"]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let decision = p.check_command("r1", "  sh   ver  ");
        let err =
            enforce_decision(decision, "execute_junos_command", "r1", "  sh   ver  ").unwrap_err();
        match err {
            JmcpError::DeniedAllowlist {
                tool,
                router,
                reason,
                input_excerpt,
            } => {
                assert_eq!(tool, "execute_junos_command");
                assert_eq!(router, "r1");
                assert_eq!(reason, "not_allowlisted");
                assert_eq!(input_excerpt, "sh ver");
            }
            other => panic!("expected DeniedAllowlist, got {other:?}"),
        }
    }

    // --- MEC-1337: disallowed-character fail-closed in allowlist mode ---

    fn allowlist_policy_for_show_version() -> Policy {
        build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","allow":["show version"]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        )
    }

    #[test]
    fn allowlist_mode_allows_plain_ascii_space() {
        let p = allowlist_policy_for_show_version();
        assert!(p.check_command("r1", "show version").is_allowed());
    }

    #[test]
    fn allowlist_mode_denies_nbsp_separator() {
        let p = allowlist_policy_for_show_version();
        let decision = p.check_command("r1", "show\u{00A0}version");
        assert!(!decision.is_allowed());
        match decision {
            Decision::DenyAllowlist { reason, .. } => {
                assert_eq!(reason.as_str(), "forbidden_metachar");
            }
            other => panic!("expected DenyAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_mode_denies_non_ascii_separators() {
        let p = allowlist_policy_for_show_version();
        for sep in ['\u{2000}', '\u{202F}', '\u{3000}', '\u{0085}'] {
            let cmd = format!("show{sep}version");
            assert!(
                !p.check_command("r1", &cmd).is_allowed(),
                "expected deny for separator U+{:04X}",
                sep as u32
            );
        }
    }

    #[test]
    fn allowlist_mode_denies_tab_separator() {
        let p = allowlist_policy_for_show_version();
        assert!(!p.check_command("r1", "show\tversion").is_allowed());
    }

    #[test]
    fn allowlist_mode_denies_control_characters() {
        let p = allowlist_policy_for_show_version();
        for raw in [
            "show\u{0000}version",
            "show\u{001B}version",
            "show\u{007F}version",
        ] {
            assert!(
                !p.check_command("r1", raw).is_allowed(),
                "expected deny for {raw:?}"
            );
        }
    }

    #[test]
    fn allowlist_mode_denies_zero_width_space() {
        let p = allowlist_policy_for_show_version();
        assert!(!p.check_command("r1", "show\u{200B}version").is_allowed());
    }

    #[test]
    fn allowlist_mode_disallowed_character_check_applies_to_pfe_commands_too() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {"mode":"allowlist","pfe_allow":["show cos"]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(p.check_pfe_command("r1", "show cos").is_allowed());
        assert!(!p.check_pfe_command("r1", "show\u{00A0}cos").is_allowed());
    }

    #[test]
    fn blocklist_mode_is_unaffected_by_disallowed_character_check() {
        let p = build_policy(
            r#"{
                "_blocklist_defaults": {
                    "mode": "blocklist",
                    "commands":[{"action":"deny","pattern":"request system reboot"}]
                },
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        assert!(
            !p.check_command("r1", "request\u{00A0}system\u{00A0}reboot")
                .is_allowed()
        );
    }
}

//! `execute_junos_rpc` — call a read-only (`get-*`) RPC the API catalog knows.
//!
//! This must not become a bypass of the command allowlist: the RPC's catalog
//! CLI equivalent plus the validated arguments is checked against the same
//! policy as `execute_junos_command`.

use crate::catalog::{Catalog, Family, Train};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::validate_input_length;
use crate::policy::{BlocklistDomain, Decision, Policy, enforce_decision};
use crate::tools::lookup_api::DeviceTrainCache;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// One RPC argument: `true`/`false` for an `empty`-typed flag, else text.
#[derive(Debug, Clone, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcArgValue {
    /// A flag argument; `false` is the same as leaving it out.
    Flag(bool),
    /// A text argument.
    Text(String),
}

/// Arguments for `execute_junos_rpc`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ExecuteRpcArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// A read-only RPC name starting with `get-`, such as
    /// `get-arp-table-information`. Find names and arguments with `lookup_junos_api`.
    pub rpc: String,
    /// RPC arguments by element name: `true` for an `empty` flag, a string
    /// for the rest. Only arguments the catalog lists for the RPC are accepted.
    #[serde(default)]
    pub args: BTreeMap<String, RpcArgValue>,
    /// RPC timeout in seconds.
    #[serde(default = "super::default_timeout")]
    pub timeout: u64,
}

/// Call a read-only catalog RPC on a device and return its XML reply.
///
/// `commands` receives the CLI strings checked against the policy, for audit.
pub async fn handle(
    args: ExecuteRpcArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    cache: &DeviceTrainCache,
    commands: &mut Vec<String>,
) -> Result<Value, JmcpError> {
    run(Catalog::embedded(), args, dm, policy, cache, commands).await
}

fn invalid(message: String) -> JmcpError {
    JmcpError::Validation(message)
}

/// Whether `value` is safe to send as an element value and echo into the
/// policy string: printable ASCII without XML metacharacters or quotes.
fn text_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| (' '..='~').contains(&c) && !matches!(c, '<' | '>' | '&' | '"' | '\'' | ';'))
}

/// Most text arguments one call may carry: each doubles the policy strings
/// checked (named and positional form).
const MAX_TEXT_ARGS: usize = 6;

/// Whether the catalog CLI is a plain `show` command (not `request`/`clear`).
fn is_show(cli: &str) -> bool {
    cli.starts_with("show ")
}

/// Checks `cli` against the command policy, recording it in `commands`.
fn check_cli(
    policy: &Policy,
    device: &str,
    cli: &str,
    commands: &mut Vec<String>,
) -> Result<(), JmcpError> {
    commands.push(cli.to_owned());
    enforce_decision(
        policy.check_command(device, cli),
        "execute_junos_rpc",
        device,
        cli,
        BlocklistDomain::Commands,
    )
}

pub(crate) async fn run(
    catalog: &Catalog,
    args: ExecuteRpcArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    cache: &DeviceTrainCache,
    commands: &mut Vec<String>,
) -> Result<Value, JmcpError> {
    if !args.rpc.starts_with("get-") {
        return Err(invalid(format!(
            "execute_junos_rpc only runs read-only RPCs whose name starts with `get-`; got {:?}",
            args.rpc
        )));
    }
    // Fail fast on unknown devices before any connection.
    let _ = dm.inventory().get(&args.device)?;

    // Before connecting: the RPC's CLI in every family must be a `show`, and
    // must not already be explicitly denied. Only an explicit deny rule is
    // acted on here; allowlist matching needs the full argument string.
    let newest = Train {
        major: u16::MAX,
        minor: u16::MAX,
    };
    let base_clis: Vec<String> = Family::ALL
        .iter()
        .filter_map(|family| {
            let resolution = catalog.resolve(*family, newest, true);
            catalog
                .rpc(&resolution, &args.rpc)
                .map(|hit| hit.cli.to_string())
        })
        .collect();
    if base_clis.is_empty() {
        return Err(invalid(format!(
            "RPC {:?} is not in the API catalog; use lookup_junos_api to find it",
            args.rpc
        )));
    }
    for base in &base_clis {
        if !is_show(base) {
            return Err(invalid(format!(
                "RPC {:?} is not read-only (CLI equivalent {base:?}); execute_junos_rpc only runs `show` RPCs",
                args.rpc
            )));
        }
        if matches!(
            policy.check_command(&args.device, base),
            Decision::Deny { .. }
        ) {
            check_cli(&policy, &args.device, base, commands)?;
        }
    }

    let (family, train, exact_family) = cache
        .detect(&dm, &args.device, Duration::from_secs(args.timeout))
        .await?;
    let resolution = catalog.resolve(family, train, exact_family);
    let hit = catalog.rpc(&resolution, &args.rpc).ok_or_else(|| {
        invalid(format!(
            "RPC {:?} is not in the {} catalog; use lookup_junos_api to find it",
            args.rpc, resolution.family
        ))
    })?;
    if !is_show(&hit.cli) {
        return Err(invalid(format!(
            "RPC {:?} is not read-only (CLI equivalent {:?}); execute_junos_rpc only runs `show` RPCs",
            args.rpc, &*hit.cli
        )));
    }

    // Validate arguments. Flags are always named in the CLI; text arguments
    // may be positional on the device, so both forms are policy-checked.
    let mut flags = String::new();
    let mut texts: Vec<(&str, &str)> = Vec::new();
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for (name, value) in &args.args {
        let callable =
            |input: &&crate::catalog::RpcInput| !input.name.contains(char::is_whitespace);
        let leaf = hit
            .input
            .iter()
            .find(|input| &*input.name == name.as_str())
            .ok_or_else(|| {
                invalid(format!(
                    "{name:?} is not an argument of {}; accepted: {}",
                    args.rpc,
                    hit.input
                        .iter()
                        .filter(callable)
                        .map(|input| &*input.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        if !callable(&leaf) {
            return Err(invalid(format!(
                "argument {name:?} is not callable via execute_junos_rpc"
            )));
        }
        let is_flag = leaf.type_name.as_deref().is_some_and(|t| t == "empty");
        match value {
            RpcArgValue::Flag(false) => {}
            RpcArgValue::Flag(true) if is_flag => {
                flags.push(' ');
                flags.push_str(name);
                pairs.push((name, ""));
            }
            RpcArgValue::Text(text) if !is_flag => {
                validate_input_length(name, text)?;
                if !text_is_safe(text) {
                    return Err(invalid(format!(
                        "argument {name:?} must be non-empty printable ASCII with no `<`, `>`, `&`, `;` or quotes"
                    )));
                }
                texts.push((name, text));
                pairs.push((name, text));
            }
            _ => {
                return Err(invalid(format!(
                    "argument {name:?} of {} takes {}",
                    args.rpc,
                    if is_flag { "true or false" } else { "a string" }
                )));
            }
        }
    }
    if texts.len() > MAX_TEXT_ARGS {
        return Err(invalid(format!(
            "at most {MAX_TEXT_ARGS} text arguments are accepted per call; got {}",
            texts.len()
        )));
    }

    // Every combination of named/positional forms must be allowed, with the
    // flags both before and after the text values (a positional value usually
    // follows the base command directly). Text order follows the catalog.
    let position = |name: &str| hit.input.iter().position(|input| &*input.name == name);
    texts.sort_by_key(|(name, _)| position(name));
    commands.clear();
    for mask in 0..(1usize << texts.len()) {
        let mut values = String::new();
        for (index, (name, text)) in texts.iter().enumerate() {
            if mask & (1 << index) != 0 {
                values.push(' ');
                values.push_str(name);
            }
            values.push(' ');
            values.push_str(text);
        }
        commands.push(format!("{}{flags}{values}", hit.cli));
        if !flags.is_empty() {
            commands.push(format!("{}{values}{flags}", hit.cli));
        }
    }
    for cli in commands.clone() {
        enforce_decision(
            policy.check_command(&args.device, &cli),
            "execute_junos_rpc",
            &args.device,
            &cli,
            BlocklistDomain::Commands,
        )?;
    }

    let timeout = Duration::from_secs(args.timeout);
    let output = tokio::time::timeout(timeout, async {
        let mut dev = dm.open(&args.device).await?;
        Ok::<_, JmcpError>(dev.rpc()?.call(&args.rpc, &pairs).await?)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))??;

    let warning = resolution
        .warning
        .into_iter()
        .chain((!hit.in_train).then(|| {
            format!(
                "{} is not defined for train {} in the catalog; called anyway using its newest definition",
                args.rpc, resolution.used
            )
        }))
        .collect::<Vec<_>>();
    Ok(json!({
        "device": args.device,
        "rpc": args.rpc,
        "train_used": resolution.used.to_string(),
        "warning": (!warning.is_empty()).then(|| warning.join("; ")),
        "output": output,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Family, Train, fixture_catalog};
    use crate::inventory::Inventory;
    use std::io::Write;

    fn setup(policy_inner: Option<&str>) -> (Arc<DeviceManager>, Arc<Policy>, DeviceTrainCache) {
        let defaults = policy_inner
            .map(|inner| format!(r#""_blocklist_defaults":{{{inner}}},"#))
            .unwrap_or_default();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r#"{{{defaults}"r1":{{"ip":"127.0.0.1","port":1,"username":"u","auth":{{"type":"password","password":"x"}}}}}}"#
        )
        .unwrap();
        let inventory = Arc::new(Inventory::load(file.path()).unwrap());
        let cache = DeviceTrainCache::default();
        // Seeded so no test needs a device for train detection.
        cache.put(
            "r1",
            (
                Family::JunosEs,
                Train {
                    major: 24,
                    minor: 2,
                },
                true,
            ),
        );
        (
            Arc::new(DeviceManager::new(inventory.clone())),
            Arc::new(Policy::build(&inventory).unwrap()),
            cache,
        )
    }

    fn call(rpc: &str, args: &[(&str, RpcArgValue)]) -> ExecuteRpcArgs {
        ExecuteRpcArgs {
            device: "r1".into(),
            rpc: rpc.into(),
            args: args
                .iter()
                .map(|(name, value)| (name.to_string(), value.clone()))
                .collect(),
            timeout: 2,
        }
    }

    /// An allowlist policy over `allow` (a JSON list body), plus extra `inner` JSON.
    fn allow(list: &str) -> Option<String> {
        Some(format!(r#""mode":"allowlist","allow":[{list}]"#))
    }

    async fn run_err(policy_json: Option<String>, args: ExecuteRpcArgs) -> JmcpError {
        run_err_in(&fixture_catalog(), policy_json, args).await.0
    }

    async fn run_err_in(
        catalog: &Catalog,
        policy_json: Option<String>,
        args: ExecuteRpcArgs,
    ) -> (JmcpError, Vec<String>) {
        let (dm, policy, cache) = setup(policy_json.as_deref());
        let mut commands = Vec::new();
        let err = run(catalog, args, dm, policy, &cache, &mut commands)
            .await
            .unwrap_err();
        (err, commands)
    }

    #[tokio::test]
    async fn rpc_rejects_non_get() {
        for rpc in ["clear-arp-table", "request-system-reboot"] {
            let err = run_err(None, call(rpc, &[])).await.to_string();
            assert!(err.contains("get-"), "{err}");
        }
    }

    #[tokio::test]
    async fn rpc_rejects_unknown_arg_and_xml_metachars() {
        let text = |s: &str| RpcArgValue::Text(s.into());
        let err = run_err(
            None,
            call("get-arp-table-information", &[("bogus", text("x"))]),
        )
        .await;
        assert!(err.to_string().contains("not an argument"), "{err}");
        for bad in ["a<b", "a>b", "a&b", "a\"b", "a'b", "a\nb", "a;b", ""] {
            let err = run_err(
                None,
                call("get-arp-table-information", &[("interface", text(bad))]),
            )
            .await;
            assert!(
                err.to_string().contains("printable ASCII"),
                "{bad:?}: {err}"
            );
        }
        // Wrong kind of value for the leaf.
        let err = run_err(
            None,
            call("get-arp-table-information", &[("no-resolve", text("x"))]),
        )
        .await;
        assert!(err.to_string().contains("true or false"), "{err}");
    }

    #[tokio::test]
    async fn rpc_policy_denial_honoured() {
        let err = run_err(
            allow(r#""show version""#),
            call("get-arp-table-information", &[]),
        )
        .await;
        assert!(matches!(err, JmcpError::DeniedAllowlist { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn rpc_policy_sees_args_in_cli() {
        let (err, commands) = run_err_in(
            &fixture_catalog(),
            allow(r#""show version""#),
            call(
                "get-arp-table-information",
                &[("interface", RpcArgValue::Text("ge-0/0/0".into()))],
            ),
        )
        .await;
        assert!(matches!(err, JmcpError::DeniedAllowlist { .. }), "{err:?}");
        assert_eq!(
            commands,
            ["show arp ge-0/0/0", "show arp interface ge-0/0/0"]
        );
    }

    #[tokio::test]
    async fn rpc_positional_form_cannot_bypass_deny_carveout() {
        // `get-log filename=messages` is `show log messages` on the device.
        let policy = Some(
            r#""mode":"allowlist","allow":["show log"],
               "commands":[{"action":"deny","pattern":"show log messages*"}]"#
                .to_string(),
        );
        let (err, commands) = run_err_in(
            Catalog::embedded(),
            policy,
            call(
                "get-log",
                &[("filename", RpcArgValue::Text("messages".into()))],
            ),
        )
        .await;
        assert!(matches!(err, JmcpError::Denied { .. }), "{err:?}");
        assert!(
            commands.contains(&"show log messages".to_string()),
            "{commands:?}"
        );
        assert!(
            commands.contains(&"show log filename messages".to_string()),
            "{commands:?}"
        );
    }

    #[tokio::test]
    async fn rpc_flag_placement_cannot_bypass_deny_carveout() {
        let policy = Some(
            r#""mode":"allowlist","allow":["show interfaces"],
               "commands":[{"action":"deny","pattern":"show interfaces ge-0/0/0*"}]"#
                .to_string(),
        );
        let (err, commands) = run_err_in(
            Catalog::embedded(),
            policy,
            call(
                "get-interface-information",
                &[
                    ("interface-name", RpcArgValue::Text("ge-0/0/0".into())),
                    ("local", RpcArgValue::Flag(true)),
                ],
            ),
        )
        .await;
        assert!(matches!(err, JmcpError::Denied { .. }), "{err:?}");
        assert!(
            commands.contains(&"show interfaces ge-0/0/0 local".to_string()),
            "{commands:?}"
        );
    }

    #[tokio::test]
    async fn rpc_rejects_non_show_get_rpcs_in_real_catalog() {
        for rpc in ["get-jfw-tpm-upgrade", "get-cfmd-clear-context-history"] {
            let (err, _) = run_err_in(Catalog::embedded(), None, call(rpc, &[])).await;
            assert!(err.to_string().contains("not read-only"), "{rpc}: {err}");
        }
    }

    #[tokio::test]
    async fn rpc_rejects_too_many_text_args_non_ascii_and_spaced_leaves() {
        let text = |s: &str| RpcArgValue::Text(s.into());
        let err = run_err(
            None,
            call(
                "get-arp-table-information",
                &[("interface", text("caf\u{e9}"))],
            ),
        )
        .await;
        assert!(err.to_string().contains("printable ASCII"), "{err}");
        let (err, _) = run_err_in(
            Catalog::embedded(),
            None,
            call("get-route-information", &[("output address", text("x"))]),
        )
        .await;
        assert!(err.to_string().contains("not callable"), "{err}");
        let many: Vec<_> = [
            "logname",
            "memory-filename",
            "filename",
            "files-path",
            "pid",
            "thread",
            "remember",
        ]
        .iter()
        .map(|name| (*name, text("x")))
        .collect();
        let (err, _) =
            run_err_in(Catalog::embedded(), None, call("get-shmlog-entries", &many)).await;
        assert!(err.to_string().contains("at most 6"), "{err}");
    }

    #[tokio::test]
    async fn rpc_pre_check_denies_before_connecting() {
        // No cache entry and an unreachable device: a plain deny must win
        // over the connection error.
        let (dm, policy, _) = setup(Some(
            r#""mode":"blocklist","commands":[{"action":"deny","pattern":"show arp*"}]"#,
        ));
        let cache = DeviceTrainCache::default();
        let err = run(
            &fixture_catalog(),
            call("get-arp-table-information", &[]),
            dm,
            policy,
            &cache,
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, JmcpError::Denied { .. }), "{err:?}");
    }

    /// Past the gates the call reaches the (unreachable) device, so the error
    /// is a connection error, never Validation or Denied; and the warning for
    /// an RPC absent from the train is exercised by the catalog fixture.
    #[tokio::test]
    async fn rpc_absent_for_train_warns() {
        assert!(
            !in_train_24_2("get-new-feature-information"),
            "fixture: absent from 24.2"
        );
        assert!(in_train_24_2("get-arp-table-information"));
        let err = run_err(None, call("get-new-feature-information", &[])).await;
        assert!(
            !matches!(err, JmcpError::Validation(_) | JmcpError::Denied { .. }),
            "should proceed to the device: {err:?}"
        );
    }

    fn in_train_24_2(rpc: &str) -> bool {
        let catalog = fixture_catalog();
        let resolution = catalog.resolve(
            Family::JunosEs,
            Train {
                major: 24,
                minor: 2,
            },
            true,
        );
        catalog.rpc(&resolution, rpc).unwrap().in_train
    }
}

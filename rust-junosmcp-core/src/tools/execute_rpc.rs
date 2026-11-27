//! `execute_junos_rpc` — call a read-only (`get-*`) RPC the API catalog knows.
//!
//! This must not become a bypass of the command allowlist: the RPC's catalog
//! CLI equivalent plus the validated arguments is checked against the same
//! policy as `execute_junos_command`.

use crate::catalog::Catalog;
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::validate_input_length;
use crate::policy::{BlocklistDomain, Policy, enforce_decision};
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
pub async fn handle(
    args: ExecuteRpcArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    cache: &DeviceTrainCache,
) -> Result<Value, JmcpError> {
    run(Catalog::embedded(), args, dm, policy, cache).await
}

fn invalid(message: String) -> JmcpError {
    JmcpError::Validation(message)
}

/// Whether `value` is safe to send as an element value and echo into the
/// policy string: no XML metacharacters and no control characters.
fn text_is_safe(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | '&' | '"' | '\''))
}

pub(crate) async fn run(
    catalog: &Catalog,
    args: ExecuteRpcArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    cache: &DeviceTrainCache,
) -> Result<Value, JmcpError> {
    if !args.rpc.starts_with("get-") {
        return Err(invalid(format!(
            "execute_junos_rpc only runs read-only RPCs whose name starts with `get-`; got {:?}",
            args.rpc
        )));
    }
    // Fail fast on unknown devices before any connection.
    let _ = dm.inventory().get(&args.device)?;
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

    // Validate arguments and build the CLI string from catalog text and
    // validated values only; flags set to false are dropped.
    let mut cli = hit.cli.to_string();
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for (name, value) in &args.args {
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
                        .map(|input| &*input.name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        let is_flag = leaf.type_name.as_deref().is_some_and(|t| t == "empty");
        match value {
            RpcArgValue::Flag(false) => {}
            RpcArgValue::Flag(true) if is_flag => {
                cli.push(' ');
                cli.push_str(name);
                pairs.push((name, ""));
            }
            RpcArgValue::Text(text) if !is_flag => {
                validate_input_length(name, text)?;
                if !text_is_safe(text) {
                    return Err(invalid(format!(
                        "argument {name:?} must be non-empty and contain no `<`, `>`, `&`, quotes or control characters"
                    )));
                }
                cli.push(' ');
                cli.push_str(name);
                cli.push(' ');
                cli.push_str(text);
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

    enforce_decision(
        policy.check_command(&args.device, &cli),
        "execute_junos_rpc",
        &args.device,
        &cli,
        BlocklistDomain::Commands,
    )?;

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

    fn setup(allowlist: Option<&str>) -> (Arc<DeviceManager>, Arc<Policy>, DeviceTrainCache) {
        let defaults = allowlist
            .map(|allow| {
                format!(r#""_blocklist_defaults":{{"mode":"allowlist","allow":[{allow}]}},"#)
            })
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

    async fn run_err(allowlist: Option<&str>, args: ExecuteRpcArgs) -> JmcpError {
        let (dm, policy, cache) = setup(allowlist);
        run(&fixture_catalog(), args, dm, policy, &cache)
            .await
            .unwrap_err()
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
        for bad in ["a<b", "a>b", "a&b", "a\"b", "a'b", "a\nb", ""] {
            let err = run_err(
                None,
                call("get-arp-table-information", &[("interface", text(bad))]),
            )
            .await;
            assert!(err.to_string().contains("contain no"), "{bad:?}: {err}");
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
            Some(r#""show version""#),
            call("get-arp-table-information", &[]),
        )
        .await;
        assert!(matches!(err, JmcpError::DeniedAllowlist { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn rpc_policy_sees_args_in_cli() {
        let err = run_err(
            Some(r#""show version""#),
            call(
                "get-arp-table-information",
                &[("interface", RpcArgValue::Text("ge-0/0/0".into()))],
            ),
        )
        .await
        .to_string();
        assert!(err.contains("show arp interface ge-0/0/0"), "{err}");
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

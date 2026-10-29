//! `get_router_list` — return the inventory's router names. Pure, no device contact.

pub use super::GetDeviceListArgs;
use crate::error::JmcpError;
use crate::inventory::{BlocklistRules, Inventory, RuleSpec};
use crate::policy::{BlocklistDomain, CommandMode, RuleSource, rule_location};
use serde_json::{Value, json};
use std::sync::Arc;

/// Return the list of device names visible to the caller (MCP tool handler entry point).
pub async fn handle(inv: Arc<Inventory>) -> Result<Value, JmcpError> {
    handle_names(inv.names()).await
}

/// Serialize names already filtered by the transport's caller scope.
///
/// Does not contact any devices — purely serializes the provided list. The
/// filtering has already happened upstream, typically via the transport's
/// token-scope device mapping.
pub async fn handle_names(names: Vec<String>) -> Result<Value, JmcpError> {
    Ok(json!(names))
}

/// Per-device effective blocklist listing for `get_device_list` with
/// `include_blocklist: true`. `names` is already caller-scope filtered.
///
/// Defaults are listed before device rules; this is a listing, not an
/// evaluation order. Sources come from [`rule_location`] so they match the
/// denial messages. Pure: no device contact.
pub fn handle_blocklist(
    names: Vec<String>,
    inv: &Inventory,
    mode: CommandMode,
) -> Result<Value, JmcpError> {
    let mode = match mode {
        CommandMode::Allowlist => "allowlist",
        CommandMode::Blocklist => "blocklist",
    };
    let defaults = inv.blocklist_defaults();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let device = inv.get(&name)?.blocklist.as_ref();
        let layers = [
            (RuleSource::Defaults, defaults),
            (RuleSource::Device, device),
        ];
        let rules = |domain: BlocklistDomain, pick: fn(&BlocklistRules) -> &Vec<RuleSpec>| {
            layers
                .iter()
                .filter_map(|(source, rules)| Some((source, pick(rules.as_ref()?))))
                .flat_map(|(source, specs)| {
                    let location = rule_location(source.as_str(), &name, domain);
                    specs.iter().map(move |spec| {
                        json!({"action": spec.action, "pattern": spec.pattern, "source": location})
                    })
                })
                .collect::<Vec<_>>()
        };
        let entries = |pick: fn(&BlocklistRules) -> &Vec<String>| {
            layers
                .iter()
                .filter_map(|(source, rules)| Some((source, pick(rules.as_ref()?))))
                .flat_map(|(source, items)| {
                    let location = rule_location(source.as_str(), &name, BlocklistDomain::Commands);
                    items
                        .iter()
                        .map(move |entry| json!({"entry": entry, "source": location}))
                })
                .collect::<Vec<_>>()
        };
        out.push(json!({"name": name, "blocklist": {
            "mode": mode,
            "commands": rules(BlocklistDomain::Commands, |r| &r.commands),
            "config": rules(BlocklistDomain::Config, |r| &r.config),
            "pfe_commands": rules(BlocklistDomain::PfeCommands, |r| &r.pfe_commands),
            "allow": entries(|r| &r.allow),
            "allowed_pipes": entries(|r| &r.allowed_pipes),
        }}));
    }
    Ok(Value::Array(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn returns_sorted_names() {
        let inv = make_inv(
            r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let v = handle(inv).await.unwrap();
        assert_eq!(v, json!(["a", "z"]));
    }

    #[tokio::test]
    async fn filtered_empty_set_is_successful_empty_array() {
        assert_eq!(handle_names(Vec::new()).await.unwrap(), json!([]));
    }

    const BL_INV: &str = r#"{
        "_blocklist_defaults": {
            "mode": "blocklist",
            "commands": [{"action":"deny","pattern":"request system *"}],
            "config": [{"action":"deny","pattern":"delete *"}],
            "allow": ["show version"]
        },
        "a":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"},
             "blocklist":{"commands":[{"action":"allow","pattern":"request system zeroize"}],
                          "pfe_commands":[{"action":"deny","pattern":"show nh *"}],
                          "allowed_pipes":["grep"]}},
        "z":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
    }"#;

    #[test]
    fn args_default_is_false_and_unknown_fields_rejected() {
        let args: GetDeviceListArgs = serde_json::from_str("{}").unwrap();
        assert!(!args.include_blocklist);
        assert!(serde_json::from_str::<GetDeviceListArgs>(r#"{"x":1}"#).is_err());
    }

    #[test]
    fn blocklist_lists_defaults_then_device_rules_with_sources() {
        let inv = make_inv(BL_INV);
        let v = handle_blocklist(inv.names(), &inv, CommandMode::Blocklist).unwrap();
        let a = &v[0];
        assert_eq!(a["name"], "a");
        let bl = &a["blocklist"];
        assert_eq!(bl["mode"], "blocklist");
        assert_eq!(
            bl["commands"],
            json!([
                {"action":"deny","pattern":"request system *","source":"_blocklist_defaults.commands"},
                {"action":"allow","pattern":"request system zeroize","source":"inventory entry 'a'.blocklist.commands"},
            ])
        );
        assert_eq!(
            bl["config"],
            json!([{"action":"deny","pattern":"delete *","source":"_blocklist_defaults.config"}])
        );
        assert_eq!(
            bl["pfe_commands"],
            json!([{"action":"deny","pattern":"show nh *","source":"inventory entry 'a'.blocklist.pfe_commands"}])
        );
        assert_eq!(
            bl["allow"],
            json!([{"entry":"show version","source":"_blocklist_defaults.commands"}])
        );
        assert_eq!(
            bl["allowed_pipes"],
            json!([{"entry":"grep","source":"inventory entry 'a'.blocklist.commands"}])
        );
    }

    #[test]
    fn device_without_blocklist_shows_only_defaults() {
        let inv = make_inv(BL_INV);
        let v = handle_blocklist(inv.names(), &inv, CommandMode::Allowlist).unwrap();
        let z = &v[1];
        assert_eq!(z["name"], "z");
        assert_eq!(z["blocklist"]["mode"], "allowlist");
        assert_eq!(
            z["blocklist"]["commands"],
            json!([{"action":"deny","pattern":"request system *","source":"_blocklist_defaults.commands"}])
        );
        assert_eq!(z["blocklist"]["pfe_commands"], json!([]));
    }

    #[test]
    fn blocklist_respects_caller_scope_names() {
        let inv = make_inv(BL_INV);
        let v = handle_blocklist(vec!["z".into()], &inv, CommandMode::Blocklist).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["name"], "z");
    }
}

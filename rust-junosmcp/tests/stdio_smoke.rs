#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Spawn the `rust-junosmcp` binary, send MCP `initialize` + `tools/list` over
//! stdin, parse responses on stdout, and assert the exact configured tool set.

mod common;
use common::{BoundedLines, binary_path};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

const JUNOS_TOOLS: &[&str] = &[
    // `get_device_list` is canonical; `get_router_list` is the deprecated alias
    // kept so existing clients keep working. Both are advertised, so both belong
    // here. This list is deliberately a second copy of the one in
    // `rust_junosmcp_auth::JUNOS_TOOLS` — it exists to catch that crate being
    // wrong, so do not collapse it into an import.
    "get_device_list",
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "commit_check_config",
    "discard_candidate",
    "rollback_config",
    "confirm_commit",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",
    "reload_devices",
    "transfer_file",
    "fetch_file",
    "list_staged_files",
    "upgrade_junos",
    // Phase 5: two-person change control on Junos.
    "create_junos_change_set",
    "approve_junos_change_set",
    "apply_junos_change_set",
    "confirm_junos_change_set",
    "cancel_junos_change_set",
    "get_junos_change_set_status",
    "list_junos_change_sets",
    "get_junos_candidate_fingerprint",
];

#[cfg(feature = "srx")]
const SRX_TOOLS: &[&str] = &[
    "srxmcp_status",
    "get_chassis_cluster_status",
    "get_srx_security_services_status",
    "check_srx_feature_license",
    "vpn_lifecycle_report",
    "srx_list_policies",
    "srx_resolve_address",
    "srx_resolve_application",
    "srx_list_nat_rules",
    "manage_idp_security_package",
    "manage_appid_signature_package",
    "validate_chassis_cluster_health",
    "collect_jtac_support_bundle",
    "srx_flow_sessions",
    "srx_policy_match",
];

#[test]
fn lists_expected_tools() {
    // Build first so the binary exists.
    common::ensure_built();

    // Empty inventory file is enough for `tools/list`.
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();
    let device_lease_dir = tempfile::tempdir().unwrap();

    let mut child = Command::new(binary_path())
        .args([
            "-f",
            inv.path().to_str().unwrap(),
            "-t",
            "stdio",
            "--device-lease-dir",
            device_lease_dir.path().to_str().unwrap(),
            "--state-file",
            device_lease_dir
                .path()
                .join("changeset-state.json")
                .to_str()
                .unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();

    // MCP framing is JSON-RPC delimited by newlines.
    fn send(stdin: &mut impl Write, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "smoke", "version": "0.1" }
            }
        }),
    );
    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        }),
    );
    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        }),
    );

    // Read until we see the tools/list response, bounded on a worker thread.
    // A deadline checked between `read_line` calls cannot fire: the response
    // never arriving is precisely what leaves `read_line` blocked, so control
    // never returns to the check and the test hangs instead of failing (#281).
    use std::io::BufReader;
    let lines = BoundedLines::spawn(BufReader::new(stdout));
    let tools_response: Option<Value> = lines
        .wait_for_line(Duration::from_secs(15), |line| {
            serde_json::from_str::<Value>(line.trim()).is_ok_and(|v| v.get("id") == Some(&json!(2)))
        })
        .map(|line| serde_json::from_str(line.trim()).expect("jsonrpc response"));

    let _ = child.kill();
    let _ = child.wait();
    let resp = tools_response.expect("did not receive tools/list response within 15s");
    let tools = resp
        .pointer("/result/tools")
        .expect("missing /result/tools")
        .as_array()
        .unwrap();
    let names: HashSet<&str> = tools
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap())
        .collect();
    let concrete_operations: HashSet<&str> = JUNOS_TOOLS.iter().copied().collect();
    #[cfg(feature = "srx")]
    let concrete_operations: HashSet<&str> = concrete_operations
        .into_iter()
        .chain(SRX_TOOLS.iter().copied())
        .collect();
    let expected: HashSet<&str> = concrete_operations
        .iter()
        .copied()
        .chain(["execute"])
        .collect();
    assert_eq!(names, expected);
    let execute = tools
        .iter()
        .find(|tool| tool["name"] == "execute")
        .expect("exactly one execute facade");
    assert_eq!(
        tools
            .iter()
            .filter(|tool| tool["name"] == "execute")
            .count(),
        1
    );
    let facade_operations: HashSet<&str> = execute
        .pointer("/inputSchema/properties/operation/enum")
        .and_then(Value::as_array)
        .expect("execute operation enum")
        .iter()
        .map(|operation| operation.as_str().expect("operation name"))
        .collect();
    assert_eq!(facade_operations, concrete_operations);
    // 28 / 19 before Phase 5; the change-set tools added four,
    // `confirm_junos_change_set` adds one more (#239),
    // `list_junos_change_sets` adds one more (#255), and
    // `cancel_junos_change_set` adds one more (#293), then execute adds one.
    // MEC-54's four SRX policy-read tools add four more, and
    // `srx_flow_sessions` + `srx_policy_match` add two more (MEC-55), and
    // `confirm_commit` adds one more (MEC-45).
    #[cfg(feature = "srx")]
    assert_eq!(names.len(), 44);
    #[cfg(not(feature = "srx"))]
    assert_eq!(names.len(), 29);
}

#[cfg(feature = "srx")]
#[test]
fn srx_status_allows_stdio_even_when_a_token_file_is_loaded() {
    let inventory = common::write_inv("{}");
    let tokens = common::write_tokens(r#"{"version":1,"tokens":[]}"#);
    let mut server = common::spawn_stdio_server_with_args(&[
        "--device-mapping",
        inventory.path().to_str().unwrap(),
        "--tokens-file",
        tokens.path().to_str().unwrap(),
    ]);
    let result = common::call_tool(&mut server, "srxmcp_status", json!({}));
    assert_eq!(result["endpoint"], "srxmcp");
}

#[test]
fn denied_command_returns_tool_error() {
    common::ensure_built();

    // Inventory with a deny rule and one (unreachable) device. The deny
    // short-circuits before any connection attempt, so unreachability is fine.
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        inv.path(),
        r#"{
            "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    )
    .unwrap();
    let device_lease_dir = tempfile::tempdir().unwrap();

    let mut child = Command::new(binary_path())
        .args([
            "-f",
            inv.path().to_str().unwrap(),
            "-t",
            "stdio",
            "--device-lease-dir",
            device_lease_dir.path().to_str().unwrap(),
            "--state-file",
            device_lease_dir
                .path()
                .join("changeset-state.json")
                .to_str()
                .unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();

    fn send(stdin: &mut impl Write, msg: &Value) {
        let line = serde_json::to_string(msg).unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    send(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":"2025-03-26","capabilities":{},
                "clientInfo":{"name":"smoke","version":"0.1"}
            }
        }),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{
                "name":"execute_junos_command",
                "arguments":{
                    "router_name":"r1",
                    "command":"request system reboot",
                    "timeout":1
                }
            }
        }),
    );

    // Bounded on a worker thread; see the note at the tools/list read above.
    use std::io::BufReader;
    let lines = BoundedLines::spawn(BufReader::new(stdout));
    let response: Option<Value> = lines
        .wait_for_line(Duration::from_secs(15), |line| {
            serde_json::from_str::<Value>(line.trim()).is_ok_and(|v| v.get("id") == Some(&json!(2)))
        })
        .map(|line| serde_json::from_str(line.trim()).expect("jsonrpc response"));

    let _ = child.kill();
    let _ = child.wait();

    let resp = response.expect("did not receive tools/call response within 15s");
    // rmcp surfaces tool errors as a CallToolResult with `isError: true` and
    // text content; assert both shape and message content.
    let result = resp.pointer("/result").expect("missing /result");
    assert_eq!(result.get("isError"), Some(&json!(true)));
    let body = serde_json::to_string(result).unwrap();
    assert!(
        body.contains("denied by blocklist"),
        "expected denial message in: {body}"
    );
    assert!(
        body.contains("request system *"),
        "expected matched-rule pattern in: {body}"
    );
}

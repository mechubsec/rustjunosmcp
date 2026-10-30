#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! End to end: an SRX workflow RPC error settles the audit exactly once and
//! reaches the client as a coded `outcome_unknown` result, with no extra
//! `dispatch_rejected` record from `call_tool`. A Junos tool is covered too:
//! device error text must be redacted in the audit `error` field.
mod common;

use common::fake_netconf::{FakeNetconf, OK, client_key_pem, rpc_error};
use common::{write_inventory_temp, write_restricted};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const VERSION_REPLY: &str = "<software-information><host-name>fake</host-name><product-model>fake-srx</product-model></software-information>";
const FAKE_PSK: &str = "FAKEpsk123";

const FACTS: [(&str, &str); 2] = [
    (
        "get-chassis-inventory",
        "<chassis-inventory><chassis><serial-number>FAKE1</serial-number></chassis></chassis-inventory>",
    ),
    (
        "get-route-engine-information",
        "<route-engine-information><route-engine><slot>0</slot></route-engine></route-engine-information>",
    ),
];

/// Run one `tools/call` against the real binary and a scripted fake device;
/// return the raw reply line and everything the server wrote to stderr.
fn run_tool(
    first_rpcs: Vec<(&'static str, String)>,
    tool: &str,
    arguments: &str,
) -> (String, String) {
    common::ensure_built();
    let mut script = first_rpcs;
    script.push(("get-software-information", VERSION_REPLY.to_string()));
    for (needle, reply) in FACTS {
        script.push((needle, reply.to_string()));
    }
    script.push(("close-session", OK.to_string()));
    let fake = FakeNetconf::start(script);
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    write_restricted(&key, &client_key_pem());
    let known_hosts = dir.path().join("known_hosts");
    write_restricted(&known_hosts, fake.known_hosts_line());
    let inventory = write_inventory_temp(&[(
        "fake",
        "127.0.0.1",
        fake.port,
        "netconf",
        key.to_str().unwrap(),
    )]);

    let mut child = Command::new(common::binary_path())
        .args(["-t", "stdio", "--device-lease-dir"])
        .arg(dir.path())
        .arg("--state-file")
        .arg(dir.path().join("changeset-state.json"))
        .args(["-f", inventory.path().to_str().unwrap()])
        .args(["--known-hosts-file", known_hosts.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"{tool}","arguments":{arguments}}}}}"#
    );
    for line in [
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        call.as_str(),
    ] {
        writeln!(stdin, "{line}").unwrap();
    }
    stdin.flush().unwrap();
    // Keep stdin open until the reply is read: EOF would cancel the call.
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let response = loop {
        let mut line = String::new();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0, "no reply");
        if line.contains("\"id\":2") {
            break line;
        }
    };
    drop(stdin);
    let _ = child.wait();
    let stderr_text = stderr_reader.join().unwrap();

    (response, stderr_text)
}

#[test]
fn cluster_status_rpc_error_is_one_settled_record_and_coded() {
    let message = format!("bad config: pre-shared-key ascii-text \"{FAKE_PSK}\"");
    let (response, stderr_text) = run_tool(
        vec![("get-chassis-cluster-status", rpc_error(&message))],
        "get_chassis_cluster_status",
        r#"{"router":"fake"}"#,
    );
    let reply: serde_json::Value = serde_json::from_str(response.trim()).unwrap();
    let body = &reply["result"]["structuredContent"];
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(body["code"], "outcome_unknown", "{reply}");
    assert_eq!(body["retryable"], false, "{reply}");
    assert!(!response.contains(FAKE_PSK), "client body leaked the key");

    let audits: Vec<&str> = stderr_text
        .lines()
        .filter(|line| line.contains("tool") && line.contains("get_chassis_cluster_status"))
        .collect();
    assert_eq!(audits.len(), 1, "audit lines: {audits:#?}");
    let line = audits[0];
    assert!(line.contains("error_kind=transport "), "{line}");
    assert!(!line.contains("unsettled"), "{line}");
    assert!(!line.contains("dispatch_rejected"), "{line}");
    assert!(!stderr_text.contains("dispatch_rejected"), "{stderr_text}");
    assert!(!stderr_text.contains(FAKE_PSK), "audit leaked the key");
}

#[test]
fn junos_tool_audit_error_text_is_redacted() {
    let message = format!("bad: pre-shared-key ascii-text \"{FAKE_PSK}\"");
    // The facts probe at session open fails first, so the Junos handler's
    // device-open failure path writes the audit error text.
    let (response, stderr_text) = run_tool(
        vec![("get-software-information", rpc_error(&message))],
        "gather_device_facts",
        r#"{"router_name":"fake"}"#,
    );
    assert!(response.contains("\"isError\":true"), "{response}");
    let audits: Vec<&str> = stderr_text
        .lines()
        .filter(|line| line.contains("tool=gather_device_facts"))
        .collect();
    assert_eq!(audits.len(), 1, "audit lines: {audits:#?}");
    assert!(audits[0].contains("result=error"), "{}", audits[0]);
    assert!(!stderr_text.contains(FAKE_PSK), "audit leaked the key");
    assert!(!response.contains(FAKE_PSK), "client body leaked the key");
}

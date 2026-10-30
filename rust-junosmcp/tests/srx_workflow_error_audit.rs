#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! End to end: an SRX workflow RPC error settles the audit exactly once and
//! reaches the client as a coded `outcome_unknown` result, with no extra
//! `dispatch_rejected` record from `call_tool`.
mod common;

use common::fake_netconf::{FakeNetconf, OK, client_key_pem, rpc_error};
use common::{write_inventory_temp, write_restricted};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const VERSION_REPLY: &str = "<software-information><host-name>fake</host-name><product-model>fake-srx</product-model></software-information>";
const FAKE_PSK: &str = "FAKEpsk123";

#[test]
fn cluster_status_rpc_error_is_one_settled_record_and_coded() {
    common::ensure_built();
    let message = format!("bad config: pre-shared-key ascii-text \"{FAKE_PSK}\"");
    let fake = FakeNetconf::start(vec![
        ("get-chassis-cluster-status", rpc_error(&message)),
        ("get-software-information", VERSION_REPLY.to_string()),
        (
            "get-chassis-inventory",
            "<chassis-inventory><chassis><serial-number>FAKE1</serial-number></chassis></chassis-inventory>".to_string(),
        ),
        (
            "get-route-engine-information",
            "<route-engine-information><route-engine><slot>0</slot></route-engine></route-engine-information>".to_string(),
        ),
        ("close-session", OK.to_string()),
    ]);
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
    for line in [
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_chassis_cluster_status","arguments":{"router":"fake"}}}"#,
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

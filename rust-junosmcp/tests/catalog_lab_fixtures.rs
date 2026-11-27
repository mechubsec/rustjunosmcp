#![allow(clippy::unwrap_used, missing_docs)]
//! Offline replay of lab captures: the RPC name a bench device reported for
//! `show version | display xml rpc` (redacted, see
//! `scripts/catalog/verify_lab.py`) is accepted by `execute_junos_rpc`.
//! Real `display xml` replies cannot be captured through the bench server (it
//! ignores that pipe), so no reply root is checked against the device.
mod common;

use common::fake_netconf::{FakeNetconf, OK, client_key_pem};
use common::{call_tool, spawn_stdio_server_with_protocol, write_restricted};
use serde_json::{Value, json};

/// (fixture file, product model, release) per catalog family. Hardcoded: the
/// fixture's xmlns carries only the release, and the model is not in the capture.
const FIXTURES: &[(&str, &str, &str)] = &[
    (
        "junos-ex-display-xml-rpc-show-version.xml",
        "EX2300-C-12P",
        "23.4R2-S2.1",
    ),
    (
        "junos-es-display-xml-rpc-show-version.xml",
        "SRX1600",
        "25.4R1.12",
    ),
];

fn rpc_name(fixture: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/catalog-lab/{fixture}",
        env!("CARGO_MANIFEST_DIR")
    );
    let xml = std::fs::read_to_string(path).unwrap();
    let after_wrapper = xml.split_once('>').unwrap().1;
    let start = after_wrapper.find('<').unwrap() + 1;
    after_wrapper[start..]
        .split(|c: char| c == '>' || c == '/' || c.is_whitespace())
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn lab_captured_rpc_name_is_accepted_by_execute_junos_rpc() {
    for (fixture, model, release) in FIXTURES {
        let rpc = rpc_name(fixture);
        assert_eq!(rpc, "get-software-information", "{fixture}");
        let version = format!(
            "<software-information><host-name>bench-fake</host-name><product-model>{model}</product-model><junos-version>{release}</junos-version></software-information>"
        );
        let fake = FakeNetconf::start(vec![
            ("get-software-information", version),
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
        let inventory = common::write_inventory_temp(&[(
            "fake",
            "127.0.0.1",
            fake.port,
            "netconf",
            key.to_str().unwrap(),
        )]);
        // Commands are fail-closed; allow the CLI form of the RPC.
        let mut devices: Value =
            serde_json::from_slice(&std::fs::read(inventory.path()).unwrap()).unwrap();
        devices["_blocklist_defaults"] = json!({ "mode": "allowlist", "allow": ["show version"] });
        std::fs::write(inventory.path(), devices.to_string()).unwrap();
        let mut server = spawn_stdio_server_with_protocol(
            &[
                "-f",
                inventory.path().to_str().unwrap(),
                "--known-hosts-file",
                known_hosts.to_str().unwrap(),
            ],
            "2025-06-18",
        );
        let resp: Value = call_tool(
            &mut server,
            "execute_junos_rpc",
            json!({ "device": "fake", "rpc": rpc }),
        );
        assert_ne!(resp.get("isError"), Some(&json!(true)), "{fixture}: {resp}");
        assert_eq!(resp["rpc"], rpc, "{resp}");
        let output = resp["output"].as_str().unwrap();
        assert!(
            output.contains("<software-information"),
            "{fixture}: {resp}"
        );
    }
}

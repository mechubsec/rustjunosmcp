#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! The plane guard end to end through the real binary against a loopback fake
//! NETCONF device: authority is declared or detected from the outbound-ssh
//! stanza, and a refusal never reaches the commit while the revert and unlock
//! still happen.
mod common;

use common::fake_netconf::{FakeNetconf, OK, Script, client_key_pem};
use common::{StdioChild, call_tool, spawn_stdio_server_with_protocol, write_restricted};
use serde_json::{Value, json};

const MIST_STANZA: &str =
    "<output>\nclient mist {\n    device-conn-retry 5;\n    services netconf;\n}</output>";
const SDC_STANZA: &str = "<output>\nclient EMS-srx.sdcloud.juniperclouds.net {\n    \
    srx.sdcloud.juniperclouds.net port 7804;\n    services netconf;\n}</output>";
const NO_STANZA: &str = "<output></output>";

fn diff_reply(diff: &str) -> String {
    format!(
        "<configuration-information><configuration-output>{diff}</configuration-output></configuration-information>"
    )
}

/// Open-session facts replies, then the config RPCs a candidate transaction
/// sends. Anything else is an `<rpc-error>`, so a surprise RPC fails loudly.
fn script(outbound_ssh_reply: &str, diff: &str) -> Script {
    vec![
        ("outbound-ssh", outbound_ssh_reply.to_string()),
        ("compare=\"rollback\"", diff_reply(diff)),
        ("<nc:lock>", OK.to_string()),
        ("<nc:unlock>", OK.to_string()),
        ("<nc:load-configuration", OK.to_string()),
        ("<nc:commit", OK.to_string()),
        (
            "get-software-information",
            "<software-information><host-name>fake</host-name><product-model>fake-srx</product-model></software-information>".to_string(),
        ),
        (
            "get-chassis-inventory",
            "<chassis-inventory><chassis><serial-number>FAKE1</serial-number></chassis></chassis-inventory>".to_string(),
        ),
        (
            "get-route-engine-information",
            "<route-engine-information><route-engine><slot>0</slot></route-engine></route-engine-information>".to_string(),
        ),
        ("close-session", OK.to_string()),
    ]
}

/// Spawn the binary with the fake as its only device; `authority` is the
/// declared `config_authority` (None leaves it `unknown`).
fn start(
    script: Script,
    authority: Option<&str>,
    extra_args: &[&str],
) -> (FakeNetconf, StdioChild, tempfile::TempDir) {
    let fake = FakeNetconf::start(script);
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    write_restricted(&key, &client_key_pem());
    let known_hosts = dir.path().join("known_hosts");
    write_restricted(&known_hosts, fake.known_hosts_line());
    let mut device = json!({
        "ip": "127.0.0.1",
        "port": fake.port,
        "username": "netconf",
        "auth": { "type": "ssh_key", "private_key_path": key.to_str().unwrap() },
    });
    if let Some(authority) = authority {
        device["config_authority"] = json!(authority);
    }
    let inventory = dir.path().join("devices.json");
    write_restricted(&inventory, &json!({ "fake": device }).to_string());
    let mut args = vec![
        "-f",
        inventory.to_str().unwrap(),
        "--known-hosts-file",
        known_hosts.to_str().unwrap(),
        "--allow-direct-commit",
    ];
    args.extend_from_slice(extra_args);
    let server = spawn_stdio_server_with_protocol(&args, "2025-06-18");
    (fake, server, dir)
}

fn load_and_commit(server: &mut StdioChild) -> Value {
    call_tool(
        server,
        "load_and_commit_config",
        json!({ "device": "fake", "config_text": "set system host-name x", "config_format": "set" }),
    )
}

fn position(requests: &[String], needle: &str) -> usize {
    requests
        .iter()
        .position(|request| request.contains(needle))
        .unwrap_or_else(|| panic!("never sent {needle}: {requests:?}"))
}

const SECURITY_DIFF: &str = "[edit security nat source]\n+   rule-set rs1;";
const INTERFACE_DIFF: &str = "[edit interfaces ge-0/0/0]\n+   description x;";

#[test]
fn detected_mist_is_refused_before_any_lock_or_load() {
    let (fake, mut server, _dir) = start(script(MIST_STANZA, INTERFACE_DIFF), None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("plan_mist_change"), "{resp}");
    assert!(fake.saw("outbound-ssh"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:lock>"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:load-configuration"), "{:?}", fake.requests());
}

#[test]
fn declared_sdc_security_diff_is_refused_reverted_and_unlocked() {
    let (fake, mut server, _dir) = start(
        script(NO_STANZA, SECURITY_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("prepare_sdc_nat_write"), "{resp}");
    let requests = fake.requests();
    // Declared authority wins: the device is never asked.
    assert!(!fake.saw("outbound-ssh"), "{requests:?}");
    assert!(!fake.saw("<nc:commit"), "{requests:?}");
    let diff = position(&requests, "compare=\"rollback\"");
    let revert = position(&requests, r#"<nc:load-configuration rollback="0"/>"#);
    let unlock = position(&requests, "<nc:unlock>");
    assert!(diff < revert && revert < unlock, "{requests:?}");
}

#[test]
fn declared_sdc_interface_diff_commits() {
    let (fake, mut server, _dir) = start(
        script(NO_STANZA, INTERFACE_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp["success"], json!(true), "{resp}");
    assert!(resp.get("warning").is_none(), "{resp}");
    assert!(fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn detected_sdc_security_diff_is_refused_and_says_how_it_was_detected() {
    let (fake, mut server, _dir) = start(script(SDC_STANZA, SECURITY_DIFF), None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(
        resp.to_string()
            .contains("detected from system services outbound-ssh"),
        "{resp}"
    );
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn allow_flag_turns_the_mist_refusal_into_a_warning() {
    let (fake, mut server, _dir) = start(
        script(MIST_STANZA, INTERFACE_DIFF),
        None,
        &["--allow-plane-owned-writes"],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp["success"], json!(true), "{resp}");
    assert!(
        resp["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("overwritten and erased")),
        "{resp}"
    );
    assert!(fake.saw("<nc:commit"), "{:?}", fake.requests());
}

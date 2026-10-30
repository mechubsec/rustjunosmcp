#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! End-to-end through the real binary against a loopback fake NETCONF device
//! (`common::fake_netconf`): a read succeeds, a refused lock and a failed
//! commit surface as coded errors and never as success.
mod common;

use common::fake_netconf::{FakeNetconf, OK, Script, client_key_pem, rpc_error};
use common::{StdioChild, call_tool, spawn_stdio_server_with_protocol, write_restricted};
use serde_json::{Value, json};

const VERSION_REPLY: &str = "<software-information><host-name>fake</host-name><product-model>fake-srx</product-model></software-information>";

/// What opening a session asks for (facts gathering), then `rest`.
fn script(rest: Script) -> Script {
    let mut table: Script = vec![
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
    ];
    table.splice(0..0, rest);
    table
}

/// Spawn the binary (2025-06-18, so errors carry `structuredContent`) with
/// the fake as its only device, trusted via `--known-hosts-file`.
fn start(script: Script) -> (FakeNetconf, StdioChild, tempfile::TempDir) {
    let fake = FakeNetconf::start(script);
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
    let server = spawn_stdio_server_with_protocol(
        &[
            "-f",
            inventory.path().to_str().unwrap(),
            "--known-hosts-file",
            known_hosts.to_str().unwrap(),
            "--allow-direct-commit",
        ],
        "2025-06-18",
    );
    (fake, server, dir)
}

fn load_and_commit(server: &mut StdioChild) -> Value {
    call_tool(
        server,
        "load_and_commit_config",
        json!({ "device": "fake", "config_text": "set system host-name x", "config_format": "set" }),
    )
}

fn assert_error(resp: &Value) {
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    let body = resp.get("structuredContent").expect("coded error body");
    assert!(body["code"].is_string(), "{resp}");
}

#[test]
fn read_tool_succeeds_against_the_fake() {
    let (fake, mut server, _dir) = start(script(vec![]));
    let resp = call_tool(
        &mut server,
        "gather_device_facts",
        json!({ "router_name": "fake" }),
    );
    assert_ne!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("fake-srx"), "{resp}");
    assert!(
        fake.saw("get-software-information"),
        "{:?}",
        fake.requests()
    );
}

#[test]
fn refused_lock_is_an_error_and_nothing_is_committed() {
    let (fake, mut server, _dir) = start(script(vec![
        // An undeclared device is probed for its managing plane before locking.
        ("outbound-ssh", "<output></output>".to_string()),
        ("<nc:lock>", rpc_error("configuration database locked")),
        ("<nc:unlock", OK.to_string()),
        ("discard", OK.to_string()),
    ]));
    let resp = load_and_commit(&mut server);
    assert_error(&resp);
    let body = &resp["structuredContent"];
    // Conservative: an rpc-error mid-workflow is not classed as retryable.
    assert_eq!(body["code"], "outcome_unknown", "{resp}");
    assert_eq!(body["retryable"], false, "{resp}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|message| message.contains("configuration database locked")),
        "{resp}"
    );
    assert!(
        fake.saw("<nc:lock>"),
        "never reached the lock: {:?}",
        fake.requests()
    );
    assert!(
        !fake.saw("<nc:commit"),
        "commit sent after refused lock: {:?}",
        fake.requests()
    );
}

#[test]
fn commit_rpc_error_is_an_error() {
    let (fake, mut server, _dir) = start(script(vec![
        ("<nc:commit>", rpc_error("commit failed: fake")),
        ("", OK.to_string()),
    ]));
    let resp = load_and_commit(&mut server);
    // This path reports failure in the tool result body, not as `isError`.
    assert_eq!(resp["success"], json!(false), "{resp}");
    assert!(resp.to_string().contains("commit failed: fake"), "{resp}");
    // The failed commit is cleaned up: candidate rolled back, then unlocked.
    let requests = fake.requests();
    let position = |needle: &str| {
        requests
            .iter()
            .position(|request| request.contains(needle))
            .unwrap_or_else(|| panic!("never sent {needle}: {requests:?}"))
    };
    let commit = position("<nc:commit>");
    let rollback = position(r#"<nc:load-configuration rollback="0"/>"#);
    let unlock = position("<nc:unlock>");
    assert!(commit < rollback && rollback < unlock, "{requests:?}");
}

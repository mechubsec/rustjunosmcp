#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Coded tool errors carry `structuredContent` only for peers that negotiated
//! 2025-06-18 or later; an older peer gets the text block alone.
mod common;

use common::{
    call_tool, spawn_stdio_server_with_protocol, write_fake_netconf_key_temp, write_inventory_temp,
};
use serde_json::{Value, json};

fn unknown_router_error(protocol_version: &str) -> Value {
    let key = write_fake_netconf_key_temp();
    let inv = write_inventory_temp(&[(
        "vsrx-test10",
        "192.0.2.1",
        830,
        "admin",
        key.path().to_str().unwrap(),
    )]);
    let mut server =
        spawn_stdio_server_with_protocol(&["-f", inv.path().to_str().unwrap()], protocol_version);
    let resp = call_tool(
        &mut server,
        "gather_device_facts",
        json!({ "router_name": "does-not-exist" }),
    );
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(
        resp.to_string().contains("not found in device mapping"),
        "{resp}"
    );
    resp
}

#[test]
fn structured_error_body_reaches_a_2025_06_18_peer() {
    let resp = unknown_router_error("2025-06-18");
    let body = resp.get("structuredContent").expect("structuredContent");
    assert_eq!(body["code"], "not_found");
    assert_eq!(body["retryable"], false);
}

#[test]
fn structured_error_body_is_withheld_from_a_2025_03_26_peer() {
    let resp = unknown_router_error("2025-03-26");
    assert!(resp.get("structuredContent").is_none(), "{resp}");
}

/// Call `tool` against a device on a closed local port (a typed `Connect`
/// failure). One server per case, so the cases' connect backoffs overlap.
fn code_against_closed_port(tool: &str, args: serde_json::Value) -> Value {
    let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let key = write_fake_netconf_key_temp();
    let inv = write_inventory_temp(&[(
        "closed",
        "127.0.0.1",
        closed_port,
        "admin",
        key.path().to_str().unwrap(),
    )]);
    let mut server = spawn_stdio_server_with_protocol(
        &["-f", inv.path().to_str().unwrap(), "--allow-direct-commit"],
        "2025-06-18",
    );
    let resp = call_tool(&mut server, tool, args);
    resp["structuredContent"].clone()
}

/// A refused connection is retryable for a retry-safe read tool, but not for
/// a write tool, which may reconnect after acting (`call_tool` scopes this).
#[test]
fn a_refused_connection_is_retryable_for_a_read_tool() {
    let body = code_against_closed_port("gather_device_facts", json!({ "router_name": "closed" }));
    assert_eq!(body["code"], "upstream_unavailable", "{body}");
    assert_eq!(body["retryable"], true, "{body}");
}

#[test]
fn a_refused_connection_keeps_its_type_through_the_fingerprint_tool() {
    let body = code_against_closed_port(
        "get_junos_candidate_fingerprint",
        json!({ "device": "closed" }),
    );
    assert_eq!(body["code"], "upstream_unavailable", "{body}");
}

#[test]
fn a_refused_connection_is_not_retryable_for_a_write_tool() {
    let body = code_against_closed_port(
        "load_and_commit_config",
        json!({ "device": "closed", "config_text": "set system host-name x", "config_format": "set" }),
    );
    assert_eq!(body["code"], "outcome_unknown", "{body}");
}

/// SRX tools open the device themselves; that path is coded too.
#[cfg(feature = "srx")]
#[test]
fn a_refused_connection_is_coded_for_an_srx_tool() {
    let body = code_against_closed_port(
        "get_srx_security_services_status",
        json!({ "router": "closed" }),
    );
    assert_eq!(body["code"], "upstream_unavailable", "{body}");
}

/// rmcp rejects a malformed argument before any handler runs; that error
/// carries the coded body too.
#[test]
fn a_malformed_argument_is_a_coded_invalid_argument() {
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();
    let mut server =
        spawn_stdio_server_with_protocol(&["-f", inv.path().to_str().unwrap()], "2025-06-18");
    let resp = call_tool(
        &mut server,
        "gather_device_facts",
        json!({ "routre": "r1" }),
    );
    assert!(
        resp.to_string()
            .contains("failed to deserialize parameters"),
        "{resp}"
    );
    assert_eq!(
        resp["structuredContent"]["code"], "invalid_argument",
        "{resp}"
    );
    assert_eq!(resp["structuredContent"]["retryable"], false, "{resp}");
}

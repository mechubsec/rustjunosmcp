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

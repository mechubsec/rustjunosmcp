#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Stdio smoke for add_device: full add -> reload -> router_list cycle.

mod common;
use common::{call_tool, spawn_stdio_server_with_args, write_inventory_in};
use serde_json::json;

#[test]
fn add_then_reload_then_router_list_shows_new_device() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    // Inventory::load validates that ssh_key paths exist on disk, so create a
    // real (empty) key file inside the tempdir for the new device to point at.
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(&key_path, b"").unwrap();

    let mut child = spawn_stdio_server_with_args(&[
        "-f",
        inv_path.to_str().unwrap(),
        "--allow-password-auth-add",
    ]);

    let r = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3",
            "device_ip":"10.0.0.3",
            "device_port":22,
            "username":"automation",
            "auth":{"type":"ssh_key","private_key_path": key_path.to_str().unwrap()}
        }),
    );
    assert_eq!(r["added"], "core-3", "got: {r}");
    assert_eq!(r["router_count"], 2, "got: {r}");

    // get_router_list reads dm.inventory() (live ArcSwap snapshot), so it
    // reflects the freshly added device immediately.
    let list = call_tool(&mut child, "get_router_list", json!({}));
    let names: Vec<String> = serde_json::from_value(list.clone())
        .unwrap_or_else(|e| panic!("get_router_list shape: {e}, got: {list}"));
    assert!(names.contains(&"core-3".to_string()), "names: {names:?}");
    assert!(names.contains(&"core-1".to_string()), "names: {names:?}");
}

#[test]
fn add_device_args_fallback_when_required_missing() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);

    let err = call_tool(&mut child, "add_device", json!({}));
    let s = err.to_string();
    assert!(s.contains("missing required arguments"), "got: {s}");
}

#[test]
fn add_device_inventory_readonly_returns_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child =
        spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap(), "--inventory-readonly"]);

    let err = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3","device_ip":"10.0.0.3","username":"u",
            "auth":{"type":"ssh_key","private_key_path":"/tmp/k"}
        }),
    );
    let s = err.to_string();
    assert!(s.contains("read-only"), "got: {s}");
}

#[test]
fn add_device_password_auth_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = write_inventory_in(
        dir.path(),
        "devices.json",
        r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.to_str().unwrap()]);

    let err = call_tool(
        &mut child,
        "add_device",
        json!({
            "device_name":"core-3","device_ip":"10.0.0.3","username":"u",
            "auth":{"type":"password","password":"x"}
        }),
    );
    let s = err.to_string();
    // MEC-14: every tool result, including error text, now passes through
    // `mecmcp_redact::redact_text` (to_call_result's last-mile pass). This
    // message's own denylisted key ("password") triggers the redactor's
    // documented over-redaction cost (mecmcp-redact's text.rs, X1): once a
    // denylisted key is found on a line with no quoting to bound its value,
    // everything from there to the end of the line is replaced, even though
    // this particular message never carried a secret. That is an accepted
    // tradeoff of the shared crate, not a defect in this server, so the
    // assertion only pins the part of the message that survives.
    assert!(s.contains("password [REDACTED]"), "got: {s}");
}

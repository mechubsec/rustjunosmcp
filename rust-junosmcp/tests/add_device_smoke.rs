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
    // the last-mile redaction pass (`to_call_result`'s call to
    // `redact_body`). MEC-2519: that pass used to fall back to
    // `mecmcp_redact::redact_text` for unstructured text, whose cross-vendor
    // denylist matches "password" as a bare word with no config-syntax
    // signal (no quote, `=`, `;`, or `set` context) and, lacking one, blanked
    // the rest of the line anyway — this message never carried a secret, so
    // that was pure over-redaction, not a safety win. `redact_body` now
    // falls back to `mecmcp_redact::junos::redact_log_text`, which only
    // redacts a sensitive key's value when a config-syntax signal is
    // present, so this prose error message now survives intact.
    assert!(
        s.contains(
            "password authentication is not allowed for add_device; \
             use --allow-password-auth-add to enable"
        ),
        "got: {s}"
    );
}

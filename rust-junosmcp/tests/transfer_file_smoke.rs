#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
mod common;

use common::{StdioChild, call_tool, spawn_stdio_server_with_args, write_inventory_temp};
use serde_json::json;
use std::path::Path;
use tempfile::NamedTempFile;

/// Shared setup: staging dir with a placeholder file, dummy SSH key, inventory,
/// and known_hosts. Returns the running StdioChild plus the inventory tempfile
/// guard — the caller MUST keep `_inv_guard` alive for the test's duration so
/// the inventory file isn't deleted out from under any later reload.
fn make_server(dir: &Path) -> (StdioChild, NamedTempFile) {
    let staging = dir.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("foo.tgz"), b"placeholder").unwrap();

    let key_file = dir.join("dummy_key");
    std::fs::write(&key_file, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let inv = write_inventory_temp(&[(
        "vsrx-test10",
        "192.0.2.1",
        830,
        "admin",
        key_file.to_str().unwrap(),
    )]);

    let known = dir.join("known_hosts");
    std::fs::write(&known, b"").unwrap();

    let server = spawn_stdio_server_with_args(&[
        "-f",
        inv.path().to_str().unwrap(),
        "--staging-dir",
        staging.to_str().unwrap(),
        "--known-hosts-file",
        known.to_str().unwrap(),
    ]);
    (server, inv)
}

#[test]
fn transfer_file_rejects_bad_source_path() {
    let dir = tempfile::tempdir().unwrap();
    let (mut server, _inv_guard) = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "../etc/passwd",
        }),
    );

    assert_eq!(
        resp.get("isError"),
        Some(&json!(true)),
        "expected tool error envelope, got: {}",
        resp
    );
    let text = resp.to_string();
    assert!(
        text.contains("code=bad_source_path"),
        "expected [code=bad_source_path] in response: {}",
        text
    );
}

#[test]
fn transfer_file_rejects_unknown_router() {
    let dir = tempfile::tempdir().unwrap();
    let (mut server, _inv_guard) = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "does-not-exist",
            "source_path": "foo.tgz",
        }),
    );

    assert_eq!(
        resp.get("isError"),
        Some(&json!(true)),
        "expected tool error envelope, got: {}",
        resp
    );
    let text = resp.to_string();
    // Pin to the actual UnknownRouter Display string, not just the input echo —
    // matching only "does-not-exist" would falsely pass if the tool ever echoed
    // its args back in a success path.
    assert!(
        text.contains("not found in device mapping") && text.contains("does-not-exist"),
        "expected UnknownRouter error for 'does-not-exist': {}",
        text
    );
}

#[test]
#[ignore = "requires outbound network to TEST-NET-1; run with --ignored in CI"]
fn transfer_file_connect_timeout_against_test_net_1() {
    let dir = tempfile::tempdir().unwrap();
    let (mut server, _inv_guard) = make_server(dir.path());

    let resp = call_tool(
        &mut server,
        "transfer_file",
        json!({
            "router_name": "vsrx-test10",
            "source_path": "foo.tgz",
            "timeout": 30,
        }),
    );

    assert_eq!(
        resp.get("isError"),
        Some(&json!(true)),
        "expected tool error envelope, got: {}",
        resp
    );
    let text = resp.to_string();
    // TEST-NET-1 (192.0.2.0/24) is unroutable so scp always exits 255 with
    // "Connection timed out" or "No route to host", both of which now produce
    // [code=connect_timeout] via the remap in handle().  We keep the OR for
    // slow CI runners where the outer tokio::time::timeout may fire first if
    // the operator passes a very low `timeout` value.
    assert!(
        text.contains("code=connect_timeout") || text.contains("code=outer_timeout"),
        "expected [code=connect_timeout] or [code=outer_timeout] in response: {}",
        text
    );
}

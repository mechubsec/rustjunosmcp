#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
mod common;

use common::{call_tool, spawn_stdio_server_with_args, write_inventory_temp};
use serde_json::json;

#[test]
fn list_staged_files_returns_host_staging_only() {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("alpha.tgz"), b"alpha-bytes").unwrap();
    std::fs::write(staging.join("beta.bin"), b"beta-bytes").unwrap();

    // Startup mode- and type-checks every private key path named in the
    // inventory, so this placeholder must be a real, 0600 regular file. We
    // never actually connect to the device in this test.
    let key_file = dir.path().join("dummy_key");
    std::fs::write(&key_file, b"").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Inventory: one ssh-key device. We never reach the device path because
    // the test omits router_name, so the placeholder ssh-key path is fine.
    let inv = write_inventory_temp(&[(
        "vsrx-test10",
        "192.0.2.1",
        830,
        "admin",
        key_file.to_str().unwrap(),
    )]);
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, b"").unwrap();

    let mut server = spawn_stdio_server_with_args(&[
        "-f",
        inv.path().to_str().unwrap(),
        "--staging-dir",
        staging.to_str().unwrap(),
        "--known-hosts-file",
        known.to_str().unwrap(),
    ]);

    let resp = call_tool(&mut server, "list_staged_files", json!({}));

    // Guard: if the tool returned an error envelope, surface it clearly
    // instead of failing later with a confusing "missing alpha.tgz" message.
    assert!(
        resp.get("isError") != Some(&json!(true)),
        "list_staged_files returned tool error: {}",
        resp
    );

    let text = resp.to_string();
    assert!(text.contains("alpha.tgz"), "missing alpha: {}", text);
    assert!(text.contains("beta.bin"), "missing beta: {}", text);
    // No router supplied: device + device_files should be null/absent.
    // The handler emits `"device": null, "device_files": null` when
    // router_name is absent. Asserting NOT containing the populated
    // device_files array shape (`"device_files":[`) is the cleanest check.
    assert!(
        !text.contains("\"device_files\":["),
        "unexpected device_files array in host-only response: {}",
        text
    );
}

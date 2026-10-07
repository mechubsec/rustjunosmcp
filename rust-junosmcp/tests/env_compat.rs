#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
mod common;

use std::process::{Command, Stdio};

#[test]
fn legacy_port_warns_and_does_not_move_stdio_startup() {
    common::ensure_built();
    let inventory = common::write_inv("{}");
    let lease_dir = tempfile::tempdir().unwrap();
    let output = Command::new(common::binary_path())
        .args([
            "--device-mapping",
            inventory.path().to_str().unwrap(),
            "--device-lease-dir",
            lease_dir.path().to_str().unwrap(),
            "--state-file",
            lease_dir
                .path()
                .join("changeset-state.json")
                .to_str()
                .unwrap(),
            "--transport",
            "stdio",
        ])
        .env_remove("JMCP_HTTP_PORT")
        .env("JMCP_SRX_HTTP_PORT", "30032")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("JMCP_SRX_HTTP_PORT"));
    assert!(stderr.contains("ignored"));
    assert!(stderr.contains("loaded inventory"));
}

#[test]
fn canonical_value_prevents_invalid_legacy_from_being_parsed() {
    common::ensure_built();
    let tokens = common::write_tokens(r#"{"version":1,"tokens":[]}"#);
    let output = Command::new(common::binary_path())
        .args([
            "token",
            "list",
            "--tokens-file",
            tokens.path().to_str().unwrap(),
        ])
        .env("JMCP_MAX_SESSIONS", "9")
        .env("JMCP_SRX_MAX_SESSIONS", "not-a-number")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("JMCP_SRX_MAX_SESSIONS"));
    assert!(stderr.contains("ignored"));
}

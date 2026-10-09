#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Spawn the `rust-junosmcp` binary and exercise the `token` subcommand.

use std::process::Command;

mod common;
use common::{binary_path, ensure_built};

#[test]
fn add_then_list_reports_name_no_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "alice",
            "--routers",
            "*",
            "--tools",
            "get_router_list,get_junos_config",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "expected empty stderr on successful add, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert_eq!(secret.len(), 43);

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(body.contains("alice"));
    assert!(!body.contains(&secret), "secret leaked into list output");
    assert!(!body.contains("sha256:"), "hash leaked into list output");
}

#[test]
fn revoke_then_list_omits_name() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "bob",
            "--routers",
            "*",
            "--tools",
            "*",
        ])
        .status()
        .unwrap();
    let out = Command::new(binary_path())
        .args([
            "token",
            "revoke",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "bob",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = Command::new(binary_path())
        .args(["token", "list", "--tokens-file", tokens.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(!body.contains("bob"));
}

#[test]
fn rotate_changes_secret_keeps_scopes() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out1 = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "carol",
            "--routers",
            "r1,r2",
            "--tools",
            "execute_junos_command",
        ])
        .output()
        .unwrap();
    let secret1 = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let out2 = Command::new(binary_path())
        .args([
            "token",
            "rotate",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "carol",
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let secret2 = String::from_utf8(out2.stdout).unwrap().trim().to_string();
    assert_ne!(secret1, secret2);

    let body = std::fs::read_to_string(&tokens).unwrap();
    assert!(body.contains("\"r1\""));
    assert!(body.contains("execute_junos_command"));
}

#[test]
fn add_rejects_wildcard_mixed_with_names() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "evil",
            "--routers",
            "*,mx-01",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("'*'"),
        "expected '*'-related error, got: {stderr}"
    );
}

#[test]
fn add_rejects_unknown_tool() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "dan",
            "--routers",
            "*",
            "--tools",
            "no_such_tool",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("no_such_tool"));
}

/// MEC-995: `--oidc-issuer`/`--oidc-subject` bind a token to an IdP identity
/// so `approve_change_set`'s two-person check can later tell this owner's
/// verified subject apart from an approver's.
#[test]
fn add_with_oidc_pair_persists_the_binding() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "alice",
            "--routers",
            "*",
            "--tools",
            "get_router_list",
            "--oidc-issuer",
            "https://idp.example.com",
            "--oidc-subject",
            "alice-sub",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body = std::fs::read_to_string(&tokens).unwrap();
    assert!(
        body.contains("https://idp.example.com") && body.contains("alice-sub"),
        "tokens file must persist the oidc_issuer/oidc_subject binding, got: {body}"
    );
}

#[test]
fn add_rejects_oidc_issuer_without_subject() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "alice",
            "--routers",
            "*",
            "--tools",
            "get_router_list",
            "--oidc-issuer",
            "https://idp.example.com",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("--oidc-subject"),
        "expected an error naming the missing pair partner, got: {stderr}"
    );
}

#[test]
fn add_accepts_srx_only_tool_scope() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "srx-read-only",
            "--routers",
            "srx-01",
            "--tools",
            "get_chassis_cluster_status,get_srx_security_services_status",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "token add rejected SRX scopes: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim().len(), 43);

    let body: serde_json::Value = serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();
    // mecmcp-auth serializes device scope as "devices", not "routers"
    assert_eq!(body["tokens"][0]["devices"], serde_json::json!(["srx-01"]));
    assert_eq!(
        body["tokens"][0]["tools"],
        serde_json::json!([
            "get_chassis_cluster_status",
            "get_srx_security_services_status"
        ])
    );
}

#[test]
fn set_scope_narrows_tools_without_reissuing_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    // Mint a token with wildcard tool scope and explicit device scope
    let out1 = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "eve",
            "--routers",
            "r1,r2",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    assert!(
        out1.status.success(),
        "{}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let secret = String::from_utf8(out1.stdout).unwrap().trim().to_string();
    assert_eq!(secret.len(), 43);

    // Read initial token to capture created_at
    let body_before: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();
    let created_at = body_before["tokens"][0]["created_at"].clone();
    assert!(
        created_at.is_string(),
        "created_at missing before set-scope"
    );

    // Narrow tool scope to explicit list
    let out2 = Command::new(binary_path())
        .args([
            "token",
            "set-scope",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "eve",
            "--tools",
            "get_router_list,get_junos_config",
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "{}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert!(out2.stdout.is_empty(), "set-scope should not print secret");

    // Read resulting token file
    let body_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();

    // 1. Assert the narrowed scope took effect
    assert_eq!(
        body_after["tokens"][0]["tools"],
        serde_json::json!(["get_router_list", "get_junos_config"]),
        "tools scope was not narrowed"
    );

    // 2. Assert device scope unchanged
    assert_eq!(
        body_after["tokens"][0]["devices"],
        serde_json::json!(["r1", "r2"]),
        "device scope changed unexpectedly"
    );

    // 3. Assert created_at unchanged
    assert_eq!(
        body_after["tokens"][0]["created_at"], created_at,
        "created_at changed unexpectedly"
    );

    // 4. Assert envelope version survived
    assert_eq!(
        body_after["version"],
        serde_json::json!(1),
        "envelope version lost"
    );

    // 5. Assert the ORIGINAL secret still authenticates (the critical property)
    // We don't have an HTTP endpoint to test auth in this subprocess test,
    // but we can confirm the digest hasn't changed by reading the file.
    // The digest is computed from the secret; if set-scope changed it,
    // the original secret would no longer match.
    assert_eq!(
        body_after["tokens"][0]["digest"], body_before["tokens"][0]["digest"],
        "secret digest changed — original secret would no longer authenticate"
    );
}

#[test]
fn set_scope_narrows_devices_without_reissuing_secret() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    // Mint a token with wildcard device scope
    let out1 = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "frank",
            "--routers",
            "*",
            "--tools",
            "get_router_list",
        ])
        .output()
        .unwrap();
    assert!(out1.status.success());
    let _secret = String::from_utf8(out1.stdout).unwrap().trim().to_string();

    let body_before: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();
    let created_at = body_before["tokens"][0]["created_at"].clone();

    // Narrow device scope to explicit list
    let out2 = Command::new(binary_path())
        .args([
            "token",
            "set-scope",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "frank",
            "--routers",
            "r3,r4",
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());

    let body_after: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&tokens).unwrap()).unwrap();

    assert_eq!(
        body_after["tokens"][0]["devices"],
        serde_json::json!(["r3", "r4"]),
        "device scope was not narrowed"
    );
    assert_eq!(
        body_after["tokens"][0]["tools"],
        serde_json::json!(["get_router_list"]),
        "tool scope changed unexpectedly"
    );
    assert_eq!(body_after["tokens"][0]["created_at"], created_at);
    assert_eq!(body_after["version"], serde_json::json!(1));
    assert_eq!(
        body_after["tokens"][0]["digest"], body_before["tokens"][0]["digest"],
        "secret changed"
    );
}

#[test]
fn set_scope_rejects_no_scopes() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");

    Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "george",
            "--routers",
            "*",
            "--tools",
            "*",
        ])
        .status()
        .unwrap();

    let out = Command::new(binary_path())
        .args([
            "token",
            "set-scope",
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--name",
            "george",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "set-scope should reject invocation with neither --routers nor --tools"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--routers") || stderr.contains("--tools"),
        "expected error mentioning scopes, got: {stderr}"
    );
}

#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

//! SIGHUP hot reload smoke. Unix-only.
//!
//! Verifies that sending SIGHUP to the running server causes it to re-read
//! the tokens file and atomically swap the in-memory store, so a token that
//! was valid before the signal becomes rejected after it.
#![cfg(unix)]

mod common;
use common::*;
#[cfg(feature = "srx")]
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::json;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn sighup_reloads_token_store() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    common::write_restricted(
        &inv,
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let toks = dir.path().join("tokens.json");

    // Mint a wildcard token via the subcommand.
    let out = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "all",
            "--routers",
            "*",
            "--tools",
            "*",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "token add failed: {:?}", out);
    let secret = String::from_utf8(out.stdout).unwrap().trim().to_string();
    assert!(!secret.is_empty(), "minted secret should not be empty");

    let s = spawn(&inv, &toks);

    // Phase 1: token is valid. Auth layer must let the request through. We
    // don't care what rmcp does with a bare tools/list (it'll likely return
    // 400/406 for missing session) — only that the auth verdict is "pass",
    // i.e. status != 401.
    let r = http_post(
        s.port,
        Some(&secret),
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_ne!(
        r.code, 401,
        "valid token should not be rejected before SIGHUP (got {})",
        r.code
    );

    // Revoke the token on disk. The running server still has the old store.
    let revoke = Command::new(binary_path())
        .args([
            "token",
            "revoke",
            "--tokens-file",
            toks.to_str().unwrap(),
            "--name",
            "all",
        ])
        .output()
        .unwrap();
    assert!(revoke.status.success(), "token revoke failed: {:?}", revoke);

    // SIGHUP the server to trigger reload.
    let pid = s.child.id() as i32;
    let pid = rustix::process::Pid::from_raw(pid).expect("valid PID");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");

    // Phase 2: same token, but now revoked + reloaded. Poll until we observe
    // 401 or hit the deadline. This is faster on the happy path than a fixed
    // sleep and tolerates slow CI.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_code = 0u16;
    let mut last_body = json!({});
    while Instant::now() < deadline {
        let r = http_post(
            s.port,
            Some(&secret),
            None,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        );
        last_code = r.code;
        last_body = r.body;
        if last_code == 401 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        last_code, 401,
        "revoked token should be 401 within 5s of SIGHUP reload (body: {})",
        last_body
    );
}

#[cfg(feature = "srx")]
#[test]
fn sighup_reloads_readonly_inventory_for_junos_and_srx_tools() {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.json");
    common::write_restricted(
        &inv,
        r#"{"r1":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = dir.path().join("tokens.json");
    // Token must explicitly grant reload_devices (a write tool) to reach
    // the inventory-readonly flag check. Wildcard tool scope no longer grants it.
    let secret = TokenStoreFile::add(
        &tokens,
        "all",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec![
            "get_router_list".into(),
            "check_srx_feature_license".into(),
            "reload_devices".into(),
        ]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    // This matches the packaged service's inventory policy.
    let server = spawn_with_auth_args(&inv, &tokens, &["--inventory-readonly"]);
    let session = initialize(server.port, secret.expose_secret());

    let router_list = |id| {
        http_post(
            server.port,
            Some(secret.expose_secret()),
            Some(&session),
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":"get_router_list","arguments":{}
            }}),
        )
    };
    let before = router_list(2);
    assert!(
        before.body.to_string().contains("r1"),
        "body: {}",
        before.body
    );
    assert!(
        !before.body.to_string().contains("r2"),
        "body: {}",
        before.body
    );

    common::write_restricted(
        &inv,
        r#"{"r2":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let pid = server.child.id() as i32;
    let pid = rustix::process::Pid::from_raw(pid).expect("valid PID");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");

    let deadline = Instant::now() + Duration::from_secs(5);
    let after = loop {
        let response = router_list(3);
        let body = response.body.to_string();
        if body.contains("r2") && !body.contains("r1") {
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "inventory was not refreshed within 5s: {}",
            response.body
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(after.code, 200, "body: {}", after.body);

    // The SRX adapter must see the same refreshed DeviceManager. A connection
    // error is expected for the local closed port; an unknown-router error is
    // evidence that SRX retained stale inventory.
    let srx = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
            "name":"check_srx_feature_license",
            "arguments":{"router":"r2","feature":"idp"}
        }}),
    );
    let srx_body = srx.body.to_string();
    assert!(
        srx_body.contains("connection failed"),
        "expected a connection error: {srx_body}"
    );
    assert!(
        !srx_body.contains("not found in device mapping"),
        "SRX used stale inventory: {srx_body}"
    );

    // SIGHUP is a trusted re-read only; the externally callable mutation tool
    // remains denied under the packaged read-only policy.
    let external_reload = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
            "name":"reload_devices","arguments":{}
        }}),
    );
    assert!(
        external_reload.body.to_string().contains("read-only"),
        "body: {}",
        external_reload.body
    );
}

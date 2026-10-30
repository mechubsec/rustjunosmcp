#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Streamable-http integration smoke for the unified server's SRX tools: auth (RFC 6750 401s),
//! rmcp 2.0 Host allowlist (#97), and the tool-surface tripwire. All tests
//! exercise the transport/auth layers only — no device is contacted.

mod common;
use common::*;
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::json;
use std::collections::HashSet;

fn add_token(path: &std::path::Path, name: &str, routers: ScopeSet, tools: ScopeSet) -> String {
    TokenStoreFile::add(
        path,
        name,
        routers,
        tools,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap()
    .expose_secret()
    .to_string()
}

fn initialize_authenticated(server: &Server, secret: &str) -> String {
    let init = http_post(server.port, Some(secret), None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let initialized = http_post(
        server.port,
        Some(secret),
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(
        initialized.code, 202,
        "initialized failed: {:?}",
        initialized.body
    );
    sid
}

fn srx_router_tool_calls() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("get_chassis_cluster_status", json!({"router":"r1"})),
        ("get_srx_security_services_status", json!({"router":"r1"})),
        (
            "check_srx_feature_license",
            json!({"router":"r1","feature":"idp"}),
        ),
        ("vpn_lifecycle_report", json!({"router":"r1"})),
        ("get_srx_feed_status", json!({"router":"r1"})),
        (
            "manage_idp_security_package",
            json!({"router":"r1","action":"check_server"}),
        ),
        (
            "manage_appid_signature_package",
            json!({"router":"r1","action":"check_server"}),
        ),
        ("validate_chassis_cluster_health", json!({"router":"r1"})),
        (
            "collect_jtac_support_bundle",
            json!({"router":"r1","problem_type":"generic"}),
        ),
    ]
}

fn placeholder_inv() -> tempfile::NamedTempFile {
    write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    )
}

#[test]
fn missing_authorization_returns_401() {
    ensure_built();
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        None,
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.to_ascii_lowercase().starts_with("bearer"),
        "challenge must use Bearer scheme: {challenge:?}"
    );
    assert_eq!(
        r.body["error"], "invalid_request",
        "missing-auth 401 body must be {{error:\"invalid_request\",...}}: {:?}",
        r.body
    );
    assert!(
        r.body["error_description"].is_string(),
        "401 body must include error_description string: {:?}",
        r.body
    );
}

#[test]
fn wrong_bearer_returns_401() {
    ensure_built();
    let inv = placeholder_inv();
    let toks = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let s = spawn(inv.path(), toks.path());
    let r = http_post(
        s.port,
        Some("not-a-real-token"),
        None,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 401);
    let challenge = r
        .www_authenticate
        .expect("401 must carry WWW-Authenticate per RFC 6750 §3");
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "wrong-bearer challenge must include error=\"invalid_token\": {challenge:?}"
    );
    assert_eq!(
        r.body["error"], "invalid_token",
        "wrong-bearer 401 body must be {{error:\"invalid_token\",...}}: {:?}",
        r.body
    );
}

/// SRX twin of `http_smoke::disallowed_host_is_rejected`; see that test for why
/// the status moved from 403 to 421 in mecmcp 0.7. The request is still refused,
/// which is the property that must never regress.
#[test]
fn disallowed_host_is_rejected() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "evil.example.com");
    assert_eq!(
        code, 421,
        "the Host allowlist must reject a disallowed Host (DNS-rebinding guard)"
    );
}

#[test]
fn allowed_host_flag_permits_custom_host() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &["--allowed-host", "friendly.example.com"]);
    let code = post_init_with_host(s.port, "friendly.example.com");
    assert_eq!(
        code, 200,
        "an --allowed-host authority must pass rmcp's Host check and reach initialize"
    );
}

/// See `http_smoke::disable_host_check_flag_is_rejected` — the flag was removed in
/// 0.15.3. Here we assert the SRX surface keeps the gate closed for an unlisted Host.
#[test]
fn foreign_host_is_rejected_with_no_escape_hatch() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    let code = post_init_with_host(s.port, "anything.example");
    assert_ne!(
        code, 200,
        "an unlisted Host must not reach initialize (DNS-rebinding guard)"
    );
}

#[test]
fn lists_all_known_tools() {
    ensure_built();
    let inv = placeholder_inv();
    let s = spawn_no_auth(inv.path(), &[]);
    // initialize (no auth) then tools/list.
    let init = http_post(s.port, None, None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let _ = http_post(
        s.port,
        None,
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    let r = http_post(
        s.port,
        None,
        Some(&sid),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(r.code, 200, "tools/list failed: {:?}", r.body);
    let tools = r
        .body
        .pointer("/result/tools")
        .and_then(|t| t.as_array())
        .expect("tools array");
    let names: HashSet<&str> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
        .collect();
    let expected: HashSet<&str> = rust_junosmcp_auth::KNOWN_TOOLS
        .iter()
        .copied()
        .filter(|name| !rust_junosmcp_auth::PSEUDO_TOOLS.contains(name))
        .collect();
    assert_eq!(names, expected);
    assert_eq!(tools.len(), 45);
    // 28 before Phase 5; the change-set tools took it to 33,
    // `confirm_junos_change_set` makes 34 (#239),
    // `list_junos_change_sets` makes 35 (#255), and
    // `cancel_junos_change_set` makes 36 (#293), and execute makes 37.
    // MEC-54's four SRX policy-read tools make 41, and
    // `srx_flow_sessions` + `srx_policy_match` make 43 (MEC-55), and
    // `confirm_commit` makes 44 (MEC-45), `get_srx_feed_status` makes 45 (#528).
    assert_eq!(names.len(), 45);
}

#[test]
fn every_srx_tool_enforces_tool_scope_before_device_access() {
    ensure_built();
    let inv = placeholder_inv();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = add_token(
        &tokens,
        "junos-only",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
    );
    let server = spawn(inv.path(), &tokens);
    let sid = initialize_authenticated(&server, &secret);

    let mut calls = vec![("srxmcp_status", json!({}))];
    calls.extend(srx_router_tool_calls());
    for (index, (tool, arguments)) in calls.into_iter().enumerate() {
        let response = http_post(
            server.port,
            Some(&secret),
            Some(&sid),
            json!({"jsonrpc":"2.0","id":index + 1,"method":"tools/call","params":{
                "name":tool,"arguments":arguments
            }}),
        );
        // Scope preflight rejects tool scope violations before dispatch with 403
        assert_eq!(response.code, 403, "{tool}: {}", response.body);
        assert_eq!(response.body["error"], "insufficient_scope", "{tool}");
    }
}

#[test]
fn every_router_tool_enforces_router_scope_without_disclosing_router() {
    ensure_built();
    let inv = placeholder_inv();
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    // Must explicitly grant SRX write tools (manage_idp_security_package, manage_appid_signature_package)
    // to reach router scope check. Wildcard tool scope no longer grants write tools.
    let secret = add_token(
        &tokens,
        "other-router-only",
        ScopeSet::Allowlist(vec!["other-router".into()]),
        ScopeSet::Allowlist(
            rust_junosmcp_auth::SRX_TOOLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        ),
    );
    let server = spawn(inv.path(), &tokens);
    let sid = initialize_authenticated(&server, &secret);

    for (index, (tool, arguments)) in srx_router_tool_calls().into_iter().enumerate() {
        let response = http_post(
            server.port,
            Some(&secret),
            Some(&sid),
            json!({"jsonrpc":"2.0","id":index + 1,"method":"tools/call","params":{
                "name":tool,"arguments":arguments
            }}),
        );
        // Scope preflight rejects router scope violations before dispatch with 403
        assert_eq!(response.code, 403, "{tool}: {}", response.body);
        assert_eq!(response.body["error"], "insufficient_scope", "{tool}");
    }
}

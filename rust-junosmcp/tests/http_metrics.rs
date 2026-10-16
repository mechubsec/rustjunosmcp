#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
mod common;

use common::{
    binary_path, close_session, ensure_built, http_get, http_post, http_post_raw, initialize,
    spawn_with_auth_args, write_inv, write_tokens,
};
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::json;
use std::process::Command;

fn fixture(
    extra: &[&str],
) -> (
    tempfile::NamedTempFile,
    tempfile::NamedTempFile,
    rust_junosmcp_auth::TokenSecret,
    common::Server,
) {
    let inventory = write_inv(
        r#"{"secret-router":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = write_tokens(r#"{"version":1,"tokens":[]}"#);
    let token = TokenStoreFile::add(
        tokens.path(),
        "secret-token-name",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();
    let server = spawn_with_auth_args(inventory.path(), tokens.path(), extra);
    (inventory, tokens, token, server)
}

#[test]
fn metrics_disabled_leaves_route_absent() {
    let (_inventory, _tokens, token, server) = fixture(&[]);
    let response = http_get(server.port, "/metrics", Some(token.expose_secret()), None);
    assert_eq!(response.code, 404);
}

/// `/metrics` is behind the Host allowlist, even though it needs no bearer token.
///
/// This is a deliberate behaviour change in mecmcp 0.7: the allowlist is applied
/// to the whole router rather than to `/mcp` alone. `/metrics` is the one
/// unauthenticated route, which makes it the most attractive DNS-rebinding
/// target (RUSTSEC-2026-0189) — an attacker-controlled page could otherwise
/// point a victim's browser at a loopback-bound server and read the scrape.
///
/// Until 0.7 this returned 200 for any Host, and the previous version of the
/// test asserted exactly that, so the hardening reads as a test failure. It is
/// the opposite. Keep this test as the record of which way round it goes.
#[test]
fn metrics_reject_a_foreign_host() {
    let (_inventory, _tokens, _token, server) = fixture(&["--enable-metrics"]);
    let response = http_get(server.port, "/metrics", None, Some("untrusted.example"));
    assert_eq!(
        response.code, 421,
        "/metrics must be behind the Host allowlist: it is unauthenticated, \
         which makes it the prime DNS-rebinding target"
    );
}

#[test]
fn enabled_metrics_are_unauthenticated_bounded_and_live() {
    let (_inventory, _tokens, token, server) =
        fixture(&["--enable-metrics", "--max-request-body-bytes", "512"]);

    // Unauthenticated: no bearer token. The Host still has to be an allowed one
    // — see metrics_reject_a_foreign_host below for why that changed.
    let initial = http_get(server.port, "/metrics", None, None);
    assert_eq!(initial.code, 200);
    assert_eq!(
        initial.content_type,
        "text/plain; version=0.0.4; charset=utf-8"
    );

    let session_id = initialize(server.port, token.expose_secret());
    let tool = http_post(
        server.port,
        Some(token.expose_secret()),
        Some(&session_id),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_router_list", "arguments": {}}
        }),
    );
    assert_eq!(tool.code, 200, "offline tool failed: {:?}", tool.body);

    let big = "x".repeat(4096);
    let body = format!(r#"{{"jsonrpc":"2.0","id":3,"method":"ping","params":"{big}"}}"#);
    assert_eq!(
        http_post_raw(server.port, token.expose_secret(), None, &body),
        413
    );

    let scrape = http_get(server.port, "/metrics", None, None);
    assert_eq!(scrape.code, 200);
    assert!(
        scrape
            .body
            .contains("junosmcp_active_sessions{server=\"junos\"} 1")
    );
    // mecmcp-audit now emits caller-supplied metric name (junosmcp_tool_duration_seconds)
    // as a histogram with buckets, configured in prometheus.rs.
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_tool_duration_seconds_bucket{")
            && line.contains("server=\"junos\"")
            && line.contains("tool=\"get_router_list\"")
            && line.contains("result=\"ok\"")
    }));
    assert!(scrape.body.lines().any(|line| {
        line.starts_with("junosmcp_limit_hits_total{")
            && line.contains("limit=\"request_body\"")
            && line.contains("event=\"request_rejected\"")
    }));
    // Report a leak by position only: the failure message must not echo the
    // forbidden value (a token or session id) or the scraped body that contains it.
    for (index, forbidden) in [
        "secret-token-name",
        token.expose_secret(),
        "secret-router",
        &session_id,
        "caller=",
        "router=",
        "session_id=",
        "correlation_id=",
        "error=",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            !scrape.body.contains(*forbidden),
            "metrics leaked forbidden item #{index} of the list above"
        );
    }

    assert!(matches!(
        close_session(server.port, token.expose_secret(), &session_id),
        200 | 202 | 204
    ));
    let closed = http_get(server.port, "/metrics", None, None);
    assert!(
        closed
            .body
            .contains("junosmcp_active_sessions{server=\"junos\"} 0")
    );
}

#[test]
fn metrics_flag_is_rejected_before_stdio_startup() {
    ensure_built();
    let output = Command::new(binary_path())
        .arg("--enable-metrics")
        .output()
        .expect("run rust-junosmcp");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--enable-metrics requires --transport streamable-http"));
}

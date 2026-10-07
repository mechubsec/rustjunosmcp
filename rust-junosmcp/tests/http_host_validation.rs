//! Host validation integration tests for mecmcp-transport 0.9.0.
//!
//! These tests verify critical production behaviors that MUST NOT regress:
//! - Portless `--allowed-host` entries match ANY port (LXC 950 production shape)
//! - Loopback hosts remain allowed after custom hosts are added
//! - Unlisted Host headers are rejected with 421 MISDIRECTED_REQUEST
//! - Origin validation works when enabled (pass-through to mecmcp_transport)
//!
//! **Migration note (mecmcp 0.9.0)**: These tests now drive real HTTP requests
//! to a bound loopback listener, as ServePlan deliberately does not expose the
//! router for `.oneshot()` calls. Every assertion survived unchanged — only the
//! delivery mechanism changed.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod common;

use mecmcp_changeset::ChangesetCoordinator;
use mecmcp_transport::LimitsConfig;
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_core::{DeviceManager, MecmcpScpRunner, Policy, TransferConfig, UpgradeConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use tokio_util::sync::CancellationToken;

/// Allocate unique test ports for parallel execution.
static TEST_PORT_COUNTER: AtomicU16 = AtomicU16::new(18800);

/// Build a minimal test handler for router tests.
/// Mirrors production initialization but with an empty inventory (no devices needed).
fn test_handler() -> JmcpHandler {
    let inventory = rust_junosmcp_core::Inventory::empty();
    let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
        Policy::build(&inventory).expect("test policy"),
    )));
    let dev_manager = Arc::new(DeviceManager::new(Arc::new(inventory)));

    // Minimal transfer/upgrade config for test purposes
    let transfer_cfg = TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp"),
        known_hosts_file: std::path::PathBuf::from("/dev/null"),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(Default::default()),
        host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
    };
    // Use a tempdir for leases to avoid permissions issues with /tmp
    let lease_dir = tempfile::tempdir().expect("test lease tempdir");
    let upgrade_cfg = UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases: Arc::new(
            rust_junosmcp_core::DeviceLeaseManager::for_directory(lease_dir.path())
                .expect("test lease manager"),
        ),
    };
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None, // in-memory
            mecmcp_changeset::OperationLimits::default(),
            std::time::Duration::from_secs(300),
            false,
        )
        .expect("test changeset coordinator"),
    );

    JmcpHandler::new(
        dev_manager,
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator,
        false,
        false,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
}

/// Start a test server and return its base URL.
///
/// Spawns `serve_router` on a unique loopback port and sleeps briefly to ensure
/// the listener is bound before returning.
async fn start_test_server(
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
) -> (String, CancellationToken) {
    let handler = test_handler();
    let shutdown = CancellationToken::new();

    let plan = rust_junosmcp::http_transport::build_http_router(
        handler,
        None, // No auth
        allowed_hosts,
        allowed_origins,
        LimitsConfig::default(),
        false, // No metrics
        false, // allow_insecure_bind: these tests bind loopback, which is exempt
        shutdown.clone(),
    )
    .expect("router build");

    let port = TEST_PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let addr = format!("127.0.0.1:{port}").parse().expect("parse address");

    tokio::spawn(async move {
        mecmcp_transport::serve_router(plan, addr, None, std::time::Duration::from_secs(5))
            .await
            .expect("serve router");
    });

    // Give the server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (format!("http://127.0.0.1:{port}"), shutdown)
}

#[tokio::test]
async fn portless_allowed_host_matches_any_port() {
    // Production shape: LXC 950 binds 0.0.0.0:30031 with `--allowed-host 192.0.2.10`
    // (no port). This MUST accept Host: 192.0.2.10:30031 (with port).
    let (base_url, shutdown) = start_test_server(
        vec!["192.0.2.10".to_string()],
        Vec::new(), // No origins
    )
    .await;

    // Request with explicit port in Host header
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "192.0.2.10:30031")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    // Should NOT be 421 (portless allowlist entry must match explicit port)
    // assert_eq, not assert_ne: a bare "not 421" also passes when the request
    // was rejected somewhere else entirely. 406 is rmcp's answer to a probe
    // carrying no `Accept: text/event-stream`, so it is positive evidence the
    // request reached rmcp rather than being turned away by the guard.
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_ACCEPTABLE,
        "portless allowlist entry MUST match explicit port (production requirement)"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn portless_allowed_host_also_matches_portless_host() {
    // A portless allowlist entry should also accept a portless Host header.
    let (base_url, shutdown) = start_test_server(vec!["192.0.2.10".to_string()], Vec::new()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "192.0.2.10")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_ACCEPTABLE,
        "portless allowlist entry should match portless Host"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn loopback_still_allowed_after_adding_host() {
    // The default loopback allowlist (localhost/127.0.0.1/[::1]) must remain
    // accessible after adding a custom host with --allowed-host.
    let (base_url, shutdown) = start_test_server(vec!["192.0.2.10".to_string()], Vec::new()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "localhost")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_ACCEPTABLE,
        "loopback must remain allowed after custom hosts are added"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn unlisted_host_rejected_with_421() {
    // An unlisted Host header must be rejected with 421 MISDIRECTED_REQUEST.
    let (base_url, shutdown) = start_test_server(vec!["192.0.2.10".to_string()], Vec::new()).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "attacker.example")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::MISDIRECTED_REQUEST,
        "unlisted Host must be rejected with 421"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn origin_allow_pass_through() {
    // When an Origin allowlist is provided, matching origins should pass.
    let (base_url, shutdown) = start_test_server(
        Vec::new(), // No extra hosts beyond loopback
        vec!["http://localhost:8080".to_string()],
    )
    .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "localhost")
        .header("Origin", "http://localhost:8080")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_ACCEPTABLE,
        "matching Origin should pass validation"
    );

    shutdown.cancel();
}

#[tokio::test]
async fn origin_deny_pass_through() {
    // When an Origin allowlist is provided, non-matching origins should be rejected.
    let (base_url, shutdown) =
        start_test_server(Vec::new(), vec!["http://localhost:8080".to_string()]).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/mcp"))
        .header("Host", "localhost")
        .header("Origin", "http://attacker.example")
        .body("{}")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::FORBIDDEN,
        "unlisted Origin must be rejected with 403"
    );

    shutdown.cancel();
}

/// The deployed LXC 950 shape must actually serve: off-loopback, plaintext,
/// with `--allow-insecure-bind` and an Origin allowlist.
///
/// Regression test for the wiring defect that took 950 down during the 0.20.0
/// upgrade. `--allow-insecure-bind` and `--allowed-origin` were both parsed by
/// the CLI, shown in `--help`, and then discarded: `serve_http` never received
/// the first, and `main.rs` passed `Vec::new()` for the second with a comment
/// claiming origins were "empty by default". Under mecmcp 0.9.x the transport
/// refuses a plaintext off-loopback listener without the acknowledgement, so
/// the server crash-looped on a flag the operator had supplied.
///
/// This binds a real off-loopback-shaped listener rather than loopback,
/// because loopback is exempt from every admission check and would pass
/// whether or not the flag is wired — which is exactly why the existing tests
/// here did not catch it.
#[tokio::test]
async fn insecure_bind_acknowledgement_reaches_the_transport() {
    // An AUTHENTICATED router. With `None` here the unauthenticated refusal
    // fires first and the insecure-bind check is never reached — the test then
    // passes whether or not the flag is wired, which is exactly how the first
    // version of this test proved nothing. Verified by sabotage: discard the
    // acknowledgement in build_http_router and this test must fail.
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens = dir.path().join("tokens.json");
    rust_junosmcp_auth::TokenStoreFile::add(
        &tokens,
        "probe",
        rust_junosmcp_auth::ScopeSet::Wildcard,
        rust_junosmcp_auth::ScopeSet::Wildcard,
        &rust_junosmcp_auth::KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .expect("mint token");
    let store = std::sync::Arc::new(
        rust_junosmcp_auth::TokenStoreFile::load(&tokens).expect("load token store"),
    );

    let shutdown = CancellationToken::new();
    let plan = rust_junosmcp::http_transport::build_http_router(
        test_handler(),
        Some(store),
        vec!["192.0.2.10".to_owned()],
        vec!["http://192.168.1.127".to_owned()],
        LimitsConfig::default(),
        false,
        true, // allow_insecure_bind — the flag under test
        shutdown.clone(),
    )
    .expect("router build");

    // 192.0.2.1 (TEST-NET-1) is non-loopback and unbindable here. If the
    // acknowledgement did NOT reach the transport we get Refused; if it did,
    // admission passes and we fail later at the bind. Distinguishing those two
    // is the whole point.
    let err = mecmcp_transport::serve_router(
        plan,
        "192.0.2.1:30031".parse().expect("address"),
        None,
        std::time::Duration::from_millis(50),
    )
    .await
    .expect_err("cannot bind TEST-NET-1");

    // Assert on the specific refusal, not on Refused generally. This router is
    // built without a token store, so UnauthenticatedOffLoopback fires first and
    // is correct — it is a different check. What must NOT appear is the
    // insecure-bind refusal, because the flag was supplied.
    assert!(
        !matches!(
            err,
            mecmcp_transport::HttpServeError::Refused(
                mecmcp_transport::ListenerRefusal::InsecureBindNotAcknowledged { .. }
            )
        ),
        "refused for want of an insecure-bind acknowledgement despite \
         allow_insecure_bind=true, so the flag never reached the transport: {err:?}"
    );
}

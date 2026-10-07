#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Real rustls handshake coverage for the unified streamable-HTTP endpoint.

#![cfg(feature = "tls")]

mod common;
use common::{
    BoundedLines, Server, binary_path, ensure_built, init_body, parse_first_sse_data, pick_port,
};
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::{Value, json};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, issued.cert.pem()).unwrap();
    std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();
    // The hardened loader (mecmcp-transport, plan decision D2) refuses a private
    // key readable by group or other. `fs::write` creates 0644 under a typical
    // umask, so without this the server exits at startup and the failure surfaces
    // as "did not become ready" rather than as anything about permissions.
    // Same step a real operator takes on upgrade.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (cert, key)
}

fn spawn_tls(inventory: &Path, tokens: &Path, cert: &Path, key: &Path) -> Server {
    let port = pick_port();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let state_file = device_lease_dir.path().join("changeset-state.json");
    let mut child = Command::new(binary_path())
        .args([
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--device-mapping",
            inventory.to_str().unwrap(),
            "--tokens-file",
            tokens.to_str().unwrap(),
            "--tls-cert",
            cert.to_str().unwrap(),
            "--tls-key",
            key.to_str().unwrap(),
            "--device-lease-dir",
            device_lease_dir.path().to_str().unwrap(),
            "--state-file",
            state_file.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn TLS server");

    let stderr = child.stderr.take().unwrap();
    // Bounded on a worker thread — a deadline checked between `read_line` calls
    // cannot fire, because the missing line is exactly what leaves `read_line`
    // blocked. See `common::BoundedLines`.
    let lines = BoundedLines::spawn(BufReader::new(stderr));
    if !lines.wait_for(Duration::from_secs(15), |line| {
        line.contains("streamable-http listening (TLS)")
    }) {
        let _ = child.kill();
        panic!(
            "server did not print the 'streamable-http listening (TLS)' readiness line within 15s \
             (if the server still works, the log line was renamed — see http_transport.rs)"
        );
    }
    // The BoundedLines worker already owns this pipe and keeps reading it, so it
    // is the drain. Do not join it — it blocks in `read_line` and would only
    // notice a dropped receiver on its next send. See `common::into_drain`.
    let drain = lines.into_drain();

    // The readiness log line is emitted just before the listener begins
    // accepting, so a client racing it can still see ECONNREFUSED. `http_tls.rs`
    // already guards this the same way; without it this test fails on a loaded
    // CI runner while passing locally.
    wait_for_port(port, Duration::from_secs(5));

    Server {
        child,
        port,
        _stderr_drain: drain,
        _device_lease_dir: device_lease_dir,
    }
}

/// Poll until TCP connections to `port` are accepted, or panic after `timeout`.
fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {port} not accepting connections within {timeout:?}");
}

fn tls_agent(cert: &Path) -> ureq::Agent {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;

    let pem = std::fs::read(cert).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(&pem) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .tls_config(Arc::new(config))
        .build()
}

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    String,
) {
    ensure_built();
    let dir = tempfile::tempdir().unwrap();
    let inventory = dir.path().join("devices.json");
    common::write_restricted(
        &inventory,
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "tls-test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap()
    .expose_secret()
    .to_string();
    let (cert, key) = write_self_signed(dir.path());
    (dir, inventory, tokens, cert, key, secret)
}

fn response_status(result: Result<ureq::Response, ureq::Error>) -> u16 {
    match result {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(error) => panic!("TLS transport error: {error}"),
    }
}

#[test]
fn tls_handshake_completes_with_bearer_auth() {
    let (_dir, inventory, tokens, cert, key, secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let response = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Authorization", &format!("Bearer {secret}"))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body())
        .expect("authenticated TLS initialize");

    assert_eq!(response.status(), 200);
    let content_type = response.header("Content-Type").unwrap_or("").to_string();
    let text = response.into_string().unwrap_or_default();
    let body: Value = if content_type.contains("text/event-stream") {
        parse_first_sse_data(&text).unwrap_or(json!({}))
    } else {
        serde_json::from_str(&text).unwrap_or(json!({}))
    };
    assert!(body.pointer("/result").is_some(), "body: {body}");
}

#[test]
fn tls_does_not_replace_bearer_authentication() {
    let (_dir, inventory, tokens, cert, key, _secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let result = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body());
    assert_eq!(response_status(result), 401);
}

#[test]
fn tls_does_not_replace_host_validation() {
    let (_dir, inventory, tokens, cert, key, secret) = fixture();
    let server = spawn_tls(&inventory, &tokens, &cert, &key);
    let result = tls_agent(&cert)
        .post(&format!("https://localhost:{}/mcp", server.port))
        .set("Host", "evil.example")
        .set("Authorization", &format!("Bearer {secret}"))
        .set("Accept", "application/json, text/event-stream")
        .send_json(init_body());
    // 421 since mecmcp 0.7 — see http_smoke::disallowed_host_is_rejected. The
    // point of this test is that TLS does not stand in for Host validation, and
    // that still holds: a foreign Host is refused over TLS exactly as over plain
    // HTTP.
    assert_eq!(response_status(result), 421);
}

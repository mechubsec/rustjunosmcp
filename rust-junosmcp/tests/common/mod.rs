#![allow(dead_code, clippy::unwrap_used)]
//! Shared test harness for rust-junosmcp integration tests.
//!
//! Two families of helpers live here:
//! - stdio smoke helpers: spawn the `rust-junosmcp` binary with `-t stdio`,
//!   perform the MCP handshake, and expose a small `call_tool` helper that
//!   returns the parsed JSON content of the tool's response.
//! - streamable-http helpers: spawn the binary on an ephemeral port, POST
//!   JSON-RPC, parse SSE, assert HTTP behavior (auth, sessions, etc.).

use serde_json::{Value, json};
use std::io::{BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

/// Absolute path to the freshly-built `rust-junosmcp` binary.
///
/// Uses `CARGO_BIN_EXE_rust-junosmcp`, which Cargo sets for integration tests
/// and honours custom `CARGO_TARGET_DIR`.
pub fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rust-junosmcp"))
}

/// No-op. Cargo has already built the binary by the time this runs.
///
/// Kept as a function so the ~40 call sites need not all change at once, and
/// because "make sure the binary exists" reads as a reasonable thing for a test
/// to want. It is not: `binary_path()` uses `CARGO_BIN_EXE_rust-junosmcp`, which
/// Cargo sets **and guarantees is built** before any integration test runs.
///
/// This used to shell out to `cargo build` from inside every test binary. Two
/// problems, both real:
///
/// 1. **It could deadlock the suite.** `cargo test` runs test binaries
///    concurrently, so each one launched its own `cargo` contending for the same
///    build-directory lock. On a 2-core CI runner that stalled a single CI step
///    for 36 minutes, against a 4–7 minute total for the whole workflow on main.
/// 2. **It could build a different binary than the one under test.** It
///    reassembled the feature list by hand from `cfg!(feature = ...)`, so any
///    drift between that list and the real build would have tests exercising a
///    binary nobody asked for.
///
/// Do not reintroduce a build step here. If the binary is genuinely missing,
/// that is a Cargo bug, and `binary_path()` failing loudly is the right outcome.
pub fn ensure_built() {}

/// Write a placeholder NETCONF private key: a regular, 0600 temp file.
///
/// Startup now mode- and type-checks every private key path named in the
/// inventory (`validate_startup_credentials`), so a stand-in like
/// `/dev/null` no longer boots the server ("not a regular file"). Use this
/// for any inventory fixture that needs a key path the server will accept
/// but never actually reads.
#[allow(dead_code)]
pub fn write_fake_netconf_key_temp() -> tempfile::NamedTempFile {
    use std::io::Write as _;
    let mut f = tempfile::NamedTempFile::new().expect("create temp key file");
    writeln!(f, "not a real key").expect("write temp key file");
    f
}

/// Write `contents` to `path` with mode 0600.
///
/// Use this for any file the server itself reads as configuration — inventory
/// and tokens. Since mecmcp 0.3.8 both go through a hardened reader that
/// refuses a group- or world-accessible file, and `std::fs::write` gives
/// whatever the umask allows (0644 on a default setup).
///
/// The failure it prevents is unhelpfully indirect: the server exits during
/// startup, before answering `initialize`, so the test reports a 15s response
/// timeout and says nothing about permissions. `write_inventory_temp` never hit
/// it because `NamedTempFile` is already 0600.
#[allow(dead_code)]
pub fn write_restricted(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write config fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict config fixture permissions");
    }
}

/// Write `json` to `dir/name` and return the full path.
#[allow(dead_code)]
pub fn write_inventory_in(dir: &Path, name: &str, json: &str) -> PathBuf {
    let path = dir.join(name);
    write_restricted(&path, json);
    path
}

/// Write a minimal JSON inventory to a temp file and return the handle.
/// Each tuple: (name, ip, port, username, key_file_path).
#[allow(dead_code)]
pub fn write_inventory_temp(devices: &[(&str, &str, u16, &str, &str)]) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::Builder::new()
        .prefix("jmcp-inv-")
        .suffix(".json")
        .tempfile()
        .expect("create temp inventory");
    let mut obj = serde_json::Map::new();
    for (name, ip, port, user, key) in devices {
        obj.insert(
            (*name).to_string(),
            serde_json::json!({
                "ip": ip,
                "port": port,
                "username": user,
                "auth": { "type": "ssh_key", "private_key_path": key },
            }),
        );
    }
    let payload = serde_json::Value::Object(obj);
    writeln!(f, "{}", serde_json::to_string_pretty(&payload).unwrap()).expect("write inventory");
    f
}

/// Live `rust-junosmcp` child wired up for JSON-RPC over stdio.
pub struct StdioChild {
    pub child: Child,
    pub stdin: ChildStdin,
    pub lines: BoundedLines,
    pub next_id: i64,
    _device_lease_dir: tempfile::TempDir,
}

impl Drop for StdioChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn send(stdin: &mut ChildStdin, msg: &Value) {
    let line = serde_json::to_string(msg).expect("serialize jsonrpc msg");
    writeln!(stdin, "{line}").expect("write stdin");
    stdin.flush().expect("flush stdin");
}

/// Read stdout until the JSON-RPC response with `id` arrives, bounded at 15s.
///
/// Bounded via `BoundedLines` rather than a deadline around `read_line`: if the
/// child stops writing, `read_line` never returns and the deadline never gets
/// looked at again. See #281.
fn read_response_with_id(lines: &BoundedLines, id: i64) -> Value {
    let wanted = json!(id);
    let found = lines.wait_for_line(Duration::from_secs(15), |line| {
        serde_json::from_str::<Value>(line.trim()).is_ok_and(|v| v.get("id") == Some(&wanted))
    });
    match found {
        Some(line) => serde_json::from_str(line.trim()).expect("jsonrpc response"),
        None => panic!("did not receive response with id={id} within 15s"),
    }
}

/// Spawn the server with `-t stdio` plus any extra CLI args (for example
/// `&["-f", path, "--allow-password-auth-add"]`). Performs the MCP
/// `initialize` (id=0) + `notifications/initialized` handshake before
/// returning. Subsequent `tools/call` ids start at 2.
pub fn spawn_stdio_server_with_args(extra_args: &[&str]) -> StdioChild {
    ensure_built();

    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let state_file = device_lease_dir.path().join("changeset-state.json");
    let mut cmd = Command::new(binary_path());
    cmd.arg("-t")
        .arg("stdio")
        .arg("--device-lease-dir")
        .arg(device_lease_dir.path())
        .arg("--state-file")
        .arg(&state_file);
    for a in extra_args {
        cmd.arg(a);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-junosmcp");

    let mut stdin = child.stdin.take().expect("take stdin");
    let stdout = child.stdout.take().expect("take stdout");
    let lines = BoundedLines::spawn(BufReader::new(stdout));

    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "smoke", "version": "0.1" }
            }
        }),
    );
    let _ = read_response_with_id(&lines, 0);

    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    StdioChild {
        child,
        stdin,
        lines,
        next_id: 2,
        _device_lease_dir: device_lease_dir,
    }
}

/// Send a `tools/call` and block until the matching response arrives.
///
/// Returns:
/// - On success: the parsed JSON in `result.content[0].text` (the handlers
///   stringify their JSON Value into a single text content), falling back to
///   `result.structuredContent` if present, else the raw `result`.
/// - On tool error (`result.isError == true`): the full `result` Value, so
///   callers can call `.to_string()` and `.contains("...")` on it.
pub fn call_tool(child: &mut StdioChild, name: &str, args: Value) -> Value {
    let id = child.next_id;
    child.next_id += 1;

    send(
        &mut child.stdin,
        &json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }),
    );

    let resp = read_response_with_id(&child.lines, id);
    let result = resp
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("missing /result in response: {resp}"));

    if result.get("isError") == Some(&json!(true)) {
        return result;
    }

    if let Some(text) = result.pointer("/content/0/text").and_then(Value::as_str)
        && let Ok(parsed) = serde_json::from_str::<Value>(text)
    {
        return parsed;
    }
    if let Some(sc) = result.get("structuredContent") {
        return sc.clone();
    }
    result
}

// ---------------------------------------------------------------------------
// streamable-http harness (shared by http_smoke.rs, http_reload.rs, and the
// non-TLS-specific bits of http_tls.rs). `binary_path`/`ensure_built` above
// are reused as-is.
// ---------------------------------------------------------------------------

pub fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// RAII child guard: kills + waits on drop so panics don't leak processes.
/// Also keeps a background drain thread on stderr so the child never blocks
/// or SIGPIPEs on log writes after the readiness line.
pub struct Server {
    pub child: Child,
    pub port: u16,
    pub _stderr_drain: std::thread::JoinHandle<()>,
    pub _device_lease_dir: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Lines read from a child pipe on a worker thread, so waits can be bounded.
///
/// **Use this instead of looping on `read_line` with a deadline.** A deadline
/// checked *between* `read_line` calls does not bind: the failure it guards
/// against — the awaited line never arriving — leaves `read_line` blocked
/// forever, so control never returns to the check. The test then hangs rather
/// than failing, and a hang reports nothing at all: no test name, no assertion,
/// no exit code.
///
/// This repo has now been bitten by that shape three times (see #281), each in
/// a separately hand-written loop. Hence one primitive rather than another copy.
pub struct BoundedLines {
    rx: std::sync::mpsc::Receiver<Option<String>>,
    worker: std::thread::JoinHandle<()>,
}

impl BoundedLines {
    pub fn spawn<R: std::io::BufRead + Send + 'static>(mut reader: R) -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        let worker = std::thread::spawn(move || {
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        let _ = tx.send(None);
                        return;
                    }
                    Ok(_) => {
                        // A failed send means the waiter is done. Keep reading
                        // and discarding rather than returning: this thread is
                        // also the drain that stops the child's pipe filling.
                        let _ = tx.send(Some(line));
                    }
                }
            }
        });
        Self { rx, worker }
    }

    /// Wait up to `timeout` for a line satisfying `matches`, returning it.
    ///
    /// `None` means the timeout expired, the pipe hit EOF, or the child died —
    /// never "still waiting".
    pub fn wait_for_line(
        &self,
        timeout: Duration,
        matches: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let deadline = Instant::now() + timeout;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.rx.recv_timeout(remaining) {
                Ok(Some(line)) if matches(&line) => return Some(line),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return None,
            }
        }
        None
    }

    /// As [`Self::wait_for_line`] when only "did it arrive" matters.
    pub fn wait_for(&self, timeout: Duration, matches: impl Fn(&str) -> bool) -> bool {
        self.wait_for_line(timeout, matches).is_some()
    }

    /// Stop waiting and leave the worker draining the pipe until EOF.
    ///
    /// Deliberately does **not** join. The worker blocks inside `read_line`, so
    /// it only observes a dropped receiver on its *next* send — if the child has
    /// gone quiet after the line we were waiting for, a join never returns. That
    /// is a hang, in the very helper written to prevent hangs, and it stalled
    /// `enabled_metrics_are_unauthenticated_bounded_and_live` under load on a
    /// 2-core runner (the process sat in `futex_wait`).
    ///
    /// The returned handle keeps the thread's ownership tied to the caller's
    /// lifetime without ever blocking on it; the thread exits at EOF, which
    /// happens when the child is killed.
    #[must_use]
    pub fn into_drain(self) -> std::thread::JoinHandle<()> {
        drop(self.rx);
        self.worker
    }
}

/// Block until `port` accepts a TCP connection, or panic at the deadline.
///
/// The stderr readiness line is logged *before* `serve_router` binds the
/// listener, so "the server said it is listening" and "the socket accepts" are
/// not the same moment. On a fast machine that gap closes before any test
/// notices; on a loaded 2-core runner it does not, and the test fails with
/// `Connection refused` on an ephemeral port that looks for all the world like
/// a port-allocation race.
pub fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {port} not accepting connections within {timeout:?}");
}

/// Wait for the "streamable-http listening" readiness line on the child's
/// stderr, then spawn a drain thread and return the guarded Server. Panics if
/// the server doesn't announce within 15s.
fn finish_spawn(mut child: Child, port: u16, device_lease_dir: tempfile::TempDir) -> Server {
    let stderr = child.stderr.take().unwrap();
    let lines = BoundedLines::spawn(BufReader::new(stderr));

    if !lines.wait_for(Duration::from_secs(15), |line| {
        line.contains("streamable-http listening")
    }) {
        let _ = child.kill();
        panic!(
            "server did not print the 'streamable-http listening' readiness line within 15s \
             (if the server still works, the log line was renamed — see http_transport.rs)"
        );
    }
    // The BoundedLines worker is already reading this pipe, so it *is* the
    // drain — a second thread on the same reader is neither possible nor needed.
    let drain = lines.into_drain();
    // The readiness line precedes the bind; wait for the socket itself.
    wait_for_port(port, Duration::from_secs(15));
    Server {
        child,
        port,
        _stderr_drain: drain,
        _device_lease_dir: device_lease_dir,
    }
}

pub fn spawn(inv_path: &Path, tokens_path: &Path) -> Server {
    spawn_with_auth_args(inv_path, tokens_path, &[])
}

pub fn spawn_with_auth_args(inv_path: &Path, tokens_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let state_file = device_lease_dir.path().join("changeset-state.json");
    let mut argv = vec![
        "-f",
        inv_path.to_str().unwrap(),
        "-t",
        "streamable-http",
        "-H",
        "127.0.0.1",
        "-p",
        &port_s,
        "--tokens-file",
        tokens_path.to_str().unwrap(),
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
        "--state-file",
        state_file.to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port, device_lease_dir)
}

/// Spawn with `--allow-no-auth` (no auth layer) plus extra CLI args (e.g.
/// `--allowed-host` / `--disable-host-check`), so rmcp's built-in Host
/// allowlist is the sole gate in front of `initialize`.
pub fn spawn_no_auth(inv_path: &Path, extra: &[&str]) -> Server {
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let state_file = device_lease_dir.path().join("changeset-state.json");
    let mut argv = vec![
        "-f",
        inv_path.to_str().unwrap(),
        "-t",
        "streamable-http",
        "-H",
        "127.0.0.1",
        "-p",
        &port_s,
        "--allow-no-auth",
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
        "--state-file",
        state_file.to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    finish_spawn(child, port, device_lease_dir)
}

/// Spawn with `--allow-no-auth` plus extra CLI args. Returns a `ServerWithToken`
/// that carries both the `Server` guard and a stub token for call-site parity
/// with the authed harness (the token is not used).
pub struct ServerWithToken {
    pub server: Server,
    pub token: String,
}

impl std::ops::Deref for ServerWithToken {
    type Target = Server;
    fn deref(&self) -> &Self::Target {
        &self.server
    }
}

pub fn spawn_with_args(extra: &[&str]) -> ServerWithToken {
    let inv = write_inv(
        r#"{"stub":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let port = pick_port();
    let port_s = port.to_string();
    let device_lease_dir = tempfile::tempdir().expect("create device lease directory");
    let state_file = device_lease_dir.path().join("changeset-state.json");
    let mut argv = vec![
        "-f",
        inv.path().to_str().unwrap(),
        "-t",
        "streamable-http",
        "-H",
        "127.0.0.1",
        "-p",
        &port_s,
        "--allow-no-auth",
        "--device-lease-dir",
        device_lease_dir.path().to_str().unwrap(),
        "--state-file",
        state_file.to_str().unwrap(),
    ];
    argv.extend_from_slice(extra);
    let child = Command::new(binary_path())
        .args(&argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let server = finish_spawn(child, port, device_lease_dir);
    ServerWithToken {
        server,
        token: String::new(),
    }
}

pub struct GetResult {
    pub code: u16,
    pub content_type: String,
    pub body: String,
}

/// A ureq agent with a finite overall timeout.
///
/// Bare `ureq::get`/`post`/`delete` have **no** timeout, so a request that stalls
/// hangs the test for as long as the runner allows — and a hung suite is far
/// worse than a failed one, because it reports nothing at all. The whole
/// workspace run stalled for 40 minutes on a single request this way, while the
/// same test passed in 0.02s on its own.
///
/// 90s is deliberately generous: the batch tests dial unreachable IPs and take
/// ~23s legitimately. This bounds a hang, it does not police latency.
fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(90))
        .build()
}

pub fn http_get(port: u16, path: &str, bearer: Option<&str>, host: Option<&str>) -> GetResult {
    let mut request = agent().get(&format!("http://127.0.0.1:{port}{path}"));
    if let Some(bearer) = bearer {
        request = request.set("Authorization", &format!("Bearer {bearer}"));
    }
    if let Some(host) = host {
        request = request.set("Host", host);
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(error) => panic!("transport error: {error}"),
    };
    let code = response.status();
    let content_type = response.header("Content-Type").unwrap_or("").to_owned();
    let body = response.into_string().unwrap_or_default();
    GetResult {
        code,
        content_type,
        body,
    }
}

/// POST raw body bytes and return just the HTTP status code (for testing
/// body-limit rejections before the JSON-RPC layer).
/// POST a raw body and return only the status.
///
/// The bearer and session id are now actually sent. They used to be ignored,
/// which was invisible while the body limit sat outside authentication: an
/// oversized anonymous request still got its 413. Under mecmcp's order —
/// authenticate, then body limit — the same request is 401, and every caller
/// here passes a real token precisely because it wants to reach the limit.
pub fn http_post_raw(port: u16, bearer: &str, session_id: Option<&str>, body: &str) -> u16 {
    let mut req = agent()
        .post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream")
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {bearer}"));
    if let Some(sid) = session_id {
        req = req.set("Mcp-Session-Id", sid);
    }
    match req.send_string(body) {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}

/// Outcome of a streamable-http POST: status, body parsed as JSON-RPC payload
/// (extracted from SSE if needed), any returned `Mcp-Session-Id`, and the
/// `WWW-Authenticate` header if present (for RFC 6750 §3 assertions on 401).
pub struct PostResult {
    pub code: u16,
    pub body: Value,
    pub session_id: Option<String>,
    pub retry_after: Option<String>,
    pub www_authenticate: Option<String>,
}

pub fn http_post(
    port: u16,
    bearer: Option<&str>,
    session_id: Option<&str>,
    body: Value,
) -> PostResult {
    let mut req = agent().post(&format!("http://127.0.0.1:{port}/mcp"));
    if let Some(b) = bearer {
        req = req.set("Authorization", &format!("Bearer {b}"));
    }
    req = req.set("Accept", "application/json, text/event-stream");
    if let Some(sid) = session_id {
        req = req.set("Mcp-Session-Id", sid);
    }
    let (code, resp_session, retry_after, content_type, www_auth, text) = match req.send_json(body)
    {
        Ok(resp) => {
            let code = resp.status();
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let retry_after = resp.header("Retry-After").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, retry_after, ct, wa, text)
        }
        Err(ureq::Error::Status(code, resp)) => {
            let sid = resp.header("Mcp-Session-Id").map(str::to_string);
            let retry_after = resp.header("Retry-After").map(str::to_string);
            let ct = resp.header("Content-Type").unwrap_or("").to_string();
            let wa = resp.header("WWW-Authenticate").map(str::to_string);
            let text = resp.into_string().unwrap_or_default();
            (code, sid, retry_after, ct, wa, text)
        }
        Err(e) => panic!("transport error: {e}"),
    };
    let body_value = if content_type.contains("text/event-stream") {
        parse_first_sse_data(&text).unwrap_or(json!({}))
    } else if !text.is_empty() {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
    } else {
        json!({})
    };
    PostResult {
        code,
        body: body_value,
        session_id: resp_session,
        retry_after,
        www_authenticate: www_auth,
    }
}

pub fn close_session(port: u16, bearer: &str, session_id: &str) -> u16 {
    let request = agent()
        .delete(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Authorization", &format!("Bearer {bearer}"))
        .set("Mcp-Session-Id", session_id);
    match request.call() {
        Ok(response) => response.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(error) => panic!("transport error: {error}"),
    }
}

/// Parse the first `data:` line from an SSE stream as JSON.
pub fn parse_first_sse_data(sse: &str) -> Option<Value> {
    // rmcp 2.0.0 prepends an empty "priming" SSE event (`data: ` with no
    // payload) before the real JSON-RPC payload when `sse_retry` is set
    // (the default), so skip blank/unparseable `data:` lines instead of
    // returning on the very first one.
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str(payload) {
                return Some(value);
            }
        }
    }
    None
}

/// Send an `initialize` request followed by the required
/// `notifications/initialized` notification, return the negotiated
/// `Mcp-Session-Id`.
pub fn initialize(port: u16, bearer: &str) -> String {
    let r = http_post(port, Some(bearer), None, init_body());
    assert_eq!(r.code, 200, "initialize failed: {:?}", r.body);
    let sid = r.session_id.expect("server did not return Mcp-Session-Id");
    // rmcp requires `notifications/initialized` before any further requests.
    let n = http_post(
        port,
        Some(bearer),
        Some(&sid),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert!(
        n.code == 200 || n.code == 202,
        "initialized notification rejected: {} {:?}",
        n.code,
        n.body
    );
    sid
}

pub fn init_body() -> Value {
    json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0.1"}
    }})
}

/// POST an `initialize` with an explicit Host header; return the HTTP status.
pub fn post_init_with_host(port: u16, host: &str) -> u16 {
    let req = agent()
        .post(&format!("http://127.0.0.1:{port}/mcp"))
        .set("Accept", "application/json, text/event-stream")
        .set("Host", host);
    match req.send_json(init_body()) {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(e) => panic!("transport error: {e}"),
    }
}

pub fn write_inv(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    f
}

pub fn write_tokens(json: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), json).unwrap();
    // Token files must be mode 0600 (mecmcp-auth permission check)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod token file");
    }
    f
}

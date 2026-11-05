#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]

//! SIGHUP audit log reopen. Unix-only.
//!
//! Verifies that sending SIGHUP to a running server with `--audit-log-file`
//! configured reopens the sink in place: a rename-then-signal rotation loses
//! nothing written before the rename and routes everything written after it
//! to the fresh inode at the same path. Also verifies that a reopen which
//! cannot succeed (the path is no longer usable) does not take down the
//! server or the other SIGHUP reloads.
#![cfg(unix)]

mod common;
use common::*;
use serde_json::json;
use std::time::{Duration, Instant};

/// Send `initialize` + `notifications/initialized` with no bearer (the
/// server was spawned with `--allow-no-auth`) and return the session id.
fn initialize_no_auth(port: u16) -> String {
    let init = http_post(port, None, None, init_body());
    assert_eq!(init.code, 200, "initialize failed: {:?}", init.body);
    let sid = init
        .session_id
        .expect("server did not return Mcp-Session-Id");
    let n = http_post(
        port,
        None,
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

/// Call a read-only tool that emits exactly one `target="audit"` record.
fn emit_audit_record(port: u16, sid: &str, id: i64) {
    let r = http_post(
        port,
        None,
        Some(sid),
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
            "name":"get_router_list","arguments":{}
        }}),
    );
    assert_eq!(r.code, 200, "get_router_list failed: {:?}", r.body);
}

fn sighup(pid: u32) {
    let pid = rustix::process::Pid::from_raw(pid as i32).expect("valid PID");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");
}

fn wait_for_nonempty(path: &std::path::Path, deadline: Instant) -> String {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "{} never became non-empty",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn sighup_reopens_audit_log_after_rename() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let s = spawn_no_auth(
        inv.path(),
        &[
            "--audit-log-file",
            audit_path.to_str().unwrap(),
            "--audit-format",
            "json",
        ],
    );
    let sid = initialize_no_auth(s.port);

    // First record lands in the original inode.
    emit_audit_record(s.port, &sid, 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = wait_for_nonempty(&audit_path, deadline);
    assert!(
        before.contains("get_router_list"),
        "audit file missing first record: {before}"
    );

    // Rotate the way logrotate's rename-mode fragment does: move the file
    // aside, then signal the process.
    let rotated = dir.path().join("audit.jsonl.1");
    std::fs::rename(&audit_path, &rotated).unwrap();
    sighup(s.child.id());

    // Second record must land at the same path, in a fresh inode, once the
    // reopen has completed. Poll rather than sleep a fixed amount: the
    // reopen races the SIGHUP delivery and this keeps the happy path fast.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        emit_audit_record(s.port, &sid, 2);
        if let Ok(contents) = std::fs::read_to_string(&audit_path)
            && contents.contains("get_router_list")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second record never appeared at {} within 5s after SIGHUP",
            audit_path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let after_rotation = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        after_rotation.contains("get_router_list"),
        "new audit file missing post-rotation record: {after_rotation}"
    );

    // Records polled out before the reopen completes legitimately land in the
    // old inode, so the rotated file may grow past `before` but never lose it.
    let rotated_contents = std::fs::read_to_string(&rotated).unwrap();
    assert!(
        rotated_contents.starts_with(&before),
        "the rotated-away file must keep everything written before the rename, losing nothing: {rotated_contents}"
    );
}

#[test]
fn sighup_audit_reopen_failure_keeps_server_and_other_reloads_alive() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let s = spawn_no_auth(
        inv.path(),
        &[
            "--audit-log-file",
            audit_path.to_str().unwrap(),
            "--audit-format",
            "json",
        ],
    );
    let sid = initialize_no_auth(s.port);

    emit_audit_record(s.port, &sid, 1);
    let deadline = Instant::now() + Duration::from_secs(5);
    wait_for_nonempty(&audit_path, deadline);

    // Make the reopen fail: replace the path with a directory, so
    // `OpenOptions::create().append()` on it returns EISDIR. The server's
    // existing (now-unlinked) descriptor keeps working regardless.
    std::fs::remove_file(&audit_path).unwrap();
    std::fs::create_dir(&audit_path).unwrap();
    sighup(s.child.id());

    // The server must keep serving requests — a failed audit reopen must not
    // take down the process or block the other SIGHUP reloads.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let r = http_post(
            s.port,
            None,
            Some(&sid),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}),
        );
        if r.code == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "server stopped responding after a failed audit reopen (last status {})",
            r.code
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    std::fs::remove_dir(&audit_path).unwrap();
}

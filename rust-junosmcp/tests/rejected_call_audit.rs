//! A call the router refuses must still produce an audit record (#268).
//!
//! The regression this guards against was invisible by construction. Every
//! handler builds its `AuditScope` as its first statement, but rmcp deserializes
//! `Parameters<T>` *before* the handler body runs — so a call rejected for a bad
//! argument returned to the caller having recorded nothing anywhere.
//!
//! That mattered because #253 deliberately made unrecognised arguments an error
//! rather than a silent fallback to broader behaviour. Without a record, an
//! integration can start failing against a new release and the server side shows
//! nothing, so "zero errors" reads as "nobody was refused" when it actually
//! means "refusals are not recorded". It was measured on a live deployment
//! before being fixed:
//!
//! ```text
//! audit lines emitted for a REJECTED call (unknown field): 0
//! audit lines emitted for an ACCEPTED call (get_router_list): 1
//! ```
//!
//! These tests assert the first number is now 1. They read the server's stderr,
//! which is where audit records go, so they need their own spawn rather than the
//! shared stdio harness (which discards stderr).

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Spawn the server over stdio, send `initialize` then `request`, and return
/// every stderr line it produced.
fn stderr_for_request(request: &str) -> Vec<String> {
    common::ensure_built();

    let lease_dir = tempfile::tempdir().expect("device lease dir");
    let inventory = common::write_inventory_temp(&[("r1", "127.0.0.1", 22, "u", "/dev/null")]);

    let mut child = Command::new(common::binary_path())
        .args(["-t", "stdio"])
        .arg("--device-lease-dir")
        .arg(lease_dir.path())
        .arg("--state-file")
        .arg(lease_dir.path().join("changeset-state.json"))
        .arg("-f")
        .arg(inventory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rust-junosmcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            request,
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }
    // Closing stdin ends the session, so the child exits and stderr reaches EOF.
    drop(child.stdin.take());

    let stderr = child.stderr.take().expect("stderr");
    let lines: Vec<String> = BufReader::new(stderr)
        .lines()
        .map_while(Result::ok)
        .map(|line| strip_ansi(&line))
        .collect();
    let _ = child.wait();
    lines
}

/// Removes ANSI CSI sequences from a captured line.
///
/// These assertions are about audit *content* -- which tool a refusal is
/// attributed to -- not about how a terminal would colour it. Without this,
/// they compare against bytes the human-readable formatter interleaves between
/// each field name and its value, so a record that reads `tool=execute` on a
/// screen is `tool\x1b[0m\x1b[2m=\x1b[0mexecute` on the wire and
/// `contains("tool=execute")` is false.
///
/// That interleaving was itself a defect, fixed upstream in mecmcp by
/// disabling ANSI when stderr is not a terminal. Normalising here as well is
/// not redundant: it keeps these tests measuring the thing they are named for,
/// so a future formatter change cannot turn an attribution regression into a
/// passing run or vice versa.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        // CSI: ESC '[' parameter/intermediate bytes, terminated by @..~.
        match chars.next() {
            Some('[') => {
                for tail in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&tail) {
                        break;
                    }
                }
            }
            // A non-CSI escape: drop the ESC, keep what followed.
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

fn audit_lines(lines: &[String]) -> Vec<&String> {
    lines.iter().filter(|line| line.contains("audit")).collect()
}

/// The regression itself: an unrecognised argument is refused during dispatch,
/// and that refusal must be recorded.
#[test]
fn a_call_rejected_for_an_unknown_argument_is_audited() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_junos_config","arguments":{"device":"r1","stanza":"routing-options"}}}"#,
    );
    let audits = audit_lines(&lines);

    assert!(
        !audits.is_empty(),
        "a rejected call must leave an audit record; before #268 it left nothing. \
         stderr was: {lines:#?}"
    );
    let record = audits
        .iter()
        .find(|line| line.contains("dispatch_rejected"))
        .unwrap_or_else(|| panic!("no dispatch_rejected record among: {audits:#?}"));

    assert!(
        record.contains("get_junos_config"),
        "the record must name the tool: {record}"
    );
    assert!(
        record.contains("stanza"),
        "the record must carry rmcp's message, which names the offending field \
         — that is the actionable part: {record}"
    );
}

/// A tool that does not exist is refused the same way and matters for the same
/// reason: someone is calling something this server does not have.
#[test]
fn a_call_to_an_unknown_tool_is_audited_without_echoing_the_name() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"definitely_not_a_tool","arguments":{}}}"#,
    );
    let audits = audit_lines(&lines);
    let record = audits
        .iter()
        .find(|line| line.contains("dispatch_rejected"))
        .unwrap_or_else(|| panic!("an unknown tool must be audited; got: {lines:#?}"));

    assert!(
        record.contains("unknown_tool"),
        "the tool field must be the placeholder, not the caller's string: {record}"
    );
}

/// The other half of the contract: an accepted call must still produce exactly
/// one record. If the dispatch-level recording also fired for calls that reached
/// a handler, every successful call would be audited twice.
#[test]
fn an_accepted_call_is_audited_exactly_once() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_router_list","arguments":{}}}"#,
    );
    let audits = audit_lines(&lines);

    assert_eq!(
        audits.len(),
        1,
        "an accepted call must be audited once, not twice: {audits:#?}"
    );
    assert!(
        !audits[0].contains("dispatch_rejected"),
        "an accepted call must not be recorded as rejected: {}",
        audits[0]
    );
}

#[test]
fn invalid_inner_arguments_are_audited_once_under_the_concrete_operation() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"operation":"gather_device_facts","arguments":{"routre":"r1"}}}}"#,
    );
    let audits = audit_lines(&lines);
    let rejected = audits
        .iter()
        .filter(|line| line.contains("dispatch_rejected"))
        .collect::<Vec<_>>();

    assert_eq!(
        rejected.len(),
        1,
        "the inner dispatch rejection must be audited exactly once: {audits:#?}"
    );
    assert!(
        rejected[0].contains("gather_device_facts"),
        "the rejection must name the concrete operation: {}",
        rejected[0]
    );
    assert!(
        !audits
            .iter()
            .any(|line| line.contains("tool=execute") && !line.contains("dispatch_rejected")),
        "the facade must not add a successful execute record: {audits:#?}"
    );
}

#[test]
fn unknown_facade_operation_is_audited_once_and_bounded() {
    let operation = "x".repeat(2048);
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"execute","arguments":{{"operation":"{operation}","arguments":{{}}}}}}}}"#
    );
    let lines = stderr_for_request(&request);
    let audits = audit_lines(&lines);
    let rejected = audits
        .iter()
        .filter(|line| line.contains("unknown_operation"))
        .collect::<Vec<_>>();

    assert_eq!(
        rejected.len(),
        1,
        "the unknown facade operation must be audited exactly once: {audits:#?}"
    );
    assert!(
        rejected[0].contains("tool=execute"),
        "unknown facade operations remain attributed to execute: {}",
        rejected[0]
    );
    assert!(
        !rejected[0].contains(&operation),
        "the audit record must not include the full raw operation: {}",
        rejected[0]
    );
}

#[test]
fn accepted_facade_read_has_one_concrete_handler_record() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"operation":"get_device_list","arguments":{}}}}"#,
    );
    let audits = audit_lines(&lines);

    assert_eq!(
        audits.len(),
        1,
        "an accepted facade read must have exactly one audit record: {audits:#?}"
    );
    assert!(
        audits[0].contains("tool=get_device_list"),
        "the concrete handler must own the audit record: {}",
        audits[0]
    );
    assert!(
        !audits[0].contains("dispatch_rejected"),
        "an accepted facade read must not be rejected: {}",
        audits[0]
    );
    assert!(
        !audits[0].contains("tool=execute"),
        "the facade must not add a successful execute record: {}",
        audits[0]
    );
}

#[test]
fn malformed_facade_arguments_remain_audited_under_execute() {
    let lines = stderr_for_request(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"operation":"get_device_list","arguments":[]}}}"#,
    );
    let audits = audit_lines(&lines);
    let rejected = audits
        .iter()
        .filter(|line| line.contains("dispatch_rejected"))
        .collect::<Vec<_>>();

    assert_eq!(
        rejected.len(),
        1,
        "a malformed facade request must be rejected exactly once: {audits:#?}"
    );
    assert!(
        rejected[0].contains("tool=execute"),
        "a malformed facade request must remain attributed to execute: {}",
        rejected[0]
    );
}

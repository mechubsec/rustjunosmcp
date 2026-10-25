#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! `--tool-mode compact` (mecmcp#547) shortens tools/list to `execute` and
//! `get_router_list`, and hides nothing from a call: listing only.
mod common;

use common::{call_tool, list_tool_names, spawn_stdio_server_with_args};
use serde_json::json;

fn names_with(extra: &[&str]) -> Vec<String> {
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();
    let mut args = vec!["-f", inv.path().to_str().unwrap()];
    args.extend_from_slice(extra);
    let mut server = spawn_stdio_server_with_args(&args);
    let mut names = list_tool_names(&mut server);
    names.sort();
    names
}

#[test]
fn compact_mode_lists_only_the_dispatcher_and_discovery() {
    assert_eq!(
        names_with(&["--tool-mode", "compact"]),
        ["execute", "get_router_list"]
    );
}

#[test]
fn full_mode_is_the_default() {
    let names = names_with(&[]);
    assert!(names.len() > 2, "{names:?}");
    assert!(names.iter().any(|name| name == "execute"), "{names:?}");
}

#[test]
fn compact_mode_still_answers_a_call_to_an_unlisted_tool() {
    let inv = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(inv.path(), "{}").unwrap();
    let mut server = spawn_stdio_server_with_args(&[
        "-f",
        inv.path().to_str().unwrap(),
        "--tool-mode",
        "compact",
    ]);
    let resp = call_tool(&mut server, "get_device_list", json!({}));
    assert_ne!(resp.get("isError"), Some(&json!(true)), "{resp}");
}

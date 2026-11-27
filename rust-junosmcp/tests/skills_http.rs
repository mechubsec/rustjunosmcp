#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Skills (SEP-2640) over Streamable HTTP: `skills/*` and `resources/*` work
//! for any valid token, whatever its tool scope, and need a token at all.
#![cfg(unix)]

mod common;
use common::*;
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::{Value, json};
use std::path::PathBuf;

const SKILLS: [&str; 4] = [
    "junos-api-lookup",
    "junos-config-paths",
    "junos-ex-switching",
    "junos-netconf-protocol",
];

fn repo_skills_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../skills")
}

/// Server with `skills_dir` and one token holding only `tools`.
fn serve(skills_dir: &str, tools: &[&str]) -> (Server, String, tempfile::TempDir) {
    ensure_built();
    let inv = write_inv("{}");
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "skills-reader",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Allowlist(tools.iter().map(|name| (*name).to_owned()).collect()),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();
    let server = spawn_with_auth_args(inv.path(), &tokens, &["--skills-dir", skills_dir]);
    (server, secret.expose_secret().to_owned(), dir)
}

fn rpc(server: &Server, token: &str, session: &str, id: u64, method: &str, params: Value) -> Value {
    let response = http_post(
        server.port,
        Some(token),
        Some(session),
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    );
    assert_eq!(response.code, 200, "{method}: {}", response.body);
    response.body
}

#[test]
fn skills_list_and_get_over_mcp() {
    let (server, token, _dir) = serve(repo_skills_dir().to_str().unwrap(), &["get_device_list"]);
    let init = http_post(server.port, Some(&token), None, init_body());
    assert!(
        init.body["result"]["capabilities"]["extensions"]
            .to_string()
            .contains("skills"),
        "{}",
        init.body
    );
    let session = initialize(server.port, &token);

    let listed = rpc(&server, &token, &session, 1, "skills/list", json!({}));
    let mut names: Vec<&str> = listed["result"]["skills"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skill| skill["frontmatter"]["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, SKILLS, "{listed}");

    let uri = "skill://junos-api-lookup/SKILL.md";
    let got = rpc(
        &server,
        &token,
        &session,
        2,
        "skills/get",
        json!({"uri": uri}),
    );
    assert_eq!(got["result"]["skill"]["uri"], uri, "{got}");

    let read = rpc(
        &server,
        &token,
        &session,
        3,
        "resources/read",
        json!({"uri": uri}),
    );
    let text = read["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(text.contains("execute_junos_rpc"), "{read}");

    let resources = rpc(&server, &token, &session, 4, "resources/list", json!({}));
    assert_eq!(
        resources["result"]["resources"].as_array().unwrap().len(),
        4
    );
}

/// A token that may only call `get_device_list` can still read skills, by
/// resource, by `skills/*` and by tool when the tool is granted.
#[test]
fn skills_readable_with_read_only_token() {
    let (server, token, _dir) = serve(
        repo_skills_dir().to_str().unwrap(),
        &["get_device_list", "list_junos_skills", "read_junos_skill"],
    );
    let session = initialize(server.port, &token);
    let uri = "skill://junos-config-paths/SKILL.md";
    for (method, params) in [
        ("skills/list", json!({})),
        ("skills/get", json!({"uri": uri})),
        ("resources/read", json!({"uri": uri})),
        ("resources/list", json!({})),
    ] {
        let body = rpc(&server, &token, &session, 1, method, params);
        assert!(body.get("error").is_none(), "{method}: {body}");
    }

    let tool = rpc(
        &server,
        &token,
        &session,
        2,
        "tools/call",
        json!({"name":"read_junos_skill","arguments":{"name":"junos-config-paths"}}),
    );
    let text = tool["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("routing-instance mgmt_junos"), "{tool}");
    let escape = rpc(
        &server,
        &token,
        &session,
        3,
        "tools/call",
        json!({"name":"read_junos_skill","arguments":{"name":"junos-config-paths","path":"../../Cargo.toml"}}),
    );
    assert_eq!(escape["result"]["isError"], true, "{escape}");
}

#[test]
fn skills_methods_without_a_token_are_401() {
    let (server, token, _dir) = serve(repo_skills_dir().to_str().unwrap(), &["get_device_list"]);
    let session = initialize(server.port, &token);
    for (method, params) in [
        ("skills/list", json!({})),
        (
            "resources/read",
            json!({"uri":"skill://junos-api-lookup/SKILL.md"}),
        ),
    ] {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let none = http_post(server.port, None, Some(&session), body.clone());
        assert_eq!(none.code, 401, "{method}: {}", none.body);
        let wrong = http_post(server.port, Some("not-a-token"), Some(&session), body);
        assert_eq!(wrong.code, 401, "{method}: {}", wrong.body);
    }
}

#[test]
fn skills_dir_missing_starts_without_extension() {
    let (server, token, _dir) = serve("/nonexistent/rust-junosmcp-skills", &["list_junos_skills"]);
    let init = http_post(server.port, Some(&token), None, init_body());
    assert_eq!(init.code, 200, "{}", init.body);
    let capabilities = &init.body["result"]["capabilities"];
    assert!(
        !capabilities.to_string().contains("skills"),
        "{capabilities}"
    );
    assert!(capabilities.get("resources").is_none(), "{capabilities}");

    let session = initialize(server.port, &token);
    let tool = rpc(
        &server,
        &token,
        &session,
        1,
        "tools/call",
        json!({"name":"list_junos_skills","arguments":{}}),
    );
    assert_eq!(tool["result"]["content"][0]["text"], "[]", "{tool}");
}

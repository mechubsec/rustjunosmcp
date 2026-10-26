#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! `--require-verified-proposer` (mecmcp#400) reaches the shipped binary's coordinator:
//! a bound token with no `Mecmcp-Proposer-Assertion` is refused at create, while the
//! same server without the flag accepts it. Needs no IdP: the refusal precedes any
//! assertion verification.

mod common;

use serde_json::json;

fn create_reply(extra_args: &[&str]) -> String {
    let inventory = common::write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let output = std::process::Command::new(common::binary_path())
        .args(["token", "add", "--tokens-file"])
        .arg(&tokens)
        .args(["--name", "alice", "--actor-type", "human", "--devices", "*"])
        .args(["--tools", "create_junos_change_set"])
        .args([
            "--oidc-issuer",
            "https://idp.example.com",
            "--oidc-subject",
            "alice",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let bearer = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let server = common::spawn_with_auth_args(inventory.path(), &tokens, extra_args);
    let session = common::initialize(server.port, &bearer);
    let reply = common::http_post(
        server.port,
        Some(&bearer),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"create_junos_change_set",
            "arguments":{"device":"r1","expected_fingerprint":format!("sha256:{}", "0".repeat(64)),
                "actions":[{"payload":{"text":"set system host-name x","format":"set"}}]}}}),
    );
    assert_eq!(reply.code, 200, "{:?}", reply.body);
    reply.body.to_string()
}

#[test]
fn the_flag_makes_the_server_refuse_an_unverified_proposal() {
    let strict = create_reply(&[
        "--oidc-issuer",
        "https://idp.example.com",
        "--oidc-audience",
        "junos-mcp",
        "--require-verified-proposer",
    ]);
    assert!(strict.contains("verified-proposer"), "{strict}");
    assert!(!strict.contains("change set created"), "{strict}");

    let lax = create_reply(&[]);
    assert!(lax.contains("change set created"), "{lax}");
}

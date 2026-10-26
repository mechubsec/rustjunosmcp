#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Static-token `device_selectors` (mecmcp#400) through the shipped binary: a token
//! minted with `token add --device-selector site=lab-*` sees only the inventory
//! devices whose attributes match, and a plain token is unaffected.

mod common;

use serde_json::json;

const PW: &str = r#""username":"u","auth":{"type":"password","password":"x"}"#;

fn mint(tokens: &std::path::Path, name: &str, selectors: &[&str]) -> String {
    let mut command = std::process::Command::new(common::binary_path());
    command
        .args(["token", "add", "--tokens-file"])
        .arg(tokens)
        .args([
            "--name",
            name,
            "--tools",
            "get_router_list",
            "--devices",
            "*",
        ]);
    for selector in selectors {
        command.args(["--device-selector", selector]);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn router_list(port: u16, bearer: &str) -> String {
    let session = common::initialize(port, bearer);
    let reply = common::http_post(
        port,
        Some(bearer),
        Some(&session),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
               "params":{"name":"get_router_list","arguments":{}}}),
    );
    assert_eq!(reply.code, 200, "{:?}", reply.body);
    reply.body.to_string()
}

#[test]
fn a_selector_token_sees_only_matching_devices() {
    let inventory = common::write_inv(&format!(
        r#"{{"lab-a":{{"ip":"203.0.113.1","port":1,{PW},"attributes":{{"site":"lab-1"}}}},
            "prod-a":{{"ip":"203.0.113.2","port":1,{PW},"attributes":{{"site":"emea-lon"}}}},
            "bare":{{"ip":"203.0.113.3","port":1,{PW}}}}}"#
    ));
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let scoped = mint(&tokens, "lab-only", &["site=lab-*"]);
    let plain = mint(&tokens, "everything", &[]);
    let server = common::spawn(inventory.path(), &tokens);

    let seen = router_list(server.port, &scoped);
    assert!(seen.contains("lab-a"), "{seen}");
    assert!(!seen.contains("prod-a"), "{seen}");
    assert!(
        !seen.contains("bare"),
        "an unlabelled device never matches: {seen}"
    );

    let all = router_list(server.port, &plain);
    assert!(
        all.contains("lab-a") && all.contains("prod-a") && all.contains("bare"),
        "{all}"
    );
}

#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Scope preflight tests: assert that out-of-scope requests are rejected
//! before dispatch, not merely that they fail.

mod common;
use common::*;
use rust_junosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::{Value, json};

fn tool_allowlist(names: &[&str]) -> ScopeSet {
    ScopeSet::Allowlist(names.iter().map(|name| (*name).to_owned()).collect())
}

fn scoped_requests(tools: ScopeSet, requests: Vec<Value>) -> Vec<PostResult> {
    ensure_built();
    // An empty inventory guarantees these scope/validation tests cannot contact devices.
    let inv = write_inv("{}");
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "execute-preflight",
        ScopeSet::Allowlist(vec!["r1".into()]),
        tools,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();
    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    requests
        .into_iter()
        .map(|request| {
            http_post(
                server.port,
                Some(secret.expose_secret()),
                Some(&session),
                request,
            )
        })
        .collect()
}

fn execute_request(arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"execute","arguments":arguments
    }})
}

fn assert_scope_denied(response: &PostResult) {
    assert_eq!(response.code, 403, "{}", response.body);
    assert_eq!(response.body["error"], "insufficient_scope");
}

fn assert_tool_success(response: &PostResult) {
    assert_eq!(response.code, 200, "{}", response.body);
    assert!(response.body.get("error").is_none(), "{}", response.body);
    assert!(
        response.body["result"]["content"].is_array(),
        "{}",
        response.body
    );
    assert_ne!(
        response.body["result"]["isError"], true,
        "{}",
        response.body
    );
}

#[test]
fn execute_requires_both_outer_and_concrete_tool_scope() {
    for tools in [
        tool_allowlist(&["execute"]),
        tool_allowlist(&["get_device_list"]),
        ScopeSet::Wildcard,
    ] {
        let responses = scoped_requests(
            tools,
            vec![execute_request(
                json!({"operation":"get_device_list","arguments":{}}),
            )],
        );
        assert_scope_denied(&responses[0]);
    }
}

#[test]
fn execute_with_both_tool_scopes_succeeds() {
    let responses = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        vec![execute_request(
            json!({"operation":"get_device_list","arguments":{}}),
        )],
    );
    assert_tool_success(&responses[0]);
}

#[test]
fn execute_read_scope_cannot_invoke_a_write() {
    let responses = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        vec![execute_request(
            json!({"operation":"load_and_commit_config","arguments":{
                "router":"r1","config_text":"set system login message test","commit_comment":"test"
            }}),
        )],
    );
    assert_scope_denied(&responses[0]);
}

#[test]
fn execute_nested_gather_device_facts_scope_is_denied() {
    let responses = scoped_requests(
        tool_allowlist(&["execute", "gather_device_facts"]),
        vec![execute_request(
            json!({"operation":"gather_device_facts","arguments":{"device":"r2"}}),
        )],
    );
    assert_scope_denied(&responses[0]);
}

#[test]
fn execute_checks_all_nested_selector_spellings_and_shapes() {
    let mut cases = Vec::new();
    for key in [
        "device",
        "device_name",
        "devices",
        "device_names",
        "router",
        "router_name",
        "routers",
        "router_names",
    ] {
        for value in [
            json!("r2"),
            json!(["r1", "r2"]),
            json!([]),
            json!(["r1", 1]),
            json!(null),
            json!(1),
            json!(true),
            json!({"name":"r1"}),
        ] {
            cases.push(json!({"operation":"get_device_list","arguments":{key:value}}));
        }
    }
    let responses = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        cases.iter().cloned().map(execute_request).collect(),
    );
    let failures: Vec<_> = cases
        .iter()
        .zip(&responses)
        .filter(|(_, response)| {
            response.code != 403 || response.body["error"] != "insufficient_scope"
        })
        .map(|(case, response)| format!("{case}: HTTP {} {}", response.code, response.body))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn execute_checks_every_nested_selector_even_after_an_allowed_one() {
    let responses = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        vec![execute_request(
            json!({"operation":"get_device_list","arguments":{
                "device":"r1","router_names":["r2"]
            }}),
        )],
    );
    assert_scope_denied(&responses[0]);
}

#[test]
fn execute_in_scope_nested_selectors_reach_concrete_validation() {
    let requests = [json!("r1"), json!(["r1"])]
        .into_iter()
        .map(|value| {
            execute_request(json!({"operation":"get_device_list","arguments":{
                "device":value,"device_name":value,"devices":value,"device_names":value,
                "router":value,"router_name":value,"routers":value,"router_names":value
            }}))
        })
        .collect();
    for response in scoped_requests(tool_allowlist(&["execute", "get_device_list"]), requests) {
        // get_device_list has no selectors: reaching its strict argument parser
        // proves preflight passed without requiring device I/O.
        assert_eq!(response.code, 200, "{}", response.body);
        assert_eq!(
            response.body["result"]["isError"], true,
            "{}",
            response.body
        );
        assert!(
            response.body["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("failed to deserialize parameters:")
        );
    }
}

#[test]
fn execute_unknown_or_recursive_operation_reaches_repair() {
    let requests = ["friendly_facts", "execute", " get_device_list"]
        .into_iter()
        .map(|operation| {
            // Unknown operations never dispatch, so nested selectors must not suppress repair.
            execute_request(json!({"operation":operation,"arguments":{"device":"r2"}}))
        })
        .collect();
    for response in scoped_requests(tool_allowlist(&["execute"]), requests) {
        assert_eq!(response.code, 200, "{}", response.body);
        assert_eq!(
            response.body["result"]["isError"], true,
            "{}",
            response.body
        );
        assert!(
            response.body["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("RJMCP_EXECUTE_UNKNOWN_OPERATION")
        );
    }
}

#[test]
fn execute_malformed_inner_shape_reaches_strict_validation() {
    let mut arguments = vec![
        json!({}),
        json!({"arguments":{}}),
        json!({"operation":null,"arguments":{}}),
        json!({"operation":12,"arguments":{}}),
        json!({"operation":"get_device_list"}),
    ];
    for value in [json!(null), json!([]), json!("r1"), json!(1), json!(true)] {
        arguments.push(json!({"operation":"get_device_list","arguments":value}));
    }
    for response in scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        arguments.into_iter().map(execute_request).collect(),
    ) {
        assert_eq!(response.code, 200, "{}", response.body);
        assert_eq!(
            response.body["result"]["isError"], true,
            "{}",
            response.body
        );
        assert!(
            response.body["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .starts_with("failed to deserialize parameters:")
        );
    }
}

#[test]
fn execute_outer_scope_precedes_malformed_or_unknown_repair() {
    let mut requests: Vec<_> = [
        json!({}),
        json!(null),
        json!([]),
        json!({"operation":"friendly_facts","arguments":{}}),
        json!({"operation":"get_device_list","arguments":[]}),
    ]
    .into_iter()
    .map(execute_request)
    .collect();
    requests
        .push(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute"}}));
    for response in scoped_requests(ScopeSet::Wildcard, requests) {
        assert_scope_denied(&response);
    }
}

#[test]
fn execute_known_concrete_scope_precedes_malformed_inner_arguments() {
    let requests = [
        json!({"operation":"get_device_list"}),
        json!({"operation":"get_device_list","arguments":[]}),
    ]
    .into_iter()
    .map(execute_request)
    .collect();
    for response in scoped_requests(tool_allowlist(&["execute"]), requests) {
        assert_scope_denied(&response);
    }
}

#[test]
fn execute_malformed_outer_arguments_reach_protocol_or_handler_validation() {
    let mut requests: Vec<_> = [json!(null), json!([]), json!(true), json!(1), json!("bad")]
        .into_iter()
        .map(execute_request)
        .collect();
    requests
        .push(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute"}}));
    for response in scoped_requests(tool_allowlist(&["execute"]), requests) {
        assert!(
            matches!(response.code, 200 | 415),
            "HTTP {} {}",
            response.code,
            response.body
        );
        if response.code == 200 {
            // A missing outer `arguments` field is rejected by rmcp before it
            // reaches the tool, while the other malformed shapes reach the
            // strict facade. Both prove that HTTP preflight deliberately left
            // outer-shape validation to the protocol/handler layer.
            assert!(
                response.body["result"]["isError"] == true || response.body["error"].is_object(),
                "{}",
                response.body
            );
        }
    }
}

#[test]
fn execute_srx_recognition_matches_compiled_features() {
    let responses = scoped_requests(
        tool_allowlist(&["execute"]),
        vec![execute_request(
            json!({"operation":"srxmcp_status","arguments":{}}),
        )],
    );
    #[cfg(feature = "srx")]
    assert_scope_denied(&responses[0]);
    #[cfg(not(feature = "srx"))]
    {
        assert_eq!(responses[0].code, 200, "{}", responses[0].body);
        assert_eq!(responses[0].body["result"]["isError"], true);
        assert!(
            responses[0]
                .body
                .to_string()
                .contains("RJMCP_EXECUTE_UNKNOWN_OPERATION")
        );
    }
}

#[test]
fn execute_batch_with_denied_concrete_scope_is_refused() {
    let direct = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"get_router_list","arguments":{}
    }});
    let facade = execute_request(json!({"operation":"get_device_list","arguments":{}}));
    for response in scoped_requests(
        tool_allowlist(&["execute", "get_router_list"]),
        vec![json!([direct, facade]), json!([facade, direct])],
    ) {
        assert_scope_denied(&response);
    }
}

#[test]
fn execute_batch_with_denied_nested_device_is_refused() {
    let response = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        vec![json!([
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_device_list","arguments":{}}},
            execute_request(json!({"operation":"get_device_list","arguments":{"device":"r2"}}))
        ])],
    );
    assert_scope_denied(&response[0]);
}

#[test]
fn execute_authorized_batch_reaches_existing_transport_validation() {
    let facade = execute_request(json!({"operation":"get_device_list","arguments":{}}));
    let direct = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"get_device_list","arguments":{}
    }});
    let responses = scoped_requests(
        tool_allowlist(&["execute", "get_device_list"]),
        vec![json!([facade, direct]), facade, direct],
    );
    // rmcp accepts single JSON-RPC messages only. The batch passes preflight
    // (also covered directly in unit tests), then fails protocol deserialization.
    assert_eq!(responses[0].code, 415, "{}", responses[0].body);
    assert!(
        responses[0].body["raw"]
            .as_str()
            .unwrap()
            .contains("fail to deserialize request body")
    );
    assert_tool_success(&responses[1]);
    assert_tool_success(&responses[2]);
}

#[test]
fn tool_out_of_scope_rejected_before_dispatch() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "read-only",
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["get_router_list".into()]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt a write tool (load_and_commit_config) that the token doesn't allow
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"load_and_commit_config",
            "arguments":{"router":"r1","config":"set system login message test","comment":"test"}
        }}),
    );

    // Preflight should reject with 403 insufficient_scope
    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(
        response.body["error"], "insufficient_scope",
        "expected insufficient_scope error: {:?}",
        response.body
    );
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router" argument
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":"r2","command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router_name() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router_name" argument
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router_name":"r2","command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_routers() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "routers" argument (array form)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":["r2"],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn device_out_of_scope_rejected_before_dispatch_router_names() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Attempt to access r2 using the "router_names" argument (array form)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"router_names":["r2"],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn in_scope_request_passes_through() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "full-access",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // An in-scope request should succeed (though the command will fail because r1 is fake)
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"get_router_list",
            "arguments":{}
        }}),
    );

    // Should get a 200 response, not 403
    assert_eq!(
        response.code, 200,
        "expected 200, got {}: {}",
        response.code, response.body
    );
    // Result should have content, not an error
    assert!(
        response.body.get("result").is_some(),
        "expected result field: {:?}",
        response.body
    );
}

#[test]
fn batched_request_with_one_out_of_scope_is_refused() {
    ensure_built();
    let inv = write_inv(
        r#"{
            "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
            "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "r1-only",
        ScopeSet::Allowlist(vec!["r1".into()]),
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    // Send a batched request where one element is out of scope
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!([
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_junos_command","arguments":{"router":"r1","command":"show version","timeout":1}}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_junos_command","arguments":{"router":"r2","command":"show version","timeout":1}}}
        ]),
    );

    // The entire batch should be rejected at preflight
    assert_eq!(
        response.code, 403,
        "expected 403, got {}: {}",
        response.code, response.body
    );
    assert_eq!(response.body["error"], "insufficient_scope");
}

// Security bypass tests: ensure malformed inputs are rejected, not silently allowed

#[test]
fn malformed_router_number_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":1,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_object_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":{"x":1},"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_null_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":null,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_router_boolean_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":{"router":true,"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn empty_routers_array_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":[],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn mixed_valid_and_malformed_array_elements_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command_batch",
            "arguments":{"routers":["r1",{"x":1}],"command":"show version","timeout":1}
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn malformed_arguments_non_object_is_denied() {
    ensure_built();
    let inv = write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();

    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());

    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"execute_junos_command",
            "arguments":"not-an-object"
        }}),
    );

    assert_eq!(response.code, 403);
    assert_eq!(response.body["error"], "insufficient_scope");
}

#[test]
fn get_device_list_include_blocklist_omits_out_of_scope_devices() {
    ensure_built();
    let inv = write_inv(
        r#"{
        "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"request system *"}]},
        "r1":{"ip":"192.0.2.1","username":"u","auth":{"type":"password","password":"x"}},
        "r2":{"ip":"192.0.2.2","username":"u","auth":{"type":"password","password":"x"},
              "blocklist":{"commands":[{"action":"deny","pattern":"secret-r2-rule"}]}}
    }"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let tokens = dir.path().join("tokens.json");
    let secret = TokenStoreFile::add(
        &tokens,
        "one-device",
        ScopeSet::Allowlist(vec!["r1".into()]),
        tool_allowlist(&["get_device_list", "get_device_list.include_blocklist"]),
        &KnownNames {
            devices: None,
            tools: rust_junosmcp_auth::KNOWN_TOOLS,
        },
    )
    .unwrap();
    let server = spawn(inv.path(), &tokens);
    let session = initialize(server.port, secret.expose_secret());
    let response = http_post(
        server.port,
        Some(secret.expose_secret()),
        Some(&session),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"get_device_list","arguments":{"include_blocklist":true}}}),
    );
    assert_tool_success(&response);
    let text = response.body["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let listing: Value = serde_json::from_str(text).unwrap();
    let names: Vec<&str> = listing
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["r1"], "{text}");
    assert!(
        !text.contains("secret-r2-rule") && !text.contains("'r2'"),
        "{text}"
    );
}

/// Call `get_device_list` with `arguments` under a token holding `tools`.
fn device_list_call(tools: ScopeSet, arguments: Value) -> PostResult {
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"get_device_list","arguments":arguments}});
    scoped_requests(tools, vec![request]).remove(0)
}

#[test]
fn include_blocklist_requires_its_own_tool_grant() {
    let tools = tool_allowlist(&["get_device_list"]);
    let denied = device_list_call(tools.clone(), json!({"include_blocklist":true}));
    assert_scope_denied(&denied);
    assert_tool_success(&device_list_call(tools.clone(), json!({})));
    assert_tool_success(&device_list_call(tools, json!({"include_blocklist":false})));
}

#[test]
fn include_blocklist_batch_member_is_preflighted() {
    let tools = tool_allowlist(&["get_device_list"]);
    let request = json!([{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"get_device_list","arguments":{"include_blocklist":true}}}]);
    assert_scope_denied(&scoped_requests(tools, vec![request]).remove(0));
}

#[test]
fn include_blocklist_allowed_with_explicit_grant() {
    let tools = tool_allowlist(&["get_device_list", "get_device_list.include_blocklist"]);
    assert_tool_success(&device_list_call(tools, json!({"include_blocklist":true})));
}

#[test]
fn include_blocklist_allowed_for_wildcard_tools() {
    assert_tool_success(&device_list_call(
        ScopeSet::Wildcard,
        json!({"include_blocklist":true}),
    ));
}

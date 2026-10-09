#![allow(clippy::unwrap_used, missing_docs)]
//! Offline contracts for strict execute dispatch through the concrete router.

mod common;
use serde_json::{Value, json};

fn with_server(test: impl FnOnce(&mut common::StdioChild)) {
    let inventory = common::write_inv(
        r#"{"unreachable":{"ip":"127.0.0.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let mut server =
        common::spawn_stdio_server_with_args(&["-f", inventory.path().to_str().unwrap()]);
    test(&mut server);
}

fn execute(server: &mut common::StdioChild, operation: &str, arguments: Value) -> Value {
    common::call_tool(
        server,
        "execute",
        json!({"operation":operation,"arguments":arguments}),
    )
}

fn error_text(result: &Value) -> &str {
    assert_eq!(result["isError"], true, "{result}");
    result
        .pointer("/content/0/text")
        .and_then(Value::as_str)
        .unwrap()
}

#[test]
fn execute_get_device_list_matches_the_direct_tool() {
    with_server(|server| {
        let direct = common::call_tool(server, "get_device_list", json!({}));
        let facade = execute(server, "get_device_list", json!({}));
        assert!(direct.is_array() || direct.is_object());
        assert_ne!(facade["isError"], true);
        assert_eq!(direct, facade);
    });
}

#[test]
fn execute_lists_empty_change_set_store() {
    with_server(|server| {
        let result = execute(server, "list_junos_change_sets", json!({}));
        assert_ne!(result["isError"], true);
        assert_eq!(result, json!([]));
    });
}

#[test]
fn execute_rejects_an_unknown_operation_with_the_exact_allowed_list() {
    with_server(|server| {
        let result = execute(server, "friendly_facts", json!({"secret":"do-not-echo"}));
        let text = error_text(&result);
        assert!(text.contains("RJMCP_EXECUTE_UNKNOWN_OPERATION"));
        assert!(text.contains("friendly_facts"));
        assert!(text.contains("retry with an exact operation name"));
        assert!(!text.contains("do-not-echo"));
        let allowed = text
            .split_once("Allowed operations: ")
            .unwrap()
            .1
            .split(", ")
            .collect::<Vec<_>>();
        let mut expected = rust_junosmcp_auth::JUNOS_TOOLS.to_vec();
        #[cfg(feature = "srx")]
        expected.extend_from_slice(rust_junosmcp_auth::SRX_TOOLS);
        expected.sort_unstable();

        // MEC-859 F2/F4: this message now passes through `redact_last_mile`
        // like every other tool response, since it is a text `ContentBlock`
        // of a `Complete` result the same as any device-derived one. That is
        // a real, known false positive here, not a functional bug in this
        // test's expectation: `mecmcp-redact`'s key denylist matches
        // `session` as a substring, so the tool name `srx_flow_sessions`
        // (`"srxflowsessions"` normalized) is itself flagged as a
        // denylisted key, and everything on the same comma-joined line
        // after it is force-redacted to a single `[REDACTED]` token (see
        // `mecmcp-redact`'s `text::redact_line`/X1). It is tracked as F4 in
        // the MEC-859 review — a `mecmcp` follow-up, not something fixable
        // from this repo — and it is not a security regression: over-
        // redacting a list of this server's own tool names costs
        // discoverability, not a leaked secret.
        #[cfg(feature = "srx")]
        {
            let split_at = expected
                .iter()
                .position(|op| *op == "srx_flow_sessions")
                .expect("srx_flow_sessions must be in SRX_TOOLS");
            let mut with_known_over_redaction = expected[..=split_at].to_vec();
            with_known_over_redaction.push("[REDACTED]");
            assert_eq!(allowed, with_known_over_redaction);
        }
        #[cfg(not(feature = "srx"))]
        assert_eq!(allowed, expected);

        assert!(!allowed.contains(&"execute"));
    });
}

fn rejects_outer(args: Value) {
    with_server(|server| {
        let result = common::call_tool(server, "execute", args);
        assert!(error_text(&result).starts_with("failed to deserialize parameters:"));
    });
}

#[test]
fn execute_rejects_missing_operation() {
    rejects_outer(json!({"arguments":{}}));
}

#[test]
fn execute_rejects_non_object_inner_arguments() {
    rejects_outer(json!({"operation":"get_device_list","arguments":[]}));
}

#[test]
fn execute_rejects_extra_outer_fields() {
    rejects_outer(json!({"operation":"get_device_list","arguments":{},"extra":true}));
}

#[test]
fn execute_bounds_a_very_long_rejected_operation() {
    with_server(|server| {
        let operation = "界".repeat(2048);
        let result = execute(server, &operation, json!({}));
        let text = error_text(&result);
        assert!(text.contains("RJMCP_EXECUTE_UNKNOWN_OPERATION"));
        assert!(!text.contains(&operation));
        assert!(text.matches('界').count() <= 96);
        assert!(text.contains("6144 bytes"));
    });
}

#[test]
fn execute_preserves_inner_typed_argument_rejection() {
    with_server(|server| {
        let result = execute(server, "gather_device_facts", json!({"routre":"r1"}));
        let text = error_text(&result);
        assert!(text.starts_with("failed to deserialize parameters:"));
        assert!(text.contains("device"));
    });
}

#[test]
fn execute_preserves_the_existing_router_alias() {
    with_server(|server| {
        let args = json!({"router":"missing-inventory-device"});
        let direct = common::call_tool(server, "gather_device_facts", args.clone());
        let facade = execute(server, "gather_device_facts", args);
        assert!(!error_text(&direct).contains("failed to deserialize parameters:"));
        assert_eq!(facade, direct);
    });
}

fn routes_connection_error(operation: &str, args: Value) {
    with_server(|server| {
        fn raw_call(server: &mut common::StdioChild, name: &str, args: Value) -> Value {
            use std::io::Write;
            let id = server.next_id;
            server.next_id += 1;
            writeln!(server.stdin, "{}", json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}})).unwrap();
            server.stdin.flush().unwrap();
            let line = server
                .lines
                .wait_for_line(std::time::Duration::from_secs(15), |line| {
                    serde_json::from_str::<Value>(line).is_ok_and(|value| value["id"] == id)
                })
                .unwrap();
            serde_json::from_str(&line).unwrap()
        }
        let result = raw_call(
            server,
            "execute",
            json!({"operation":operation,"arguments":args}),
        );
        if operation == "check_srx_feature_license" {
            assert_eq!(result["error"]["code"], -32603);
        }
        let text = result
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_else(|| error_text(&result["result"]));
        assert!(!text.contains("RJMCP_EXECUTE_UNKNOWN_OPERATION"));
        assert!(!text.contains("failed to deserialize parameters:"));
        assert!(text.to_lowercase().contains("connect"), "{text}");
        let direct = raw_call(server, operation, args);
        assert_eq!(result.get("error"), direct.get("error"));
        let direct_text = direct
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_else(|| error_text(&direct["result"]));
        assert_eq!(text, direct_text);
    });
}

#[test]
fn execute_routes_a_junos_operation_without_mutation() {
    routes_connection_error(
        "gather_device_facts",
        json!({"device":"unreachable","timeout":10}),
    );
}

#[cfg(feature = "srx")]
#[test]
fn execute_routes_an_srx_operation_without_mutation() {
    routes_connection_error(
        "check_srx_feature_license",
        json!({"router":"unreachable","feature":"idp"}),
    );
}

#[test]
fn execute_cannot_recurse() {
    with_server(|server| {
        let result = execute(
            server,
            "execute",
            json!({"operation":"get_device_list","arguments":{}}),
        );
        assert!(error_text(&result).contains("RJMCP_EXECUTE_UNKNOWN_OPERATION"));
    });
}

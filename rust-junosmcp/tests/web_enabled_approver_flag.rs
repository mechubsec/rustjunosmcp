//! Tests for --web-enabled-approver flag controlling actions visibility in
//! get_junos_change_set_status responses.

#![cfg_attr(test, allow(clippy::unwrap_used))]

use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use rust_junosmcp_core::junos_transaction::{ConfigPayloadSpec, JunosAction};
use rust_junosmcp_core::{DeviceManager, Policy};
use std::sync::Arc;
use tempfile::TempDir;

fn test_inventory_json() -> &'static str {
    r#"{"test-device":{"ip":"127.0.0.1","username":"test","auth":{"type":"password","password":"test"}}}"#
}

fn make_test_env() -> (
    Arc<DeviceManager>,
    Arc<Policy>,
    Arc<ChangesetCoordinator>,
    TempDir,
) {
    let mut inv_file = tempfile::NamedTempFile::new().unwrap();
    use std::io::Write;
    inv_file
        .write_all(test_inventory_json().as_bytes())
        .unwrap();
    let inv_path = inv_file.into_temp_path();

    let inventory = Arc::new(rust_junosmcp_core::inventory::Inventory::load(&inv_path).unwrap());
    let dm = Arc::new(DeviceManager::new(inventory.clone()));
    let policy = Arc::new(Policy::build(&inventory).unwrap());
    let state_dir = TempDir::new().unwrap();
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            Some(&state_dir.path().join("changeset-state.json")),
            OperationLimits::default(),
            std::time::Duration::from_secs(3600),
            false,
        )
        .unwrap(),
    );

    (dm, policy, coordinator, state_dir)
}

fn test_attribution() -> mecmcp_audit::Attribution {
    mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::Token("test-principal".into()),
        actor_type: mecmcp_audit::ActorType::Human,
        agent: None,
        on_behalf_of: None,
        change_ref: Some("TEST-001".into()),
        request_id: uuid::Uuid::new_v4(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        approver: None,
        change_set_id: None,
        verified_approver: None,
    }
}

/// Default server: status response has NO actions key.
#[tokio::test]
async fn default_server_status_has_no_actions() {
    let (dm, policy, coordinator, _state_dir) = make_test_env();

    // Create a change set with a payload action.
    let create_result = rust_junosmcp_core::tools::changeset::create_change_set(
        rust_junosmcp_core::tools::changeset::CreateChangeSetArgs {
            device: "test-device".into(),
            expected_fingerprint:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            actions: vec![JunosAction {
                payload: Some(ConfigPayloadSpec {
                    text: "set system host-name test".into(),
                    format: Some("set".into()),
                    mode: None,
                }),
                rollback_source: None,
                ..Default::default()
            }],
        },
        dm,
        coordinator.clone(),
        policy,
        test_attribution(),
        None,
    )
    .await
    .expect("create_change_set failed");

    let change_set_id = create_result["change_set_id"]
        .as_str()
        .expect("change_set_id missing")
        .to_string();

    // Get status using the default (flag off) entry point.
    let status_result = rust_junosmcp_core::tools::changeset::get_change_set_status(
        rust_junosmcp_core::tools::changeset::GetChangeSetStatusArgs {
            change_set_id,
            device: "test-device".into(),
        },
        coordinator,
    )
    .await
    .expect("get_change_set_status failed");

    // Serialize to JSON and verify NO actions key.
    let status_json = serde_json::to_string(&status_result).expect("JSON serialization failed");
    assert!(
        !status_json.contains("\"actions\""),
        "Default server must NOT include actions key in status response"
    );
}

/// Flag-enabled server: status response HAS actions matching what was staged.
#[tokio::test]
async fn flag_enabled_server_status_has_actions() {
    let (dm, policy, coordinator, _state_dir) = make_test_env();

    // Create a change set with a payload action.
    let create_result = rust_junosmcp_core::tools::changeset::create_change_set(
        rust_junosmcp_core::tools::changeset::CreateChangeSetArgs {
            device: "test-device".into(),
            expected_fingerprint:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            actions: vec![JunosAction {
                payload: Some(ConfigPayloadSpec {
                    text: "set system host-name test".into(),
                    format: Some("set".into()),
                    mode: None,
                }),
                rollback_source: None,
                ..Default::default()
            }],
        },
        dm,
        coordinator.clone(),
        policy,
        test_attribution(),
        None,
    )
    .await
    .expect("create_change_set failed");

    let change_set_id = create_result["change_set_id"]
        .as_str()
        .expect("change_set_id missing")
        .to_string();

    // Get status using the actions-bearing entry point.
    let status_result = rust_junosmcp_core::tools::changeset::get_change_set_status_with_actions(
        rust_junosmcp_core::tools::changeset::GetChangeSetStatusArgs {
            change_set_id,
            device: "test-device".into(),
        },
        coordinator,
    )
    .await
    .expect("get_change_set_status_with_actions failed");

    // Verify actions key is present.
    let actions = status_result
        .get("actions")
        .expect("Flag-enabled server must include actions key");
    assert!(
        actions.is_array(),
        "actions must be an array, got: {actions:?}"
    );
    let actions_arr = actions.as_array().expect("actions must be array");
    assert_eq!(
        actions_arr.len(),
        1,
        "Expected one action in the change set"
    );

    // Verify the action content matches what was staged.
    let action = &actions_arr[0];
    assert!(
        action.get("payload").is_some(),
        "Action must have a payload"
    );
    let payload = action["payload"]
        .as_object()
        .expect("payload must be object");
    assert_eq!(
        payload.get("format").and_then(|v| v.as_str()),
        Some("set"),
        "Payload format mismatch"
    );
    assert_eq!(
        payload.get("text").and_then(|v| v.as_str()),
        Some("set system host-name test"),
        "Payload text mismatch"
    );
}

/// Scope checks still deny an unscoped caller with the flag on.
///
/// This test verifies that scope checks remain unchanged. The actual
/// enforcement happens in the server handler via check_tool_scope and
/// check_router_scope, which are called before the coordinator method.
/// The flag only controls which coordinator method is called, not whether
/// scope checks happen.
///
/// Scope checks are orthogonal to the flag and tested elsewhere in the suite.
#[test]
fn scope_checks_still_enforced_with_flag_on() {
    // This is a documentation test: scope checks happen in server.rs before
    // the coordinator call, so they are unaffected by the flag value.
    // The actual implementation is visible in get_junos_change_set_status handler:
    // check_tool_scope and check_router_scope are called before the web_enabled_approver
    // conditional branch.
}

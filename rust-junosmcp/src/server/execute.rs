//! Strict operation facade over the compiled concrete tool router.

use super::{JmcpHandler, audit_scope, caller_ctx};
use rmcp::handler::server::{
    router::tool::{ToolRoute, ToolRouter},
    tool::{ToolCallContext, parse_json_object},
};
use rmcp::model::{CallToolRequestParams, CallToolResult, Tool, ToolAnnotations};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) const NAME: &str = "execute";
const UNKNOWN_CODE: &str = "RJMCP_EXECUTE_UNKNOWN_OPERATION";
const MAX_REJECTED_OPERATION_CHARS: usize = 96;
const MAX_OPERATION_CHARS: usize = 128;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecuteArgs {
    pub operation: String,
    pub arguments: Map<String, Value>,
}

pub(super) fn route(concrete: ToolRouter<JmcpHandler>) -> ToolRoute<JmcpHandler> {
    let attr = facade_tool(&concrete.list_all());
    let mut allowed = concrete
        .list_all()
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect::<Vec<_>>();
    allowed.sort_unstable();
    ToolRoute::new_dyn(attr, move |context: ToolCallContext<'_, JmcpHandler>| {
        let concrete = concrete.clone();
        let allowed = allowed.clone();
        Box::pin(async move {
            let caller = caller_ctx(&context.request_context.extensions);
            if let Err(error) = context.service.check_tool_scope(caller, NAME) {
                let mut audit = audit_scope(caller, NAME, "reject", vec![]);
                audit.deny("tool_scope");
                return JmcpHandler::scope_to_call_result(error).map(Into::into);
            }
            let outer = parse_json_object::<ExecuteArgs>(context.arguments.unwrap_or_default())?;
            let operation = if outer
                .operation
                .chars()
                .take(MAX_OPERATION_CHARS + 1)
                .count()
                > MAX_OPERATION_CHARS
            {
                None
            } else {
                allowed.iter().find(|name| name.as_str() == outer.operation)
            };
            let Some(operation) = operation else {
                return Ok(unknown_operation_result(&outer.operation, &allowed, caller).into());
            };
            let mut request =
                CallToolRequestParams::new(operation.clone()).with_arguments(outer.arguments);
            request.input_responses = context.input_responses;
            request.request_state = context.request_state;
            concrete
                .call(ToolCallContext::new(
                    context.service,
                    request,
                    context.request_context,
                ))
                .await
        })
    })
}

fn unknown_operation_result(
    operation: &str,
    allowed: &[String],
    caller: Option<&rust_junosmcp_auth::CallerCtx>,
) -> CallToolResult {
    let summary = operation
        .chars()
        .take(MAX_REJECTED_OPERATION_CHARS)
        .collect::<String>();
    let mut audit = audit_scope(caller, NAME, "reject", vec![]);
    audit.meta("operation", summary.clone());
    audit.meta("operation_bytes", operation.len() as u64);
    audit.fail_kind("unknown_operation", UNKNOWN_CODE);
    super::coded_error(
        mecmcp_server::ToolErrorCode::InvalidArgument,
        &format!(
            "{UNKNOWN_CODE}: rejected operation {summary:?} ({} bytes); retry with an exact operation name. Allowed operations: {}",
            operation.len(),
            allowed.join(", ")
        ),
    )
}

/// Resolve a raw facade operation only when it exactly matches a compiled
/// concrete tool, without echoing caller-controlled strings into audit fields.
pub(super) fn concrete_operation(arguments: Option<&Map<String, Value>>) -> Option<&'static str> {
    let operation = arguments?.get("operation")?.as_str()?;
    let names = rust_junosmcp_auth::JUNOS_TOOLS.iter();
    #[cfg(feature = "srx")]
    let names = names.chain(rust_junosmcp_auth::SRX_TOOLS);
    names.copied().find(|name| *name == operation)
}

fn required_groups(schema: &Value) -> String {
    let mut groups = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for (keyword, separator) in [("allOf", " and "), ("anyOf", " or "), ("oneOf", " or ")] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            let rendered = branches.iter().map(required_groups).collect::<Vec<_>>();
            // An empty branch means different things under conjunction and
            // disjunction, so it cannot be rendered the same way for both.
            //
            // Under `allOf` a branch that requires nothing adds nothing to the
            // requirement, and naming it produced `required: none and none and
            // none` for tools whose only `allOf` members are `not` constraints.
            // A model reading the catalog sees three requirements where there
            // are zero. Under `anyOf`/`oneOf` the same branch is real
            // information -- it is what makes the whole group optional -- so it
            // is still named there.
            let branches = if keyword == "allOf" {
                rendered
                    .into_iter()
                    .filter(|group| !group.is_empty())
                    .collect::<Vec<_>>()
            } else {
                rendered
                    .into_iter()
                    .map(|group| {
                        if group.is_empty() {
                            "none".to_owned()
                        } else {
                            group
                        }
                    })
                    .collect::<Vec<_>>()
            };
            if !branches.is_empty() {
                let joined = branches.join(separator);
                groups.push(if keyword == "allOf" {
                    joined
                } else {
                    format!("({joined})")
                });
            }
        }
    }
    groups.join(" and ")
}

fn catalog(tools: &[Tool]) -> String {
    let mut tools = tools.iter().collect::<Vec<_>>();
    tools.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    tools
        .into_iter()
        .map(|tool| {
            let description = tool.description.as_deref().unwrap_or("");
            let first = description
                .split_once(". ")
                .map_or(description, |(first, _)| first);
            let required = required_groups(&Value::Object((*tool.input_schema).clone()));
            let required = if required.is_empty() {
                "none"
            } else {
                &required
            };
            format!(
                "{}: {}. required: {}",
                tool.name,
                first.trim_end_matches('.'),
                required
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn facade_tool(tools: &[Tool]) -> Tool {
    assert!(
        tools.iter().all(|tool| tool.name != NAME),
        "facade cannot contain itself"
    );
    let mut operation_names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>();
    operation_names.sort_unstable();
    let mut expected = rust_junosmcp_auth::JUNOS_TOOLS.to_vec();
    #[cfg(feature = "srx")]
    expected.extend_from_slice(rust_junosmcp_auth::SRX_TOOLS);
    expected.sort_unstable();
    assert_eq!(
        operation_names, expected,
        "concrete operation registry drift"
    );
    let catalog = catalog(tools);
    let description = "Execute one exact RustJunosMCP operation. Copy a name from the operation enum and pass its arguments unchanged.";
    assert!(
        description.len() + catalog.len() < 32 * 1024,
        "facade description exceeds 32 KiB"
    );
    let schema = json!({
        "type": "object", "additionalProperties": false,
        "required": ["operation", "arguments"],
        "properties": {
            "operation": {"type": "string", "enum": operation_names, "description": catalog},
            "arguments": {"type": "object", "description": "Pass the selected operation's arguments unchanged. Use its exact argument names."}
        }
    });
    let mut tool = Tool::new(
        NAME,
        description,
        Arc::new(schema.as_object().expect("object schema").clone()),
    );
    tool.annotations = Some(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(false),
    );
    tool
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::JmcpHandler;
    use serde_json::{Value, json};

    fn test_tools() -> Vec<rmcp::model::Tool> {
        let router = JmcpHandler::junos_tool_router();
        #[cfg(feature = "srx")]
        let router = router + JmcpHandler::srx_tool_router();
        router.list_all()
    }

    #[test]
    fn schema_is_closed_and_has_the_exact_concrete_enum() {
        let tool = facade_tool(&test_tools());
        let schema = Value::Object((*tool.input_schema).clone());
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["operation", "arguments"]));
        assert_eq!(schema["properties"].as_object().unwrap().len(), 2);
        assert_eq!(schema["properties"]["arguments"]["type"], "object");
        let names = schema["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        let mut expected = rust_junosmcp_auth::JUNOS_TOOLS.to_vec();
        #[cfg(feature = "srx")]
        expected.extend_from_slice(rust_junosmcp_auth::SRX_TOOLS);
        expected.sort_unstable();
        assert_eq!(
            *names,
            expected.iter().map(|name| json!(name)).collect::<Vec<_>>()
        );
        assert_eq!(names.len(), if cfg!(feature = "srx") { 43 } else { 28 });
        assert!(!names.contains(&json!("execute")));
        assert!(
            tool.description.as_ref().unwrap().len()
                + schema["properties"]["operation"]["description"]
                    .as_str()
                    .unwrap()
                    .len()
                < 32 * 1024
        );
    }

    #[test]
    fn compact_catalog_preserves_required_and_alias_groups() {
        let catalog = catalog(&test_tools());
        assert!(catalog.contains("gather_device_facts"));
        assert!(catalog.contains("device"));
        #[cfg(feature = "srx")]
        {
            assert!(catalog.contains("check_srx_feature_license"));
            assert!(catalog.contains("router"));
        }
        assert!(catalog.contains("required"));
    }

    #[test]
    fn recursive_required_groups_preserve_alternatives() {
        let schema = json!({"required":["action"], "allOf":[
            {"anyOf":[{"required":["device"]}, {"required":["router"]}]},
            {"oneOf":[{"required":["file", "checksum"]}, {"required":["package"]}]}
        ]});
        assert_eq!(
            required_groups(&schema),
            "action and (device or router) and (file and checksum or package)"
        );
    }

    #[test]
    fn facade_annotations_are_conservative() {
        let annotations = facade_tool(&test_tools()).annotations.unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(true));
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(false));
    }

    #[test]
    fn concrete_recognition_is_exact_and_feature_aware() {
        for tool in test_tools() {
            let args = json!({"operation":tool.name});
            assert_eq!(
                concrete_operation(args.as_object()),
                Some(tool.name.as_ref())
            );
        }
        assert_eq!(concrete_operation(None), None);
        for args in [
            json!({}),
            json!({"operation":1}),
            json!({"operation":"execute"}),
            json!({"operation":"friendly_facts"}),
            json!({"operation":" get_device_list"}),
        ] {
            assert_eq!(concrete_operation(args.as_object()), None);
        }
        #[cfg(not(feature = "srx"))]
        assert_eq!(
            concrete_operation(json!({"operation":"srxmcp_status"}).as_object()),
            None
        );
    }
}

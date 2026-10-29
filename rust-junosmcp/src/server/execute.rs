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
/// Also the prefix `call_tool` recognises to audit the rejection once, under
/// the concrete operation and its device, like rmcp's own argument errors.
pub(super) const INVALID_ARGUMENT_CODE: &str = "RJMCP_EXECUTE_INVALID_ARGUMENT";
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
    let schemas = concrete
        .list_all()
        .into_iter()
        .map(|tool| (tool.name.into_owned(), tool.input_schema))
        .collect::<std::collections::HashMap<_, _>>();
    ToolRoute::new_dyn(attr, move |context: ToolCallContext<'_, JmcpHandler>| {
        let concrete = concrete.clone();
        let allowed = allowed.clone();
        let schemas = schemas.clone();
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
            if let Some(problem) = schemas
                .get(operation)
                .and_then(|schema| validate_arguments(schema, &outer.arguments))
            {
                return Ok(invalid_argument_result(&problem).into());
            }
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

/// Not audited here: `call_tool` records it under the concrete operation.
fn invalid_argument_result(problem: &str) -> CallToolResult {
    super::coded_error(
        mecmcp_server::ToolErrorCode::InvalidArgument,
        // No operation name: a `session` word later on the line (srx_flow_sessions)
        // makes last-mile redaction blank the quoted field name. The caller sent
        // the operation, and the audit record carries it.
        &format!("{INVALID_ARGUMENT_CODE}: {problem}"),
    )
}

/// Check forwarded arguments against the target tool's input schema before
/// dispatch: top-level `required` names are present and each supplied value
/// has the JSON type its property declares. Returns a message naming only the
/// offending field (never its value), or `None` when the arguments pass.
///
/// Required-ness follows `allOf` (every branch) and `anyOf`/`oneOf` (at least
/// one branch), which is how the device/router alias group is expressed.
///
/// shortcut: `oneOf`'s at-most-one half, `$ref`, `const`, bounds and nested
/// objects are left to the tool's own serde deserialisation; extend here if a
/// tool's schema starts relying on them.
fn validate_arguments(
    schema: &Map<String, Value>,
    arguments: &Map<String, Value>,
) -> Option<String> {
    let properties = schema.get("properties").and_then(Value::as_object)?;
    // An unknown name is usually a typo (`routre`); serde's unknown-field error
    // names it, where "missing device" would point the caller the wrong way.
    if arguments.keys().any(|name| !properties.contains_key(name)) {
        return None;
    }
    if let Some(problem) = missing_required(&Value::Object(schema.clone()), arguments) {
        return Some(problem);
    }
    arguments.iter().find_map(|(name, value)| {
        let declared = properties.get(name)?.get("type")?;
        let declared = match declared {
            Value::String(single) => vec![single.as_str()],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => return None,
        };
        let matches = declared.iter().any(|json_type| match *json_type {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            "null" => value.is_null(),
            _ => true,
        });
        (!matches).then(|| {
            format!(
                "argument {name:?} must be of type {}",
                declared.join(" or ")
            )
        })
    })
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

/// The first unmet requirement in `schema`, named from the schema only.
fn missing_required(schema: &Value, arguments: &Map<String, Value>) -> Option<String> {
    let missing = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find(|name| !arguments.contains_key(*name));
    if let Some(name) = missing {
        return Some(format!("missing required argument {name:?}"));
    }
    let branches = |keyword| schema.get(keyword).and_then(Value::as_array);
    if let Some(problem) = branches("allOf")
        .into_iter()
        .flatten()
        .find_map(|branch| missing_required(branch, arguments))
    {
        return Some(problem);
    }
    for keyword in ["anyOf", "oneOf"] {
        let Some(alternatives) = branches(keyword) else {
            continue;
        };
        if !alternatives
            .iter()
            .any(|branch| missing_required(branch, arguments).is_none())
        {
            let group = alternatives
                .iter()
                .map(required_groups)
                .collect::<Vec<_>>()
                .join(" or ");
            return Some(format!("missing required argument: one of {group}"));
        }
    }
    None
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
        assert_eq!(names.len(), if cfg!(feature = "srx") { 44 } else { 28 });
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
    fn validation_follows_the_device_alias_group() {
        let schema = json!({"allOf":[{"oneOf":[
            {"required":["device"]},{"required":["router_name"]},{"required":["router"]}]}],
            "required":["command"],
            "properties":{"device":{"type":"string"},"router_name":{"type":"string"},
                "router":{"type":"string"},"command":{"type":"string"}}});
        let schema = schema.as_object().unwrap();
        let check = |args: Value| validate_arguments(schema, args.as_object().unwrap());
        assert_eq!(check(json!({"command":"x","router":"r1"})), None);
        let missing = check(json!({"command":"x"})).unwrap();
        assert!(
            missing.contains("device") && missing.contains("router_name"),
            "{missing}"
        );
        assert!(
            check(json!({"router":"r1"}))
                .unwrap()
                .contains("\"command\"")
        );
        // A typo is left to serde, whose unknown-field error names it.
        assert_eq!(check(json!({"command":"x","routre":"r1"})), None);
    }

    #[test]
    fn validation_flags_missing_required_and_wrong_types_without_values() {
        let schema = json!({"required":["a"],"properties":{
            "a":{"type":"string"},"n":{"type":["integer","null"]},"b":{"type":"boolean"},
            "r":{"$ref":"#/x"}}});
        let schema = schema.as_object().unwrap();
        let check = |args: Value| validate_arguments(schema, args.as_object().unwrap());
        assert_eq!(check(json!({"a":"x","n":null,"b":true,"r":1})), None);
        assert!(check(json!({})).unwrap().contains("\"a\""));
        let wrong = check(json!({"a":"x","n":"s3cret"})).unwrap();
        assert!(wrong.contains("\"n\"") && !wrong.contains("s3cret"));
        assert!(check(json!({"a":"x","n":1.5})).is_some());
        assert!(check(json!({"a":7})).is_some());
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

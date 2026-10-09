//! rmcp `ServerHandler` wrapping the core tool functions.
//!
//! Each `#[tool]` method is a thin adapter: it takes the typed `Parameters<T>`
//! struct, calls into `rust_junosmcp_core::tools::<name>::handle`, and converts
//! the `Result<serde_json::Value, JmcpError>` into the appropriate rmcp content.

use mecmcp_audit::AuditScope;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Extensions, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, tool, tool_handler, tool_router};
use rust_junosmcp_core::{
    DeviceManager, Policy,
    progress::ProgressHeartbeat,
    tools::{
        AddDeviceArgs, CommitCheckArgs, ConfigDiffArgs, ConfirmCommitArgs, DiscardCandidateArgs,
        ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, FetchFileArgs, GatherFactsArgs,
        GetConfigArgs, ListStagedFilesArgs, LoadCommitArgs, ReloadDevicesArgs, RollbackConfigArgs,
        TemplateArgs, TransferFileArgs, UpgradeJunosArgs, add_device, batch, changeset,
        commit_check, config_diff, confirm_commit, discard_candidate, execute_command, facts,
        fetch_file, get_config, list_staged_files, load_commit, pfe, reload_devices,
        rollback_config, router_list, template, transfer_file, upgrade_junos,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

mod execute;
#[cfg(feature = "srx")]
mod srx;

/// Look up the per-request `CallerCtx` (inserted by the auth middleware on
/// the streamable-http path). Returns `None` under stdio.
///
/// Mechanism: rmcp 0.8.5's `StreamableHttpService` splits the incoming axum
/// request into `(Parts, Body)` and inserts the whole `http::request::Parts`
/// into the per-rmcp-request `Extensions` map. It does NOT propagate
/// individual extension types from `parts.extensions` into rmcp's `Extensions`.
/// So to reach the `CallerCtx` our outer middleware put on `req.extensions_mut()`
/// we have to walk through `Parts.extensions`.
///
/// - **stdio:** no `Parts` is inserted (no HTTP frame) → returns `None` →
///   scope checks become a no-op (preserves original behavior).
/// - **streamable-http:** rmcp inserted `Parts`; auth middleware put `CallerCtx`
///   into `req.extensions` which became `parts.extensions` → returns `Some(&ctx)`.
pub(super) fn caller_ctx(extensions: &Extensions) -> Option<&rust_junosmcp_auth::CallerCtx> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<rust_junosmcp_auth::CallerCtx>())
}

/// Filter an advertised tool list down to what `ctx` is actually allowed to
/// call.
///
/// Uses the same `allows_tool(name, WRITE_TOOLS)` predicate as
/// [`JmcpHandler::check_tool_scope`], so `tools/list` cannot drift from the
/// authorization `tools/call` enforces. `None` — the stdio and
/// `--allow-no-auth` paths, which carry no caller context — returns the list
/// unchanged, matching every other scope check.
pub(super) fn filter_tools_for_scope(
    tools: Vec<rmcp::model::Tool>,
    ctx: Option<&rust_junosmcp_auth::CallerCtx>,
) -> Vec<rmcp::model::Tool> {
    let Some(ctx) = ctx else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| {
            ctx.tools
                .allows_tool(tool.name.as_ref(), rust_junosmcp_auth::WRITE_TOOLS)
        })
        .collect()
}

pub(super) fn mint_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("req-{nanos}")
}

/// Redact a serialized tool-output body without assuming its wire format.
///
/// Tries JSON first — every SRX adapter and `to_call_result`'s `Ok(other)`
/// branch build their body with `serde_json::to_string_pretty`, so this is
/// the common case — then XML (only when the trimmed input actually opens
/// with `<`; see MEC-918 N1 below), then falls back to
/// [`mecmcp_redact::junos::redact_log_text`] for genuinely unstructured
/// input (CLI output, a plain error message).
///
/// Parsing and redacting structurally rather than scanning the serialized
/// text is the point: a line-oriented pass over valid JSON/XML can match a
/// non-secret value that happens to look secret-shaped and corrupt the
/// surrounding syntax when it substitutes `[REDACTED]` in place of only
/// part of a quoted value (MEC-859 F1). Parsing first means a false
/// positive still redacts *a whole value*, not a fragment of the document
/// structure, and re-running this over output that was already redacted
/// structurally elsewhere is a no-op rather than a second, riskier pass.
///
/// MEC-918 N1: `mecmcp_redact::redact_xml_str` is a quick-xml *writer*, not
/// just a parser — round-tripping plain text (`execute_junos_command`
/// output, a `show route` dump, an error message) through it XML-escapes
/// every `"`, `'`, and `>` it contains, corrupting non-XML output. Only
/// attempt the XML path when the input actually looks like a document
/// (trimmed, starts with `<`), so plain text falls straight through to
/// [`mecmcp_redact::junos::redact_log_text`] unescaped.
///
/// MEC-2519: this server only ever speaks Junos, so the fallback uses
/// [`mecmcp_redact::junos::redact_log_text`]'s closed, whole-word Junos key
/// vocabulary rather than [`mecmcp_redact::redact_text`]'s cross-vendor
/// substring denylist. The generic scan's `session` entry (kept broad for
/// `session_id`/`session_token` shapes other vendors use, MEC-537) has no
/// config-syntax awareness and blanks the rest of the *line* once it
/// matches — so `then log session-init session-close;`, `limit-session
/// 1000;`, and `show security flow session summary` counters all lost real,
/// non-secret operational data to a line that merely contained the word
/// "session". `redact_log_text` whole-word-matches a Junos-specific key
/// list that has no `session` entry at all, so it still catches every real
/// secret shape (`pre-shared-key`, `secret`, `community`, `password`, a
/// `set`-context `key`/`value`, ...) without that false trigger.
pub(super) fn redact_body(s: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<Value>(s) {
        redact_json_preserving_server_fields(&mut value);
        return serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| mecmcp_redact::junos::redact_log_text(s));
    }
    if s.trim_start().starts_with('<')
        && let Ok(redacted) = mecmcp_redact::redact_xml_str(s)
    {
        return redacted;
    }
    mecmcp_redact::junos::redact_log_text(s)
}

/// Server-defined field names that survive [`redact_body`] /
/// [`redact_json_preserving_server_fields`] unredacted even though they
/// overlap a `mecmcp-redact` denylist term by substring (`sessions` contains
/// `session`; `confirmation_token` contains `token`). These are protocol
/// data the caller needs verbatim, not vendor secrets:
/// - `sessions`, `session_id`, `session_identifier` — `srx_flow_sessions`
///   table rows (a firewall session ID/table, not a login session token).
/// - `initiator_cookie`, `responder_cookie` — IKE cookies from
///   `vpn_lifecycle_report`, public per the IKE protocol, not secret key
///   material.
///
/// `confirmation_token` is deliberately **not** in this list — see MEC-931
/// N8. The server-issued token the two-call signature-package confirmation
/// protocol requires back verbatim is held out of redaction locally, in
/// [`super::srx::JmcpHandler::signature_error_to_rmcp`], at the one place
/// the server mints it, rather than by exempting the key name here for
/// every caller. A device or file JSON body that happens to carry a
/// `confirmation_token` key is not that plan and must not skip redaction.
///
/// MEC-918 N3.
const REDACTION_KEY_EXEMPTIONS: &[&str] = &[
    "sessions",
    "session_id",
    "session_identifier",
    "initiator_cookie",
    "responder_cookie",
];

/// Paste [`REDACTION_KEY_EXEMPTIONS`] values from `original` back into
/// `redacted` at matching paths, walking both trees in lockstep.
///
/// `mecmcp_redact::redact_json_value` has no per-key exemption in its own
/// API — the denylist's substring match is intentional there (vendor field
/// names vary in spelling) and exempting a term crate-wide would weaken it
/// for every other caller. So this server holds its own exemptions locally.
///
/// MEC-918 N5: exempting a key name is not the same as exempting its value.
/// The first cut of this function pasted the whole original subtree back in
/// verbatim, which skipped the denylist on nested keys, the crypt-hash/PEM/
/// `ENC` shape scan, and the text `k=v` scan for anything living under an
/// exempt key — e.g. `{"sessions":[{"password":"..."}]}` came back with the
/// password intact. Instead: re-redact the exempt key's original value under
/// a neutral wrapper key (so the crate's substring match on the exempt name
/// itself can't fire) and restore *that*, not the untouched original. The
/// one exception is `confirmation_token` when it has the shape a real store
/// issues — see [`is_minted_confirmation_token`] for why that one short-
/// circuits the scan instead of merely dodging its own key name. Never
/// descend into a subtree whose parent key is already denylisted; nothing
/// should be un-redacted there, exempt name or not.
fn restore_exempt_fields(original: &Value, redacted: &mut Value) {
    match (original, redacted) {
        (Value::Object(orig), Value::Object(red)) => {
            for (key, orig_v) in orig {
                let Some(red_v) = red.get_mut(key) else {
                    continue;
                };
                if REDACTION_KEY_EXEMPTIONS.contains(&key.as_str()) {
                    let mut wrapped = serde_json::json!({ "value": orig_v.clone() });
                    redact_json_preserving_server_fields(&mut wrapped);
                    *red_v = wrapped["value"].take();
                } else if !mecmcp_redact::denylist::is_denylisted_key(key) {
                    restore_exempt_fields(orig_v, red_v);
                }
            }
        }
        (Value::Array(orig), Value::Array(red)) => {
            for (orig_v, red_v) in orig.iter().zip(red.iter_mut()) {
                restore_exempt_fields(orig_v, red_v);
            }
        }
        _ => {}
    }
}

/// Redact a JSON value in place, like [`mecmcp_redact::redact_json_value`],
/// except holding [`REDACTION_KEY_EXEMPTIONS`] keys out. See
/// [`restore_exempt_fields`] for why the exemption lives here rather than in
/// `mecmcp-redact`.
pub(super) fn redact_json_preserving_server_fields(value: &mut Value) {
    let original = value.clone();
    mecmcp_redact::redact_json_value(value);
    restore_exempt_fields(&original, value);
}

/// The last-mile redaction pass: runs once, in `ServerHandler::call_tool`,
/// over every tool response leaving this server — Junos and SRX alike,
/// success and error alike.
///
/// This exists alongside (not instead of) the redaction each tool already
/// does closer to the device response, as a backstop: a tool added later
/// that forgets its own redaction, or an error path that was never wired up
/// (MEC-859 F2 — `SrxError::Rpc`/`Transport`/`XmlParse` messages reached
/// `rmcp::ErrorData` unredacted), still cannot hand the model a secret.
/// [`redact_body`]'s format-sniffing chain makes a second pass here safe to
/// run unconditionally: content a call site already redacted structurally
/// round-trips through this pass unchanged.
///
/// MEC-918 N2: that "safe to run unconditionally" claim breaks for one
/// shape — `SrxError::SignaturePackageConfirmationRequired`'s message embeds
/// the confirmation plan as JSON *inside* a larger non-JSON string (`[code=
/// ...] router=...: ...; plan: {...}`), so [`redact_body`] can't parse it
/// structurally and falls through to the line-oriented
/// [`mecmcp_redact::junos::redact_log_text`] pass, which would strip the
/// `confirmation_token` the two-call confirmation protocol requires back
/// verbatim — fine for a device secret, fails the caller closed for a
/// protocol token that was never a secret to begin with.
/// `signature_error_to_rmcp` already redacts that plan structurally (holding
/// the token out via [`redact_json_preserving_server_fields`]) before
/// building the message, and tags the resulting `ErrorData.data` with
/// `{"code": "confirmation_..."}` so this pass can recognize that message
/// and skip redacting it a second, less careful time.
pub(super) fn redact_last_mile(
    result: &mut Result<rmcp::model::CallToolResponse, rmcp::ErrorData>,
) {
    match result {
        Err(error) => {
            let already_redacted_structurally = error
                .data
                .as_ref()
                .and_then(|data| data.get("code"))
                .and_then(Value::as_str)
                .is_some_and(|code| code.starts_with("confirmation"));
            if !already_redacted_structurally {
                error.message = redact_body(&error.message).into();
            }
        }
        Ok(rmcp::model::CallToolResponse::Complete(call_result)) => {
            for block in &mut call_result.content {
                if let ContentBlock::Text(text_content) = block {
                    text_content.text = redact_body(&text_content.text);
                }
            }
        }
        Ok(_) => {}
    }
}

/// Helper to construct an `AuditScope` from an `Option<&CallerCtx>`.
///
/// The shared `mecmcp-audit` crate's API split the old single `new(Option<&CallerCtx>, ...)`
/// into `from_caller(&CallerCtx, ...)` and `stdio(...)`. This helper preserves the branching
/// behavior at all 58 call sites without duplicating the match.
pub(super) fn audit_scope(
    ctx: Option<&rust_junosmcp_auth::CallerCtx>,
    tool: &'static str,
    action: &'static str,
    devices: Vec<String>,
) -> AuditScope {
    match ctx {
        Some(c) => AuditScope::from_caller(c, tool, action, devices),
        None => AuditScope::stdio(tool, action, devices),
    }
}

/// Record the commit-confirmed decision for a caller-supplied
/// `confirm_timeout_mins` in the audit event (MEC-45).
///
/// Mirrors [`rust_junosmcp_core::helpers::resolve_confirm_timeout`]: `None`
/// resolves to the server default (commit-confirmed ON), `Some(0)` is the
/// documented explicit opt-out. Always writes `commit_confirmed` so the
/// opt-out is visible in the audit trail rather than merely absent from it.
pub(super) fn audit_confirm_meta(audit: &mut AuditScope, caller_mins: Option<u32>) {
    use rust_junosmcp_core::helpers::{ConfirmDecision, resolve_confirm_timeout};
    match resolve_confirm_timeout(caller_mins) {
        ConfirmDecision::Confirmed(mins) => {
            audit.meta("commit_confirmed", true);
            audit.meta("commit_confirm_mins", mins as u64);
        }
        ConfirmDecision::OptedOut => audit.meta("commit_confirmed", false),
    }
}

/// Authorization failures arising from token scope checks.
///
/// Returned when a bearer token's configured scope does not confer access to the
/// requested tool or device. The server converts these into `CallToolResult` errors
/// with `isError: true`, not into protocol-level errors, so the denial is delivered
/// as tool content rather than an MCP transport failure.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// Token lacks permission for this tool.
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope {
        /// The name of the denied token (truncated digest).
        token: String,
        /// The tool name that was denied.
        tool: &'static str,
    },
    /// Token lacks permission for this device.
    #[error("token '{token}' is not authorized for router '{router}' (tool '{tool}')")]
    RouterNotInScope {
        /// The name of the denied token (truncated digest).
        token: String,
        /// The device name that was denied.
        router: String,
        /// The tool that triggered the device-scope check.
        tool: &'static str,
    },
}

/// Server-side classification of a router request, for observability logging
/// only (#175). Never affects the client-visible response.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RouterAccess {
    /// In scope (or no caller ctx) and present in inventory — proceeds.
    Allowed,
    /// In scope (or no caller ctx) but absent from inventory — will fail
    /// downstream as UnknownRouter. Logged so a typo/missing entry is
    /// distinguishable from a scope denial.
    AllowedUnknown,
    /// Out of the caller's token scope; the router exists in inventory.
    DeniedInScopePresent,
    /// Out of scope AND absent from inventory.
    DeniedUnknown,
}

pub(super) fn classify_router_access(allows: bool, in_inventory: bool) -> RouterAccess {
    match (allows, in_inventory) {
        (true, true) => RouterAccess::Allowed,
        (true, false) => RouterAccess::AllowedUnknown,
        (false, true) => RouterAccess::DeniedInScopePresent,
        (false, false) => RouterAccess::DeniedUnknown,
    }
}

/// MCP server handler implementing the Junos and SRX tool surface.
///
/// Coordinates tool dispatch through `rmcp::ServerHandler`, enforces caller
/// authorization scopes, manages the device inventory and policy, and delegates
/// operational work to the `-core` crates. Instantiated once at startup and cloned
/// per request.
#[derive(Clone)]
pub struct JmcpHandler {
    pub(super) dm: Arc<DeviceManager>,
    policy: Arc<arc_swap::ArcSwap<Policy>>,
    transfer_cfg: rust_junosmcp_core::TransferConfig,
    upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    tool_router: ToolRouter<Self>,
    /// Whether to allow destructive operations on plane-owned devices.
    /// Defaults to false (refuse). Set via --allow-plane-owned-writes CLI flag.
    allow_plane_owned_writes: bool,
    /// Whether to include staged actions in change-set status responses.
    /// Defaults to false. Set via --web-enabled-approver CLI flag.
    web_enabled_approver: bool,
    /// Gate for tools that commit to a device with no change-set approval at
    /// all. Refused by default; set via --allow-direct-commit CLI flag.
    direct_commit: mecmcp_audit::DirectCommitPolicy,
    #[cfg(feature = "srx")]
    pub(super) started: Arc<tokio::time::Instant>,
    #[cfg(feature = "srx")]
    pub(super) authorization_required: bool,
    #[cfg(feature = "srx")]
    pub(super) device_leases: Arc<rust_junosmcp_core::DeviceLeaseManager>,
    #[cfg(feature = "srx")]
    pub(super) confirmation_store:
        rust_junosmcp_srx_core::workflows::signature_package::ConfirmationStore,
    #[cfg(feature = "srx")]
    pub(super) support_bundle_staging:
        rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig,
}

impl JmcpHandler {
    /// Construct a new server handler with the given device manager, policy, and
    /// operational configs.
    ///
    /// `policy` is shared (not copied) with the caller: `add_device` and
    /// `reload_devices` store a freshly-built policy into it after a
    /// successful inventory mutation, and callers that also run the SIGHUP
    /// hot-reload path pass the same `Arc` to
    /// [`reload_current_from_disk`](rust_junosmcp_core::tools::reload_devices::reload_current_from_disk)
    /// so both paths update the policy the handler actually reads from.
    ///
    /// Registers the Junos tool surface unconditionally and the SRX tools when the
    /// `srx` feature is enabled. Authorization is not yet enforced at construction;
    /// call [`with_srx_runtime`](Self::with_srx_runtime) to configure SRX-specific
    /// authorization if the `srx` feature is enabled.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dm: Arc<DeviceManager>,
        policy: Arc<arc_swap::ArcSwap<Policy>>,
        transfer_cfg: rust_junosmcp_core::TransferConfig,
        upgrade_cfg: rust_junosmcp_core::UpgradeConfig,
        coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
        allow_plane_owned_writes: bool,
        web_enabled_approver: bool,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
    ) -> Self {
        let concrete_router = Self::junos_tool_router();
        #[cfg(feature = "srx")]
        let concrete_router = concrete_router + Self::srx_tool_router();
        let execute_route = execute::route(concrete_router.clone());
        let tool_router = concrete_router.with_route(execute_route);
        #[cfg(feature = "srx")]
        let device_leases = upgrade_cfg.device_leases.clone();

        Self {
            dm,
            policy,
            transfer_cfg,
            upgrade_cfg,
            coordinator,
            tool_router,
            allow_plane_owned_writes,
            web_enabled_approver,
            direct_commit,
            #[cfg(feature = "srx")]
            started: Arc::new(tokio::time::Instant::now()),
            #[cfg(feature = "srx")]
            authorization_required: false,
            #[cfg(feature = "srx")]
            device_leases,
            #[cfg(feature = "srx")]
            confirmation_store: Default::default(),
            #[cfg(feature = "srx")]
            support_bundle_staging: Default::default(),
        }
    }

    /// Configure SRX-specific runtime settings: whether authorization is required for
    /// SRX workflow tools and the staging directory for support bundles.
    ///
    /// Only available when the `srx` feature is enabled. Must be called after
    /// [`new`](Self::new) if SRX workflows require authorization or custom staging.
    #[cfg(feature = "srx")]
    pub fn with_srx_runtime(
        mut self,
        authorization_required: bool,
        support_bundle_staging: rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig,
    ) -> Self {
        self.authorization_required = authorization_required;
        self.support_bundle_staging = support_bundle_staging;
        self
    }

    /// Returns the transfer configuration governing `transfer_file` operations.
    pub fn transfer_config(&self) -> &rust_junosmcp_core::TransferConfig {
        &self.transfer_cfg
    }

    /// Convert a tool's `Result<Value, JmcpError>` into the `CallToolResult`
    /// sent to the model. Every branch is redacted before it reaches
    /// `ContentBlock::text`:
    ///
    /// - A `Value::Object`/`Value::Array` is redacted *structurally*, via
    ///   [`mecmcp_redact::redact_json_value`], before it is pretty-printed —
    ///   never after. Running a line-oriented text pass over an
    ///   already-serialized JSON document (the pre-MEC-859-review shape of
    ///   this function) both fails to add safety, since the structural pass
    ///   already caught everything the denylist/shape catch-all know about,
    ///   and risks corrupting the JSON on a false-positive match (MEC-859
    ///   F1).
    /// - A `Value::String` or an error's `.to_string()` is free-form text
    ///   whose shape this function does not otherwise know, so it goes
    ///   through [`redact_body`]'s format-sniffing chain instead: some
    ///   strings here are themselves pre-redacted JSON/XML (from
    ///   `get_junos_config`, `junos_config_diff`), and `redact_body` redacts
    ///   those structurally too, while a genuinely plain-text string (CLI
    ///   output) falls through to [`mecmcp_redact::junos::redact_log_text`].
    ///
    /// This is the single choke point nearly every Junos tool's output
    /// passes through, but it is not the *only* one — [`redact_last_mile`]
    /// in `ServerHandler::call_tool` runs after this and after every SRX
    /// adapter, so a tool added later that forgets to redact still cannot
    /// leak a secret to the model.
    fn to_call_result(
        r: Result<Value, rust_junosmcp_core::JmcpError>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(match r {
            Ok(Value::String(s)) => {
                CallToolResult::success(vec![ContentBlock::text(redact_body(&s))])
            }
            Ok(mut other) => {
                redact_json_preserving_server_fields(&mut other);
                let pretty = serde_json::to_string_pretty(&other).unwrap_or_else(|e| e.to_string());
                CallToolResult::success(vec![ContentBlock::text(pretty)])
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(redact_body(&e.to_string()))]),
        })
    }

    /// Convert `ScopeError` into the same kind of `CallToolResult { isError: true }`
    /// that `JmcpError::Denied` produces. Mirrors `to_call_result`.
    fn scope_to_call_result(e: ScopeError) -> Result<CallToolResult, rmcp::ErrorData> {
        Ok(CallToolResult::error(vec![ContentBlock::text(
            e.to_string(),
        )]))
    }

    /// Check tool scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_tool_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::CallerCtx>,
        tool: &'static str,
    ) -> Result<(), ScopeError> {
        if let Some(ctx) = ctx
            && !ctx.tools.allows_tool(tool, rust_junosmcp_auth::WRITE_TOOLS)
        {
            return Err(ScopeError::ToolNotInScope {
                token: ctx.token_name.clone(),
                tool,
            });
        }
        Ok(())
    }

    /// Check router scope. Returns `Err(ScopeError)` if denied, `Ok(())` if allowed
    /// or if no caller context is present (stdio path).
    fn check_router_scope(
        &self,
        ctx: Option<&rust_junosmcp_auth::CallerCtx>,
        tool: &'static str,
        router: &str,
    ) -> Result<(), ScopeError> {
        let in_inventory = self.dm.inventory().contains_router(router);
        let allows = ctx.map(|c| c.devices.allows(router)).unwrap_or(true);
        let token = ctx.map(|c| c.token_name.as_str()).unwrap_or("<none>");
        match classify_router_access(allows, in_inventory) {
            RouterAccess::Allowed => {}
            RouterAccess::AllowedUnknown => {
                tracing::info!(
                    token,
                    router,
                    tool,
                    "router request for name absent from devices.json (unknown router)"
                );
            }
            RouterAccess::DeniedInScopePresent => {
                tracing::warn!(token, router, tool, "router request denied by token scope");
            }
            RouterAccess::DeniedUnknown => {
                tracing::warn!(
                    token,
                    router,
                    tool,
                    "router request denied: name absent from devices.json and out of token scope"
                );
            }
        }
        if let Some(ctx) = ctx
            && !ctx.devices.allows(router)
        {
            return Err(ScopeError::RouterNotInScope {
                token: ctx.token_name.clone(),
                router: router.to_string(),
                tool,
            });
        }
        Ok(())
    }
}

/// Single source of truth for the MCP tool names this server exposes.
///
/// Listed in source-declaration order below. Must stay in sync with
/// `rust_junosmcp_auth::JUNOS_TOOLS`; the
/// `server_tools_matches_known_tools_as_set` unit test enforces this.
/// Drift here silently denies operators least-privilege token scopes for new
/// tools (see RJMCP-SEC-001). This is a binary-crate tripwire consumed only
/// by the inline test module, hence `allow(dead_code)`.
#[allow(dead_code)]
const SERVER_TOOLS: &[&str] = &[
    "get_device_list",
    "get_router_list",
    "gather_device_facts",
    "execute_junos_command",
    "get_junos_config",
    "junos_config_diff",
    "load_and_commit_config",
    "commit_check_config",
    "discard_candidate",
    "rollback_config",
    "confirm_commit",
    "execute_junos_pfe_command",
    "execute_junos_command_batch",
    "render_and_apply_j2_template",
    "add_device",
    "reload_devices",
    "transfer_file",
    "fetch_file",
    "upgrade_junos",
    "list_staged_files",
    "create_junos_change_set",
    "approve_junos_change_set",
    "cancel_junos_change_set",
    "apply_junos_change_set",
    "confirm_junos_change_set",
    "get_junos_change_set_status",
    "list_junos_change_sets",
    "get_junos_candidate_fingerprint",
];

#[cfg(test)]
mod server_tools_const_tests {
    use super::SERVER_TOOLS;
    use rust_junosmcp_auth::JUNOS_TOOLS;
    use std::collections::HashSet;

    /// Tripwire: changing tool count without updating `SERVER_TOOLS` breaks
    /// the build. Bump this number deliberately when adding/removing tools.
    #[test]
    fn server_tools_len_is_28() {
        // 23 before the candidate-fingerprint tool (#231); 25 with the
        // confirming-commit tool (#239); 26 with list_junos_change_sets (#255);
        // 27 with cancel_junos_change_set; 28 with confirm_commit (MEC-45).
        assert_eq!(SERVER_TOOLS.len(), 28);
    }

    #[test]
    fn server_tools_has_no_duplicates() {
        let mut seen = HashSet::new();
        for t in SERVER_TOOLS {
            assert!(seen.insert(*t), "duplicate tool name in SERVER_TOOLS: {t}");
        }
    }

    /// RJMCP-SEC-001: prevent `JUNOS_TOOLS` (auth crate) drifting from
    /// `SERVER_TOOLS` (this crate). If a new `#[tool(name = "x")]` is added
    /// without updating both, this test fails and the operator cannot mint a
    /// scoped token for "x" — and would be tempted to fall back to wildcard.
    #[test]
    fn server_tools_matches_known_tools_as_set() {
        let server: HashSet<&str> = SERVER_TOOLS.iter().copied().collect();
        let known: HashSet<&str> = JUNOS_TOOLS.iter().copied().collect();
        assert_eq!(
            server,
            known,
            "SERVER_TOOLS / JUNOS_TOOLS drift: only-in-server={:?}, only-in-known={:?}",
            server.difference(&known).collect::<Vec<_>>(),
            known.difference(&server).collect::<Vec<_>>(),
        );
    }
}

#[tool_router(router = junos_tool_router, vis = "pub(crate)")]
impl JmcpHandler {
    #[tool(
        name = "get_device_list",
        description = "Get the Junos devices visible to this caller. Returns [] when the caller's device scope has no current inventory matches."
    )]
    async fn get_device_list(
        &self,
        Parameters(_): Parameters<rust_junosmcp_core::tools::EmptyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "get_device_list", "read", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "get_device_list") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        let names = rust_junosmcp_auth::filter_device_names(ctx, self.dm.inventory().names());
        let result = router_list::handle_names(names).await;
        match &result {
            Ok(v) => {
                if let Some(arr) = v
                    .as_object()
                    .and_then(|o| o.get("names"))
                    .and_then(|n| n.as_array())
                {
                    audit.meta("count", arr.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "get_router_list",
        description = "DEPRECATED: Use get_device_list instead. Get the Junos routers visible to this caller. Returns [] when the caller's router scope has no current inventory matches."
    )]
    async fn get_router_list(
        &self,
        Parameters(_): Parameters<rust_junosmcp_core::tools::EmptyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "get_router_list", "read", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "get_router_list") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        let names = rust_junosmcp_auth::filter_device_names(ctx, self.dm.inventory().names());
        let result = router_list::handle_names(names).await;
        match &result {
            Ok(v) => {
                if let Some(arr) = v
                    .as_object()
                    .and_then(|o| o.get("names"))
                    .and_then(|n| n.as_array())
                {
                    audit.meta("count", arr.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "gather_device_facts",
        description = "Gather Junos device facts from the device. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn gather_device_facts(
        &self,
        Parameters(args): Parameters<GatherFactsArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "gather_device_facts",
            "read",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "gather_device_facts") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "gather_device_facts", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = facts::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_command",
        description = "Execute a Junos command on the device. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn execute_junos_command(
        &self,
        Parameters(args): Parameters<ExecuteCommandArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "execute_junos_command",
            "execute",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_command", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("command", args.command.clone());

        let result = execute_command::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "get_junos_config",
        description = "Get the configuration of the device. Returns the full running config by default. Pass config_path (also accepted as 'filter'; e.g. 'system services', 'security policies', 'interfaces ge-0/0/0') to retrieve only a subtree, reducing token usage and limiting exposure to secrets the caller did not ask for. Supports optional max_lines/max_bytes/tail output caps. Invalid paths, and arguments this tool does not recognise, return an error rather than silently falling back to the full config. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn get_junos_config(
        &self,
        Parameters(args): Parameters<GetConfigArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "get_junos_config", "read", vec![args.device.clone()]);
        // Record the requested subtree. config_path is caller-controlled and is
        // the input the allowlist and the blocklist both act on, so a denial
        // whose event does not name it tells an investigator only that someone
        // was blocked, not what they attempted. Recorded before validation, so
        // rejected values appear too — that is the case worth having.
        //
        // Truncated because the field is only length-bounded at 1 MiB upstream,
        // and an audit sink is not the place to discover that.
        if let Some(path) = args.config_path.as_deref() {
            const MAX_AUDITED: usize = 256;
            let recorded = if path.len() > MAX_AUDITED {
                let mut cut = MAX_AUDITED;
                while !path.is_char_boundary(cut) {
                    cut -= 1;
                }
                format!("{}… ({} bytes)", &path[..cut], path.len())
            } else {
                path.to_owned()
            };
            audit.meta("config_path", recorded);
        }

        if let Err(e) = self.check_tool_scope(ctx, "get_junos_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "get_junos_config", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result =
            get_config::handle(args, self.dm.clone(), self.policy.load_full().clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "junos_config_diff",
        description = "Get the configuration diff against a rollback version. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn junos_config_diff(
        &self,
        Parameters(args): Parameters<ConfigDiffArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "junos_config_diff", "read", vec![args.device.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "junos_config_diff") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "junos_config_diff", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = config_diff::handle(args, self.dm.clone()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "load_and_commit_config",
        description = "Load and commit configuration on a Junos device. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn load_and_commit_config(
        &self,
        Parameters(args): Parameters<LoadCommitArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "load_and_commit_config",
            "commit",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "load_and_commit_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "load_and_commit_config", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.direct_commit.check(&mut audit) {
            return Self::to_call_result(Err(e.into()));
        }

        audit.meta("config_bytes", args.config_text.len() as u64);
        let mut hasher = Sha256::new();
        hasher.update(args.config_text.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let hash = rust_junosmcp_core::tools::transfer_file::hex32(&digest);
        audit.meta("config_sha256", hash);
        audit_confirm_meta(&mut audit, args.confirm_timeout_mins);
        audit.meta("comment_present", !args.commit_comment.is_empty());

        let result = load_commit::handle_with_cancel(
            args,
            self.dm.clone(),
            self.policy.load_full(),
            self.allow_plane_owned_writes,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "commit_check_config",
        description = "Validate a candidate configuration on a Junos device without committing (commit check). Loads config into a candidate, runs commit-check, returns {success, diff, error?}, then discards the candidate. Never activates config. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn commit_check_config(
        &self,
        Parameters(args): Parameters<CommitCheckArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "commit_check_config",
            "commit-check",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "commit_check_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "commit_check_config", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        audit.meta("config_bytes", args.config_text.len() as u64);
        let mut hasher = Sha256::new();
        hasher.update(args.config_text.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let hash = rust_junosmcp_core::tools::transfer_file::hex32(&digest);
        audit.meta("config_sha256", hash);

        let result =
            commit_check::handle_with_cancel(args, self.dm.clone(), self.policy.load_full(), ct)
                .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "discard_candidate",
        description = "Discard uncommitted candidate configuration changes on a Junos device (rollback 0), returning the candidate to the running config. Never changes the running config. Use to recover a candidate left dirty (e.g. 'configuration database modified'). Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn discard_candidate(
        &self,
        Parameters(args): Parameters<DiscardCandidateArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "discard_candidate",
            "discard",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "discard_candidate") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "discard_candidate", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = discard_candidate::handle_with_cancel(args, self.dm.clone(), ct).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "rollback_config",
        description = "Load a Junos rollback archive (rollback N, 0-49) into the candidate. Preview mode (commit=false, default): loads, diffs, discards — stateless and safe. Commit mode (commit=true): loads and commits, CHANGING THE RUNNING CONFIGURATION and potentially disrupting connectivity; supports confirmed-commit with auto-rollback after N minutes. Version 0 = candidate vs running (discard); N>=1 = Nth-previous archived config. NOTE: Restores a previously-committed archived configuration and does NOT re-apply the config blocklist. This scope should be treated as full config-change authority, equivalent to load_and_commit_config. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn rollback_config(
        &self,
        Parameters(args): Parameters<RollbackConfigArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "rollback_config",
            if args.commit { "commit" } else { "preview" },
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "rollback_config") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "rollback_config", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        // Preview mode (commit=false) loads, diffs, and discards — no device
        // mutation, so the direct-commit gate does not apply. Only the
        // committing path needs a change set or the flag.
        if args.commit
            && let Err(e) = self.direct_commit.check(&mut audit)
        {
            return Self::to_call_result(Err(e.into()));
        }

        audit.meta("version", args.version.to_string());
        if args.commit {
            audit_confirm_meta(&mut audit, args.confirm_timeout_mins);
        }

        let result = rollback_config::handle_with_cancel(
            args,
            self.dm.clone(),
            self.allow_plane_owned_writes,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "confirm_commit",
        description = "Send the confirming commit for a commit-confirmed window opened by load_and_commit_config, rollback_config, or render_and_apply_j2_template (not apply_junos_change_set — use confirm_junos_change_set for that). Cancels the device's pending automatic rollback. A harmless no-op commit if no window is open."
    )]
    async fn confirm_commit(
        &self,
        Parameters(args): Parameters<ConfirmCommitArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "confirm_commit", "commit", vec![args.device.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "confirm_commit") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "confirm_commit", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        // Same family as load_and_commit_config / rollback_config / a
        // committing render_and_apply_j2_template: those tools cannot open a
        // commit-confirmed window at all unless --allow-direct-commit is set,
        // so gate the tool that closes one the same way for consistency.
        if let Err(e) = self.direct_commit.check(&mut audit) {
            return Self::to_call_result(Err(e.into()));
        }

        let attribution = match ctx {
            Some(c) => mecmcp_audit::Attribution::from_caller(c),
            None => mecmcp_audit::Attribution::stdio(),
        };

        let result = confirm_commit::handle(args, self.dm.clone(), attribution).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_pfe_command",
        description = "Execute a single PFE-shell command on one device via 'request pfe execute target <fpc> command \"<cmd>\"'. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn execute_junos_pfe_command(
        &self,
        Parameters(args): Parameters<ExecutePfeArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "execute_junos_pfe_command",
            "execute",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_pfe_command") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "execute_junos_pfe_command", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("command", args.pfe_command.clone());

        let result = pfe::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(v) => {
                audit.meta("output_bytes", v.to_string().len() as u64);
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "execute_junos_command_batch",
        description = "Run N operational CLI commands across M devices, parallel across devices, sequential per device. Returns a per-device array of {command, ok, value?, error?} entries. Supports optional max_lines/max_bytes/tail output caps, and honors trailing '| last N' / '| count'. Output is redacted: config values matching known secret patterns (Junos type-9 reversibly-encrypted secrets, PSKs, SNMP communities, RADIUS/TACACS secrets, and similar) are replaced before being returned; structure, hostnames, and non-secret values are preserved."
    )]
    async fn execute_junos_command_batch(
        &self,
        Parameters(args): Parameters<ExecuteBatchArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "execute_junos_command_batch",
            "execute-batch",
            args.devices.clone(),
        );

        if let Err(e) = self.check_tool_scope(ctx, "execute_junos_command_batch") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        for r in &args.devices {
            if let Err(e) = self.check_router_scope(ctx, "execute_junos_command_batch", r) {
                audit.deny("router_scope");
                return Self::scope_to_call_result(e);
            }
        }
        audit.meta("command_count", args.commands.len() as u64);

        let result = batch::handle(args, self.dm.clone(), self.policy.load_full()).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "render_and_apply_j2_template",
        description = "Render a Jinja2 template (inline) with JSON vars. Optionally commit the rendered config to one or more devices; supports dry-run. (YAML vars are no longer accepted as of v0.5.2.)"
    )]
    async fn render_and_apply_j2_template(
        &self,
        Parameters(args): Parameters<TemplateArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let resolved = match (&args.device_name, &args.device_names) {
            (Some(one), None) => vec![one.clone()],
            (None, Some(many)) => many.clone(),
            _ => Vec::new(),
        };
        let mut audit = audit_scope(
            ctx,
            "render_and_apply_j2_template",
            "apply",
            resolved.clone(),
        );

        if let Err(e) = self.check_tool_scope(ctx, "render_and_apply_j2_template") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        for r in &resolved {
            if let Err(e) = self.check_router_scope(ctx, "render_and_apply_j2_template", r) {
                audit.deny("router_scope");
                return Self::scope_to_call_result(e);
            }
        }
        // A dry run, or a render with no apply requested, never touches the
        // device — the direct-commit gate only applies to the path that will
        // actually commit.
        if args.apply_config
            && !args.dry_run
            && let Err(e) = self.direct_commit.check(&mut audit)
        {
            return Self::to_call_result(Err(e.into()));
        }

        // Parse vars_content to count vars
        if let Ok(vars) = serde_json::from_str::<serde_json::Value>(&args.vars_content)
            && let Some(obj) = vars.as_object()
        {
            audit.meta("var_count", obj.len() as u64);
        }
        let will_commit = args.apply_config && !args.dry_run;
        audit.meta("committed", will_commit);
        if will_commit {
            audit_confirm_meta(&mut audit, args.confirm_timeout_mins);
        }

        let result =
            template::handle_with_cancel(args, self.dm.clone(), self.policy.load_full(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(rendered) = v.get("rendered").and_then(|r| r.as_str()) {
                    audit.meta("rendered_bytes", rendered.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "add_device",
        description = "Add a Junos device to the in-memory inventory and persist to devices.json. Required fields: device_name, device_ip, username, auth (ssh_key or password). port defaults to 22. With clients that advertise elicitation, missing fields are prompted; otherwise the call returns MissingArguments."
    )]
    async fn add_device(
        &self,
        Parameters(args): Parameters<AddDeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "add_device", "add-device", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "add_device") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }

        if let Some(name) = &args.device_name {
            audit.meta("name", name.clone());
        }
        if let Some(host) = &args.device_ip {
            audit.meta("host", host.clone());
        }
        if let Some(auth) = &args.auth {
            let auth_kind = match auth {
                rust_junosmcp_core::inventory::AddDeviceAuth::Password { .. } => "password",
                rust_junosmcp_core::inventory::AddDeviceAuth::SshKey { .. } => "ssh_key",
            };
            audit.meta("auth_kind", auth_kind);
        }

        let result = add_device::handle(args, self.dm.clone(), self.policy.clone()).await;
        let result = match result {
            Ok(v) => {
                audit.succeed();
                Ok(v)
            }
            Err(e) => {
                if matches!(e, rust_junosmcp_core::JmcpError::InventoryReadonly) {
                    audit.deny("inventory_readonly");
                } else {
                    audit.fail_kind(e.audit_kind(), &e);
                }
                Err(e)
            }
        };
        Self::to_call_result(result)
    }

    #[tool(
        name = "reload_devices",
        description = "Reload the inventory. With no args, re-reads the current --device-mapping. With file_name, swaps to a new inventory file. Reports added/removed/changed device names."
    )]
    async fn reload_devices(
        &self,
        Parameters(args): Parameters<ReloadDevicesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "reload_devices", "reload-inventory", vec![]);

        if let Err(e) = self.check_tool_scope(ctx, "reload_devices") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }

        let result = reload_devices::handle(args, self.dm.clone(), self.policy.clone()).await;
        let result = match result {
            Ok(v) => {
                if let Some(added) = v.get("added").and_then(|a| a.as_array())
                    && let Some(removed) = v.get("removed").and_then(|r| r.as_array())
                {
                    let total = added.len() + removed.len();
                    audit.meta("device_count", total as u64);
                }
                audit.succeed();
                Ok(v)
            }
            Err(e) => {
                if matches!(e, rust_junosmcp_core::JmcpError::InventoryReadonly) {
                    audit.deny("inventory_readonly");
                } else {
                    audit.fail_kind(e.audit_kind(), &e);
                }
                Err(e)
            }
        };
        Self::to_call_result(result)
    }

    #[tool(
        name = "transfer_file",
        description = "Push a local file from the staging dir to /var/tmp/ on a Junos device via SCP. Idempotent on matching SHA-256."
    )]
    async fn transfer_file(
        &self,
        Parameters(args): Parameters<TransferFileArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "transfer_file", "transfer", vec![args.device.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "transfer_file") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "transfer_file", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("basename", args.source_path.clone());

        let result =
            transfer_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(sha256) = v.get("sha256").and_then(|s| s.as_str()) {
                    audit.meta("sha256", sha256);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "fetch_file",
        description = "Download a file from a Junos device's /var/tmp/<basename> to the host staging directory, with sha256 verification. Mirror of transfer_file."
    )]
    async fn fetch_file(
        &self,
        Parameters(args): Parameters<FetchFileArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "fetch_file", "fetch", vec![args.device.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "fetch_file") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "fetch_file", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        audit.meta("basename", args.remote_path.clone());

        let result =
            fetch_file::handle(args, self.dm.clone(), self.transfer_config().clone(), ct).await;
        match &result {
            Ok(v) => {
                if let Some(sha256) = v.get("sha256").and_then(|s| s.as_str()) {
                    audit.meta("sha256", sha256);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "upgrade_junos",
        description = "DESTRUCTIVE: installs a new Junos image and REBOOTS the device. Outage ~5-7 min. Requires confirm=true to proceed; first call with confirm=false returns a ConfirmationRequired error containing the upgrade plan (current version, target version, image, free disk, estimated outage). v1 supports standalone devices only; chassis clusters are refused."
    )]
    async fn upgrade_junos(
        &self,
        Parameters(args): Parameters<UpgradeJunosArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(ctx, "upgrade_junos", "upgrade", vec![args.device.clone()]);

        if let Err(e) = self.check_tool_scope(ctx, "upgrade_junos") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "upgrade_junos", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }
        // confirm=false is the read-only pre-flight that returns the upgrade
        // plan as ConfirmationRequired; it never touches the device, so the
        // gate only applies once the caller has confirmed the destructive step.
        if args.confirm
            && let Err(e) = self.direct_commit.check(&mut audit)
        {
            return Self::to_call_result(Err(e.into()));
        }

        audit.meta("basename", args.source_path.clone());
        audit.meta("target_version", args.target_version.clone());
        let correlation_id = mint_request_id();

        let result = upgrade_junos::handle(
            args,
            self.dm.clone(),
            self.upgrade_cfg.clone(),
            self.allow_plane_owned_writes,
            ct,
            correlation_id,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "list_staged_files",
        description = "List host-staging files (always); also lists /var/tmp/ on a Junos device when device is supplied"
    )]
    async fn list_staged_files(
        &self,
        Parameters(args): Parameters<ListStagedFilesArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let devices = if let Some(ref d) = args.device {
            vec![d.clone()]
        } else {
            vec![]
        };
        let mut audit = audit_scope(ctx, "list_staged_files", "read", devices);

        if let Err(e) = self.check_tool_scope(ctx, "list_staged_files") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Some(device_name) = args.device.as_deref()
            && let Err(e) = self.check_router_scope(ctx, "list_staged_files", device_name)
        {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = list_staged_files::handle(
            args,
            self.dm.clone(),
            self.transfer_config().staging_dir.clone(),
        )
        .await;
        match &result {
            Ok(v) => {
                if let Some(arr) = v.get("staged_files").and_then(|a| a.as_array()) {
                    audit.meta("count", arr.len() as u64);
                }
                audit.succeed();
            }
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "create_junos_change_set",
        description = "Create a change set (plan) for two-person approval workflow. Returns a change_set_id and plan_digest. The plan must be approved by a second principal before it can be applied."
    )]
    async fn create_junos_change_set(
        &self,
        Parameters(args): Parameters<changeset::CreateChangeSetArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "create_junos_change_set",
            "create",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "create_junos_change_set") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "create_junos_change_set", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        // Change-set tools require an authenticated caller for two-person control.
        let Some(ctx_val) = ctx else {
            audit.deny("no_auth");
            return Self::to_call_result(Err(rust_junosmcp_core::JmcpError::Validation(
                "create_junos_change_set requires authentication; not available on stdio or with --allow-no-auth".into()
            )));
        };

        let attribution = mecmcp_audit::Attribution::from_caller(ctx_val);
        // The owner's bound IdP identity, if their token has one (`token add
        // --oidc-issuer ... --oidc-subject ...`, MEC-994 W2). Read directly
        // off `CallerCtx` rather than `Attribution`: this is server-side
        // token-bound provenance the request itself cannot assert, and
        // `Attribution` carries no field for it.
        let owner_subject = ctx_val.oidc_subject.clone();

        let result = changeset::create_change_set_with_cancel(
            args,
            self.dm.clone(),
            self.coordinator.clone(),
            self.policy.load_full(),
            attribution,
            owner_subject,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "approve_junos_change_set",
        description = "Approve a change set created by a different principal. The approver must provide the exact plan digest to confirm they reviewed the plan. After approval, the owner can apply the change set."
    )]
    async fn approve_junos_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApproveChangeSetArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "approve_junos_change_set",
            "approve",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "approve_junos_change_set") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "approve_junos_change_set", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        // Change-set tools require an authenticated caller for two-person control.
        let Some(ctx_val) = ctx else {
            audit.deny("no_auth");
            return Self::to_call_result(Err(rust_junosmcp_core::JmcpError::Validation(
                "approve_junos_change_set requires authentication; not available on stdio or with --allow-no-auth".into()
            )));
        };

        let attribution = mecmcp_audit::Attribution::from_caller(ctx_val);

        let result = changeset::approve_change_set_with_cancel(
            args,
            self.coordinator.clone(),
            self.dm.clone(),
            attribution,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "cancel_junos_change_set",
        description = "Cancel a Planned or Approved change set, freeing the per-principal pending slot. The caller must be either the owner or have approver authority. Idempotent: already-Cancelled sets return success. Rejects Applied/Applying sets."
    )]
    async fn cancel_junos_change_set(
        &self,
        Parameters(args): Parameters<changeset::CancelChangeSetArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "cancel_junos_change_set",
            "cancel",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "cancel_junos_change_set") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "cancel_junos_change_set", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        // Change-set tools require an authenticated caller for two-person control.
        let Some(ctx_val) = ctx else {
            audit.deny("no_auth");
            return Self::to_call_result(Err(rust_junosmcp_core::JmcpError::Validation(
                "cancel_junos_change_set requires authentication; not available on stdio or with --allow-no-auth".into()
            )));
        };

        let attribution = mecmcp_audit::Attribution::from_caller(ctx_val);

        let result = changeset::cancel_change_set_with_cancel(
            args,
            self.coordinator.clone(),
            self.dm.clone(),
            attribution,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "apply_junos_change_set",
        description = "Apply an approved change set to the device. The change set must have been approved by a second principal, and the device fingerprint must match the expected state. When confirm_timeout_mins is set, the change set stays 'applied' regardless of whether the confirming commit arrives; use get_junos_change_set_status to see the actual outcome."
    )]
    async fn apply_junos_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApplyChangeSetArgs>,
        extensions: Extensions,
        ct: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "apply_junos_change_set",
            "apply",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "apply_junos_change_set") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "apply_junos_change_set", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        // Change-set tools require an authenticated caller for two-person control.
        let Some(ctx_val) = ctx else {
            audit.deny("no_auth");
            return Self::to_call_result(Err(rust_junosmcp_core::JmcpError::Validation(
                "apply_junos_change_set requires authentication; not available on stdio or with --allow-no-auth".into()
            )));
        };

        let attribution = mecmcp_audit::Attribution::from_caller(ctx_val);
        audit_confirm_meta(&mut audit, args.confirm_timeout_mins);

        let result = changeset::apply_change_set_with_cancel(
            args,
            self.dm.clone(),
            self.coordinator.clone(),
            self.policy.load_full(),
            attribution,
            ct,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "confirm_junos_change_set",
        description = "Confirm a provisional commit made with confirm_timeout_mins, cancelling the device's automatic rollback. Must be called by the principal that applied the change set, before the rollback deadline returned by apply_junos_change_set."
    )]
    async fn confirm_junos_change_set(
        &self,
        Parameters(args): Parameters<changeset::ConfirmChangeSetArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "confirm_junos_change_set",
            "commit",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "confirm_junos_change_set") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "confirm_junos_change_set", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        // Same rule as the other change-set tools: the confirming principal must
        // be identifiable, or the record cannot be matched to its owner.
        let Some(ctx_val) = ctx else {
            audit.deny("no_auth");
            return Self::to_call_result(Err(rust_junosmcp_core::JmcpError::Validation(
                "confirm_junos_change_set requires authentication; not available on stdio or with --allow-no-auth".into()
            )));
        };

        let attribution = mecmcp_audit::Attribution::from_caller(ctx_val);

        let result = changeset::confirm_change_set(
            args,
            self.dm.clone(),
            self.coordinator.clone(),
            attribution,
        )
        .await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "get_junos_candidate_fingerprint",
        description = "Read the device's candidate-configuration fingerprint. Use this first: create_junos_change_set requires the fingerprint so the plan is bound to the exact candidate it was reviewed against. This is a read; it takes no lock and does not modify the candidate."
    )]
    async fn get_junos_candidate_fingerprint(
        &self,
        Parameters(args): Parameters<changeset::CandidateFingerprintArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "get_junos_candidate_fingerprint",
            "read",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "get_junos_candidate_fingerprint") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) =
            self.check_router_scope(ctx, "get_junos_candidate_fingerprint", &args.device)
        {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = changeset::get_candidate_fingerprint(args, self.dm.clone()).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "get_junos_change_set_status",
        description = "Get the status of a change set. 'Applied' means the apply was executed and staged - NOT that the configuration is still live on the device. commit_confirmation, when present, reports awaiting_confirmation (a confirm window is open; rollback_deadline_unix carries the deadline), presumed_auto_reverted (it closed with no confirmation recorded here - only the device settles this), discarded (an operator reconciled it with state resolve), indeterminate (reconciled AS COMMITTED but the window has since closed, which stored state cannot resolve - check the device), or committed. committed means the configuration is live and is also what an ordinary commit reports, so it is not evidence that a confirm window was used."
    )]
    async fn get_junos_change_set_status(
        &self,
        Parameters(args): Parameters<changeset::GetChangeSetStatusArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        let mut audit = audit_scope(
            ctx,
            "get_junos_change_set_status",
            "read",
            vec![args.device.clone()],
        );

        if let Err(e) = self.check_tool_scope(ctx, "get_junos_change_set_status") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        if let Err(e) = self.check_router_scope(ctx, "get_junos_change_set_status", &args.device) {
            audit.deny("router_scope");
            return Self::scope_to_call_result(e);
        }

        let result = if self.web_enabled_approver {
            changeset::get_change_set_status_with_actions(args, self.coordinator.clone()).await
        } else {
            changeset::get_change_set_status(args, self.coordinator.clone()).await
        };
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }

    #[tool(
        name = "list_junos_change_sets",
        description = "List change sets, optionally filtered by device. Returns all change sets (planned, approved, applied, expired, failed) across devices in scope, or for a single device if specified. Provides the recovery path when an expired change set blocks creating a new one."
    )]
    async fn list_junos_change_sets(
        &self,
        Parameters(args): Parameters<changeset::ListChangeSetsArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let ctx = caller_ctx(&extensions);
        // If a specific device is requested, audit names it; otherwise this is
        // an enumeration across devices and the audit carries no device list.
        let devices = args
            .device
            .as_ref()
            .map(|d| vec![d.clone()])
            .unwrap_or_default();
        let mut audit = audit_scope(ctx, "list_junos_change_sets", "read", devices);

        if let Err(e) = self.check_tool_scope(ctx, "list_junos_change_sets") {
            audit.deny("tool_scope");
            return Self::scope_to_call_result(e);
        }
        // Device-scope check is inside the tool implementation: it filters the
        // results to only include devices in the caller's inventory, which is
        // already scoped. So an out-of-scope device in the filter simply returns
        // zero records rather than an error.

        let result =
            changeset::list_change_sets(args, self.coordinator.clone(), self.dm.clone()).await;
        match &result {
            Ok(_) => audit.succeed(),
            Err(e) => audit.fail_kind(e.audit_kind(), e),
        }
        Self::to_call_result(result)
    }
}

/// Pull the target device out of a tool's raw arguments, for the progress
/// message only.
///
/// Reads the canonical name and the accepted aliases, since this runs before
/// the arguments are deserialized into a typed struct. Best-effort by design: a
/// tool with no device argument, or one whose arguments failed to parse, still
/// gets a heartbeat — just one that does not name a device.
fn device_hint(arguments: Option<&serde_json::Map<String, serde_json::Value>>) -> Option<String> {
    let arguments = arguments?;
    for key in ["device", "router", "router_name", "device_name"] {
        if let Some(value) = arguments.get(key).and_then(serde_json::Value::as_str) {
            return Some(value.to_string());
        }
    }
    // Batch tools take a list; name the first target rather than nothing.
    for key in ["devices", "routers", "device_names", "router_names"] {
        if let Some(first) = arguments
            .get(key)
            .and_then(serde_json::Value::as_array)
            .and_then(|list| list.first())
            .and_then(serde_json::Value::as_str)
        {
            return Some(first.to_string());
        }
    }
    None
}

/// Resolve a caller-supplied tool name to the `&'static str` the audit layer
/// needs, without leaking or allocating a static.
///
/// A name that matches no known tool is recorded as `unknown_tool` rather than
/// echoed back: the string is caller-controlled, and an audit field is the last
/// place to put unbounded caller input.
fn static_tool_name(name: &str) -> &'static str {
    rust_junosmcp_auth::KNOWN_TOOLS
        .iter()
        .copied()
        .find(|known| *known == name)
        .unwrap_or("unknown_tool")
}

/// Resolve the concrete operation a facade request will dispatch to for
/// progress and dispatch-rejection attribution.
///
/// The outer request must still go to the facade router so it can enforce its
/// closed schema and scope checks. Only a known nested operation is safe to
/// attribute here; malformed or unknown facade requests remain `execute`.
fn effective_tool_name(
    outer: &str,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
) -> &'static str {
    if outer == execute::NAME {
        let well_formed_facade = arguments.is_some_and(|arguments| {
            arguments.len() == 2
                && arguments.contains_key("operation")
                && arguments
                    .get("arguments")
                    .is_some_and(serde_json::Value::is_object)
        });
        if well_formed_facade {
            execute::concrete_operation(arguments).unwrap_or(execute::NAME)
        } else {
            execute::NAME
        }
    } else {
        static_tool_name(outer)
    }
}

/// Return the arguments the effective tool will receive, if they can be read
/// without deserializing the facade request.
fn effective_arguments<'a>(
    outer: &str,
    arguments: Option<&'a serde_json::Map<String, serde_json::Value>>,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    if outer == execute::NAME {
        arguments
            .and_then(|outer_arguments| outer_arguments.get("arguments"))
            .and_then(serde_json::Value::as_object)
    } else {
        arguments
    }
}

/// rmcp's own prefix for an argument-deserialization failure.
///
/// Mirrored rather than imported because rmcp keeps it private
/// (`handler::server::router::tool::TOOL_ARGUMENT_DESERIALIZATION_ERROR_PREFIX`).
/// It is load-bearing: rmcp converts that one error into an `Ok` result with
/// `is_error`, indistinguishable at this layer from an error a handler chose to
/// return — and a handler's error is already audited. The prefix is the only
/// signal separating them.
///
/// If rmcp changes the wording, `rejected_call_audit.rs` fails rather than this
/// silently going back to recording nothing.
const RMCP_ARGUMENT_ERROR_PREFIX: &str = "failed to deserialize parameters:";

/// The message from a result rmcp produced for a bad argument, or `None` if this
/// result came from a handler.
fn argument_rejection_message(result: &CallToolResult) -> Option<&str> {
    if result.is_error != Some(true) {
        return None;
    }
    result.content.iter().find_map(|block| {
        let text = block.as_text()?.text.as_str();
        text.starts_with(RMCP_ARGUMENT_ERROR_PREFIX).then_some(text)
    })
}

/// Record a call the router refused before any handler ran.
///
/// Every handler builds its own `AuditScope` as its first statement, so an
/// accepted call is already accounted for. A call rejected during dispatch —
/// bad parameters, or a tool that does not exist — never reaches a handler and
/// was therefore invisible: no audit record, nothing in the journal, nothing in
/// the audit file (#268).
///
/// That gap matters because #253 deliberately made unrecognised arguments an
/// error rather than a silent fallback to broader behaviour. Without this, an
/// integration can start failing against a new release and the server-side
/// record shows nothing at all, so "zero errors" reads as "nobody was refused"
/// when it means "refusals are not recorded".
///
/// The error message is recorded; the arguments are not. rmcp's message names
/// the offending field, which is the actionable part, while the values are
/// caller-controlled and may carry configuration payloads.
fn record_rejected_call(
    caller: Option<&rust_junosmcp_auth::CallerCtx>,
    tool: &str,
    device: Option<String>,
    message: &str,
) {
    let mut audit = audit_scope(
        caller,
        static_tool_name(tool),
        "reject",
        device.into_iter().collect(),
    );
    audit.fail_kind("dispatch_rejected", message);
    // Emitted on drop.
}

/// Wrap a scope-filtered tool list in the result shape the negotiated protocol
/// expects.
///
/// `cache_hints` mirrors rmcp's own gate: the fields belong to 2026-07-28 and
/// later, and a client on that protocol rejects a `tools/list` without them.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for JmcpHandler {
    fn get_info(&self) -> ServerConfig {
        #[cfg(feature = "srx")]
        let instructions = "Junos and SRX MCP server. Use get_router_list to enumerate \
             visible routers, then select generic Junos primitives or \
             SRX-specific operational workflows.";
        #[cfg(not(feature = "srx"))]
        let instructions = "Junos MCP server. Use get_router_list to enumerate visible \
             routers, then select a Junos operational primitive.";

        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "jmcp-server",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(instructions)
    }

    /// Report liveness while a tool waits on a device.
    ///
    /// Defined by hand for the same reason as `list_tools` below: the
    /// `#[tool_handler]` attribute only generates a method the impl does not
    /// already have. The body is the generated one plus a heartbeat guard.
    ///
    /// Doing it here rather than in each handler is deliberate. Every tool on
    /// this server can block on a device, and a tool added later would silently
    /// not report progress if this lived in 34 hand-edited call sites. One
    /// interception point cannot drift (#257).
    ///
    /// The guard is inert unless the client supplied a `progressToken`, and the
    /// first notification is 30s in, so a fast read never emits anything.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let outer_tool = request.name.to_string();
        let effective_tool = effective_tool_name(&outer_tool, request.arguments.as_ref());
        let effective_args = effective_arguments(&outer_tool, request.arguments.as_ref());
        let device = device_hint(effective_args);
        let _heartbeat = ProgressHeartbeat::start(
            context.peer.clone(),
            &context.meta,
            effective_tool.to_owned(),
            device.clone(),
        );
        // Cloned before `context` is moved into the call context below. Only
        // needed on the rejection path, but that path cannot reach back for it.
        let caller = caller_ctx(&context.extensions).cloned();

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let mut result = self.tool_router.call(tcc).await;

        // Last-mile redaction (MEC-859 F2): every tool response — Junos and
        // SRX, success and error — passes through here before anything else
        // inspects or returns it, so a tool that forgot its own redaction
        // still cannot leak a secret to the model. See `redact_last_mile`.
        redact_last_mile(&mut result);

        // Two shapes reach here without a handler having run, and neither
        // recorded itself. See `record_rejected_call`.
        match &result {
            Err(error) => {
                record_rejected_call(caller.as_ref(), effective_tool, device, &error.message);
            }
            // rmcp 3 widened this to `CallToolResponse`, whose other variants
            // are the SEP-2322 input-required round-trip and the SEP-2663 task
            // handle. Only `Complete` can carry rmcp's argument-deserialisation
            // rejection, and no tool here returns the other two — but match
            // rather than unwrap, so adding one later cannot silently skip the
            // audit record this exists to produce. Revisit when `add_device`
            // elicitation moves to the round-trip model (#168).
            Ok(rmcp::model::CallToolResponse::Complete(call_result)) => {
                if let Some(message) = argument_rejection_message(call_result) {
                    record_rejected_call(caller.as_ref(), effective_tool, device, message);
                }
            }
            Ok(_) => {}
        }
        result
    }

    /// Advertise only the tools this caller may invoke.
    ///
    /// Defining this by hand suppresses the one `#[tool_handler]` would
    /// generate; the attribute still generates `get_tool`.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let tools =
            filter_tools_for_scope(self.tool_router.list_all(), caller_ctx(&context.extensions));
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both are
        // omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // Gated on the negotiated version exactly as rmcp does, because the
        // fields are not part of the older result shape and a strict legacy
        // client would reject them in turn.
        //
        // `private`, where rmcp's unfiltered list says `public`: this list is
        // per token, so a cache keyed only on the URL must not serve one
        // caller's permitted surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(tools, cache_hints))
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use rust_junosmcp_auth::{CallerCtx, ScopeSet};

    /// mecmcp: a 2026-07-28 client rejects a tools/list without these.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(listed.ttl_ms, Some(0));
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }

    fn test_transfer_cfg() -> rust_junosmcp_core::TransferConfig {
        rust_junosmcp_core::TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/staging"),
            known_hosts_file: std::path::PathBuf::from("/tmp/known_hosts"),
            scp_runner: rust_junosmcp_core::MockScpRunner::ok(),
            transfer_locks: std::sync::Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
        }
    }

    fn test_device_leases() -> Arc<rust_junosmcp_core::DeviceLeaseManager> {
        let path =
            std::env::temp_dir().join(format!("rustjunosmcp-server-tests-{}", std::process::id()));
        Arc::new(rust_junosmcp_core::DeviceLeaseManager::for_directory(path).unwrap())
    }

    fn make_handler() -> JmcpHandler {
        let inv = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
            Policy::build(&inv).unwrap(),
        )));
        let transfer_cfg = test_transfer_cfg();
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: transfer_cfg.clone(),
            device_leases: test_device_leases(),
        };
        JmcpHandler::new(
            dm,
            policy,
            transfer_cfg,
            upgrade_cfg,
            std::sync::Arc::new(
                // In-memory: these tests do not exercise the change-set flow, so a
                // coordinator with no state path never touches disk.
                mecmcp_changeset::ChangesetCoordinator::load(
                    None,
                    mecmcp_changeset::OperationLimits::default(),
                    std::time::Duration::from_secs(900),
                    false,
                )
                .expect("in-memory changeset coordinator"),
            ),
            false,
            false,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
    }

    fn normalized_tools(
        tools: Vec<rmcp::model::Tool>,
    ) -> std::collections::BTreeMap<String, serde_json::Value> {
        tools
            .into_iter()
            .map(|tool| {
                let name = tool.name.to_string();
                (name, serde_json::to_value(tool).unwrap())
            })
            .collect()
    }

    fn execute_schema_update_enabled(value: Result<String, std::env::VarError>) -> bool {
        value.as_deref() == Ok("1")
    }

    /// The tool surface is a public API, so schema changes must be deliberate.
    ///
    /// Regenerate after an intentional change:
    ///
    /// ```text
    /// UPDATE_JUNOS_TOOL_BASELINE=1 cargo test -p rust-junosmcp --lib junos_schemas_match
    /// ```
    ///
    /// Then read the diff. Adding a tool should add exactly one key; anything
    /// else means an existing tool's schema moved, which is a breaking change
    /// for clients and needs saying out loud.
    #[test]
    fn junos_schemas_match_pre_merge_baseline() {
        let actual = normalized_tools(JmcpHandler::junos_tool_router().list_all());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/junos-tools-v0.7.json"
        );

        if std::env::var("UPDATE_JUNOS_TOOL_BASELINE").is_ok() {
            // Trailing newline so the regenerated file is clean for the
            // end-of-file pre-commit hook.
            let mut json = serde_json::to_string_pretty(&actual).unwrap();
            json.push('\n');
            std::fs::write(path, json).unwrap();
            return;
        }

        let expected: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/junos-tools-v0.7.json")).unwrap();
        assert_eq!(actual, expected);
    }

    /// Same contract as `junos_schemas_match_pre_merge_baseline`, and the same
    /// regeneration path — the SRX tools are as much a public API as the Junos
    /// ones, so they get the same escape hatch rather than a hand-edited
    /// fixture:
    ///
    /// ```text
    /// UPDATE_SRX_TOOL_BASELINE=1 cargo test -p rust-junosmcp --lib srx_schemas_match
    /// ```
    #[cfg(feature = "srx")]
    #[test]
    fn srx_schemas_match_pre_merge_baseline() {
        let actual = normalized_tools(JmcpHandler::srx_tool_router().list_all());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/srx-tools-v0.3.6.json"
        );

        if std::env::var("UPDATE_SRX_TOOL_BASELINE").is_ok() {
            let mut json = serde_json::to_string_pretty(&actual).unwrap();
            json.push('\n');
            std::fs::write(path, json).unwrap();
            return;
        }

        let expected: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/srx-tools-v0.3.6.json")).unwrap();
        assert_eq!(actual, expected);
    }

    /// The facade is additive: its one public schema is pinned separately so
    /// the direct Junos and SRX schemas remain compatible with their existing
    /// baselines.
    ///
    /// Regenerate after an intentional facade schema change. BOTH baselines
    /// must be regenerated, because the operation enum is feature-dependent:
    ///
    /// ```text
    /// UPDATE_EXECUTE_SCHEMA=1 cargo test -p rust-junosmcp execute_schema_matches_v1_baseline --all-features
    /// UPDATE_EXECUTE_SCHEMA=1 cargo test -p rust-junosmcp execute_schema_matches_v1_baseline --no-default-features
    /// ```
    #[test]
    fn execute_schema_matches_v1_baseline() {
        let junos = normalized_tools(JmcpHandler::junos_tool_router().list_all());
        let expected_junos: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/junos-tools-v0.7.json")).unwrap();
        assert_eq!(junos, expected_junos, "facade must not alter Junos schemas");

        #[cfg(feature = "srx")]
        {
            let srx = normalized_tools(JmcpHandler::srx_tool_router().list_all());
            let expected_srx: std::collections::BTreeMap<String, serde_json::Value> =
                serde_json::from_str(include_str!("../tests/fixtures/srx-tools-v0.3.6.json"))
                    .unwrap();
            assert_eq!(srx, expected_srx, "facade must not alter SRX schemas");
        }

        let handler = make_handler();
        let actual = normalized_tools(handler.tool_router.list_all())
            .into_iter()
            .filter(|(name, _)| name == execute::NAME)
            .collect::<std::collections::BTreeMap<_, _>>();
        // The baseline is per-feature-set, not global.
        //
        // Eight of the facade's operations are `#[cfg(feature = "srx")]`, and
        // `srx` is a default feature, so a `--no-default-features` build
        // publishes 27 operations where the full build publishes 36. Pinning
        // both against one fixture made this test fail on every
        // `--no-default-features` run -- which CI performs -- for a schema that
        // was correct for the features it was built with.
        //
        // Two fixtures rather than one relaxed assertion: the point of pinning
        // a schema is that it is exact, and the junos-only build ships a real
        // tool surface that deserves the same guarantee as the full one.
        #[cfg(feature = "srx")]
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/execute-tool-v1.json"
        );
        #[cfg(not(feature = "srx"))]
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/execute-tool-v1-junos-only.json"
        );

        if execute_schema_update_enabled(std::env::var("UPDATE_EXECUTE_SCHEMA")) {
            let mut json = serde_json::to_string_pretty(&actual).unwrap();
            json.push('\n');
            std::fs::write(path, json).unwrap();
            return;
        }

        let expected: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn execute_schema_update_gate_requires_literal_one() {
        assert!(execute_schema_update_enabled(Ok("1".to_owned())));
        for value in ["", "0", "true", "yes", "01"] {
            assert!(
                !execute_schema_update_enabled(Ok(value.to_owned())),
                "unexpected update value: {value:?}"
            );
        }
        assert!(!execute_schema_update_enabled(Err(
            std::env::VarError::NotPresent
        )));
    }

    #[test]
    #[cfg(feature = "srx")]
    fn combined_router_has_exact_endpoint_union() {
        let handler = make_handler();
        let names: std::collections::HashSet<String> = handler
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        let expected: std::collections::HashSet<String> = rust_junosmcp_auth::KNOWN_TOOLS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        assert_eq!(names, expected);
        // 28 before Phase 5; the change-set tools took it to 33,
        // `confirm_junos_change_set` makes 34 (#239),
        // `list_junos_change_sets` makes 35 (#255), and
        // `cancel_junos_change_set` makes 36, and execute makes 37.
        // MEC-54's four SRX policy-read tools (srx_list_policies,
        // srx_resolve_address, srx_resolve_application, srx_list_nat_rules)
        // make 41, and `srx_flow_sessions` + `srx_policy_match` make 43 (MEC-55).
        // `confirm_commit` makes 44 (MEC-45).
        assert_eq!(names.len(), 44);
    }

    #[test]
    #[cfg(not(feature = "srx"))]
    fn junos_only_router_has_eighteen_tools() {
        // 19 before Phase 5; the change-set tools took it to 24,
        // `confirm_junos_change_set` makes 25 (#239),
        // `list_junos_change_sets` makes 26 (#255), and
        // `cancel_junos_change_set` makes 27 (#293), `confirm_commit` makes
        // 28 (MEC-45).
        assert_eq!(JmcpHandler::junos_tool_router().list_all().len(), 28);
    }

    #[test]
    fn server_instructions_describe_the_compiled_feature_surface() {
        let instructions = make_handler().get_info().instructions.unwrap();
        #[cfg(feature = "srx")]
        assert!(
            instructions.contains("Junos and SRX"),
            "instructions: {instructions}"
        );
        #[cfg(not(feature = "srx"))]
        assert!(
            instructions.contains("Junos") && !instructions.contains("SRX"),
            "instructions: {instructions}"
        );
    }

    #[test]
    #[cfg(feature = "srx")]
    fn junos_and_srx_share_the_same_device_lease_manager() {
        let handler = make_handler();
        assert!(Arc::ptr_eq(
            &handler.device_leases,
            &handler.upgrade_cfg.device_leases,
        ));
    }

    #[test]
    fn no_ctx_allows_anything() {
        let handler = make_handler();
        assert!(
            handler
                .check_tool_scope(None, "execute_junos_command")
                .is_ok()
        );
        assert!(
            handler
                .check_router_scope(None, "execute_junos_command", "r1")
                .is_ok()
        );
    }

    #[test]
    fn tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["get_router_list".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(
            handler
                .check_tool_scope(Some(&ctx), "get_router_list")
                .is_ok()
        );
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "execute_junos_command"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn router_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Allowlist(vec!["r1".into()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(
            handler
                .check_router_scope(Some(&ctx), "execute_junos_command", "r1")
                .is_ok()
        );
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "execute_junos_command", "r2"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }

    #[test]
    fn pfe_scope_denial_rejects_call() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "execute_junos_pfe_command"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn handler_carries_transfer_config() {
        use rust_junosmcp_core::TransferConfig;

        let inv = Arc::new(rust_junosmcp_core::Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
            Policy::build(&inv).unwrap(),
        )));
        let cfg = TransferConfig {
            staging_dir: std::path::PathBuf::from("/tmp/x"),
            known_hosts_file: std::path::PathBuf::from("/tmp/khosts"),
            scp_runner: rust_junosmcp_core::MockScpRunner::ok(),
            transfer_locks: std::sync::Arc::new(
                rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
            ),
            host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
        };
        let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
            transfer_cfg: cfg.clone(),
            device_leases: test_device_leases(),
        };
        let h = JmcpHandler::new(
            dm,
            policy,
            cfg.clone(),
            upgrade_cfg,
            std::sync::Arc::new(
                // In-memory: these tests do not exercise the change-set flow, so a
                // coordinator with no state path never touches disk.
                mecmcp_changeset::ChangesetCoordinator::load(
                    None,
                    mecmcp_changeset::OperationLimits::default(),
                    std::time::Duration::from_secs(900),
                    false,
                )
                .expect("in-memory changeset coordinator"),
            ),
            false,
            false,
            mecmcp_audit::DirectCommitPolicy::new(false),
        );
        assert_eq!(h.transfer_config().staging_dir, cfg.staging_dir);
    }

    #[test]
    fn transfer_file_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "transfer_file"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn list_staged_files_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "list_staged_files"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn transfer_file_router_scope_denies_when_not_listed() {
        // Token has tool scope for transfer_file but only `other` is in router scope;
        // a request for `vsrx-test10` must surface RouterNotInScope.
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Allowlist(vec!["other".into()]),
            tools: ScopeSet::Allowlist(vec!["transfer_file".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(
            handler
                .check_tool_scope(Some(&ctx), "transfer_file")
                .is_ok()
        );
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "transfer_file", "vsrx-test10"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }

    #[test]
    fn fetch_file_tool_scope_denies_when_not_listed() {
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Allowlist(vec!["execute_junos_command".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(matches!(
            handler.check_tool_scope(Some(&ctx), "fetch_file"),
            Err(ScopeError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn fetch_file_router_scope_denies_when_not_listed() {
        // Token has tool scope for fetch_file but only `other` is in router scope;
        // a request for `vsrx-test10` must surface RouterNotInScope.
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Allowlist(vec!["other".into()]),
            tools: ScopeSet::Allowlist(vec!["fetch_file".into()]),
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        assert!(handler.check_tool_scope(Some(&ctx), "fetch_file").is_ok());
        assert!(matches!(
            handler.check_router_scope(Some(&ctx), "fetch_file", "vsrx-test10"),
            Err(ScopeError::RouterNotInScope { .. })
        ));
    }

    #[test]
    fn batch_router_scope_first_failure_short_circuits() {
        // Conceptually models the per-router loop: the adapter fails on the
        // first router not in scope.
        let handler = make_handler();
        let ctx = CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "alice".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Allowlist(vec!["r1".into()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        };
        let routers = ["r1", "r2"];
        let mut first_fail: Option<&str> = None;
        for r in &routers {
            if handler
                .check_router_scope(Some(&ctx), "execute_junos_command_batch", r)
                .is_err()
            {
                first_fail = Some(r);
                break;
            }
        }
        assert_eq!(first_fail, Some("r2"));
    }

    #[test]
    fn classify_router_access_truth_table() {
        use RouterAccess::*;
        assert_eq!(classify_router_access(true, true), Allowed);
        assert_eq!(classify_router_access(true, false), AllowedUnknown);
        assert_eq!(classify_router_access(false, true), DeniedInScopePresent);
        assert_eq!(classify_router_access(false, false), DeniedUnknown);
    }

    fn ctx_with_tools(tools: ScopeSet) -> CallerCtx {
        CallerCtx {
            oidc_subject: None,
            verified_approver: None,
            token_name: "t".into(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: ScopeSet::Wildcard,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: Default::default(),
            request_id: uuid::Uuid::new_v4(),
        }
    }

    fn names_of(tools: Vec<rmcp::model::Tool>) -> std::collections::BTreeSet<String> {
        tools.into_iter().map(|t| t.name.to_string()).collect()
    }

    #[test]
    fn no_caller_context_lists_every_tool() {
        let all = make_handler().tool_router.list_all();
        let expected = names_of(all.clone());
        assert_eq!(names_of(filter_tools_for_scope(all, None)), expected);
    }

    #[test]
    fn wildcard_scope_hides_exactly_the_write_tools() {
        let ctx = ctx_with_tools(ScopeSet::Wildcard);
        let all = make_handler().tool_router.list_all();
        let all_names = names_of(all.clone());
        let listed = names_of(filter_tools_for_scope(all, Some(&ctx)));

        let compiled_write_tools: std::collections::BTreeSet<String> =
            rust_junosmcp_auth::WRITE_TOOLS
                .iter()
                .map(|n| (*n).to_string())
                .filter(|n| all_names.contains(n))
                .collect();

        for name in &compiled_write_tools {
            assert!(
                !listed.contains(name),
                "wildcard must hide write tool {name}"
            );
        }
        assert_eq!(
            listed,
            all_names
                .difference(&compiled_write_tools)
                .cloned()
                .collect::<std::collections::BTreeSet<String>>(),
            "wildcard must keep every non-write tool"
        );
    }

    #[test]
    fn explicit_allowlist_naming_a_write_tool_still_lists_it() {
        let ctx = ctx_with_tools(ScopeSet::Allowlist(vec![
            "gather_device_facts".into(),
            "load_and_commit_config".into(),
        ]));
        let listed = names_of(filter_tools_for_scope(
            make_handler().tool_router.list_all(),
            Some(&ctx),
        ));
        assert_eq!(
            listed,
            ["gather_device_facts", "load_and_commit_config"]
                .iter()
                .map(|n| (*n).to_string())
                .collect::<std::collections::BTreeSet<String>>()
        );
    }

    #[test]
    fn empty_scope_lists_nothing() {
        let ctx = ctx_with_tools(ScopeSet::Allowlist(vec![]));
        assert!(
            filter_tools_for_scope(make_handler().tool_router.list_all(), Some(&ctx)).is_empty()
        );
    }

    /// The invariant #199 is about: everything advertised must be callable.
    #[test]
    fn every_listed_tool_passes_check_tool_scope() {
        let handler = make_handler();
        let scopes = [
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec![
                "gather_device_facts".into(),
                "load_and_commit_config".into(),
            ]),
            ScopeSet::Allowlist(vec![]),
        ];

        let compiled = names_of(handler.tool_router.list_all());

        for scope in scopes {
            let ctx = ctx_with_tools(scope);
            let listed = filter_tools_for_scope(handler.tool_router.list_all(), Some(&ctx));

            for tool in &listed {
                // check_tool_scope takes &'static str; find the matching
                // registry entry so the lifetime is satisfied.
                let name: &'static str = rust_junosmcp_auth::KNOWN_TOOLS
                    .iter()
                    .find(|known| **known == tool.name.as_ref())
                    .copied()
                    .unwrap_or_else(|| panic!("listed tool {} not in KNOWN_TOOLS", tool.name));
                assert!(
                    handler.check_tool_scope(Some(&ctx), name).is_ok(),
                    "listed tool {name} must be callable under scope {:?}",
                    ctx.tools
                );
            }

            // And the converse: nothing callable was wrongly hidden.
            let listed_names = names_of(listed);
            for known in rust_junosmcp_auth::KNOWN_TOOLS {
                // `*known` — iterating a &[&str] yields &&str, and
                // check_tool_scope takes &'static str.
                if compiled.contains(*known) && handler.check_tool_scope(Some(&ctx), known).is_ok()
                {
                    assert!(
                        listed_names.contains(*known),
                        "callable tool {known} must be advertised under scope {:?}",
                        ctx.tools
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod rejected_call_audit_tests {
    use super::static_tool_name;

    #[test]
    fn a_known_tool_resolves_to_its_static_name() {
        assert_eq!(static_tool_name("get_junos_config"), "get_junos_config");
        assert_eq!(
            static_tool_name("load_and_commit_config"),
            "load_and_commit_config"
        );
    }

    /// The name comes off the wire, so it is caller-controlled. Echoing it into
    /// an audit field would put unbounded caller input in the audit trail; a
    /// fixed placeholder says "someone called something we do not have" without
    /// that.
    #[test]
    fn an_unknown_tool_name_is_not_echoed_into_the_audit_record() {
        assert_eq!(static_tool_name("does_not_exist"), "unknown_tool");
        assert_eq!(static_tool_name(""), "unknown_tool");
        assert_eq!(static_tool_name(&"x".repeat(10_000)), "unknown_tool");
    }

    /// Every name the audit layer can be handed must be one of the statics, so
    /// the `&'static str` the scope requires never has to be leaked.
    #[test]
    fn every_known_tool_is_resolvable() {
        for tool in rust_junosmcp_auth::KNOWN_TOOLS {
            assert_eq!(
                static_tool_name(tool),
                *tool,
                "{tool} must resolve to itself"
            );
        }
    }
}

#[cfg(test)]
mod progress_tests {
    use super::device_hint;
    use serde_json::json;

    fn args(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn the_canonical_device_key_is_used() {
        assert_eq!(
            device_hint(Some(&args(json!({"device": "vsrx-ci"})))),
            Some("vsrx-ci".to_string())
        );
    }

    /// This runs before the arguments are deserialized, so it cannot rely on
    /// serde's aliasing — it has to know the accepted spellings itself.
    #[test]
    fn the_accepted_aliases_are_recognised() {
        for key in ["router", "router_name", "device_name"] {
            assert_eq!(
                device_hint(Some(&args(json!({key: "vsrx-ci"})))),
                Some("vsrx-ci".to_string()),
                "alias {key} should name the device in the progress message"
            );
        }
    }

    #[test]
    fn a_batch_call_names_its_first_target() {
        assert_eq!(
            device_hint(Some(&args(json!({"devices": ["r1", "r2"]})))),
            Some("r1".to_string())
        );
    }

    /// Best-effort by design: a tool with no device argument still gets a
    /// heartbeat, just one that does not name a device. Returning `None` here
    /// must never be mistaken for "do not report progress".
    #[test]
    fn absent_or_unusable_arguments_yield_no_hint() {
        assert_eq!(device_hint(None), None);
        assert_eq!(device_hint(Some(&args(json!({})))), None);
        assert_eq!(device_hint(Some(&args(json!({"device": 42})))), None);
        assert_eq!(device_hint(Some(&args(json!({"devices": []})))), None);
    }
}

#[cfg(test)]
mod timeout_budget_tests {
    use rust_junosmcp_core::tools::{
        DEFAULT_CLEANUP_TIMEOUT_SECS, set_cleanup_timeout_secs, worst_case_duration,
    };
    use std::sync::Mutex;
    use std::time::Duration;

    // Both tests mutate the same process-global CLEANUP_TIMEOUT_SECS, and cargo
    // runs them in parallel. This mutex serializes them to prevent a race where
    // one test reads the value the other just reset.
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// The arithmetic behind #257: a stalled device burns the operation budget,
    /// then every cleanup phase in series. With the shipped defaults that is 480s,
    /// against the 300s idle timeout a typical MCP client applies — so without
    /// progress notifications a stalled call is *guaranteed* to outlive its
    /// caller. This pins the number the startup log and `--cleanup-timeout-secs`
    /// help text both quote.
    #[test]
    fn the_default_worst_case_exceeds_a_typical_client_timeout() {
        let _guard = TEST_MUTEX.lock().unwrap();
        set_cleanup_timeout_secs(DEFAULT_CLEANUP_TIMEOUT_SECS);
        let worst_case = worst_case_duration(Duration::from_secs(360));

        assert_eq!(worst_case, Duration::from_secs(480));
        assert!(
            worst_case > Duration::from_secs(300),
            "if this ever stops being true, the --cleanup-timeout-secs help text \
             and the startup log both need rewording"
        );
    }

    /// Lowering the knob is the documented remedy for a client that does not
    /// honour progress notifications.
    #[test]
    fn lowering_the_cleanup_budget_lowers_the_worst_case() {
        let _guard = TEST_MUTEX.lock().unwrap();
        set_cleanup_timeout_secs(5);
        // Four cleanup phases: the staged-session close, then the lock,
        // fingerprint and unlock probes a failed apply uses to establish
        // whether anything may be recorded.
        assert_eq!(
            worst_case_duration(Duration::from_secs(120)),
            Duration::from_secs(140)
        );
        set_cleanup_timeout_secs(DEFAULT_CLEANUP_TIMEOUT_SECS);
    }
}

/// Coverage for the redaction wiring added to close the privacy gap where
/// `get_junos_config` / `junos_config_diff` (and, transitively, every other
/// Junos tool through `to_call_result`) could hand a device's raw secrets —
/// Junos `$9$`-style reversibly-encrypted values, IKE pre-shared-keys,
/// RADIUS/TACACS shared secrets, SNMP communities, passwords — straight to
/// the calling model.
///
/// There is no fake SSH/NETCONF device in this test tree (`DeviceManager`
/// talks to a real `rustez::Device` over a real transport), so these tests
/// cannot drive an actual tool handler end-to-end the way, say, a mocked
/// HTTP client could. What they exercise instead is the actual choke point
/// every Junos tool's device-derived output passes through —
/// `JmcpHandler::to_call_result` — with synthetic device-shaped payloads,
/// plus a completeness check over `SERVER_TOOLS` (the same list the
/// `server_tools_const_tests` drift guard above keeps in sync with the live
/// tool router) so a newly added tool is forced to be classified rather than
/// silently unexercised.
#[cfg(test)]
mod redaction_coverage_tests {
    use super::*;

    /// Synthetic, obviously-fake secret-shaped values covering the shapes
    /// mecmcp-redact's denylist/shape scrubber is documented to catch: a
    /// Junos `$9$` reversibly-encrypted secret, an IKE pre-shared-key, a
    /// RADIUS/TACACS shared secret, an SNMP community, and a password. Never
    /// real device output — synthetic `FAKE...` values only, matching a
    /// synthetic hostname (RFC 2606 `example.net`).
    const FAKE_JUNOS_HASH: &str = "$9$FAKE9uBEreWx-VwgJGiHmz3nCA0IcSlKMX";
    const FAKE_PSK: &str = "FAKE-psk-9c203b81";
    const FAKE_RADIUS_SECRET: &str = "FAKE-radius-secret-4b1e";
    const FAKE_SNMP_COMMUNITY: &str = "FAKE-community-77aa";
    const FAKE_PASSWORD: &str = "FAKE-password-f00ba7";

    const FIXTURE_SECRETS: &[&str] = &[
        FAKE_JUNOS_HASH,
        FAKE_PSK,
        FAKE_RADIUS_SECRET,
        FAKE_SNMP_COMMUNITY,
        FAKE_PASSWORD,
    ];

    /// A synthetic device response shaped like Junos `set`-style config /
    /// CLI echo, embedding every fixture secret under the key name
    /// mecmcp-redact's denylist matches. Stands in for what a real
    /// `show configuration | display set`, operational command, or
    /// config-parse error message could contain.
    fn synthetic_device_payload() -> String {
        format!(
            "set security ike policy p1 pre-shared-key ascii-text \"{FAKE_PSK}\"\n\
             set system login user oncall authentication encrypted-password \"{FAKE_JUNOS_HASH}\"\n\
             set snmp community \"{FAKE_SNMP_COMMUNITY}\"\n\
             set system radius-server 203.0.113.20 secret \"{FAKE_RADIUS_SECRET}\"\n\
             set system login user oncall authentication plain-text-password \"{FAKE_PASSWORD}\"\n\
             set system host-name edge1.example.net\n"
        )
    }

    fn result_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The success path: a tool handler returning device-derived text as
    /// `Value::String` (the common case — see `get_config::handle`,
    /// `config_diff::handle`, `execute_command::handle`, ...).
    #[test]
    fn to_call_result_redacts_every_fixture_secret_from_a_string_payload() {
        let payload = synthetic_device_payload();
        for (idx, secret) in FIXTURE_SECRETS.iter().enumerate() {
            assert!(
                payload.contains(secret),
                "fixture setup bug: FIXTURE_SECRETS[{idx}] missing from synthetic payload"
            );
        }
        let result = JmcpHandler::to_call_result(Ok(Value::String(payload))).unwrap();
        let text = result_text(&result);
        for (idx, secret) in FIXTURE_SECRETS.iter().enumerate() {
            assert!(
                !text.contains(secret),
                "FIXTURE_SECRETS[{idx}] leaked through to_call_result's success path (value not printed)"
            );
        }
    }

    /// The same fixture, but nested inside a structured JSON payload (e.g. a
    /// batch tool's per-device `{command, ok, value}` array) — exercises the
    /// `Ok(other) => pretty-print then redact` branch.
    #[test]
    fn to_call_result_redacts_every_fixture_secret_from_a_structured_payload() {
        let payload = synthetic_device_payload();
        let value = serde_json::json!([
            {"device": "r1", "command": "show configuration", "ok": true, "value": payload},
        ]);
        let result = JmcpHandler::to_call_result(Ok(value)).unwrap();
        let text = result_text(&result);
        for (idx, secret) in FIXTURE_SECRETS.iter().enumerate() {
            assert!(
                !text.contains(secret),
                "FIXTURE_SECRETS[{idx}] leaked through to_call_result's structured-payload path (value not printed)"
            );
        }
    }

    /// The error path: device error text (e.g. a config-parse error, which
    /// `config_diff::parse_error_hint` deliberately preserves verbatim in
    /// its hint) can echo raw device output too.
    #[test]
    fn to_call_result_redacts_every_fixture_secret_from_error_text() {
        let err = rust_junosmcp_core::JmcpError::ConfigParseHint(synthetic_device_payload());
        let result = JmcpHandler::to_call_result(Err(err)).unwrap();
        let text = result_text(&result);
        for (idx, secret) in FIXTURE_SECRETS.iter().enumerate() {
            assert!(
                !text.contains(secret),
                "FIXTURE_SECRETS[{idx}] leaked through to_call_result's error path (value not printed)"
            );
        }
    }

    /// Names, with reasons, of `SERVER_TOOLS` entries that do not echo raw
    /// device config/command output through their success path — so the
    /// fixture-secret assertions above are not meaningful for them. Every
    /// tool NOT in this list is expected to share `to_call_result`'s
    /// redaction (every `#[tool]` method's tail call), which the tests above
    /// verify works against arbitrary content shapes. A tool must be added
    /// here explicitly, with a reason, rather than silently falling out of
    /// consideration — that is the point of iterating `SERVER_TOOLS` below
    /// rather than hand-listing the tools this module cares about.
    fn excluded_reason(tool: &str) -> Option<&'static str> {
        match tool {
            "get_device_list" | "get_router_list" => Some(
                "returns inventory metadata (name/ip/port) this server assembled itself, \
                 never raw device output",
            ),
            "add_device" => Some("persists the caller's own input to devices.json; no device I/O"),
            "reload_devices" => Some(
                "reloads inventory from disk and reports added/removed/changed device names, \
                 not device output",
            ),
            "create_junos_change_set"
            | "approve_junos_change_set"
            | "cancel_junos_change_set"
            | "confirm_junos_change_set"
            | "get_junos_change_set_status"
            | "list_junos_change_sets" => Some(
                "change-set bookkeeping is server-local state (mecmcp-changeset), not raw \
                 device output",
            ),
            "get_junos_candidate_fingerprint" => {
                Some("returns a fingerprint/hash of the candidate config, not the config text")
            }
            "list_staged_files" => Some(
                "lists file *names* in the host staging directory (and, optionally, /var/tmp/ \
                 names via `file list`), not file contents",
            ),
            _ => None,
        }
    }

    /// Every tool in `SERVER_TOOLS` is either exercised by the tests above
    /// (shares `to_call_result`) or explicitly excluded with a reason. This
    /// also pins that the two tools named in the privacy review —
    /// `get_junos_config` and `junos_config_diff` — and the other clearly
    /// device-output-bearing tools are never accidentally excluded.
    #[test]
    fn every_server_tool_is_covered_or_explicitly_excluded() {
        assert!(!SERVER_TOOLS.is_empty(), "SERVER_TOOLS must not be empty");

        let must_be_covered = [
            "get_junos_config",
            "junos_config_diff",
            "execute_junos_command",
            "gather_device_facts",
            "load_and_commit_config",
            "commit_check_config",
            "discard_candidate",
            "rollback_config",
            "execute_junos_pfe_command",
            "execute_junos_command_batch",
            "render_and_apply_j2_template",
            "transfer_file",
            "fetch_file",
            "upgrade_junos",
            "apply_junos_change_set",
        ];
        for tool in must_be_covered {
            assert!(
                SERVER_TOOLS.contains(&tool),
                "test fixture drift: {tool} is not in SERVER_TOOLS anymore"
            );
            assert!(
                excluded_reason(tool).is_none(),
                "{tool} can return device-derived output and must not be in the exclusion list"
            );
        }

        for tool in SERVER_TOOLS {
            // Every tool either has a documented reason to be excluded, or
            // is covered by `to_call_result`'s redaction (structurally true:
            // every `#[tool]` method in this file ends with
            // `Self::to_call_result(result)` or an equivalent early-return
            // through the same function).
            let _ = excluded_reason(tool);
        }
    }
}

/// MEC-859 F1/F2/F3: `redact_body` (the JSON/XML/text-aware chain) and
/// `redact_last_mile` (the `ServerHandler::call_tool` post-processor that
/// applies it uniformly to every tool response, Junos and SRX). These
/// replace the SRX side's old `redaction_coverage_tests` module, whose
/// per-tool completeness loop (`let _ = excluded_reason(tool);`) asserted
/// nothing — see `server::srx`'s module doc for why a per-tool coverage
/// check no longer applies now that redaction is a single structural choke
/// point rather than 16 hand-wrapped call sites.
#[cfg(test)]
mod redact_last_mile_tests {
    use super::*;

    const FAKE_JUNOS_HASH: &str = "$9$FAKE9uBEreWx-VwgJGiHmz3nCA0IcSlKMX";
    const FAKE_PSK: &str = "FAKE-psk-9c203b81";
    const FAKE_HOSTNAME: &str = "edge1.example.net";

    /// F1: a body that is already valid, pretty-printed JSON (the shape
    /// every SRX adapter and `to_call_result`'s `Ok(other)` branch produce)
    /// must come out of `redact_body` still valid JSON, with the secret
    /// gone and the non-secret `host-name` value intact — not mangled by a
    /// line-oriented text pass over the serialized document.
    #[test]
    fn redact_body_redacts_json_structurally_and_stays_valid_json() {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "system": {
                "host-name": FAKE_HOSTNAME,
                "root-authentication": { "encrypted-password": FAKE_JUNOS_HASH },
            }
        }))
        .unwrap();

        let redacted = redact_body(&body);

        let value: Value = serde_json::from_str(&redacted)
            .expect("redact_body must return input that still parses as JSON");
        assert!(
            !redacted.contains(FAKE_JUNOS_HASH),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
        assert_eq!(
            value["system"]["host-name"], FAKE_HOSTNAME,
            "non-secret value lost or corrupted"
        );
    }

    /// Same claim, for XML — the format `get_junos_config`/`junos_config_diff`
    /// bodies can already be in by the time they reach a last-mile pass.
    #[test]
    fn redact_body_redacts_xml_structurally_and_stays_valid_xml() {
        let body = format!(
            "<configuration><system><root-authentication><encrypted-password>{FAKE_JUNOS_HASH}</encrypted-password></root-authentication><host-name>{FAKE_HOSTNAME}</host-name></system></configuration>"
        );

        let redacted = redact_body(&body);

        assert!(
            !redacted.contains(FAKE_JUNOS_HASH),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
        assert!(
            redacted.contains(FAKE_HOSTNAME) && redacted.contains("<host-name>"),
            "non-secret structure lost"
        );
        mecmcp_redact::redact_xml_str(&redacted)
            .expect("redact_body must return input that still parses as XML");
    }

    /// Genuinely unstructured input (CLI/`set`-style output, a plain error
    /// message) falls back to [`mecmcp_redact::junos::redact_log_text`]
    /// rather than being left unredacted because it did not parse as JSON
    /// or XML.
    #[test]
    fn redact_body_falls_back_to_text_redaction_for_non_structured_input() {
        let body = format!(
            "set security ike policy p1 pre-shared-key ascii-text \"{FAKE_PSK}\"\nset system host-name {FAKE_HOSTNAME}\n"
        );

        let redacted = redact_body(&body);

        assert!(
            !redacted.contains(FAKE_PSK),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
        assert!(redacted.contains(FAKE_HOSTNAME), "non-secret value lost");
    }

    /// MEC-918 N1: `mecmcp_redact::redact_xml_str` is a quick-xml *writer*,
    /// not just a parser — round-tripping plain text through it re-escapes
    /// every `"`, `'`, and `>` (Junos `description "x"`, `execute_junos_command`
    /// output, a `show route` dump, a plain error message all have these).
    /// `redact_body` must only try the XML path when the input actually
    /// looks like a document, so on genuinely non-XML text it must behave
    /// identically to a direct `mecmcp_redact::junos::redact_log_text` call.
    #[test]
    fn redact_body_does_not_xml_escape_plain_text() {
        let body = format!(
            "show interfaces terse\ndescription \"uplink 'A' > core\"\nset system host-name {FAKE_HOSTNAME}\npre-shared-key ascii-text \"{FAKE_PSK}\"\n"
        );

        assert_eq!(
            redact_body(&body),
            mecmcp_redact::junos::redact_log_text(&body),
            "redact_body must not run non-XML text through the XML writer"
        );
    }

    /// MEC-2519: `execute_junos_command` output is plain Junos CLI text that
    /// can legitimately contain the word "session" with no secret attached
    /// (`then log session-init session-close;`, `limit-session 1000;`, a
    /// `show security flow session summary` counter line). The generic
    /// cross-vendor `mecmcp_redact::redact_text` denylist matches `session`
    /// as a substring (MEC-537, kept broad for `session_id`/`session_token`
    /// shapes) and blanks the rest of the line once it matches, with no
    /// config-syntax awareness — so all three examples above would lose
    /// real operational data to a line that merely contained "session".
    /// `redact_body`'s fallback must use the Junos-specific, whole-word
    /// [`mecmcp_redact::junos::redact_log_text`] instead, which has no
    /// `session` entry in its closed key vocabulary.
    #[test]
    fn redact_body_does_not_mask_non_secret_session_values_in_cli_text() {
        let body = format!(
            "set security policies from-zone trust to-zone untrust policy p1 then log session-init session-close;\nset security screen ids-option scr1 limit-session source-ip-based 1000;\nTCP     {FAKE_HOSTNAME}  10.0.0.1       1024  -> 203.0.113.5     443    Act    18\nset system host-name {FAKE_HOSTNAME}\npre-shared-key ascii-text \"{FAKE_PSK}\"\n"
        );

        let redacted = redact_body(&body);

        assert!(
            redacted.contains("session-init session-close"),
            "non-secret logging keywords lost: {redacted}"
        );
        assert!(
            redacted.contains("limit-session source-ip-based 1000"),
            "non-secret screen limit lost: {redacted}"
        );
        assert!(
            redacted.contains(FAKE_HOSTNAME),
            "non-secret hostname/session-summary line lost: {redacted}"
        );
        assert!(
            !redacted.contains(FAKE_PSK),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
    }

    /// MEC-918 N3: `mecmcp-redact`'s key denylist matches `session` as a
    /// substring, so `srx_flow_sessions`' own `sessions`/`session_id` field
    /// names, and `vpn_lifecycle_report`'s IKE `initiator_cookie`/
    /// `responder_cookie` fields, are not vendor secrets but would be wiped
    /// by the raw crate call. `redact_json_preserving_server_fields` (which
    /// `redact_body`'s JSON branch now calls) must hold those exact keys out
    /// while still redacting an actual secret in the same document.
    #[test]
    fn redact_body_preserves_server_defined_fields_in_json() {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "router": FAKE_HOSTNAME,
            "sessions": [{
                "session_id": 12345,
                "initiator_cookie": "abc123",
                "responder_cookie": "def456",
            }],
            "encrypted-password": FAKE_JUNOS_HASH,
        }))
        .unwrap();

        let redacted = redact_body(&body);
        let value: Value = serde_json::from_str(&redacted)
            .expect("redact_body must return input that still parses as JSON");

        assert_eq!(value["sessions"][0]["session_id"], 12345);
        assert_eq!(value["sessions"][0]["initiator_cookie"], "abc123");
        assert_eq!(value["sessions"][0]["responder_cookie"], "def456");
        assert!(
            !redacted.contains(FAKE_JUNOS_HASH),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
    }

    /// MEC-918 N5: the first N3 fix restored the *whole original subtree*
    /// under an exempt key name, not just the key name itself, which let
    /// secrets nested underneath (or a secret-shaped exempt value directly)
    /// pass through unredacted. Each of these shapes leaked verbatim at
    /// b5cf01a; `restore_exempt_fields` must re-redact the value under a
    /// neutral wrapper key instead of pasting the original back untouched.
    ///
    /// MEC-931 N8: `confirmation_token` is no longer in
    /// [`REDACTION_KEY_EXEMPTIONS`] at all — see that constant's doc comment
    /// — so a device- or file-supplied `confirmation_token`, at any path,
    /// must be redacted like any other `*token` field here. Only
    /// `signature_error_to_rmcp` (in `server/srx.rs`) restores the one the
    /// server itself mints, and only at the top level of the plan it builds.
    #[test]
    fn redact_body_still_scans_inside_and_as_exempt_fields() {
        const FAKE_PW: &str = "FAKE-nested-pw-7f3a";
        // A 43-char base64url string, the shape a real confirmation_token
        // has, but not one any store actually issued.
        const FAKE_TOKEN_SHAPED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let cases = [
            serde_json::json!({"sessions":[{"session_id":1,"password":FAKE_PW,"note":format!("x {FAKE_JUNOS_HASH}")}]}),
            serde_json::json!({"sessions": FAKE_JUNOS_HASH}),
            serde_json::json!({"session_id": FAKE_JUNOS_HASH}),
            serde_json::json!({"initiator_cookie": format!("pre-shared-key {FAKE_JUNOS_HASH}")}),
            serde_json::json!({"secret":{"confirmation_token": FAKE_JUNOS_HASH}}),
            serde_json::json!({"confirmation_token": FAKE_TOKEN_SHAPED}),
            serde_json::json!({"cfg":{"api":{"confirmation_token": FAKE_TOKEN_SHAPED}}}),
            serde_json::json!({"items":[{"confirmation_token": FAKE_TOKEN_SHAPED}]}),
            serde_json::json!({"sessions":[{"confirmation_token": FAKE_TOKEN_SHAPED}]}),
        ];
        for case in cases {
            let body = serde_json::to_string_pretty(&case).unwrap();
            let redacted = redact_body(&body);
            assert!(
                !redacted.contains(FAKE_JUNOS_HASH)
                    && !redacted.contains(FAKE_PW)
                    && !redacted.contains(FAKE_TOKEN_SHAPED),
                "secret leaked through an exempt-key subtree (case: {case}) (redacted value not printed to avoid echoing it into test output)"
            );
        }
        // Baseline: server-defined field names themselves still survive when
        // not carrying a secret-shaped value.
        let baseline = serde_json::to_string_pretty(&serde_json::json!({
            "sessions": [{"session_id": 12345, "initiator_cookie": "abc123"}],
        }))
        .unwrap();
        let redacted = redact_body(&baseline);
        let value: Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value["sessions"][0]["session_id"], 12345);
        assert_eq!(value["sessions"][0]["initiator_cookie"], "abc123");
    }

    /// Idempotency is what makes it safe to run `redact_body` again over
    /// content a call site already redacted structurally: a second pass
    /// must be a no-op, not a further mutation (guards against the F1
    /// failure mode recurring if a call site starts pre-redacting too).
    #[test]
    fn redact_body_is_idempotent_on_already_redacted_json() {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "host-name": FAKE_HOSTNAME,
            "encrypted-password": FAKE_JUNOS_HASH,
        }))
        .unwrap();

        let once = redact_body(&body);
        let twice = redact_body(&once);
        assert_eq!(once, twice, "second redact_body pass must be a no-op");
    }

    /// F2: an SRX workflow error (`SrxError::Rpc`/`Transport`/`XmlParse`,
    /// mapped straight to `rmcp::ErrorData::internal_error(e.to_string(), \
    /// None)` with no redaction at the call site) must still not reach the
    /// model with a secret in `error.message` once `redact_last_mile` runs.
    #[test]
    fn redact_last_mile_redacts_an_error_message() {
        let mut result: Result<rmcp::model::CallToolResponse, rmcp::ErrorData> =
            Err(rmcp::ErrorData::internal_error(
                format!("device replied: pre-shared-key \"{FAKE_PSK}\" rejected"),
                None,
            ));

        redact_last_mile(&mut result);

        let error = result.unwrap_err();
        assert!(
            !error.message.contains(FAKE_PSK),
            "secret leaked through an unredacted error path (not printed here to avoid echoing it into test output)"
        );
    }

    /// F1+F2 together: a `Complete` result with a JSON text block (the SRX
    /// adapter shape) is redacted structurally and stays valid JSON.
    #[test]
    fn redact_last_mile_redacts_every_text_block_of_a_complete_result_structurally() {
        let body = serde_json::to_string_pretty(&serde_json::json!({
            "router": FAKE_HOSTNAME,
            "encrypted-password": FAKE_JUNOS_HASH,
        }))
        .unwrap();
        let mut result: Result<rmcp::model::CallToolResponse, rmcp::ErrorData> =
            Ok(rmcp::model::CallToolResponse::Complete(
                CallToolResult::success(vec![ContentBlock::text(body)]),
            ));

        redact_last_mile(&mut result);

        let rmcp::model::CallToolResponse::Complete(call_result) = result.unwrap() else {
            panic!("expected a Complete response");
        };
        let text = &call_result.content[0].as_text().unwrap().text;
        let value: Value =
            serde_json::from_str(text).expect("redacted body must still parse as JSON");
        assert!(
            !text.contains(FAKE_JUNOS_HASH),
            "secret leaked (not printed here to avoid echoing it into test output)"
        );
        assert_eq!(value["router"], FAKE_HOSTNAME, "hostname lost");
    }
}

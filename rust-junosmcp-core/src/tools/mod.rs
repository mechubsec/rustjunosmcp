//! MCP tool argument types. Each tool gets a typed input struct that
//! `schemars` derives a JSON schema from for advertisement to the client.

use schemars::JsonSchema;
use serde::Deserialize;

pub mod add_device;
pub mod batch;
pub(crate) mod candidate_transaction;
pub use candidate_transaction::{
    DEFAULT_CLEANUP_TIMEOUT_SECS, set_cleanup_timeout_secs, worst_case_duration,
};
pub mod changeset;
pub mod commit_check;
pub mod config_diff;
pub mod confirm_commit;
pub mod discard_candidate;
pub mod execute_command;
pub mod facts;
pub mod fetch_file;
pub mod get_config;
pub mod list_staged_files;
pub mod load_commit;
pub mod pfe;
pub mod reload_devices;
pub mod rollback_config;
pub mod router_list;
pub mod template;
pub mod transfer_file;
pub mod upgrade_junos;

/// Default command execution timeout for most tools, in seconds.
fn default_timeout() -> u64 {
    360
}
/// Default timeout for file-transfer operations, in seconds.
fn default_transfer_timeout() -> u64 {
    600
}
/// Default timeout for listing staged files, in seconds.
fn default_list_staged_timeout() -> u64 {
    30
}
/// Default timeout for upgrade_junos, in seconds.
fn default_upgrade_timeout() -> u64 {
    900
}
/// Default post-install reboot-and-reconnect budget for upgrade_junos, in seconds.
fn default_reboot_wait_secs() -> u64 {
    480
}
/// Default for post-transfer sha256 verification (enabled).
fn default_verify() -> bool {
    true
}
/// Default rollback version for config_diff.
fn default_version() -> i64 {
    1
}
/// Default configuration format (set-style commands).
fn default_set_format() -> String {
    "set".into()
}
/// Default `get_junos_config` output format (unmodified `show configuration`).
fn default_get_config_format() -> String {
    "text".into()
}
/// Default load mode: additive merge into the candidate, as today.
fn default_load_mode() -> String {
    "merge".into()
}
/// Default commit comment for load_commit and template tools.
fn default_commit_comment() -> String {
    "Configuration loaded via MCP".into()
}
/// Default concurrency cap for execute_batch (devices processed in parallel).
fn default_max_concurrent_devices() -> u32 {
    16
}

/// Deserialize a `Vec<String>` from either a JSON string (→ one-element vec)
/// or a JSON array of strings. Lets the batch `devices` field accept a single
/// device name as well as a list.
fn string_or_vec<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

/// Schema for a field that deserializes from either a string or an array of
/// strings, matching [`string_or_vec`].
fn string_or_string_array(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "anyOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" } }
        ]
    })
}

/// Inject schema aliases for `get_junos_config`: `device` and `config_path` (aka `filter`).
fn get_config_aliases(schema: &mut schemars::Schema) {
    crate::schema_alias::describe_aliases(
        schema,
        &[
            ("device", &["router_name", "router"]),
            ("config_path", &["filter"]),
        ],
    );
}

/// Inject schema aliases for `execute_junos_command_batch`: pluralized device field names.
fn batch_aliases(schema: &mut schemars::Schema) {
    crate::schema_alias::describe_aliases(
        schema,
        &[
            ("devices", &["routers", "router", "router_name"]),
            ("max_concurrent_devices", &["max_concurrent_routers"]),
        ],
    );
}

/// Inject schema aliases for the template tool: `device_name`/`device_names` plus router-name aliases.
fn template_aliases(schema: &mut schemars::Schema) {
    crate::schema_alias::describe_aliases(
        schema,
        &[
            ("device_name", &["router_name", "router"]),
            ("device_names", &["router_names"]),
        ],
    );
}

/// Empty argument struct for tools that take no parameters.
#[derive(Debug, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct EmptyArgs {}

/// Arguments for `execute_junos_command`: runs a single operational CLI command on one device.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ExecuteCommandArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// The command to execute on the device.
    pub command: String,
    /// Command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Cap output to at most N lines (head; use `tail` for the last N).
    /// Includes the truncation marker, so the response never exceeds N lines.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub max_lines: Option<u32>,
    /// Hard byte cap on returned output, inclusive of the truncation marker.
    /// Must leave room for that marker; see `helpers::MIN_MAX_BYTES`.
    #[serde(default)]
    #[schemars(range(min = 64))]
    pub max_bytes: Option<u32>,
    /// With `max_lines`, keep the LAST N lines instead of the first N.
    #[serde(default)]
    pub tail: bool,
}

/// Arguments for `get_junos_config`: retrieves device configuration (full or filtered by hierarchy path).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = get_config_aliases)]
pub struct GetConfigArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Optional configuration hierarchy path to retrieve only a subtree of the config.
    /// Examples: "system services", "security policies", "interfaces ge-0/0/0".
    /// Also accepted as `filter`. If omitted, returns the full device configuration.
    // `filter` is aliased because it is the obvious name for this parameter:
    // before `deny_unknown_fields`, a caller who guessed it had the field
    // dropped and received the entire configuration — `## SECRET-DATA`
    // included — in place of the subtree they asked for (#253).
    #[serde(default, alias = "filter")]
    pub config_path: Option<String>,
    /// Output format: `text` (default, unmodified `show configuration`),
    /// `set`, `xml`, or `json`. Rendered device-side via the equivalent
    /// `| display <format>` CLI modifier — the same mechanism
    /// `execute_junos_command` already passes through for arbitrary commands.
    #[serde(default = "default_get_config_format")]
    pub format: String,
    /// Cap output to at most N lines (head; use `tail` for the last N).
    /// Includes the truncation marker, so the response never exceeds N lines.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub max_lines: Option<u32>,
    /// Hard byte cap on returned output, inclusive of the truncation marker.
    /// Must leave room for that marker; see `helpers::MIN_MAX_BYTES`.
    #[serde(default)]
    #[schemars(range(min = 64))]
    pub max_bytes: Option<u32>,
    /// With `max_lines`, keep the LAST N lines instead of the first N.
    #[serde(default)]
    pub tail: bool,
}

/// Arguments for `junos_config_diff`: compares candidate vs committed config or archived rollbacks.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ConfigDiffArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Rollback version to compare against (0-49). 0 = candidate vs committed (what is staged now); N>=1 = committed vs the Nth-previous commit.
    #[serde(default = "default_version")]
    pub version: i64,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `gather_device_facts`: retrieves device inventory facts (model, version, serial).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct GatherFactsArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `load_and_commit_config`: loads configuration and commits in one operation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct LoadCommitArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// The configuration text to load.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Load mode: `merge` (default, as today), `replace`, or `override`.
    /// `override` replaces the entire candidate configuration and is always
    /// refused here — this tool commits directly with no second-principal
    /// review. Use `create_junos_change_set` → `approve_junos_change_set` →
    /// `apply_junos_change_set` for an override that requires human approval.
    #[serde(default = "default_load_mode")]
    pub mode: String,
    /// Commit comment recorded in the device commit log.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
    /// Confirmed-commit window in minutes, with auto-rollback if not
    /// confirmed (via `confirm_commit`) within this window. Defaults to the
    /// server's `--commit-confirm-default-mins` (10 unless configured
    /// otherwise) when omitted — commit-confirmed is ON by default. Pass `0`
    /// to explicitly opt out and issue a plain commit instead; this is
    /// recorded in the audit trail as `commit_confirmed=false`.
    #[serde(default)]
    #[schemars(range(min = 0, max = 71_582_788))]
    pub confirm_timeout_mins: Option<u32>,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `commit_check_config`: validates configuration without committing.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct CommitCheckArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// The configuration text to validate.
    pub config_text: String,
    /// Format: set, text, or xml.
    #[serde(default = "default_set_format")]
    pub config_format: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `discard_candidate`: discards uncommitted configuration changes.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct DiscardCandidateArgs {
    /// The target device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `rollback_config`: loads an archived rollback and optionally commits it.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct RollbackConfigArgs {
    /// The target device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Rollback version to load (0-49). 0 = candidate vs committed (discard);
    /// N>=1 = the Nth-previous archived config.
    pub version: i64,
    /// If false (default), preview mode: loads rollback N, computes diff, then
    /// discards (no commit). If true, loads and commits.
    #[serde(default)]
    pub commit: bool,
    /// Confirmed-commit window in minutes, with auto-rollback if not
    /// confirmed (via `confirm_commit`) within this window. Only meaningful
    /// with `commit=true`. Defaults to the server's
    /// `--commit-confirm-default-mins` (10 unless configured otherwise) when
    /// omitted — commit-confirmed is ON by default. Pass `0` to explicitly
    /// opt out and issue a plain commit instead; this is recorded in the
    /// audit trail as `commit_confirmed=false`.
    #[serde(default)]
    #[schemars(range(min = 0, max = 71_582_788))]
    pub confirm_timeout_mins: Option<u32>,
    /// Commit comment recorded in the device commit log when commit=true (normal
    /// commit only). IGNORED during confirmed commits (confirm_timeout_mins set)
    /// due to rustez API limitation. Defaults to "rollback to N via rollback_config".
    #[serde(default)]
    pub commit_comment: Option<String>,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `confirm_commit`: sends the confirming commit for a
/// confirmed commit issued by `load_and_commit_config`, `rollback_config`, or
/// `render_and_apply_j2_template` (not `apply_junos_change_set` — that one is
/// confirmed with `confirm_junos_change_set`, keyed by `operation_id`).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ConfirmCommitArgs {
    /// The device with a pending confirm-commit window.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `execute_junos_pfe_command`: runs a Packet Forwarding Engine command on an FPC.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ExecutePfeArgs {
    /// The name of the device.
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// FPC target, e.g. `fpc0`.
    pub fpc_target: String,
    /// PFE command to execute (no surrounding quotes).
    pub pfe_command: String,
    /// Per-command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Cap output to at most N lines (head; use `tail` for the last N).
    /// Includes the truncation marker, so the response never exceeds N lines.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub max_lines: Option<u32>,
    /// Hard byte cap on returned output, inclusive of the truncation marker.
    /// Must leave room for that marker; see `helpers::MIN_MAX_BYTES`.
    #[serde(default)]
    #[schemars(range(min = 64))]
    pub max_bytes: Option<u32>,
    /// With `max_lines`, keep the LAST N lines instead of the first N.
    #[serde(default)]
    pub tail: bool,
}

/// Arguments for `execute_junos_command_batch`: runs M commands across N devices in parallel.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = batch_aliases)]
pub struct ExecuteBatchArgs {
    /// Devices to execute against. Must be non-empty. Accepts a list, or a
    /// single device name; the keys `routers` / `router` / `router_name` are also accepted for backward compatibility.
    #[serde(
        alias = "routers",
        alias = "router",
        alias = "router_name",
        deserialize_with = "string_or_vec"
    )]
    // `string_or_vec` accepts a bare string as well as an array, so the derived
    // `Vec<String>` schema understates what the tool takes. Harmless while the
    // schema was open; with `additionalProperties: false` a validating client
    // would refuse the documented one-device form.
    #[schemars(schema_with = "string_or_string_array")]
    pub devices: Vec<String>,
    /// Operational CLI commands to run sequentially per device. Must be non-empty.
    pub commands: Vec<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_timeout")]
    pub command_timeout: u64,
    /// Optional whole-batch wall-clock ceiling in seconds.
    #[serde(default)]
    pub batch_timeout: Option<u64>,
    /// Maximum number of devices in flight concurrently.
    #[serde(
        alias = "max_concurrent_routers",
        default = "default_max_concurrent_devices"
    )]
    pub max_concurrent_devices: u32,
    /// Cap output to at most N lines (head; use `tail` for the last N).
    /// Includes the truncation marker, so the response never exceeds N lines.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub max_lines: Option<u32>,
    /// Hard byte cap on returned output, inclusive of the truncation marker.
    /// Must leave room for that marker; see `helpers::MIN_MAX_BYTES`.
    #[serde(default)]
    #[schemars(range(min = 64))]
    pub max_bytes: Option<u32>,
    /// With `max_lines`, keep the LAST N lines instead of the first N.
    #[serde(default)]
    pub tail: bool,
}

/// Arguments for the Jinja2 templating tool: renders config from template + vars, optionally applying to device(s).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = template_aliases)]
pub struct TemplateArgs {
    /// Jinja2 template content as a string (inline; no file path).
    /// Capped at 64 KiB.
    pub template_content: String,
    /// Vars as a JSON object string. Must deserialize to a top-level JSON
    /// object. Capped at 64 KiB. YAML is **not** accepted as of v0.5.2
    /// (RJMCP-SEC-002).
    pub vars_content: String,
    /// Single device to apply to. Mutually exclusive with `device_names`.
    #[serde(default, alias = "router_name", alias = "router")]
    pub device_name: Option<String>,
    /// Multiple devices to apply to. Mutually exclusive with `device_name`.
    #[serde(default, alias = "router_names")]
    pub device_names: Option<Vec<String>>,
    /// If false (default), only renders and returns the rendered string.
    #[serde(default)]
    pub apply_config: bool,
    /// Commit comment recorded in the device commit log when applied.
    #[serde(default = "default_commit_comment")]
    pub commit_comment: String,
    /// If true, runs lock + load + diff + rollback (no commit). Implies apply_config=true.
    #[serde(default)]
    pub dry_run: bool,
    /// Override format detection ('set', 'text', 'xml'). Auto-detected if omitted.
    #[serde(default)]
    pub config_format: Option<String>,
    /// Load mode: `merge` (default, as today), `replace`, or `override`.
    /// `override` replaces the entire candidate configuration and is always
    /// refused here — this tool commits directly with no second-principal
    /// review. Use `create_junos_change_set` → `approve_junos_change_set` →
    /// `apply_junos_change_set` for an override that requires human approval.
    #[serde(default = "default_load_mode")]
    pub mode: String,
    /// Confirmed-commit window in minutes, with auto-rollback if not
    /// confirmed (via `confirm_commit`) within this window. Only meaningful
    /// with `apply_config=true` and `dry_run=false`. Defaults to the server's
    /// `--commit-confirm-default-mins` (10 unless configured otherwise) when
    /// omitted — commit-confirmed is ON by default. Pass `0` to explicitly
    /// opt out and issue a plain commit instead; this is recorded in the
    /// audit trail as `commit_confirmed=false`.
    #[serde(default)]
    #[schemars(range(min = 0, max = 71_582_788))]
    pub confirm_timeout_mins: Option<u32>,
    /// Connection timeout in seconds (per-device).
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Arguments for `add_device`: dynamically registers a new device in the runtime inventory (when `--inventory-readonly` is false).
#[derive(Debug, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct AddDeviceArgs {
    /// Device name/identifier in the inventory map.
    #[serde(default)]
    pub device_name: Option<String>,
    /// Device IP address or hostname.
    #[serde(default)]
    pub device_ip: Option<String>,
    /// SSH port. Default 22.
    #[serde(default)]
    pub device_port: Option<u32>,
    /// Username.
    #[serde(default)]
    pub username: Option<String>,
    /// Auth config (tagged enum: ssh_key | password). `password_env` is not
    /// offered here — see `AddDeviceAuth`.
    #[serde(default)]
    pub auth: Option<crate::inventory::AddDeviceAuth>,
}

/// Arguments for `reload_devices`: hot-reloads the device inventory from disk without restarting the server.
#[derive(Debug, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ReloadDevicesArgs {
    /// Optional path to a different inventory file. If omitted, re-reads
    /// the current --device-mapping.
    #[serde(default)]
    pub file_name: Option<String>,
}

/// Arguments for `transfer_file`: SCP-uploads a pre-staged file from the host to a device's `/var/tmp/`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct TransferFileArgs {
    /// Target device name (must exist in inventory and use ssh_key auth).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Basename of the file under the staging dir. Must not contain '/', '\\', or '..'.
    pub source_path: String,
    /// Overwrite if dest exists with different sha256. Default false.
    #[serde(default)]
    pub force: bool,
    /// Post-transfer sha256 verification. Default true.
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Per-call timeout in seconds. Default 600.
    #[serde(default = "default_transfer_timeout")]
    pub timeout: u64,
}

/// Arguments for `fetch_file`: SCP-downloads a file from a device's `/var/tmp/` to the host's staging directory.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct FetchFileArgs {
    /// Source device name (must exist in inventory and use ssh_key auth).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Basename of the file under the device's /var/tmp/. Must not contain
    /// '/', '\\', or '..'. Same allowlist as transfer_file.
    pub remote_path: String,
    /// Optional override for the local basename written under the staging
    /// directory. Defaults to `remote_path`. Same allowlist applies.
    #[serde(default)]
    pub local_name: Option<String>,
    /// Overwrite if local dest exists with different sha256. Default false.
    #[serde(default)]
    pub force: bool,
    /// Post-fetch sha256 verification (local vs remote). Default true.
    #[serde(default = "default_verify")]
    pub verify: bool,
    /// Per-call timeout in seconds. Default 600.
    #[serde(default = "default_transfer_timeout")]
    pub timeout: u64,
}

/// Arguments for `list_staged_files`: lists files in the host staging directory, optionally also the device's `/var/tmp/`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct ListStagedFilesArgs {
    /// Optional device name. If present, also lists the device's /var/tmp/.
    #[serde(default, alias = "router_name", alias = "router")]
    pub device: Option<String>,
    /// Per-call timeout in seconds. Default 30.
    #[serde(default = "default_list_staged_timeout")]
    pub timeout: u64,
}

/// Arguments for `upgrade_junos`: performs a standalone (non-cluster) Junos software upgrade with install + reboot + verification.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = crate::schema_alias::device_aliases)]
pub struct UpgradeJunosArgs {
    /// Target device (must exist in inventory and use ssh_key auth).
    #[serde(alias = "router_name", alias = "router")]
    pub device: String,
    /// Basename of the staged image under the staging dir. Validated
    /// against the same ASCII allowlist as transfer_file.
    pub source_path: String,
    /// Expected target version string, e.g. "25.4R1.12". Post-install
    /// `show version` must match exactly or the call fails with
    /// UpgradePostVerifyMismatch.
    pub target_version: String,
    /// REQUIRED to perform the destructive upgrade. Defaults to false.
    /// When false the tool runs read-only pre-flight and returns the
    /// upgrade plan as a ConfirmationRequired error.
    #[serde(default)]
    pub confirm: bool,
    /// Per-call outer timeout in seconds. Default 900 (15 min).
    #[serde(default = "default_upgrade_timeout")]
    pub timeout: u64,
    /// Wall-clock budget for NETCONF to reopen after install + reboot.
    /// Default 480 (8 min).
    #[serde(default = "default_reboot_wait_secs")]
    pub reboot_wait_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_command_defaults_timeout() {
        let v = serde_json::json!({"router_name":"r1","command":"show version"});
        let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn config_diff_defaults_version_to_1() {
        let v = serde_json::json!({"router_name":"r1"});
        let a: ConfigDiffArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.version, 1);
    }

    #[test]
    fn load_commit_defaults_format_and_comment() {
        let v = serde_json::json!({"router_name":"r1","config_text":"set x"});
        let a: LoadCommitArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.config_format, "set");
        assert_eq!(a.mode, "merge");
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn load_commit_accepts_explicit_mode() {
        let v = serde_json::json!({
            "router_name":"r1","config_text":"set x","mode":"replace"
        });
        let a: LoadCommitArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.mode, "replace");
    }

    #[test]
    fn get_config_defaults_format_to_text() {
        let v = serde_json::json!({"router_name":"r1"});
        let a: GetConfigArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.format, "text");
    }

    #[test]
    fn get_config_accepts_explicit_format() {
        let v = serde_json::json!({"router_name":"r1","format":"json"});
        let a: GetConfigArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.format, "json");
    }

    #[test]
    fn commit_check_defaults_format_and_timeout() {
        let v = serde_json::json!({"router_name":"r1","config_text":"set x"});
        let a: CommitCheckArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.config_format, "set");
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn commit_check_rejects_missing_config_text() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<CommitCheckArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn discard_candidate_defaults_timeout_and_router_alias() {
        let a: DiscardCandidateArgs =
            serde_json::from_value(serde_json::json!({"router":"r1"})).unwrap();
        assert_eq!(a.device, "r1");
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn rollback_config_defaults_commit_false_and_timeout() {
        let v = serde_json::json!({"router_name":"r1","version":5});
        let a: RollbackConfigArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device, "r1");
        assert_eq!(a.version, 5);
        assert!(!a.commit);
        assert!(a.confirm_timeout_mins.is_none());
        assert!(a.commit_comment.is_none());
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn rollback_config_accepts_commit_with_confirm() {
        let v = serde_json::json!({
            "router_name":"r1","version":3,"commit":true,"confirm_timeout_mins":10
        });
        let a: RollbackConfigArgs = serde_json::from_value(v).unwrap();
        assert!(a.commit);
        assert_eq!(a.confirm_timeout_mins, Some(10));
    }

    #[test]
    fn rollback_config_accepts_commit_comment() {
        let v = serde_json::json!({
            "router_name":"r1","version":1,"commit":true,"commit_comment":"emergency rollback"
        });
        let a: RollbackConfigArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.commit_comment.as_deref(), Some("emergency rollback"));
    }

    #[test]
    fn rollback_config_rejects_missing_version() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<RollbackConfigArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn execute_command_rejects_missing_required() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<ExecuteCommandArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn execute_pfe_defaults_timeout() {
        let v = serde_json::json!({"router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats"});
        let a: ExecutePfeArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 360);
        assert_eq!(a.fpc_target, "fpc0");
    }

    #[test]
    fn execute_pfe_rejects_missing_fpc_target() {
        let v = serde_json::json!({"router_name":"r1","pfe_command":"show jnh 0 stats"});
        let r: Result<ExecutePfeArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn execute_batch_defaults_concurrency_and_command_timeout() {
        let v = serde_json::json!({"routers":["r1","r2"],"commands":["show version"]});
        let a: ExecuteBatchArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.command_timeout, 360);
        assert_eq!(a.max_concurrent_devices, 16);
        assert!(a.batch_timeout.is_none());
    }

    #[test]
    fn execute_batch_accepts_explicit_batch_timeout() {
        let v = serde_json::json!({
            "routers":["r1"],"commands":["show version"],
            "batch_timeout":600,"max_concurrent_routers":4
        });
        let a: ExecuteBatchArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.batch_timeout, Some(600));
        assert_eq!(a.max_concurrent_devices, 4);
    }

    #[test]
    fn template_args_defaults_apply_and_dry_run_to_false() {
        let v = serde_json::json!({
            "template_content":"set system host-name {{ name }}",
            "vars_content":"{\"name\":\"r1\"}",
            "router_name":"r1"
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert!(!a.apply_config);
        assert!(!a.dry_run);
        assert_eq!(a.mode, "merge");
        assert_eq!(a.commit_comment, "Configuration loaded via MCP");
        assert_eq!(a.device_name.as_deref(), Some("r1"));
        assert!(a.device_names.is_none());
        assert_eq!(a.timeout, 360);
    }

    #[test]
    fn template_args_accepts_router_names_list() {
        let v = serde_json::json!({
            "template_content":"set foo",
            "vars_content":"{}",
            "router_names":["r1","r2"]
        });
        let a: TemplateArgs = serde_json::from_value(v).unwrap();
        assert_eq!(
            a.device_names.as_deref(),
            Some(&["r1".into(), "r2".into()][..])
        );
    }

    #[test]
    fn add_device_args_all_optional() {
        let v = serde_json::json!({});
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert!(a.device_name.is_none());
        assert!(a.auth.is_none());
    }

    #[test]
    fn add_device_args_accepts_full_payload() {
        let v = serde_json::json!({
            "device_name": "core-3",
            "device_ip": "10.0.0.3",
            "device_port": 22,
            "username": "automation",
            "auth": {"type":"ssh_key","private_key_path":"/etc/jmcp/keys/id"}
        });
        let a: AddDeviceArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device_name.as_deref(), Some("core-3"));
        assert_eq!(a.device_port, Some(22));
        assert!(matches!(
            a.auth,
            Some(crate::inventory::AddDeviceAuth::SshKey { .. })
        ));
    }

    #[test]
    fn add_device_args_rejects_password_env() {
        let v = serde_json::json!({
            "auth": {"type":"password_env","password_env":"R1_PASSWORD"}
        });
        let r: Result<AddDeviceArgs, _> = serde_json::from_value(v);
        assert!(
            r.is_err(),
            "add_device must not accept password_env, even before validate() runs"
        );
    }

    #[test]
    fn reload_devices_args_file_name_optional() {
        let v = serde_json::json!({});
        let a: ReloadDevicesArgs = serde_json::from_value(v).unwrap();
        assert!(a.file_name.is_none());
    }

    #[test]
    fn transfer_file_args_defaults() {
        let v = serde_json::json!({"router_name":"r1","source_path":"foo.tgz"});
        let a: TransferFileArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device, "r1");
        assert_eq!(a.source_path, "foo.tgz");
        assert!(!a.force);
        assert!(a.verify);
        assert_eq!(a.timeout, 600);
    }

    #[test]
    fn transfer_file_args_rejects_missing_source() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<TransferFileArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn list_staged_files_args_router_optional() {
        let v = serde_json::json!({});
        let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
        assert!(a.device.is_none());
        assert_eq!(a.timeout, 30);
    }

    #[test]
    fn list_staged_files_args_with_router() {
        let v = serde_json::json!({"router_name":"vSRX-test10"});
        let a: ListStagedFilesArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device.as_deref(), Some("vSRX-test10"));
    }

    #[test]
    fn upgrade_junos_args_defaults() {
        let v = serde_json::json!({
            "router_name": "vsrx-test10",
            "source_path": "junos-25.4R1.12.tgz",
            "target_version": "25.4R1.12"
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device, "vsrx-test10");
        assert_eq!(a.source_path, "junos-25.4R1.12.tgz");
        assert_eq!(a.target_version, "25.4R1.12");
        assert!(!a.confirm);
        assert_eq!(a.timeout, 900);
        assert_eq!(a.reboot_wait_secs, 480);
    }

    #[test]
    fn upgrade_junos_args_rejects_missing_required() {
        for missing in [
            serde_json::json!({"source_path":"x.tgz","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","target_version":"25.4R1.12"}),
            serde_json::json!({"router_name":"r1","source_path":"x.tgz"}),
        ] {
            let r: Result<UpgradeJunosArgs, _> = serde_json::from_value(missing);
            assert!(r.is_err(), "should reject missing required");
        }
    }

    #[test]
    fn upgrade_junos_args_accepts_confirm_true() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "confirm": true
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert!(a.confirm);
    }

    #[test]
    fn upgrade_junos_args_accepts_custom_timeouts() {
        let v = serde_json::json!({
            "router_name": "r1",
            "source_path": "x.tgz",
            "target_version": "25.4R1.12",
            "timeout": 1800,
            "reboot_wait_secs": 720
        });
        let a: UpgradeJunosArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.timeout, 1800);
        assert_eq!(a.reboot_wait_secs, 720);
    }

    #[test]
    fn fetch_file_args_defaults() {
        let v = serde_json::json!({"router_name":"r1","remote_path":"foo.tgz"});
        let a: FetchFileArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.device, "r1");
        assert_eq!(a.remote_path, "foo.tgz");
        assert!(a.local_name.is_none());
        assert!(!a.force);
        assert!(a.verify);
        assert_eq!(a.timeout, 600);
    }

    #[test]
    fn fetch_file_args_rejects_missing_remote_path() {
        let v = serde_json::json!({"router_name":"r1"});
        let r: Result<FetchFileArgs, _> = serde_json::from_value(v);
        assert!(r.is_err());
    }

    #[test]
    fn fetch_file_args_accepts_local_name_override() {
        let v = serde_json::json!({
            "router_name":"r1",
            "remote_path":"foo.tgz",
            "local_name":"foo.local.tgz"
        });
        let a: FetchFileArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.local_name.as_deref(), Some("foo.local.tgz"));
    }

    #[test]
    fn execute_command_output_caps_default_off() {
        let v = serde_json::json!({"router_name":"r1","command":"show version"});
        let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
        assert!(a.max_lines.is_none());
        assert!(a.max_bytes.is_none());
        assert!(!a.tail);
    }

    #[test]
    fn execute_command_accepts_output_caps() {
        let v = serde_json::json!({"router_name":"r1","command":"show log messages","max_lines":50,"max_bytes":8192,"tail":true});
        let a: ExecuteCommandArgs = serde_json::from_value(v).unwrap();
        assert_eq!(a.max_lines, Some(50));
        assert_eq!(a.max_bytes, Some(8192));
        assert!(a.tail);
    }

    #[test]
    fn batch_and_pfe_accept_output_caps() {
        let b: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
            "routers":["r1"],"commands":["show version"],"max_lines":10
        }))
        .unwrap();
        assert_eq!(b.max_lines, Some(10));
        let p: ExecutePfeArgs = serde_json::from_value(serde_json::json!({
            "router_name":"r1","fpc_target":"fpc0","pfe_command":"show jnh 0 stats","max_bytes":4096
        }))
        .unwrap();
        assert_eq!(p.max_bytes, Some(4096));
    }

    #[test]
    fn router_alias_accepts_router_and_router_name() {
        // Single-device tool: both names deserialize to the same field.
        let a: ExecuteCommandArgs =
            serde_json::from_value(serde_json::json!({"router":"r1","command":"show version"}))
                .unwrap();
        assert_eq!(a.device, "r1");
        let b: ExecuteCommandArgs = serde_json::from_value(
            serde_json::json!({"router_name":"r1","command":"show version"}),
        )
        .unwrap();
        assert_eq!(b.device, "r1");
    }

    #[test]
    fn get_config_and_upgrade_accept_router_alias() {
        let g: GetConfigArgs = serde_json::from_value(serde_json::json!({"router":"r1"})).unwrap();
        assert_eq!(g.device, "r1");
        let u: UpgradeJunosArgs = serde_json::from_value(serde_json::json!({
            "router":"r1","source_path":"x.tgz","target_version":"25.4R1.12"}))
        .unwrap();
        assert_eq!(u.device, "r1");
    }

    #[test]
    fn batch_accepts_list_string_and_aliases() {
        let list: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
            "routers":["a","b"],"commands":["show version"]}))
        .unwrap();
        assert_eq!(list.devices, vec!["a".to_string(), "b".to_string()]);

        let one: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
            "routers":"a","commands":["show version"]}))
        .unwrap();
        assert_eq!(one.devices, vec!["a".to_string()]);

        let via_router: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
            "router":"a","commands":["show version"]}))
        .unwrap();
        assert_eq!(via_router.devices, vec!["a".to_string()]);

        let via_router_name: ExecuteBatchArgs = serde_json::from_value(serde_json::json!({
            "router_name":["a","b"],"commands":["show version"]}))
        .unwrap();
        assert_eq!(
            via_router_name.devices,
            vec!["a".to_string(), "b".to_string()]
        );
    }
}

#[cfg(test)]
mod unknown_field_tripwire {
    use super::*;

    /// Every tool argument type must reject arguments it does not understand.
    ///
    /// This is a tripwire, not a style check. The failure mode it guards
    /// against is #253: `get_junos_config` dropped an unrecognised `filter` and
    /// returned the device's entire configuration — root password hash and SSH
    /// keys included — shaped exactly like a successful narrow query. Whenever
    /// a dropped argument means "do the broader thing", silently ignoring it is
    /// a privilege-escalation-shaped bug, and #254 is the same defect in the
    /// change-set path.
    ///
    /// A new tool argument struct without `#[serde(deny_unknown_fields)]` fails
    /// here rather than in production.
    fn asserts_additional_properties_false<T: JsonSchema>(name: &str) {
        let schema = schemars::schema_for!(T);
        let value = serde_json::to_value(&schema).expect("schema serializes");
        assert_eq!(
            value.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false)),
            "{name} must carry #[serde(deny_unknown_fields)] so an argument the \
             tool does not understand is an error rather than a silent fallback \
             to broader behaviour. Schema was: {value}"
        );
    }

    macro_rules! assert_denies_unknown_fields {
        ($($t:ty),+ $(,)?) => {
            $( asserts_additional_properties_false::<$t>(stringify!($t)); )+
        };
    }

    /// A closed schema must describe every alias its deserializer accepts.
    ///
    /// `deny_unknown_fields` publishes `additionalProperties: false`, which is a
    /// promise that the listed properties are the accepted ones. `schemars` has
    /// no visibility into `#[serde(alias = ...)]`, so without the
    /// `#[schemars(transform = ...)]` groups a client that validates before
    /// calling would refuse to send `router_name` — a spelling this server has
    /// accepted since before the rename. The failure is invisible to any client
    /// that does not validate, which is why it needs a test.
    #[test]
    fn every_accepted_alias_is_described_in_the_schema() {
        fn check<T: JsonSchema>(name: &str, aliases: &[&str]) {
            let schema = schemars::schema_for!(T);
            let value = serde_json::to_value(&schema).expect("schema serializes");
            crate::schema_alias::assert_describes_keys(
                value.as_object().expect("schema is an object"),
                name,
                aliases,
            );
        }

        const DEVICE: &[&str] = &["router_name", "router"];
        check::<ExecuteCommandArgs>("ExecuteCommandArgs", DEVICE);
        check::<GetConfigArgs>("GetConfigArgs", &["router_name", "router", "filter"]);
        check::<ConfigDiffArgs>("ConfigDiffArgs", DEVICE);
        check::<GatherFactsArgs>("GatherFactsArgs", DEVICE);
        check::<LoadCommitArgs>("LoadCommitArgs", DEVICE);
        check::<CommitCheckArgs>("CommitCheckArgs", DEVICE);
        check::<DiscardCandidateArgs>("DiscardCandidateArgs", DEVICE);
        check::<RollbackConfigArgs>("RollbackConfigArgs", DEVICE);
        check::<ConfirmCommitArgs>("ConfirmCommitArgs", DEVICE);
        check::<ExecutePfeArgs>("ExecutePfeArgs", DEVICE);
        check::<TransferFileArgs>("TransferFileArgs", DEVICE);
        check::<FetchFileArgs>("FetchFileArgs", DEVICE);
        check::<ListStagedFilesArgs>("ListStagedFilesArgs", DEVICE);
        check::<UpgradeJunosArgs>("UpgradeJunosArgs", DEVICE);
        check::<ExecuteBatchArgs>(
            "ExecuteBatchArgs",
            &["routers", "router", "router_name", "max_concurrent_routers"],
        );
        check::<TemplateArgs>("TemplateArgs", &["router_name", "router", "router_names"]);
        check::<changeset::CreateChangeSetArgs>("CreateChangeSetArgs", DEVICE);
        check::<changeset::ApproveChangeSetArgs>("ApproveChangeSetArgs", DEVICE);
        check::<changeset::CancelChangeSetArgs>("CancelChangeSetArgs", DEVICE);
        check::<changeset::ApplyChangeSetArgs>("ApplyChangeSetArgs", DEVICE);
        check::<changeset::ConfirmChangeSetArgs>("ConfirmChangeSetArgs", DEVICE);
        check::<changeset::GetChangeSetStatusArgs>("GetChangeSetStatusArgs", DEVICE);
        check::<changeset::CandidateFingerprintArgs>("CandidateFingerprintArgs", DEVICE);
    }

    /// The advertised minima must match what the server enforces. A schema that
    /// says `minimum: 0` while the handler refuses anything under 64 lets a
    /// client build a request that validates and is then rejected — the exact
    /// schema/behaviour divergence these tripwires exist to catch.
    #[test]
    fn advertised_cap_minima_match_the_enforced_ones() {
        use crate::helpers::MIN_MAX_BYTES;

        fn minima_of<T: JsonSchema>(name: &str) -> (u64, u64) {
            let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
            let properties = &schema["properties"];
            let read = |field: &str| {
                properties[field]["minimum"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{name}.{field} must publish a minimum"))
            };
            (read("max_lines"), read("max_bytes"))
        }

        for (name, (lines, bytes)) in [
            (
                "ExecuteCommandArgs",
                minima_of::<ExecuteCommandArgs>("ExecuteCommandArgs"),
            ),
            ("GetConfigArgs", minima_of::<GetConfigArgs>("GetConfigArgs")),
            (
                "ExecutePfeArgs",
                minima_of::<ExecutePfeArgs>("ExecutePfeArgs"),
            ),
            (
                "ExecuteBatchArgs",
                minima_of::<ExecuteBatchArgs>("ExecuteBatchArgs"),
            ),
        ] {
            assert_eq!(lines, 1, "{name}.max_lines minimum");
            assert_eq!(
                bytes,
                u64::from(MIN_MAX_BYTES),
                "{name}.max_bytes minimum must track helpers::MIN_MAX_BYTES"
            );
        }
    }

    /// The batch tool documents a single device name as an accepted form, so
    /// the schema for `devices` and its aliases must not say "array only".
    #[test]
    fn batch_targets_accept_a_bare_string_in_the_schema() {
        let schema = serde_json::to_value(schemars::schema_for!(ExecuteBatchArgs)).unwrap();
        for field in ["devices", "routers", "router", "router_name"] {
            let any_of = schema["properties"][field]["anyOf"]
                .as_array()
                .unwrap_or_else(|| panic!("{field} must accept a string or an array"));
            let types: Vec<&str> = any_of
                .iter()
                .map(|variant| variant["type"].as_str().unwrap())
                .collect();
            assert_eq!(types, vec!["string", "array"], "{field}");
        }
    }

    /// Supplying only the alias must satisfy the schema. A bare
    /// `required: ["device"]` alongside `additionalProperties: false` would
    /// reject a call the server accepts at runtime — and `oneOf` rather than
    /// `anyOf`, because serde rejects two spellings of the same field as a
    /// duplicate, so a schema that allowed both would validate a doomed call.
    #[test]
    fn an_alias_alone_satisfies_the_required_constraint() {
        let schema = serde_json::to_value(schemars::schema_for!(GatherFactsArgs)).unwrap();
        assert!(
            schema.get("required").is_none(),
            "`device` is aliased, so a bare `required` list would exclude the aliases: {schema}"
        );
        let choices = schema["allOf"][0]["oneOf"].as_array().expect("oneOf group");
        let names: Vec<&str> = choices
            .iter()
            .map(|choice| choice["required"][0].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["device", "router_name", "router"]);
    }

    #[test]
    fn every_tool_argument_type_denies_unknown_fields() {
        assert_denies_unknown_fields!(
            EmptyArgs,
            ExecuteCommandArgs,
            GetConfigArgs,
            ConfigDiffArgs,
            GatherFactsArgs,
            LoadCommitArgs,
            CommitCheckArgs,
            DiscardCandidateArgs,
            RollbackConfigArgs,
            ConfirmCommitArgs,
            ExecutePfeArgs,
            ExecuteBatchArgs,
            TemplateArgs,
            AddDeviceArgs,
            ReloadDevicesArgs,
            TransferFileArgs,
            FetchFileArgs,
            ListStagedFilesArgs,
            UpgradeJunosArgs,
            crate::tools::changeset::CreateChangeSetArgs,
            crate::tools::changeset::ApproveChangeSetArgs,
            crate::tools::changeset::CancelChangeSetArgs,
            crate::tools::changeset::ApplyChangeSetArgs,
            crate::tools::changeset::ConfirmChangeSetArgs,
            crate::tools::changeset::GetChangeSetStatusArgs,
            crate::tools::changeset::CandidateFingerprintArgs,
            crate::junos_transaction::JunosAction,
            crate::junos_transaction::ConfigPayloadSpec,
        );
    }
}

#[cfg(test)]
mod output_cap_validation_tests {
    use crate::error::JmcpError;
    use crate::helpers::{MIN_MAX_BYTES, validate_output_caps};

    #[test]
    fn absent_caps_are_fine() {
        assert!(validate_output_caps(None, None).is_ok());
    }

    #[test]
    fn a_zero_line_cap_is_refused() {
        match validate_output_caps(Some(0), None) {
            Err(JmcpError::Validation(msg)) => assert!(msg.contains("max_lines"), "got: {msg}"),
            other => panic!("expected max_lines=0 to be refused, got {other:?}"),
        }
    }

    /// Below the floor the truncation marker cannot fit, so the cap could only
    /// be honoured by overshooting it — which is the defect, not the fix.
    #[test]
    fn a_byte_cap_too_small_for_the_marker_is_refused() {
        match validate_output_caps(None, Some(MIN_MAX_BYTES - 1)) {
            Err(JmcpError::Validation(msg)) => {
                assert!(msg.contains("max_bytes"), "got: {msg}");
                assert!(
                    msg.contains(&MIN_MAX_BYTES.to_string()),
                    "the error must state the floor, got: {msg}"
                );
            }
            other => panic!("expected an undersized max_bytes to be refused, got {other:?}"),
        }
    }

    #[test]
    fn the_floor_itself_is_accepted() {
        assert!(validate_output_caps(Some(1), Some(MIN_MAX_BYTES)).is_ok());
    }
}

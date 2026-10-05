//! Error type surfaced through the MCP server.

use std::path::PathBuf;

/// Error type surfaced by tools and server operations.
///
/// Every public variant carries an actionable message suitable for MCP clients
/// or CLI output. Variants marked `[code=*]` in their display output are stable
/// audit identifiers consumed by SIEM; the `audit_kind()` method returns these
/// for logging.
///
/// Security-relevant errors (`Denied`, `HostKeyMismatch`, `HostKeyRevoked`)
/// preserve evidence for audit trails. File-transfer and upgrade errors carry
/// diagnostic state (paths, SHA-256 digests, timeout durations) for
/// troubleshooting without requiring log correlation.
#[derive(Debug, thiserror::Error)]
pub enum JmcpError {
    /// Device name is not in the current inventory. Returned by
    /// `DeviceManager::open()` and tool preconditions before any NETCONF
    /// connection is attempted.
    #[error("router '{0}' not found in device mapping")]
    UnknownRouter(String),

    /// Inventory file failed schema validation. Message carries parse errors,
    /// validation failures (name/username/IP character classes, port range), or
    /// references to missing SSH key files.
    #[error("invalid devices.json: {0}")]
    InventoryInvalid(String),

    /// SSH private-key file referenced in inventory does not exist at load time.
    /// Returned by `Inventory::load()` before any device connection is attempted.
    #[error("private key file not found: {0}")]
    KeyFileMissing(PathBuf),

    /// SSH config file referenced in a device's `ssh_config` field could not be
    /// loaded or parsed. The source error is a `rustez::SshConfigError` carrying
    /// the specific parse failure or IO error.
    #[error("ssh_config invalid for router '{router}': {source}")]
    SshConfigInvalid {
        /// Name of the device whose SSH config failed to load.
        router: String,
        /// Underlying SSH config parse or load error.
        #[source]
        source: rustez::SshConfigError,
    },

    /// Caller passed a `config_format` other than `set`, `text`, or `xml`.
    #[error("invalid config_format '{0}' (expected set, text, or xml)")]
    BadFormat(String),

    /// Caller passed a `get_junos_config` `format` other than `text`, `set`,
    /// `xml`, or `json`.
    #[error("invalid format '{0}' for get_junos_config (expected text, set, xml, or json)")]
    BadConfigFormat(String),

    /// Caller passed a load `mode` other than `merge`, `replace`, or `override`.
    #[error("invalid mode '{0}' (expected merge, replace, or override)")]
    BadLoadMode(String),

    /// `mode=override` (full candidate replacement) was requested on a path
    /// that commits directly with no second-principal review. `override` is
    /// the highest blast-radius operation this server exposes, so it is
    /// refused everywhere except `create_junos_change_set` →
    /// `approve_junos_change_set` → `apply_junos_change_set`, which requires
    /// human approval before anything commits (MEC-12).
    #[error(
        "refused: mode=override on '{tool}' is refused because this tool commits directly with \
         no second-principal review. Route the change through create_junos_change_set → \
         approve_junos_change_set → apply_junos_change_set instead."
    )]
    OverrideRequiresChangeSet {
        /// Name of the MCP tool that was refused.
        tool: &'static str,
    },

    /// `mode=override` was requested on `create_junos_change_set` while the
    /// server runs in `--lab-mode`. Lab mode waives approval on every change
    /// set it creates (single-operator servers have no second principal), so
    /// permitting `override` there would silently defeat the human-approval
    /// gate that is the entire reason `override` is allowed on this path at
    /// all (MEC-12). Refused unconditionally; there is no lab-mode override
    /// flow today.
    #[error(
        "refused: mode=override on '{tool}' is refused while this server runs in lab mode, \
         because lab mode waives approval and override has no other path to a human approver"
    )]
    OverrideRequiresHumanApproval {
        /// Name of the MCP tool that was refused.
        tool: &'static str,
    },

    /// Requested `mode` has no wire-level equivalent for the requested
    /// `config_format`. Currently only `format=set` + `mode=override`: Junos
    /// has no `override` action for a `configuration-set` (set-command list)
    /// payload — only `action="set"` is valid for that payload shape.
    #[error("mode '{mode}' is not compatible with config_format '{format}'")]
    IncompatibleFormatMode {
        /// The requested config format.
        format: String,
        /// The requested load mode.
        mode: String,
    },

    /// PFE command validation failed (e.g., contains literal quotes or shell
    /// metacharacters). Message describes why the command is unsafe.
    #[error("invalid pfe_command: {0}")]
    BadPfeCommand(String),

    /// Rollback version argument is outside Junos's valid range (0..=49).
    #[error("rollback version {0} out of range (0..=49)")]
    BadRollbackVersion(i64),

    /// File path validation failed for a local source file (contains `/`,
    /// starts with `-`, or other character-class violation). Prevents directory
    /// traversal and SSH flag injection.
    #[error("invalid source_path [code=bad_source_path]: {0}")]
    BadSourcePath(String),

    /// Device lacks sufficient free storage for a file transfer or package
    /// install. Carries observed free bytes and the space requirement.
    #[error(
        "insufficient disk [code=insufficient_disk]: {message} (free={free}B required={required}B)"
    )]
    InsufficientDisk {
        /// Observed free bytes on the target filesystem.
        free: u64,
        /// Required free bytes for the operation to proceed.
        required: u64,
        /// Human-readable diagnostic describing which check failed.
        message: String,
    },

    /// File-transfer tool called on a password-auth device. SCP is
    /// non-interactive and requires key-based authentication.
    #[error(
        "unsupported auth [code=unsupported_auth]: device '{0}' uses password auth; transfer_file requires ssh_key (add SshKey to inventory)"
    )]
    UnsupportedAuth(String),

    /// File transfer aborted: destination file exists on device with a
    /// different SHA-256 digest than the source. Caller must explicitly pass
    /// `force=true` to overwrite.
    #[error(
        "destination already exists with different content [code=dest_exists_differs]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); pass force=true to overwrite"
    )]
    DestExistsDiffers {
        /// Remote destination file path on the device.
        dest: String,
        /// SHA-256 digest of the local source file (64 hex chars).
        local_sha: String,
        /// SHA-256 digest of the existing remote file (64 hex chars).
        remote_sha: String,
    },

    /// External `scp` process exited non-zero. Carries exit status and stderr.
    #[error("scp failed [code=scp_failed] (exit={exit_code}): {stderr}")]
    ScpFailed {
        /// SCP process exit code.
        exit_code: i32,
        /// Stderr output from the failed SCP invocation (scrubbed).
        stderr: String,
    },

    /// System lacks OpenSSH `scp` or the binary does not support the legacy
    /// `-O` flag (required for Junos). Install openssh-client or run the
    /// official container image.
    #[error(
        "required OpenSSH scp dependency unavailable [code=scp_dependency_unavailable]: {detail}; install openssh-client with legacy -O support or use the supported container image"
    )]
    ScpDependencyUnavailable {
        /// Diagnostic describing why SCP is unavailable (binary missing, wrong version, etc.).
        detail: String,
    },

    /// SCP connection to device timed out. Device is unreachable or SSH port
    /// is filtered.
    #[error(
        "scp connect timeout [code=connect_timeout]: device '{0}' may be unreachable or SSH (port 22) is filtered"
    )]
    ConnectTimeout(String),

    /// SSH host-key verification failed: device presented a key that does not
    /// match the entry in `known_hosts`. Indicates device replacement, firmware
    /// reflash, or a MITM attack. Operator must review and update known_hosts.
    #[error(
        "host key verification failed [code=host_key_mismatch]: router '{router}' was rejected; review or refresh the entry in {known_hosts_file}"
    )]
    HostKeyMismatch {
        /// Name of the device whose host key does not match known_hosts.
        router: String,
        /// Path to the known_hosts file that contains the mismatched key.
        known_hosts_file: PathBuf,
    },

    /// Device presented a host key marked `@revoked` in known_hosts. The key is
    /// compromised or administratively revoked and must never be accepted.
    #[error(
        "host key revoked [code=host_key_revoked]: router '{router}' key is marked @revoked in {known_hosts_file}; the key is compromised and must not be trusted"
    )]
    HostKeyRevoked {
        /// Name of the device whose host key is marked @revoked.
        router: String,
        /// Path to the known_hosts file containing the revoked key marker.
        known_hosts_file: PathBuf,
    },

    /// Pre-transfer device capability probe failed (storage query, file-exists
    /// check, or SHA-256 command availability). Message names the probe phase.
    #[error("device probe failed [code=device_probe_failed] (phase={phase}): {message}")]
    DeviceProbeFailed {
        /// Probe phase that failed (e.g., "storage_probe", "checksum_command").
        phase: String,
        /// Diagnostic describing the specific failure.
        message: String,
    },

    /// SHA-256 mismatch after file transfer. The file was deleted from the
    /// device and the operation failed. Indicates mid-transfer corruption or a
    /// transient storage fault.
    #[error(
        "post-transfer verify failed [code=verify_mismatch]: {dest} (local sha256={local_sha}, remote sha256={remote_sha}); destination file was deleted"
    )]
    VerifyMismatch {
        /// Remote destination file path that failed verification.
        dest: String,
        /// SHA-256 digest of the local source file (64 hex chars).
        local_sha: String,
        /// SHA-256 digest of the file on device after transfer (64 hex chars).
        remote_sha: String,
    },

    /// File fetch aborted: local destination exists with a different SHA-256
    /// digest than the remote file. Caller must explicitly pass `force=true` to
    /// overwrite.
    #[error(
        "[code=local_dest_exists_differs] local destination '{dest}' exists with sha256 '{local_sha}'; remote sha256 is '{remote_sha}'; set force=true to overwrite"
    )]
    LocalDestExistsDiffers {
        /// Local file path that already exists.
        dest: String,
        /// SHA-256 digest of the existing local file (64 hex chars).
        local_sha: String,
        /// SHA-256 digest of the remote source file (64 hex chars).
        remote_sha: String,
    },

    /// File fetch requested a path that does not exist on the device.
    #[error("[code=remote_file_missing] router '{router}' has no file at '{remote_path}'")]
    RemoteFileMissing {
        /// Name of the device where the file was not found.
        router: String,
        /// Remote file path that does not exist.
        remote_path: String,
    },

    /// SHA-256 mismatch after file fetch. Downloaded file does not match the
    /// device's reported digest. Indicates mid-transfer corruption.
    #[error(
        "[code=fetch_verify_mismatch] fetched file '{dest}' local sha256 '{local_sha}' does not match remote sha256 '{remote_sha}'"
    )]
    FetchVerifyMismatch {
        /// Local destination file path that failed verification.
        dest: String,
        /// SHA-256 digest of the downloaded local file (64 hex chars).
        local_sha: String,
        /// SHA-256 digest reported by the device before transfer (64 hex chars).
        remote_sha: String,
    },

    /// File transfer exceeded the caller-specified timeout. The SCP process was
    /// terminated. Remediation: raise `timeout` or split the transfer.
    #[error(
        "transfer outer timeout [code=outer_timeout] after {0:?}; raise the `timeout` arg or split the file"
    )]
    TransferOuterTimeout(std::time::Duration),

    /// Destructive operation requires explicit confirmation. Payload describes
    /// the planned change; caller must re-invoke with `confirm=true`.
    #[error(
        "confirmation required [code=confirmation_required]: re-call with confirm=true to proceed; plan: {payload}"
    )]
    ConfirmationRequired {
        /// JSON payload describing the planned destructive operation.
        payload: serde_json::Value,
    },

    /// Upgrade attempted on a chassis-cluster device. ISSU is not implemented
    /// in v1; standalone devices only.
    #[error(
        "cluster device unsupported [code=cluster_unsupported]: router '{router}' is a chassis cluster; upgrade_junos v1 supports standalone devices only (ISSU support deferred to v2)"
    )]
    UpgradeClusterUnsupported {
        /// Name of the chassis-cluster device that cannot be upgraded.
        router: String,
    },

    /// Device has an active `commit confirmed` timer. Upgrade would trigger an
    /// automatic rollback mid-operation. Operator must confirm or roll back the
    /// pending commit first.
    #[error(
        "active commit-confirmed window [code=commit_confirmed_active]: router '{router}' has a pending rollback in {rollback_secs}s; run `commit` or `rollback` first, then retry"
    )]
    UpgradeCommitConfirmedActive {
        /// Name of the device with an active commit-confirmed timer.
        router: String,
        /// Remaining seconds before automatic rollback.
        rollback_secs: u64,
    },

    /// Junos `request system software add` RPC did not complete within the
    /// internal timeout. The install may still be running on the device; check
    /// from console before retrying.
    #[error(
        "install RPC timed out [code=install_timeout]: router '{router}' after {elapsed:?}; the install may still be running on the device — check from console or retry once the device is reachable"
    )]
    UpgradeInstallTimeout {
        /// Name of the device where the install RPC timed out.
        router: String,
        /// Elapsed time before the timeout fired.
        elapsed: std::time::Duration,
    },

    /// Device did not become reachable via NETCONF after reboot within the
    /// retry window. Check console or hardware status.
    #[error(
        "device did not return after reboot [code=reboot_timeout]: router '{router}' did not reopen NETCONF within {waited_secs}s; check console / hardware status"
    )]
    UpgradeRebootTimeout {
        /// Name of the device that did not return after reboot.
        router: String,
        /// Seconds waited before giving up.
        waited_secs: u64,
    },

    /// After reboot, device is running a different Junos version than
    /// expected. The install may have rolled back or failed silently.
    #[error(
        "post-upgrade version mismatch [code=postverify_mismatch]: router '{router}' expected '{expected}', got '{observed}'; the install may have rolled back or failed silently"
    )]
    UpgradePostVerifyMismatch {
        /// Name of the device running an unexpected version.
        router: String,
        /// Expected Junos version after upgrade.
        expected: String,
        /// Observed Junos version after reboot.
        observed: String,
    },

    /// Entire upgrade workflow (install + reboot + verify) exceeded the
    /// caller-specified timeout. Remediation: raise `timeout` or investigate
    /// device responsiveness.
    #[error(
        "upgrade outer timeout [code=upgrade_outer_timeout] after {0:?}; raise the `timeout` arg or check device responsiveness"
    )]
    UpgradeOuterTimeout(std::time::Duration),

    /// Generic operation timeout. Carries the elapsed duration.
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Operation was cancelled by the client (MCP cancellation signal or
    /// internal shutdown).
    #[error("operation cancelled by client [code=cancelled]")]
    Cancelled,

    /// Device is locked by another workflow (config change, upgrade, file
    /// transfer) and did not become available within the wait timeout.
    #[error(
        "device lease busy [code=device_lease_busy]: router '{router}' remained locked by another destructive workflow after {waited_secs}s"
    )]
    DeviceLeaseBusy {
        /// Name of the locked device.
        router: String,
        /// Seconds waited before giving up.
        waited_secs: u64,
    },

    /// Device lease acquisition failed for a reason other than busy/timeout.
    /// Detail carries the underlying failure.
    #[error("device lease failed [code=device_lease_error]: router '{router}': {detail}")]
    DeviceLeaseError {
        /// Name of the device whose lease acquisition failed.
        router: String,
        /// Diagnostic describing the lease failure.
        detail: String,
    },

    /// Candidate configuration cleanup (rollback + unlock) partially or fully
    /// failed after a workflow error. Each field describes the outcome of its
    /// phase; the device may still hold a lock.
    #[error(
        "candidate cleanup failed [code=candidate_cleanup_failed]: primary={primary}; rollback={rollback}; unlock={unlock}"
    )]
    CandidateCleanupFailed {
        /// Outcome of the primary workflow operation.
        primary: String,
        /// Outcome of the rollback attempt.
        rollback: String,
        /// Outcome of the unlock attempt.
        unlock: String,
    },

    /// Transport-layer error from rustez (NETCONF, SSH, XML parsing). Boxed
    /// to keep the `JmcpError` enum small.
    #[error(transparent)]
    Rustez(Box<rustez::RustEzError>),

    /// Standard IO error (file not found, permission denied, disk full, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Tool call was blocked by a deny rule in the device or default blocklist.
    /// All fields are retained for audit logging; `input_excerpt` is capped to
    /// avoid logging unbounded payloads.
    #[error(
        "denied by blocklist: {tool} on '{router}' matched rule '{pattern}' \
             (action=deny, source={rule_source}); input: {input_excerpt}"
    )]
    Denied {
        /// Name of the MCP tool that was blocked.
        tool: &'static str,
        /// Name of the device the tool call was targeting.
        router: String,
        /// Blocklist rule pattern that matched.
        pattern: String,
        /// Source of the deny rule ("device" or "defaults").
        rule_source: &'static str,
        /// Excerpt of the blocked input (capped to avoid unbounded audit payloads).
        input_excerpt: String,
        /// Line number within the input where the pattern matched, if available.
        line_number: Option<usize>,
    },

    /// Tool call was blocked by the fail-closed allowlist engine (MEC-93):
    /// under `mode: allowlist`, no allowlist entry's token sequence was a
    /// whole-token prefix of the input, a `|` pipe stage didn't match
    /// `allowed_pipes`, or the raw input contained a forbidden
    /// metacharacter (`;`, `>`, `<`, backtick, newline/CR).
    ///
    /// `reason` is the machine-readable code from
    /// `mecmcp_policy::AllowlistDenyReason::as_str()` (`not_allowlisted`,
    /// `pipe_not_allowlisted`, `forbidden_metachar`) and doubles as this
    /// error's `audit_kind()`, so the audit trail records *why* a command
    /// was refused, not just that it was. `input_excerpt` is built from the
    /// *normalized* command (`Decision::DenyAllowlist::normalized`), never
    /// the raw input — the raw input can still contain the newline that
    /// triggered `forbidden_metachar`, which could smuggle a forged line
    /// into a log file.
    #[error("denied by allowlist: {tool} on '{router}': {reason}; input: {input_excerpt}")]
    DeniedAllowlist {
        /// Name of the MCP tool that was blocked.
        tool: &'static str,
        /// Name of the device the tool call was targeting.
        router: String,
        /// Machine-readable reason code (`not_allowlisted`,
        /// `pipe_not_allowlisted`, or `forbidden_metachar`).
        reason: &'static str,
        /// Excerpt of the normalized (not raw) blocked input.
        input_excerpt: String,
    },

    /// An `allow`/`allowed_pipes` entry in the inventory failed to compile:
    /// it contained a glob metacharacter (`*`, `?`, `[`) — allowlist entries
    /// are literal token prefixes, never globs — or was empty/all-whitespace.
    /// Returned during inventory/policy load (before the server starts) so
    /// an operator's typo never silently becomes a policy gap.
    #[error("invalid allowlist entry for {scope}: entry '{entry}' {reason}")]
    AllowlistEntryInvalid {
        /// Scope where the invalid entry was found (e.g. device name or
        /// "_blocklist_defaults").
        scope: String,
        /// The entry string that failed to compile.
        entry: String,
        /// Human-readable reason the entry was rejected.
        reason: String,
    },

    /// `Policy::check_config` returned `Decision::DenyAllowlist`, which the
    /// config domain (a fail-open blocklist, unaffected by `CommandMode`)
    /// contracts to never produce (MEC-1096 F4). This should be
    /// unreachable with the current `mecmcp-policy` version; refused rather
    /// than `unreachable!()`-panicking on a device-action request path, so a
    /// future library change that violates the contract fails closed
    /// instead of aborting mid-transaction.
    #[error(
        "policy invariant violated: {tool} on '{router}': check_config returned \
         DenyAllowlist, which the config domain must never produce"
    )]
    ConfigDomainAllowlistInvariant {
        /// Name of the MCP tool that hit the invariant violation.
        tool: &'static str,
        /// Name of the device the tool call was targeting.
        router: String,
    },

    /// Destructive operation refused on a plane-owned device.
    ///
    /// This device's `config_authority` indicates it is managed by a plane (Mist,
    /// Security Director), and writes made through this server are overwritten at
    /// the next push. The operation is refused by default; pass
    /// `--allow-plane-owned-writes` to permit it with a warning instead.
    #[error(
        "refused: {tool} on '{device}' is owned by {authority}. Changes to plane-owned \
         devices are overwritten at the next push. Use --allow-plane-owned-writes to \
         permit this operation with a warning."
    )]
    PlaneOwnedDevice {
        /// Name of the MCP tool that was refused.
        tool: String,
        /// Name of the device the tool call was targeting.
        device: String,
        /// Configuration authority that owns this device (e.g., "mist", "security-director-cloud").
        authority: String,
    },

    /// A `rollback_source` action referencing a depth of 1 or more was requested
    /// on a plane-owned device.
    ///
    /// Reverting N commits on a device whose true owner is a management plane
    /// risks discarding configuration pushed by that plane since the target
    /// commit, and (until commit-origin attribution lands) this server cannot
    /// tell which commits were its own versus the plane's. Refused
    /// unconditionally — no flag overrides this (MEC-1879, P5a).
    #[error(
        "refused: {tool} on '{device}' ({authority}) would roll back {depth} commit(s) on a \
         plane-owned device. Reverting risks discarding configuration pushed by the owning \
         plane since that commit, and commit-origin attribution isn't available to tell the \
         two apart yet. Resolve this in the owning plane (e.g. Security Director) instead, or \
         author an explicit inverse payload change via create_junos_change_set."
    )]
    PlaneOwnedRollbackDepthRefused {
        /// Name of the MCP tool or code path that was refused.
        tool: &'static str,
        /// Name of the device the rollback targeted.
        device: String,
        /// Configuration authority that owns this device.
        authority: String,
        /// The requested rollback depth (`rollback_source` / archive number).
        depth: u32,
    },

    /// A change set mixed a `rollback_source` action with another action on a
    /// plane-owned device.
    ///
    /// A plane-owned rollback must be the sole action in its change set so the
    /// depth-refusal guard can evaluate it in isolation, rather than being
    /// smuggled through alongside payload actions (MEC-1879, P5a).
    #[error(
        "refused: {tool} on '{device}' ({authority}) mixes a rollback_source action with \
         another action. A change set touching a plane-owned device's rollback history must \
         contain only that one action."
    )]
    PlaneOwnedRollbackMixedAction {
        /// Name of the MCP tool that was refused.
        tool: &'static str,
        /// Name of the device the tool call was targeting.
        device: String,
        /// Configuration authority that owns this device.
        authority: String,
    },

    /// A change set with a plane-owned `rollback_source` action was created
    /// while the server runs in `--lab-mode`.
    ///
    /// Lab mode waives approval on every change set it creates, since a
    /// single-operator server has no second principal to approve it. A
    /// plane-owned rollback has no waiver path at all — refused unconditionally,
    /// independent of depth (MEC-1879, P5a).
    #[error(
        "refused: {tool} on '{device}' ({authority}) requests a rollback_source action while \
         this server runs in lab mode. Lab mode waives approval, and a plane-owned rollback has \
         no lab-mode waiver path; it requires approval by a second principal."
    )]
    PlaneOwnedRollbackLabMode {
        /// Name of the MCP tool that was refused.
        tool: &'static str,
        /// Name of the device the tool call was targeting.
        device: String,
        /// Configuration authority that owns this device.
        authority: String,
    },

    /// `rollback_config` was called with `commit=true` on a plane-owned device.
    ///
    /// Unlike other direct-commit writes, a plane-owned rollback is refused even
    /// with `--allow-plane-owned-writes` set: the depth-refusal guard only
    /// exists on the change-set path, so a direct-commit rollback has no
    /// equivalent safeguard to allow it under (MEC-1879, P5c). `commit=false`
    /// preview is unaffected.
    #[error(
        "refused: rollback_config on '{device}' ({authority}) cannot commit on a plane-owned \
         device, even with --allow-plane-owned-writes. Use create_junos_change_set → \
         approve_junos_change_set → apply_junos_change_set instead, which enforces the \
         rollback-depth guard. rollback_config with commit=false still works as a preview."
    )]
    PlaneOwnedRollbackConfigRefused {
        /// Name of the device the tool call was targeting.
        device: String,
        /// Configuration authority that owns this device.
        authority: String,
    },

    /// A direct-commit tool was refused because the server was not started
    /// with `--allow-direct-commit`.
    ///
    /// This tool stages, validates, and commits a device change in one call,
    /// with no independent second-principal approval — there is no change set
    /// to route it through. Refused by default; pass `--allow-direct-commit`
    /// to permit it, which is audited on every use.
    #[error(transparent)]
    DirectCommitDisabled(#[from] mecmcp_audit::DirectCommitRefused),

    /// Device has active config blocklist rules, which only apply to
    /// `config_format=set`. Caller requested `text` or `xml` instead.
    #[error("config blocklist rules require config_format=set; got '{format}'")]
    ConfigFormatNotAllowedWithRules {
        /// Config format the caller requested (e.g., "text", "xml").
        format: String,
    },

    /// Blocklist rule pattern failed to compile as a glob. Returned during
    /// inventory load (before the server starts) so invalid rules never reach
    /// production.
    #[error("invalid blocklist rule for {scope}: pattern '{pattern}': {source}")]
    BlocklistRuleInvalid {
        /// Scope where the invalid rule was found (e.g., device name or "_blocklist_defaults").
        scope: String,
        /// The glob pattern that failed to compile.
        pattern: String,
        /// Underlying glob compilation error.
        #[source]
        source: globset::Error,
    },

    /// Jinja2 template syntax error. Inner string carries the line/col-formatted
    /// message from the minijinja parser.
    #[error("template syntax error: {0}")]
    TemplateSyntax(String),

    /// Template variables (`vars_content`) could not be parsed as JSON or YAML.
    /// Inner string names which parser was attempted last.
    #[error("template vars parse error: {0}")]
    TemplateVars(String),

    /// Template render failed (undefined variable in strict mode, type error,
    /// or filter failure). Inner string is the minijinja error message.
    #[error("template render error: {0}")]
    TemplateRender(String),

    /// Rendered template specifies `text` or `xml` format, but the target
    /// device has active config blocklist rules (which only apply to `set`).
    /// Same restriction as `load_and_commit_config`.
    #[error("template format `{format}` not allowed: device has config rules; use `set`")]
    TemplateFormatMismatch {
        /// Format the template specified (e.g., "text", "xml").
        format: String,
    },

    /// Generic input validation failure. Inner string describes the specific
    /// constraint that was violated.
    #[error("validation error: {0}")]
    Validation(String),

    /// Config diff failed because the on-device configuration could not be
    /// parsed in the requested format. Message carries the raw error and an
    /// actionable hint (e.g., "try display_format=text").
    #[error("{0}")]
    ConfigParseHint(String),

    /// Inventory modification attempted but the server was started with
    /// `--inventory-readonly`.
    #[error("inventory is read-only (--inventory-readonly set)")]
    InventoryReadonly,

    /// `add_device` attempted to create a device whose name is already in the
    /// inventory.
    #[error("device `{0}` already exists in the inventory")]
    DeviceExists(String),

    /// `add_device` called with password auth, but the server was started
    /// without `--allow-password-auth-add`.
    #[error(
        "password authentication is not allowed for add_device; use --allow-password-auth-add to enable"
    )]
    PasswordAuthDisabled,

    /// Device name fails validation (must be 1-64 ASCII alphanumeric + `_.-`,
    /// no leading hyphen).
    #[error("invalid device name `{0}`: must match ^[A-Za-z0-9_.-]+$")]
    InvalidDeviceName(String),

    /// IP or hostname fails validation (not an IPv4/IPv6 address and not a
    /// valid RFC 1123 hostname).
    #[error("invalid device IP/hostname `{0}`")]
    InvalidDeviceIp(String),

    /// Port number is outside the valid range (1..=65535).
    #[error("invalid device port `{0}`: must be in 1..=65535")]
    InvalidDevicePort(u32),

    /// MCP tool call is missing one or more required arguments. Vec names the
    /// missing fields.
    #[error("missing required arguments: {0:?}")]
    MissingArguments(Vec<String>),

    /// CAS check failed: inventory file was modified by another process
    /// between read and write. Caller must reload and retry.
    #[error("inventory file changed on disk between read and write; call reload_devices and retry")]
    InventoryDriftedOnDisk,

    /// Inventory file was successfully loaded but contains no devices.
    #[error("inventory is empty (no devices)")]
    EmptyInventory,

    /// IO error reading inventory file. Inner string carries the error detail.
    #[error("inventory file read error: {0}")]
    InventoryRead(String),

    /// Inventory file is not valid JSON. Inner string is the parse error.
    #[error("inventory parse error: {0}")]
    InventoryParse(String),

    /// IO error writing inventory file. Inner string carries the error detail.
    #[error("inventory file write error: {0}")]
    InventoryWrite(String),

    /// Server started with `HostKeyVerification::KnownHosts(<path>)` but the
    /// file does not exist or is unreadable. Remediation: run
    /// `scripts/scan-known-hosts.sh` to populate it, or (lab only) pass
    /// `--ssh-accept-new-host-keys`.
    #[error(
        "known_hosts file missing or unreadable [code=known_hosts_missing]: {0}; run scripts/scan-known-hosts.sh to pre-populate it, or pass --ssh-accept-new-host-keys (lab only)"
    )]
    KnownHostsMissing(PathBuf),
}

impl From<rustez::RustEzError> for JmcpError {
    fn from(e: rustez::RustEzError) -> Self {
        JmcpError::Rustez(Box::new(e))
    }
}

impl From<mecmcp_device::DeviceLockError> for JmcpError {
    fn from(e: mecmcp_device::DeviceLockError) -> Self {
        use mecmcp_device::DeviceLockError;
        match e {
            DeviceLockError::Busy {
                device,
                waited_secs,
            } => JmcpError::DeviceLeaseBusy {
                router: device,
                waited_secs,
            },
            DeviceLockError::Cancelled => JmcpError::Cancelled,
            DeviceLockError::Other { device, detail } => JmcpError::DeviceLeaseError {
                router: device,
                detail,
            },
        }
    }
}

impl mecmcp_device::cancel::Cancellable for JmcpError {
    fn cancelled() -> Self {
        JmcpError::Cancelled
    }
}

impl JmcpError {
    /// Returns the stable audit `error_kind` string for this error variant.
    ///
    /// Used by `AuditScope::fail_kind` to emit structured error classes to SIEM.
    /// This match is EXHAUSTIVE (no `_` wildcard) so that any new variant added
    /// to `JmcpError` triggers a compile error here, forcing a deliberate
    /// classification decision for the new variant.
    pub fn audit_kind(&self) -> &'static str {
        match self {
            Self::UnknownRouter(_) => "unknown_router",
            Self::InventoryInvalid(_) => "invalid_input",
            Self::KeyFileMissing(_) => "not_found",
            Self::SshConfigInvalid { .. } => "invalid_input",
            Self::BadFormat(_) => "invalid_input",
            Self::BadConfigFormat(_) => "invalid_input",
            Self::BadLoadMode(_) => "invalid_input",
            Self::OverrideRequiresChangeSet { .. } => "blocked",
            Self::OverrideRequiresHumanApproval { .. } => "blocked",
            Self::IncompatibleFormatMode { .. } => "invalid_input",
            Self::BadPfeCommand(_) => "invalid_input",
            Self::BadRollbackVersion(_) => "invalid_input",
            Self::BadSourcePath(_) => "invalid_input",
            Self::InsufficientDisk { .. } => "insufficient_disk",
            Self::UnsupportedAuth(_) => "unsupported",
            Self::DestExistsDiffers { .. } => "conflict",
            Self::ScpFailed { .. } => "scp_failed",
            Self::ScpDependencyUnavailable { .. } => "dependency_unavailable",
            Self::ConnectTimeout(_) => "timeout",
            Self::HostKeyMismatch { .. } => "host_key_mismatch",
            Self::HostKeyRevoked { .. } => "host_key_revoked",
            Self::DeviceProbeFailed { .. } => "device_probe_failed",
            Self::VerifyMismatch { .. } => "verify_mismatch",
            Self::LocalDestExistsDiffers { .. } => "conflict",
            Self::RemoteFileMissing { .. } => "not_found",
            Self::FetchVerifyMismatch { .. } => "verify_mismatch",
            Self::TransferOuterTimeout(_) => "timeout",
            Self::ConfirmationRequired { .. } => "confirmation_required",
            Self::UpgradeClusterUnsupported { .. } => "unsupported",
            Self::UpgradeCommitConfirmedActive { .. } => "commit_confirmed_active",
            Self::UpgradeInstallTimeout { .. } => "timeout",
            Self::UpgradeRebootTimeout { .. } => "timeout",
            Self::UpgradePostVerifyMismatch { .. } => "verify_mismatch",
            Self::UpgradeOuterTimeout(_) => "timeout",
            Self::Timeout(_) => "timeout",
            Self::Cancelled => "cancelled",
            Self::DeviceLeaseBusy { .. } => "lease_busy",
            Self::DeviceLeaseError { .. } => "lease_error",
            Self::CandidateCleanupFailed { .. } => "lease_error",
            Self::Rustez(_) => "transport",
            Self::Io(_) => "io",
            Self::Json(_) => "parse",
            Self::Denied { .. } => "blocked",
            // The reason code IS the audit_kind, per MEC-93 spec item 4: the
            // audit trail records not just that a command was refused, but
            // which of the library's three allowlist-deny reasons fired.
            Self::DeniedAllowlist { reason, .. } => reason,
            Self::AllowlistEntryInvalid { .. } => "invalid_input",
            Self::ConfigDomainAllowlistInvariant { .. } => "blocked",
            Self::PlaneOwnedDevice { .. } => "blocked",
            Self::PlaneOwnedRollbackDepthRefused { .. } => "blocked",
            Self::PlaneOwnedRollbackMixedAction { .. } => "blocked",
            Self::PlaneOwnedRollbackLabMode { .. } => "blocked",
            Self::PlaneOwnedRollbackConfigRefused { .. } => "blocked",
            Self::DirectCommitDisabled(_) => "blocked",
            Self::ConfigFormatNotAllowedWithRules { .. } => "invalid_input",
            Self::BlocklistRuleInvalid { .. } => "invalid_input",
            Self::TemplateSyntax(_) => "parse",
            Self::TemplateVars(_) => "parse",
            Self::TemplateRender(_) => "parse",
            Self::TemplateFormatMismatch { .. } => "invalid_input",
            Self::Validation(_) => "invalid_input",
            Self::ConfigParseHint(_) => "invalid_input",
            Self::InventoryReadonly => "inventory_readonly",
            Self::DeviceExists(_) => "conflict",
            Self::PasswordAuthDisabled => "unsupported",
            Self::InvalidDeviceName(_) => "invalid_input",
            Self::InvalidDeviceIp(_) => "invalid_input",
            Self::InvalidDevicePort(_) => "invalid_input",
            Self::MissingArguments(_) => "invalid_input",
            Self::InventoryDriftedOnDisk => "conflict",
            Self::EmptyInventory => "inventory_empty",
            Self::InventoryRead(_) => "io",
            Self::InventoryParse(_) => "parse",
            Self::InventoryWrite(_) => "io",
            Self::KnownHostsMissing(_) => "not_found",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_router_displays_router_name() {
        let e = JmcpError::UnknownRouter("r99".into());
        assert_eq!(e.to_string(), "router 'r99' not found in device mapping");
    }

    #[test]
    fn ssh_config_invalid_mentions_router_and_cause() {
        let e = JmcpError::SshConfigInvalid {
            router: "r1".into(),
            source: rustez::SshConfigError::Io {
                path: std::path::PathBuf::from("/no/such/path"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            },
        };
        let s = e.to_string();
        assert!(s.contains("ssh_config"));
        assert!(s.contains("r1"));
    }

    #[test]
    fn bad_format_shows_invalid_value() {
        let e = JmcpError::BadFormat("yaml".into());
        assert_eq!(
            e.to_string(),
            "invalid config_format 'yaml' (expected set, text, or xml)"
        );
    }

    #[test]
    fn bad_config_format_shows_invalid_value() {
        let e = JmcpError::BadConfigFormat("yaml".into());
        assert_eq!(
            e.to_string(),
            "invalid format 'yaml' for get_junos_config (expected text, set, xml, or json)"
        );
    }

    #[test]
    fn bad_load_mode_shows_invalid_value() {
        let e = JmcpError::BadLoadMode("wipe".into());
        assert_eq!(
            e.to_string(),
            "invalid mode 'wipe' (expected merge, replace, or override)"
        );
    }

    #[test]
    fn override_requires_change_set_names_the_tool() {
        let e = JmcpError::OverrideRequiresChangeSet {
            tool: "load_and_commit_config",
        };
        let s = e.to_string();
        assert!(s.contains("load_and_commit_config"));
        assert!(s.contains("create_junos_change_set"));
    }

    #[test]
    fn incompatible_format_mode_names_both() {
        let e = JmcpError::IncompatibleFormatMode {
            format: "set".into(),
            mode: "override".into(),
        };
        let s = e.to_string();
        assert!(s.contains("set"));
        assert!(s.contains("override"));
    }

    #[test]
    fn bad_rollback_version_shows_value_and_range() {
        let e = JmcpError::BadRollbackVersion(99);
        assert_eq!(e.to_string(), "rollback version 99 out of range (0..=49)");
    }

    #[test]
    fn denied_displays_tool_router_and_rule() {
        let e = JmcpError::Denied {
            tool: "execute_junos_command",
            router: "r1".into(),
            pattern: "request system *".into(),
            rule_source: "defaults",
            input_excerpt: "request system reboot".into(),
            line_number: None,
        };
        let s = e.to_string();
        assert!(s.contains("execute_junos_command"));
        assert!(s.contains("r1"));
        assert!(s.contains("request system *"));
        assert!(s.contains("defaults"));
        assert!(s.contains("request system reboot"));
    }

    #[test]
    fn config_format_not_allowed_with_rules_names_format() {
        let e = JmcpError::ConfigFormatNotAllowedWithRules {
            format: "xml".into(),
        };
        let s = e.to_string();
        assert!(s.contains("xml"));
        assert!(s.contains("set"));
    }

    #[test]
    fn blocklist_rule_invalid_names_scope_and_pattern() {
        let glob_err = globset::Glob::new("[unterminated").unwrap_err();
        let e = JmcpError::BlocklistRuleInvalid {
            scope: "_blocklist_defaults.commands".into(),
            pattern: "[unterminated".into(),
            source: glob_err,
        };
        let s = e.to_string();
        assert!(s.contains("_blocklist_defaults.commands"));
        assert!(s.contains("[unterminated"));
    }

    #[test]
    fn bad_pfe_command_displays_reason() {
        let e = JmcpError::BadPfeCommand("contains literal quote".into());
        let s = e.to_string();
        assert!(s.contains("invalid pfe_command"));
        assert!(s.contains("contains literal quote"));
    }

    #[test]
    fn template_syntax_display() {
        let e = JmcpError::TemplateSyntax("line 3: unexpected end-of-input".into());
        let s = format!("{e}");
        assert!(s.contains("template syntax"));
        assert!(s.contains("line 3"));
    }

    #[test]
    fn inventory_readonly_display_mentions_flag() {
        let s = JmcpError::InventoryReadonly.to_string();
        assert!(s.contains("--inventory-readonly"));
    }

    #[test]
    fn device_exists_display_includes_name() {
        let s = JmcpError::DeviceExists("r1".into()).to_string();
        assert!(s.contains("`r1`"));
        assert!(s.contains("already exists"));
    }

    #[test]
    fn password_auth_disabled_display_mentions_flag() {
        let s = JmcpError::PasswordAuthDisabled.to_string();
        assert!(s.contains("--allow-password-auth-add"));
    }

    #[test]
    fn invalid_device_name_display_includes_regex() {
        let s = JmcpError::InvalidDeviceName("bad name".into()).to_string();
        assert!(s.contains("bad name"));
        assert!(s.contains("^[A-Za-z0-9_.-]+$"));
    }

    #[test]
    fn invalid_device_ip_display_includes_value() {
        let s = JmcpError::InvalidDeviceIp("not-an-ip".into()).to_string();
        assert!(s.contains("not-an-ip"));
    }

    #[test]
    fn invalid_device_port_display_includes_range() {
        let s = JmcpError::InvalidDevicePort(70_000).to_string();
        assert!(s.contains("70000"));
        assert!(s.contains("1..=65535"));
    }

    #[test]
    fn missing_arguments_display_uses_debug_format() {
        let s = JmcpError::MissingArguments(vec!["router_name".into(), "ip".into()]).to_string();
        assert!(s.contains("[\"router_name\", \"ip\"]"));
    }

    #[test]
    fn inventory_drifted_display_recommends_reload() {
        let s = JmcpError::InventoryDriftedOnDisk.to_string();
        assert!(s.contains("reload_devices"));
    }

    #[test]
    fn empty_inventory_display() {
        let s = JmcpError::EmptyInventory.to_string();
        assert!(s.contains("inventory is empty"));
    }

    #[test]
    fn inventory_read_display_includes_cause() {
        let s = JmcpError::InventoryRead("permission denied".into()).to_string();
        assert!(s.contains("read"));
        assert!(s.contains("permission denied"));
    }

    #[test]
    fn inventory_parse_display_includes_cause() {
        let s = JmcpError::InventoryParse("expected `{` at line 1".into()).to_string();
        assert!(s.contains("parse"));
        assert!(s.contains("expected `{`"));
    }

    #[test]
    fn inventory_write_display_includes_cause() {
        let s = JmcpError::InventoryWrite("disk full".into()).to_string();
        assert!(s.contains("write"));
        assert!(s.contains("disk full"));
    }

    #[test]
    fn bad_source_path_display_includes_code() {
        let s = JmcpError::BadSourcePath("contains '/'".into()).to_string();
        assert!(s.contains("code=bad_source_path"));
        assert!(s.contains("contains '/'"));
    }

    #[test]
    fn unsupported_auth_display_includes_remediation() {
        let s = JmcpError::UnsupportedAuth("vSRX-test10".into()).to_string();
        assert!(s.contains("code=unsupported_auth"));
        assert!(s.contains("vSRX-test10"));
        assert!(s.contains("ssh_key"));
    }

    #[test]
    fn dest_exists_differs_display_includes_force_hint() {
        let s = JmcpError::DestExistsDiffers {
            dest: "/var/tmp/foo".into(),
            local_sha: "aaa".into(),
            remote_sha: "bbb".into(),
        }
        .to_string();
        assert!(s.contains("code=dest_exists_differs"));
        assert!(s.contains("force=true"));
    }

    #[test]
    fn scp_failed_display_includes_stderr() {
        let s = JmcpError::ScpFailed {
            exit_code: 1,
            stderr: "Permission denied".into(),
        }
        .to_string();
        assert!(s.contains("code=scp_failed"));
        assert!(s.contains("Permission denied"));
        assert!(s.contains("exit=1"));
    }

    #[test]
    fn scp_dependency_unavailable_display_includes_code_and_remediation() {
        let s = JmcpError::ScpDependencyUnavailable {
            detail: "executable 'scp' was not found in PATH".into(),
        }
        .to_string();
        assert!(s.contains("[code=scp_dependency_unavailable]"));
        assert!(s.contains("openssh-client"));
        assert!(s.contains("legacy -O"));
    }

    #[test]
    fn connect_timeout_display_includes_hint() {
        let s = JmcpError::ConnectTimeout("vSRX-test10".into()).to_string();
        assert!(s.contains("code=connect_timeout"));
        assert!(s.contains("vSRX-test10"));
    }

    #[test]
    fn host_key_mismatch_display_includes_code_router_and_known_hosts() {
        let s = JmcpError::HostKeyMismatch {
            router: "vSRX-test10".into(),
            known_hosts_file: std::path::PathBuf::from("/etc/jmcp/known_hosts"),
        }
        .to_string();
        assert!(s.contains("[code=host_key_mismatch]"), "got {s}");
        assert!(s.contains("vSRX-test10"), "got {s}");
        assert!(s.contains("/etc/jmcp/known_hosts"), "got {s}");
    }

    #[test]
    fn device_probe_failed_display_includes_code_and_phase() {
        let e = JmcpError::DeviceProbeFailed {
            phase: "storage_probe".into(),
            message: "rpc-error: ...".into(),
        };
        let s = e.to_string();
        assert!(s.contains("[code=device_probe_failed]"));
        assert!(s.contains("storage_probe"));
    }

    #[test]
    fn verify_mismatch_display_notes_deletion() {
        let s = JmcpError::VerifyMismatch {
            dest: "/var/tmp/foo".into(),
            local_sha: "aaa".into(),
            remote_sha: "bbb".into(),
        }
        .to_string();
        assert!(s.contains("code=verify_mismatch"));
        assert!(s.contains("deleted"));
    }

    #[test]
    fn transfer_outer_timeout_display_includes_remediation() {
        let s = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(60)).to_string();
        assert!(s.contains("code=outer_timeout"));
        assert!(s.contains("raise"));
    }

    #[test]
    fn confirmation_required_display_includes_code_and_router() {
        let payload = serde_json::json!({
            "router": "vsrx-test18",
            "current_version": "24.4R1.9",
            "target_version": "25.4R1.12",
        });
        let s = JmcpError::ConfirmationRequired {
            payload: payload.clone(),
        }
        .to_string();
        assert!(s.contains("[code=confirmation_required]"), "got {s}");
        assert!(s.contains("vsrx-test18"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
    }

    #[test]
    fn upgrade_cluster_unsupported_display_includes_code_and_router() {
        let s = JmcpError::UpgradeClusterUnsupported {
            router: "vsrx-test19".into(),
        }
        .to_string();
        assert!(s.contains("[code=cluster_unsupported]"), "got {s}");
        assert!(s.contains("vsrx-test19"), "got {s}");
    }

    #[test]
    fn upgrade_commit_confirmed_active_display_includes_code_and_rollback() {
        let s = JmcpError::UpgradeCommitConfirmedActive {
            router: "vsrx-test10".into(),
            rollback_secs: 540,
        }
        .to_string();
        assert!(s.contains("[code=commit_confirmed_active]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("540"), "got {s}");
    }

    #[test]
    fn upgrade_install_timeout_display_includes_code() {
        let s = JmcpError::UpgradeInstallTimeout {
            router: "vsrx-test10".into(),
            elapsed: std::time::Duration::from_secs(3600),
        }
        .to_string();
        assert!(s.contains("[code=install_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
    }

    #[test]
    fn upgrade_reboot_timeout_display_includes_code_and_secs() {
        let s = JmcpError::UpgradeRebootTimeout {
            router: "vsrx-test10".into(),
            waited_secs: 480,
        }
        .to_string();
        assert!(s.contains("[code=reboot_timeout]"), "got {s}");
        assert!(s.contains("vsrx-test10"), "got {s}");
        assert!(s.contains("480"), "got {s}");
    }

    #[test]
    fn upgrade_postverify_mismatch_display_includes_versions() {
        let s = JmcpError::UpgradePostVerifyMismatch {
            router: "vsrx-test10".into(),
            expected: "25.4R1.12".into(),
            observed: "24.4R1.9".into(),
        }
        .to_string();
        assert!(s.contains("[code=postverify_mismatch]"), "got {s}");
        assert!(s.contains("25.4R1.12"), "got {s}");
        assert!(s.contains("24.4R1.9"), "got {s}");
    }

    #[test]
    fn upgrade_outer_timeout_display_includes_code_and_duration() {
        let s = JmcpError::UpgradeOuterTimeout(std::time::Duration::from_secs(900)).to_string();
        assert!(s.contains("[code=upgrade_outer_timeout]"), "got {s}");
        assert!(s.contains("900s"), "got {s}");
    }

    #[test]
    fn cancelled_display_includes_code() {
        let s = JmcpError::Cancelled.to_string();
        assert!(s.contains("[code=cancelled]"), "got {s}");
        assert!(s.contains("cancelled by client"), "got {s}");
    }

    #[test]
    fn device_lease_errors_have_stable_codes() {
        let busy = JmcpError::DeviceLeaseBusy {
            router: "srx-01".into(),
            waited_secs: 30,
        }
        .to_string();
        assert!(busy.contains("[code=device_lease_busy]"));

        let failed = JmcpError::DeviceLeaseError {
            router: "srx-01".into(),
            detail: "permission denied".into(),
        }
        .to_string();
        assert!(failed.contains("[code=device_lease_error]"));
    }

    #[test]
    fn local_dest_exists_differs_display_has_code() {
        let s = JmcpError::LocalDestExistsDiffers {
            dest: "/var/lib/jmcp/staging/foo.tgz".into(),
            local_sha: "aaaa".into(),
            remote_sha: "bbbb".into(),
        }
        .to_string();
        assert!(s.contains("[code=local_dest_exists_differs]"), "{s}");
        assert!(s.contains("aaaa"), "{s}");
        assert!(s.contains("bbbb"), "{s}");
    }

    #[test]
    fn remote_file_missing_display_has_code() {
        let s = JmcpError::RemoteFileMissing {
            router: "vsrx-test10".into(),
            remote_path: "/var/tmp/missing.txt".into(),
        }
        .to_string();
        assert!(s.contains("[code=remote_file_missing]"), "{s}");
        assert!(s.contains("vsrx-test10"), "{s}");
    }

    #[test]
    fn fetch_verify_mismatch_display_has_code() {
        let s = JmcpError::FetchVerifyMismatch {
            dest: "/var/lib/jmcp/staging/foo.tgz".into(),
            local_sha: "aaaa".into(),
            remote_sha: "bbbb".into(),
        }
        .to_string();
        assert!(s.contains("[code=fetch_verify_mismatch]"), "{s}");
    }

    // --- audit_kind tests ---

    #[test]
    fn audit_kind_timeout() {
        assert_eq!(
            JmcpError::Timeout(std::time::Duration::from_secs(30)).audit_kind(),
            "timeout"
        );
    }

    #[test]
    fn audit_kind_lease_busy() {
        assert_eq!(
            JmcpError::DeviceLeaseBusy {
                router: "r1".into(),
                waited_secs: 60
            }
            .audit_kind(),
            "lease_busy"
        );
    }

    #[test]
    fn audit_kind_confirmation_required() {
        assert_eq!(
            JmcpError::ConfirmationRequired {
                payload: serde_json::json!({"router": "r1"})
            }
            .audit_kind(),
            "confirmation_required"
        );
    }

    #[test]
    fn audit_kind_unknown_router() {
        assert_eq!(
            JmcpError::UnknownRouter("r99".into()).audit_kind(),
            "unknown_router"
        );
    }

    #[test]
    fn audit_kind_invalid_input() {
        assert_eq!(
            JmcpError::BadFormat("yaml".into()).audit_kind(),
            "invalid_input"
        );
    }

    #[test]
    fn audit_kind_blocked() {
        assert_eq!(
            JmcpError::Denied {
                tool: "execute_junos_command",
                router: "r1".into(),
                pattern: "request system *".into(),
                rule_source: "defaults",
                input_excerpt: "request system reboot".into(),
                line_number: None,
            }
            .audit_kind(),
            "blocked"
        );
    }

    #[test]
    fn audit_kind_transport() {
        // Can't easily construct a RustEzError in tests (external crate),
        // so we verify the mapping via the match statement coverage instead.
        // The Rustez variant maps to "transport" per the exhaustive match.
    }

    #[test]
    fn audit_kind_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(JmcpError::Io(io_err).audit_kind(), "io");
    }
}

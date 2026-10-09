//! Junos and SRX MCP server.
//!
//! Provides MCP tools for Junos device management (generic operations across all
//! Junos platforms) and SRX-specific operational workflows. Authenticates remote
//! callers via HTTP Bearer tokens with per-token tool and device scopes, and
//! supports unauthenticated stdio transport for local-only operation.
//!
//! See [`server::JmcpHandler`] for the tool surface and
//! `rust-junosmcp-auth::tower` for the authentication boundary.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod cli;
mod env_compat;
mod state_cmd;
#[cfg(feature = "tls")]
mod tls;
mod token_cmd;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use cli::{Command, Transport};
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use rmcp::ServiceExt;
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_auth::TokenStoreFile;
use rust_junosmcp_core::{DeviceManager, Inventory, MecmcpScpRunner, Policy, TransferConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Resolve the token store, applying the legacy fallback ONLY for the canonical path.
///
/// The migration fallback exists so an upgrade that has not yet moved
/// `/etc/jmcp/tokens.json` still starts. It must not apply to an operator's own
/// path: if `--tokens-file /srv/custom.json` is missing — a typo, or a deleted
/// store — falling back to the legacy file would silently reactivate unrelated
/// or revoked credentials. A non-canonical path is loaded directly and fails if
/// absent, which is the honest outcome.
fn resolve_tokens(configured: &std::path::Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    let (canonical, legacy) = token_store_paths();
    resolve_tokens_with(configured, &canonical, &legacy)
}

/// Canonical token store and the legacy `/etc` location an unmigrated install
/// may still be using. Both come from [`cli::server_naming`], which is
/// `jmcp`, so the paths stay `/var/lib/jmcp/tokens.json` and
/// `/etc/jmcp/tokens.json`.
fn token_store_paths() -> (PathBuf, PathBuf) {
    let naming = cli::server_naming();
    (
        naming.state_dir.join("tokens.json"),
        naming.config_dir.join("tokens.json"),
    )
}

/// Credential-adjacent files whose modes are checked together, before any of
/// them is loaded.
///
/// A startup that checks one file and exits reports the next loose mode only
/// on the next restart. [`validate_startup_credentials`] asks `mecmcp-secret`
/// to report every offender in this list at once.
///
/// `known_hosts` is not here. Nothing mode-checks it today: the packaged mode
/// is `0644`, and a strict check would refuse every current install. A custom
/// CA bundle is likewise not a secret file.
struct StartupCredentialFiles<'a> {
    /// `devices.json`. Required. Holds credentials, so it is owner-only, the
    /// same ceiling [`Inventory::load`] enforces.
    inventory: &'a Path,
    /// NETCONF SSH private keys named by the inventory. Each is required.
    private_keys: &'a [PathBuf],
    /// Bearer-token store this process will load. Required when set.
    ///
    /// This is the path [`resolve_tokens`] already selected, including the
    /// legacy `/etc/jmcp/tokens.json` store when that fallback is in effect.
    /// stdio does not load a token store, so it passes `None`.
    tokens: Option<&'a Path>,
    /// SSDF password files this process will load. Each is required.
    ssdf_password_files: &'a [PathBuf],
    /// SSDF segment signing key. Required when the pipeline will load it.
    ssdf_signing_key: Option<&'a Path>,
    /// Forward-sink bearer token. Required when the pipeline will load it.
    audit_forward_token: Option<&'a Path>,
    /// Audit HMAC key. Required when set; the caller creates a missing key first.
    audit_hmac_key: Option<&'a Path>,
    /// Listener TLS private key. Required when this process will load it.
    tls_key: Option<&'a Path>,
    /// Approval digest key from `--approval-digest-key-file`. Required when set.
    approval_digest_key: Option<&'a Path>,
}

/// Check every credential-adjacent file in one pass.
///
/// # Errors
/// Returns the aggregate validation error when any listed file is missing or
/// fails its mode check. The error names every offender.
fn validate_startup_credentials(
    files: &StartupCredentialFiles<'_>,
) -> Result<(), mecmcp_secret::CredentialValidationError> {
    let mut specs =
        Vec::with_capacity(1 + files.private_keys.len() + files.ssdf_password_files.len() + 6);
    specs.push(CredentialFileSpec {
        path: files.inventory,
        role: CredentialFileRole::Secret,
        description: "device inventory",
        required: true,
    });
    for path in files.private_keys {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "NETCONF private key",
            required: true,
        });
    }
    if let Some(path) = files.tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    for path in files.ssdf_password_files {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "SSDF password file",
            required: true,
        });
    }
    if let Some(path) = files.ssdf_signing_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "SSDF signing key",
            required: true,
        });
    }
    if let Some(path) = files.audit_forward_token {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit forward bearer token",
            required: true,
        });
    }
    if let Some(path) = files.audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    if let Some(path) = files.tls_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "TLS private key",
            required: true,
        });
    }
    if let Some(path) = files.approval_digest_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "approval digest key",
            required: true,
        });
    }

    validate_credential_files(&specs)
}

/// SSDF password files the evidence pipeline will actually load.
///
/// Absent `--ssdf-audit-endpoint`, `into_config` never opens these files, so
/// a loose mode on an unused path must not refuse startup.
fn ssdf_password_files(evidence: &mecmcp_runtime::cli::EvidenceArgs) -> Vec<PathBuf> {
    if evidence.ssdf_audit_endpoint.is_none() {
        return Vec::new();
    }
    let mut paths = Vec::new();
    if let Some(path) = &evidence.ssdf_audit_password_file {
        paths.push(path.clone());
    }
    if let Some(path) = &evidence.ssdf_audit_verify_password_file {
        push_unique(&mut paths, path);
    }
    paths
}

fn push_unique(paths: &mut Vec<PathBuf>, path: &Path) {
    if !paths.iter().any(|existing| existing == path) {
        paths.push(path.to_path_buf());
    }
}

/// The rule behind [`resolve_tokens`], with the two well-known paths injected so
/// it can be exercised against real files in a test rather than against absolute
/// paths that never exist there.
fn resolve_tokens_with(
    configured: &std::path::Path,
    canonical: &std::path::Path,
    legacy: &std::path::Path,
) -> Result<mecmcp_auth::ResolvedTokenPath> {
    // Byte-exact, not `Path` equality. `Path` comparison normalizes away trailing
    // separators and `.` components, so `/var/lib/<svc>/tokens.json/` compares
    // EQUAL to the canonical path — while `metadata()` on that spelling returns
    // NotFound when the file is absent, indistinguishable from the plain form.
    // A typo would therefore pass this gate and activate the legacy store, which
    // is exactly the fail-closed behaviour this check exists to provide.
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }

    mecmcp_auth::resolve_token_path(configured, legacy).context("resolving token file path")
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in, see docs/AUDIT.md), so this alone does not turn
/// redaction on; it just means the key is already there the moment an
/// operator flips `--audit-redact ...=hmac` on, instead of failing with
/// `HmacKeyUnreadable` on that first restart.
///
/// `-s` (not `-e`): a zero-byte key file is indistinguishable from "never
/// generated" and would make every HMAC output constant, so rewriting it
/// here is a repair, not data loss. A non-empty file is never rotated --
/// that would silently break verification of every audit record signed
/// under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    use rand::TryRng as _;
    rand::rngs::SysRng.try_fill_bytes(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_compat::ParsedCli {
        cli: args,
        warnings,
    } = env_compat::parse();

    // `mecmcp-http`'s `HttpClient` (via `HttpKeySource`, used only when
    // `--oidc-issuer` is configured below) requires a process-wide rustls
    // `CryptoProvider`. Installed unconditionally and ignored if already
    // installed: `install_default` is a one-shot, and every other rustls use
    // in this binary (TLS serving) builds and passes its own provider
    // explicitly rather than relying on the global default, so this cannot
    // conflict with it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(key_path) = args.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("invalid --audit-redact: {e}"))?,
        )
    };
    let audit_cfg = mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        // rust-junosmcp does not expose `--otel-endpoint`; OTel export stays
        // off until this server's CLI wires it through.
        otel: None,
    };
    let audit_sink =
        mecmcp_audit::init_tracing(&audit_cfg).context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("junosmcp_tool_duration_seconds");
    env_compat::emit_warnings(&warnings);

    match args.command {
        Some(Command::Token { action }) => return token_cmd::run(action),
        Some(Command::State { action }) => return state_cmd::run(action),
        None => {}
    }

    // Convert to shared CLI for validation
    let shared_cli = mecmcp_runtime::cli::Cli {
        command: None, // Not checked by validate
        device_mapping: args.device_mapping.clone(),
        transport: args.transport,
        host: args.host.clone(),
        port: args.port,
        tokens_file: args.tokens_file.clone(),
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        allow_no_auth: args.allow_no_auth,
        allow_insecure_bind: args.allow_insecure_bind,
        allowed_host: args.allowed_host.clone(),
        allowed_origin: args.allowed_origin.clone(),
        audit_format: args.audit_format.clone(),
        audit_log_file: args.audit_log_file.clone(),
        audit_journald: args.audit_journald,
        audit_redact: args.audit_redact.clone(),
        audit_hmac_key_file: args.audit_hmac_key_file.clone(),
        // Not exposed as a rust-junosmcp CLI flag yet, same as above: no
        // `--otel-endpoint`/`--otel-service-name` flags exist on this
        // binary's own `Cli`, so OTel export stays disabled.
        otel_endpoint: None,
        otel_service_name: "mecmcp".to_string(),
        evidence: args.evidence.clone(),
        approval_digest_key_file: args.approval_digest_key_file.clone(),
    };
    mecmcp_runtime::cli_validate::validate(&shared_cli).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Cross-check the verified-approver flags against this binary's own
    // --approval-digest-key-file and --lab-mode, which `VerifiedApproverArgs`
    // cannot see on its own (mecmcp-runtime has no dependency on
    // mecmcp-changeset and does not know this server's lab-mode flag).
    args.verified_approver
        .validate(args.approval_digest_key_file.is_some(), args.lab_mode)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Vendor-specific validation.
    //
    // These two rules cannot live in mecmcp-runtime: --inventory-readonly,
    // --allow-password-auth-add, and --enable-metrics are junos flags, and the
    // shared Cli struct has no fields for them. The Phase 3b migration moved
    // cli_validate.rs upstream and dropped the inventory rule on the way — the
    // doc comment on --allow-password-auth-add still promised "Mutually
    // exclusive with --inventory-readonly" while the binary happily accepted
    // both, which is the same class of defect as #217 with the polarity
    // reversed: documentation asserting a constraint nothing enforces.
    if args.inventory_readonly && args.allow_password_auth_add {
        anyhow::bail!(
            "--inventory-readonly and --allow-password-auth-add are mutually exclusive: \
             the first rejects add_device outright, the second widens what it accepts"
        );
    }
    if args.enable_metrics && args.transport != Transport::StreamableHttp {
        anyhow::bail!("--enable-metrics requires --transport streamable-http");
    }

    // Validated the same way as a per-call `confirm_timeout_mins` (MEC-45):
    // must convert to seconds without overflow. Set once, before any tool
    // call can read it via `resolve_confirm_timeout`.
    rust_junosmcp_core::helpers::confirm_timeout_to_secs(args.commit_confirm_default_mins)
        .map_err(|e| anyhow::anyhow!("invalid --commit-confirm-default-mins: {e}"))?;
    rust_junosmcp_core::helpers::set_commit_confirm_default_mins(args.commit_confirm_default_mins);

    // Only the files this process will load. stdio ignores `--tokens-file`.
    // The legacy `/etc` fallback is applied here so the mode pass checks the
    // store that will actually be loaded, not a canonical path that is not
    // there yet. A non-canonical path is never substituted.
    let private_keys = Inventory::netconf_private_key_paths(&args.device_mapping);
    let tokens_resolved = match (&args.tokens_file, args.transport) {
        (Some(configured), transport) if transport != Transport::Stdio => {
            Some(resolve_tokens(configured)?)
        }
        _ => None,
    };
    let ssdf_passwords = ssdf_password_files(&args.evidence);
    // The signing key and the forward token are read only once the SSDF
    // pipeline is actually built. A path set without `--ssdf-audit-endpoint`
    // is not opened.
    let ssdf_signing_key = args
        .evidence
        .ssdf_audit_endpoint
        .as_ref()
        .and(args.evidence.ssdf_audit_signing_key.as_deref());
    let audit_forward_token = match (
        &args.evidence.ssdf_audit_endpoint,
        &args.evidence.audit_forward_endpoint,
    ) {
        (Some(_), Some(_)) => args.evidence.audit_forward_token_file.as_deref(),
        _ => None,
    };
    // The listener key is loaded only for streamable-http, and only when both
    // halves of the pair are set. A stdio process never opens it.
    #[cfg(feature = "tls")]
    let tls_key = if args.transport == Transport::StreamableHttp {
        match (&args.tls_cert, &args.tls_key) {
            (Some(_), Some(key)) => Some(key.as_path()),
            _ => None,
        }
    } else {
        None
    };
    #[cfg(not(feature = "tls"))]
    let tls_key = None;
    validate_startup_credentials(&StartupCredentialFiles {
        inventory: &args.device_mapping,
        private_keys: &private_keys,
        tokens: tokens_resolved
            .as_ref()
            .map(|resolved| resolved.path.as_path()),
        ssdf_password_files: &ssdf_passwords,
        ssdf_signing_key,
        audit_forward_token,
        audit_hmac_key: args.audit_hmac_key_file.as_deref(),
        tls_key,
        approval_digest_key: args.approval_digest_key_file.as_deref(),
    })
    .context("credential file validation")?;

    let inv_path = args.device_mapping.clone();
    let (inventory, inv_hash) = rust_junosmcp_core::bootstrap::load_inventory(&inv_path)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("loading {}", inv_path.display()))?;
    tracing::info!(
        devices = inventory.names().len(),
        path = %inv_path.display(),
        "loaded inventory"
    );

    let built_policy = Policy::build(&inventory).context("compiling blocklist policy")?;
    let counts = built_policy.rule_counts();
    tracing::info!(
        default_command_rules = counts.default_commands,
        default_config_rules = counts.default_config,
        devices_with_rules = counts.devices_with_rules,
        total_devices = inventory.names().len(),
        "blocklist policy loaded"
    );
    // Shared with the SIGHUP hot-reload path below: `add_device`,
    // `reload_devices`, and the SIGHUP inventory re-read all store a
    // freshly-built policy into this same `ArcSwap` after a successful
    // mutation, so every path the handler reads from (`self.policy`) sees
    // the update.
    let policy = Arc::new(ArcSwap::from(Arc::new(built_policy)));
    // Mirror the scp host-key posture for NETCONF SSH:
    //   default                              → strict KnownHosts lookup against --known-hosts-file
    //   --ssh-accept-new-host-keys           → real TOFU (AcceptNew): pin unknown hosts, refuse changed keys
    //   --ssh-insecure-accept-any-host-key   → lab-only, no verification at all (AcceptAll)
    // clap's conflicts_with on the two flags guarantees at most one is set.
    // Without one of them the rustez/rustnetconf 0.11+ default is RejectAll
    // (fail-closed) and every op command would error `Unknown server key`.
    use rust_junosmcp_core::bootstrap::SshHostKeyMode;
    let host_key_mode = if args.ssh_accept_new_host_keys {
        SshHostKeyMode::AcceptNew
    } else if args.ssh_insecure_accept_any_host_key {
        SshHostKeyMode::AcceptAll
    } else {
        SshHostKeyMode::Strict
    };
    let host_key_policy = rust_junosmcp_core::bootstrap::build_host_key_policy(
        host_key_mode,
        args.known_hosts_file.clone(),
    );
    let dev_manager = Arc::new(
        DeviceManager::with_path(
            inventory.clone(),
            inv_path,
            inv_hash,
            args.inventory_readonly,
            args.allow_password_auth_add,
        )
        .with_host_key_policy(host_key_policy),
    );

    // Build the token store (or None for --allow-no-auth / stdio).
    //
    // Stdio never reaches `serve_http` (see the `Transport::Stdio` arm below),
    // so a bearer-token store would be loaded only to sit unused -- at the
    // cost of making a container's fixed `--tokens-file` path (baked into
    // ENTRYPOINT so it still protects a manually-run HTTP server) a hard
    // startup requirement for stdio too. A caller spawning the image for
    // stdio with no tokens.json mounted would otherwise fail before ever
    // reaching the MCP handshake, for a file that gates nothing it uses.
    let token_store = match (
        args.tokens_file.as_deref(),
        tokens_resolved,
        args.allow_no_auth,
        args.transport,
    ) {
        (Some(_), None, _, Transport::Stdio) => {
            tracing::info!("--tokens-file ignored: stdio has no bearer-token listener to protect");
            None
        }
        (Some(configured_path), Some(resolved), _, _) => {
            // See resolve_tokens: the legacy /etc fallback applies only to the
            // canonical path, never to an operator-supplied one.
            if let Some(from) = &resolved.fallback_from {
                tracing::warn!(
                    configured = %configured_path.display(),
                    legacy = %from.display(),
                    "tokens.json read from the legacy /etc location; migrate it to the \
                     configured path and remove the stale copy. It is NOT copied \
                     automatically, and /etc is read-only to the service under \
                     ProtectSystem=strict."
                );
            }

            let store_file = TokenStoreFile::load(&resolved.path)
                .with_context(|| format!("loading {}", resolved.path.display()))?;
            tracing::info!(
                tokens = store_file.store().len(),
                path = %resolved.path.display(),
                "token store loaded"
            );
            Some(Arc::new(store_file))
        }
        (None, None, true, _) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, None, false, Transport::StreamableHttp) => {
            unreachable!(
                "mecmcp_runtime::cli_validate::validate should have refused this combination"
            );
        }
        (None, None, false, _) => None,
        (Some(_), None, _, _) | (None, Some(_), _, _) => {
            anyhow::bail!(
                "internal: token-store resolution did not match --tokens-file and --transport"
            );
        }
    };

    match host_key_mode {
        SshHostKeyMode::AcceptNew => {
            tracing::warn!(
                "--ssh-accept-new-host-keys: scp and NETCONF SSH both pin unknown host keys on \
                 first contact (TOFU) and refuse a host presenting a different key afterward. \
                 The first connection to a given host is unauthenticated."
            );
        }
        SshHostKeyMode::AcceptAll => {
            tracing::warn!(
                target: "audit",
                "--ssh-insecure-accept-any-host-key: NETCONF SSH and scp \
                 (transfer_file/fetch_file/upgrade_junos) accept ANY device host key \
                 unconditionally, with no known_hosts persistence and no mismatch detection. \
                 This gives no protection against a man-in-the-middle. Lab-only — do not run \
                 this against production devices."
            );
        }
        SshHostKeyMode::Strict => {
            tracing::info!(
                known_hosts = %args.known_hosts_file.display(),
                "ssh host-key policy: scp and NETCONF SSH both require a matching pinned key (strict, default)"
            );
        }
    }
    let transfer_cfg = TransferConfig {
        staging_dir: args.staging_dir.clone(),
        known_hosts_file: args.known_hosts_file.clone(),
        scp_runner: std::sync::Arc::new(MecmcpScpRunner),
        // Process-wide per-router serialization (issue #26, L4).
        transfer_locks: std::sync::Arc::new(
            rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
        ),
        // scp shares the exact same host-key mode as NETCONF SSH above:
        // `--ssh-insecure-accept-any-host-key` now gives scp a real
        // mecmcp_scp::HostKeyVerification::AcceptAll, not TOFU (MEC-44
        // follow-up — the flag name must mean the same thing on both
        // transports).
        host_key_mode,
    };
    let device_leases = std::sync::Arc::new(
        rust_junosmcp_core::DeviceLeaseManager::for_directory(&args.device_lease_dir)
            .with_context(|| {
                format!(
                    "initializing device leases in {}",
                    args.device_lease_dir.display()
                )
            })?,
    );
    let upgrade_cfg = rust_junosmcp_core::UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases,
    };
    rust_junosmcp_core::tools::set_cleanup_timeout_secs(args.cleanup_timeout_secs);
    // State the aggregate at startup rather than leaving an operator to derive
    // it. The mismatch between this and a client's idle timeout is what turns a
    // stalled device into "sent no response" with no other explanation (#257).
    tracing::info!(
        cleanup_timeout_secs = args.cleanup_timeout_secs,
        worst_case_secs =
            rust_junosmcp_core::tools::worst_case_duration(std::time::Duration::from_secs(360))
                .as_secs(),
        "device operation budget: a stalled 360s call can run to the worst case \
         before returning; a client idle timeout below that will abandon it"
    );

    // Lab mode removes two-person control, so say so where an operator will
    // actually see it. Reading it off flags typed weeks ago is not visibility.
    if args.lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets are approved on creation with no second \
             principal. Records carry approval_waiver=lab-mode. Do not run this against \
             production devices."
        );
    }

    // Plane-owned writes flag defeats the durability check #292 was created to
    // provide. Log its state at startup so it's visible, not just a flag typed once.
    //
    // Deliberately NOT on `target: "audit"`. That stream carries one record per
    // tool call with a fixed schema — request_id, caller, tool, action, result —
    // and downstream SIEM queries parse it on that basis. A startup banner has
    // none of those fields, so emitting it there pollutes the audit stream with
    // something no consumer can interpret as an action record.
    if args.allow_plane_owned_writes {
        tracing::warn!(
            "allow-plane-owned-writes enabled: destructive operations on devices owned by \
             management planes (Mist, Security Director) will proceed with a warning instead \
             of refusal. Changes to plane-owned devices may be overwritten at the next push. \
             This flag is for break-glass scenarios only."
        );
    } else {
        tracing::info!(
            "plane-owned device protection active: load_and_commit_config, rollback_config, \
             and upgrade_junos refuse operations on devices whose config_authority is not \
             'local' or 'unknown' (default). Use --allow-plane-owned-writes for break-glass."
        );
    }

    // Direct-commit tools (load_and_commit_config, a committing
    // render_and_apply_j2_template, rollback_config with commit=true, and a
    // confirmed upgrade_junos) never create a change set, so they have no
    // second-principal approval by construction. Refused by default; logging
    // here mirrors the lab-mode and plane-owned-writes banners above.
    let direct_commit = mecmcp_audit::DirectCommitPolicy::new(args.allow_direct_commit);
    direct_commit.log_startup("rust-junosmcp");
    if !args.allow_direct_commit {
        tracing::info!(
            "direct-commit tools disabled: load_and_commit_config, a committing \
             render_and_apply_j2_template, a committing rollback_config, and a confirmed \
             upgrade_junos are refused on stdio and HTTP alike. Use --allow-direct-commit to \
             enable them."
        );
    }

    // The SSDF evidence pipeline, when configured. Built before the coordinator
    // because the coordinator takes its recorder, and started here rather than
    // lazily so a misconfiguration -- an unwritable spool, a credential with
    // the wrong mode, an unreachable ClickHouse -- fails the server at startup
    // instead of at the first change, which is the worst moment to discover it.
    let evidence = match args.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let transport = std::sync::Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    // Keyed approval digest (MEC-457). Loaded here, before the coordinator
    // reads the state file, so any on-disk v6-digested approval is verified
    // against it at load time rather than only on new approvals
    // (`load_with_key`'s whole reason for existing over `with_approval_digest_key`).
    let approval_digest_key = args
        .approval_digest_key_file
        .as_deref()
        .map(mecmcp_changeset::ApprovalDigestKey::load_from_file)
        .transpose()
        .context("loading --approval-digest-key-file")?;

    // Step-up approver-assertion verifier (MEC-994/MEC-995), when an issuer
    // is configured. `None` behaves identically to a server with no OIDC
    // support at all: `mecmcp-transport`'s bearer boundary refuses a
    // presented `Mecmcp-Approver-Assertion` header with 400 rather than
    // silently accepting it.
    let approver_assertion_verifier = args
        .verified_approver
        .oidc_issuer
        .as_deref()
        .map(|issuer| -> Result<_> {
            let audience = args
                .verified_approver
                .oidc_audience
                .clone()
                .context("--oidc-issuer requires --oidc-audience (checked above)")?;
            let http_client =
                mecmcp_http::HttpClient::new(mecmcp_http::HttpClientConfig::default())
                    .context("building the OIDC discovery/JWKS HTTP client")?;
            let key_source: std::sync::Arc<dyn mecmcp_oidc::KeySource> =
                std::sync::Arc::new(mecmcp_oidc::HttpKeySource::new(http_client));
            let oidc_config = mecmcp_oidc::OidcConfig::new(
                issuer,
                audience,
                args.verified_approver.oidc_role_claim.clone(),
            );
            let token_verifier =
                std::sync::Arc::new(mecmcp_oidc::TokenVerifier::new(oidc_config, key_source));
            let policy = args
                .verified_approver
                .approver_policy()
                .context("--oidc-issuer is set, so approver_policy() must be Some")?;
            Ok(std::sync::Arc::new(
                mecmcp_transport::ApproverAssertionVerifier::new(token_verifier, issuer, policy),
            ))
        })
        .transpose()
        .context("configuring the verified-approver assertion verifier")?;
    if args.verified_approver.require_verified_approver {
        tracing::warn!(
            target: "audit",
            "strict verified-approver mode enabled: approve_junos_change_set requires a fresh \
             IdP-verified approver assertion, and create_junos_change_set requires the owner's \
             token to carry an oidc_subject binding."
        );
    }

    let mut changeset_coordinator = mecmcp_changeset::ChangesetCoordinator::load_with_key(
        Some(&args.changeset_state_file),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(args.changeset_approval_timeout_secs),
        args.lab_mode,
        approval_digest_key,
    )
    .with_context(|| {
        format!(
            "initializing changeset coordinator at {}",
            args.changeset_state_file.display()
        )
    })?;
    if let Some(service) = &evidence {
        changeset_coordinator = changeset_coordinator.with_evidence(service.recorder());
    }
    changeset_coordinator = changeset_coordinator
        .with_require_verified_approver(args.verified_approver.require_verified_approver);
    let coordinator = std::sync::Arc::new(changeset_coordinator);

    // #370: settle commits this process's predecessor died in the middle of.
    // `ChangesetCoordinator::load` has just rewritten every non-terminal
    // operation to `Indeterminate`; the ones carrying an attribution had
    // reached the commit, and the device can be asked whether it landed.
    //
    // Detached deliberately. This does device I/O, and a candidate on an
    // unreachable device costs 20s — longer than the readiness budget the test
    // harness and package smoke allow — so blocking startup on it would turn a
    // recoverable record into a server that is killed and retried on every
    // boot. Nothing is lost by serving first: an unresolved record is
    // non-terminal, and a non-terminal operation already blocks a new one on
    // its device, so the records this settles keep gating writes until it does.
    {
        let dm = dev_manager.clone();
        let coordinator = coordinator.clone();
        tokio::spawn(async move {
            let summary =
                rust_junosmcp_core::changeset_recovery::sweep_crashed_commits(dm, coordinator)
                    .await;
            if summary.candidates > 0 {
                tracing::info!(
                    settled = summary.settled,
                    // Everything not settled is still indeterminate — provisional
                    // commits, failed writes and candidates the timeout never
                    // reached included. Summing only the probe outcomes would
                    // undercount exactly the cases an operator needs to chase.
                    left_unknown = summary.candidates - summary.settled,
                    timed_out = summary.timed_out,
                    "startup re-probe settled {} of {} interrupted commits",
                    summary.settled,
                    summary.candidates
                );
            }
        });
    }

    let handler = JmcpHandler::new(
        dev_manager.clone(),
        policy.clone(),
        transfer_cfg,
        upgrade_cfg,
        coordinator,
        args.allow_plane_owned_writes,
        args.web_approver.web_enabled_approver,
        direct_commit,
    );
    #[cfg(feature = "srx")]
    let handler = handler.with_srx_runtime(
        token_store.is_some() && matches!(args.transport, Transport::StreamableHttp),
        rust_junosmcp_srx_core::workflows::support_bundle::SupportBundleStagingConfig::new(
            args.support_bundle_staging_dir.clone(),
            args.support_bundle_staging_max_bytes,
        ),
    );

    // SIGHUP hot reload (unix only): reopen the audit file for lossless log
    // rotation, then — when configured — re-read the tokens file and
    // inventory and atomically swap them in. The audit reopen runs whenever a
    // file sink is configured, independent of the token store: stdio mode and
    // --allow-no-auth still audit to a file and still need rotation to work.
    #[cfg(unix)]
    if audit_sink.is_some() || token_store.is_some() {
        let store_and_path = match (token_store.clone(), args.tokens_file.clone()) {
            (Some(store_file), Some(_path)) => Some(store_file),
            _ => None,
        };
        // Inventory is now mutable at runtime (add_device / reload_devices).
        let dm = dev_manager.clone();
        let hup_policy = policy.clone();
        let hup_audit_sink = audit_sink.clone();
        tokio::spawn(async move {
            let mut hup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGHUP handler; reload disabled");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                tracing::info!("SIGHUP: reopening audit log and reloading token store/inventory");
                // Reopen first: this is the lossless half of log rotation
                // (rename the file, signal the process), and a failure here
                // must not block the reloads below.
                if let Some(sink) = &hup_audit_sink {
                    match sink.reopen() {
                        Ok(()) => {
                            tracing::info!(path = %sink.path().display(), "audit log reopened");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, path = %sink.path().display(), "audit log reopen failed; keeping previous sink");
                        }
                    }
                }
                let Some(store_file) = &store_and_path else {
                    continue;
                };
                // Reload inventory and rebuild the policy from it together, so the
                // token store below never sees a half-updated state. A policy build
                // failure fails the whole reload: both the inventory and the
                // policy stay exactly as they were.
                match rust_junosmcp_core::tools::reload_devices::reload_current_from_disk(
                    dm.clone(),
                    hup_policy.clone(),
                )
                .await
                {
                    Ok(result) => {
                        tracing::info!(?result, "inventory and policy reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "inventory reload failed; keeping previous inventory and policy");
                    }
                }
                // Reload the token store. The shared TokenStoreFile's reload()
                // method swaps the internal store atomically.
                match store_file.reload() {
                    Ok(()) => {
                        tracing::info!(path = %store_file.path().display(), "token store reloaded");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SIGHUP reload failed; keeping previous store");
                    }
                }
            }
        });
    }

    // Bound rather than propagated with `?`, so the evidence flush below runs
    // whichever way serving ended. Returning the error directly would skip it,
    // and `EvidenceService::Drop` deliberately does not spool -- a Drop that
    // performs network I/O turns teardown into an unpredictable stall -- so
    // every proposal and approval the recorder still held would be lost on a
    // controlled transport failure. That is the case the trail exists for.
    let served: anyhow::Result<()> = async {
        match args.transport {
        Transport::Stdio => {
            let service = handler
                .serve((tokio::io::stdin(), tokio::io::stdout()))
                .await
                .context("starting MCP stdio service")?;
            service
                .waiting()
                .await
                .context("MCP service exited with error")?;
        }
        Transport::StreamableHttp => {
            let addr: std::net::SocketAddr = format!("{}:{}", args.host, args.port)
                .parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;

            #[cfg(feature = "tls")]
            let tls_cfg = match (&args.tls_cert, &args.tls_key) {
                (Some(cert), Some(key)) => {
                    Some(tls::load(cert, key).context("loading TLS cert/key")?)
                }
                _ => None,
            };

            #[cfg(not(feature = "tls"))]
            if args.tls_cert.is_some() || args.tls_key.is_some() {
                anyhow::bail!(
                    "rust-junosmcp built without the 'tls' feature; cannot honor --tls-cert/--tls-key"
                );
            }

            let limits = mecmcp_transport::LimitsConfig {
                max_request_body_bytes: args.max_request_body_bytes,
                max_inflight_requests: args.max_inflight_requests,
                max_inflight_requests_per_token: args.max_inflight_requests_per_token,
                max_requests_per_second_per_ip: args.max_requests_per_second_per_ip,
                max_request_burst_per_ip: args.max_request_burst_per_ip,
                max_requests_per_second_per_token: args.max_requests_per_second_per_token,
                max_request_burst_per_token: args.max_request_burst_per_token,
                max_inflight_requests_per_device: args.max_inflight_requests_per_router,
                // Not exposed as a rust-junosmcp CLI flag yet: X-Forwarded-For
                // is never trusted, matching this crate's own pre-trusted-proxy
                // behavior (the peer address is always the rate-limit key).
                trusted_proxies: Vec::new(),
                max_sessions: args.max_sessions,
                max_sessions_per_token: args.max_sessions_per_token,
                session_idle_timeout_secs: args.session_idle_timeout_secs,
                session_max_lifetime_secs: args.session_max_lifetime_secs,
            };

            // Install graceful shutdown handler for SIGINT/SIGTERM.
            // mecmcp-runtime 0.7.0: GracefulShutdown::new() returns Result.
            let shutdown_coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new()
                .context("installing shutdown signal handlers")?;

            // The shutdown token is passed to both the router builder (which gives it to
            // rmcp for SSE session termination) and serve_router (which uses it to drain
            // in-flight HTTP connections). Using separate tokens would leave SSE streams
            // live past the drain timeout.
            let shutdown_token = tokio_util::sync::CancellationToken::new();

            // Wire the shutdown coordinator to the token so SIGTERM/SIGINT trigger it.
            let shutdown_signal = shutdown_coordinator.subscribe();
            let shutdown_token_clone = shutdown_token.clone();
            tokio::spawn(async move {
                shutdown_signal.await;
                shutdown_token_clone.cancel();
            });

            // Shutdown timeout: give in-flight requests 10s to complete.
            // rmcp terminates SSE sessions immediately on the same token, so this
            // timeout only bounds stuck connections (e.g., slow clients, network issues).
            let shutdown_timeout = std::time::Duration::from_secs(10);

            rust_junosmcp::http_transport::serve_http(
                handler,
                addr,
                token_store,
                args.allowed_host.clone(),
                // Was Vec::new() with a comment claiming "empty by default (no
                // browser CORS)". The CLI has always accepted --allowed-origin,
                // and LXC 950's unit passes it — so the flag was parsed, shown in
                // --help, and silently discarded here. Same defect class as
                // mecmcp#273: present but ignored.
                args.allowed_origin.clone(),
                limits,
                args.enable_metrics,
                #[cfg(feature = "tls")]
                tls_cfg,
                #[cfg(not(feature = "tls"))]
                None,
                args.allow_insecure_bind,
                shutdown_token,
                shutdown_timeout,
                approver_assertion_verifier,
            )
            .await?;
        }
        }
        Ok(())
    }
    .await;

    // Deliver what is still spooled before the process leaves. The drain ships
    // on an interval, so without this every record written since the last tick
    // waits for the next start -- and a segment still open has never been
    // spooled at all. A failure here is reported rather than swallowed: the
    // records stay in the outbox and the next start replays them, but an
    // operator stopping a server has no other signal that its trail is behind.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod token_path_tests {
    use super::resolve_tokens_with;

    /// The canonical path is absent and the legacy store exists: the fallback
    /// must fire, so an upgrade that has not migrated yet still starts.
    #[test]
    fn canonical_path_falls_back_to_an_existing_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let resolved = resolve_tokens_with(&canonical, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, legacy,
            "the legacy store should have been used"
        );
        assert!(resolved.used_fallback);
    }

    /// The same legacy store exists, but the operator configured a DIFFERENT
    /// path. Falling back here would silently reactivate credentials they did
    /// not ask for — a typo or a deleted store must fail, not resurrect tokens.
    #[test]
    fn a_custom_path_never_falls_back_to_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();
        let custom = dir.path().join("operator-chosen.json");

        let resolved = resolve_tokens_with(&custom, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, custom,
            "an operator-supplied path must be used verbatim"
        );
        assert!(
            !resolved.used_fallback,
            "a custom path must never resolve to the legacy /etc store"
        );
    }

    /// A malformed spelling of the canonical path must NOT reach the fallback.
    ///
    /// `Path` equality normalizes away a trailing separator, so
    /// `.../tokens.json/` compares equal to the canonical path; and when the
    /// file is absent `metadata()` returns NotFound for that spelling too,
    /// indistinguishable from the plain form. A typo would therefore activate
    /// the legacy store — the opposite of fail-closed. The comparison is
    /// byte-exact for this reason.
    #[test]
    fn a_trailing_slash_spelling_does_not_reach_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let mut malformed = canonical.clone().into_os_string();
        malformed.push("/");
        let malformed = std::path::PathBuf::from(malformed);

        let resolved = resolve_tokens_with(&malformed, &canonical, &legacy).unwrap();
        assert!(
            !resolved.used_fallback,
            "a trailing-slash spelling must not activate the legacy store"
        );
        assert_eq!(
            resolved.path, malformed,
            "the given path must be used verbatim"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod audit_hmac_key_tests {
    use super::ensure_audit_hmac_key;

    /// The common case: no entry point has ever run here before (fresh
    /// container volume, fresh LXC install). A key must be created, be
    /// non-empty, and be mode 0600 so it is not group/world-readable.
    #[test]
    fn generates_a_key_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "generated key file must not be empty");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be mode 0600");
        }
    }

    /// A key already exists (install.sh ran, or this is not the first
    /// container start against this volume). It must be left byte-for-byte
    /// untouched -- rotating it here would silently break verification of
    /// every audit record HMAC'd under the old key.
    #[test]
    fn does_not_rotate_an_existing_nonempty_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"existing-key-material").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"existing-key-material");
    }

    /// A zero-byte key file is indistinguishable from "never generated" (a
    /// truncated write, an `install -m 0600 /dev/null ...` placeholder, an
    /// interrupted first run) and would make every HMAC output constant. It
    /// must be repaired, not treated as already-present.
    #[test]
    fn repairs_an_empty_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-hmac.key");
        std::fs::write(&path, b"").unwrap();

        ensure_audit_hmac_key(&path).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(!contents.is_empty(), "empty key file must be repaired");
    }

    /// Two independent calls must not produce the same key -- otherwise the
    /// "random" key is really a constant and every deployment's audit HMAC
    /// is forgeable by anyone who reads this test.
    #[test]
    fn successive_generations_differ() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.key");
        let path_b = dir.path().join("b.key");

        ensure_audit_hmac_key(&path_a).unwrap();
        ensure_audit_hmac_key(&path_b).unwrap();

        let a = std::fs::read(&path_a).unwrap();
        let b = std::fs::read(&path_b).unwrap();
        assert_ne!(a, b, "two generated keys must not collide");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod startup_credential_tests {
    use super::{StartupCredentialFiles, token_store_paths, validate_startup_credentials};
    use std::path::{Path, PathBuf};

    #[test]
    fn deployed_token_paths_stay_on_the_jmcp_layout() {
        let (canonical, legacy) = token_store_paths();
        assert_eq!(canonical, PathBuf::from("/var/lib/jmcp/tokens.json"));
        assert_eq!(legacy, PathBuf::from("/etc/jmcp/tokens.json"));
        assert_eq!(
            super::cli::server_naming().config_dir,
            PathBuf::from("/etc/jmcp")
        );
        assert_eq!(
            super::cli::server_naming().state_dir,
            PathBuf::from("/var/lib/jmcp")
        );
    }

    #[cfg(unix)]
    fn write_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn files<'a>(
        inventory: &'a Path,
        private_keys: &'a [PathBuf],
        tokens: Option<&'a Path>,
        ssdf_password_files: &'a [PathBuf],
    ) -> StartupCredentialFiles<'a> {
        StartupCredentialFiles {
            inventory,
            private_keys,
            tokens,
            ssdf_password_files,
            ssdf_signing_key: None,
            audit_forward_token: None,
            audit_hmac_key: None,
            tls_key: None,
            approval_digest_key: None,
        }
    }

    /// Two loose modes must come back together. The failure this guards is a
    /// startup that names the inventory, exits, and only names the password
    /// file after that restart.
    #[cfg(unix)]
    #[test]
    fn one_pass_reports_every_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        let inventory = write_file(dir.path(), "devices.json", 0o644);
        let passwords = vec![write_file(dir.path(), "ssdf-audit.pw", 0o640)];

        let error = validate_startup_credentials(&files(&inventory, &[], None, &passwords))
            .expect_err("both files are looser than a secret file allows");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("devices.json"), "{message}");
        assert!(message.contains("ssdf-audit.pw"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(message.contains("0640"), "{message}");
    }

    /// Owner-only secret files pass together. A `0644` known_hosts is not an
    /// input to this pass: nothing mode-checks that file today.
    #[cfg(unix)]
    #[test]
    fn acceptable_modes_pass_together() {
        let dir = tempfile::tempdir().unwrap();
        let inventory = write_file(dir.path(), "devices.json", 0o600);
        let private_keys = vec![write_file(dir.path(), "id_ed25519", 0o600)];
        let tokens = write_file(dir.path(), "tokens.json", 0o600);
        let passwords = vec![
            write_file(dir.path(), "ssdf-audit.pw", 0o600),
            write_file(dir.path(), "ssdf-audit-verify.pw", 0o600),
        ];
        let hmac = write_file(dir.path(), "audit-hmac.key", 0o600);
        let tls = write_file(dir.path(), "server.key", 0o600);
        let _known_hosts = write_file(dir.path(), "known_hosts", 0o644);

        let mut checked = files(&inventory, &private_keys, Some(&tokens), &passwords);
        checked.audit_hmac_key = Some(&hmac);
        checked.tls_key = Some(&tls);
        validate_startup_credentials(&checked).expect("0600 secret files pass together");
    }
}

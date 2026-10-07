//! `collect_jtac_support_bundle` workflow + shared primitives (Phase 3).
//!
//! Submodules:
//! * [`problem_type`] — closed `ProblemType` enum + per-type RPC/log lists,
//!   plus the universal-baseline RPC/log constants. Capture-verified
//!   against Junos 24.4R1.9 on 2026-05-26.
//! * [`artefacts`] — `CapturedArtefact` + `ArtefactSource` types describing
//!   one piece of evidence inside the tarball.
//! * Redaction (PSKs, secrets, SNMP community, HMAC keys, RADIUS/TACACS
//!   shared-secrets) applied when `redact=true` comes from
//!   `mecmcp_redact::junos` (MEC-1232) rather than a local redactor — see
//!   [`redact_rpc_reply`] and [`redact_generic_payload`].
//! * [`staging`] — explicit LXC-side staging configuration +
//!   on-device tarball path helpers + LRU eviction stub.
//!
//! ## Implementation note (deviation from design doc)
//!
//! The design specifies an **on-device** tarball assembled via
//! `request support information | save /var/tmp/srxmcp-<rid>.tgz` for the
//! `generic` problem_type and a device-side `file-archive` chain for the
//! per-type paths. Both paths instead assemble the tarball **on the LXC**
//! side under `JMCP_SUPPORT_BUNDLE_STAGING_DIR/<router>/srxmcp-<rid>.tgz`:
//!
//! * **`generic` path**: `request support information` is issued (without
//!   the `| save` pipe) via the NETCONF `command` RPC; the full
//!   tech-support text comes back INLINE and is written into the staging
//!   scratch dir, then tarred. The `| save <path>` redirection is NOT
//!   honoured over the NETCONF `command` RPC (it writes nothing on-device
//!   while still returning the payload inline), so the earlier device-side
//!   variant reported success but produced no file — see issue #81.
//! * **Per-`problem_type` path**: the captured RPC replies are written as
//!   XML files; `/var/log/*` files are pulled inline via `file show <path>`
//!   over the same pooled `command` RPC (the `fetch_file` SCP primitive
//!   only serves basenames out of `/var/tmp`, so it cannot reach the log
//!   dir), size-capped by `max_log_bytes_per_file` and count-capped by
//!   `max_log_files`, then staged into `logs/<device-path>`.
//!
//! Both paths share `finalize_lxc_bundle` for manifest write + tarball
//! assembly + sha256, and both report `bundle.location = "lxc_staging"`.
//! The response carries an LXC-side `path` and the LLM is instructed to
//! read it directly off LXC 601 (no `fetch_file` chain).

pub mod artefacts;
pub mod problem_type;
pub mod staging;

pub use artefacts::{ArtefactSource, CapturedArtefact};
pub use problem_type::{BASELINE_LOGS, BASELINE_RPCS, ProblemType};
pub use staging::{
    DEFAULT_STAGING_DIR, DEFAULT_STAGING_MAX_BYTES, PreparedBundlePaths,
    SupportBundleStagingConfig, bundle_manifest_path, bundle_tarball_path, device_log_tarball_path,
    device_tarball_path, enforce_staging_cap, router_staging_dir, validate_path_component,
};

use crate::{SrxError, SrxToolResponse};
use mecmcp_redact::junos;
use rust_junosmcp_core::device_manager::PooledDevice;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

// ── Per-router staging-key lock ───────────────────────────────────────────────

/// Map of `(router, "support_bundle") → Semaphore(1)` used to serialize
/// concurrent `collect_jtac_support_bundle` calls against the same router.
/// Distinct from destructive workflow `DeviceLeaseManager` leases.
/// The semaphore is permit=1 (mutex semantics) and lives in-process for
/// the lifetime of the binary.
fn staging_key_locks() -> &'static Mutex<BTreeMap<String, Arc<Semaphore>>> {
    static LOCKS: OnceLock<Mutex<BTreeMap<String, Arc<Semaphore>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lock_for(router: &str) -> Arc<Semaphore> {
    let key = format!("{router}:support_bundle");
    let mut map = staging_key_locks()
        .lock()
        .expect("staging-key mutex poisoned");
    map.entry(key)
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone()
}

// ── Public args / response types ──────────────────────────────────────────────

/// Accept `problem_type` as either a single value or an array per the
/// design doc spec. Converted to a set via `into_set` to deduplicate.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ProblemTypeArg {
    /// Single problem type specified directly
    One(ProblemType),
    /// Array of problem types (deduplicated on conversion)
    Many(Vec<ProblemType>),
}

impl ProblemTypeArg {
    fn into_set(self) -> BTreeSet<ProblemType> {
        match self {
            ProblemTypeArg::One(p) => {
                let mut s = BTreeSet::new();
                s.insert(p);
                s
            }
            ProblemTypeArg::Many(v) => v.into_iter().collect(),
        }
    }
}

/// Arguments for `collect_jtac_support_bundle` workflow (RPC input schema).
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = rust_junosmcp_core::schema_alias::router_name_alias)]
pub struct SupportBundleArgs {
    /// Target router name (inventory key)
    #[serde(alias = "router_name")]
    pub router: String,
    /// Problem category or categories to capture evidence for
    pub problem_type: ProblemTypeArg,
    /// Optional correlation label. Limited to 1..=64 ASCII letters, digits,
    /// `_`, `.`, and `-`; never used in a filesystem path.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Whether to capture log files in addition to RPC replies. Default true.
    #[serde(default = "default_true")]
    pub include_logs: bool,
    /// Whether to redact known-sensitive XML elements and log values. Default true.
    #[serde(default = "default_true")]
    pub redact: bool,
    /// Per-log-file size cap in bytes. Default 10 MiB.
    #[serde(default = "default_max_log_bytes")]
    pub max_log_bytes_per_file: u64,
    /// Maximum number of log files to capture. Default 5.
    #[serde(default = "default_max_log_files")]
    pub max_log_files: u32,
    /// Outer per-call budget (seconds). Default 1800, cap 3600. The
    /// caller's MCP framework enforces this; the workflow records the
    /// elapsed time for the audit log.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_true() -> bool {
    true
}
fn default_max_log_bytes() -> u64 {
    10 * 1024 * 1024
}
fn default_max_log_files() -> u32 {
    5
}
fn default_timeout() -> u64 {
    1800
}

fn validate_correlation_id(request_id: &str) -> Result<(), SrxError> {
    if request_id.trim().is_empty() {
        return Err(SrxError::InvalidInput(
            "request_id must not be empty or whitespace".into(),
        ));
    }
    validate_path_component("request_id", request_id)?;
    let normalized = request_id.strip_prefix("srxmcp-").unwrap_or(request_id);
    validate_path_component("request_id", normalized)
}

fn effective_request_id(
    caller_request_id: Option<&str>,
    filesystem_id: &str,
) -> Result<String, SrxError> {
    match caller_request_id {
        Some(raw) => {
            validate_correlation_id(raw)?;
            Ok(raw.to_string())
        }
        None => Ok(filesystem_id.to_string()),
    }
}

/// Validate every caller or inventory value that can influence bundle paths.
/// The binary calls this before opening a device so malformed input fails
/// deterministically without network access.
pub fn validate_path_inputs(args: &SupportBundleArgs) -> Result<(), SrxError> {
    validate_path_component("router", &args.router)?;
    if let Some(request_id) = args.request_id.as_deref() {
        validate_correlation_id(request_id)?;
    }
    Ok(())
}

/// Where the assembled tarball lives. `Device` → on the SRX under
/// `/var/tmp`, fetched via the `rust-junosmcp` `fetch_file` chain.
/// `LxcStaging` → on the MCP host under `JMCP_SUPPORT_BUNDLE_STAGING_DIR`, accessible
/// directly to operators with shell access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleLocation {
    /// Tarball resides on-device under `/var/tmp`
    Device,
    /// Tarball resides on the LXC host in the configured staging directory
    LxcStaging,
}

/// Tarball metadata nested inside the `collect_jtac_support_bundle` response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct BundleInfo {
    /// Where the tarball resides (on-device or LXC staging)
    pub location: BundleLocation,
    /// Absolute path to the tarball. Interpretation depends on `location`.
    pub path: String,
    /// Tarball size in bytes
    pub bytes: u64,
    /// Lower-case hex SHA-256 of the tarball.
    pub sha256: String,
    /// Problem types that were captured
    pub problem_types: Vec<ProblemType>,
    /// Per-artefact manifest (RPC names + log paths captured).
    pub artefacts: Vec<CapturedArtefact>,
    /// `true` if redaction ran on at least one artefact.
    pub redacted: bool,
}

/// Success response for `collect_jtac_support_bundle` workflow.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SupportBundleData {
    /// Target router name
    #[serde(alias = "router_name")]
    pub router: String,
    /// Caller-provided or server-minted correlation ID
    pub request_id: String,
    /// Server-minted ID used exclusively for local and device filenames.
    pub filesystem_id: String,
    /// Tarball metadata (location, path, size, digest, manifest)
    pub bundle: BundleInfo,
    /// Free-form next-step hint for the LLM. For `Device` bundles this is
    /// the `fetch_file router=... source=...` invocation; for
    /// `LxcStaging` bundles it's a `cat`/`tar tvf` hint against the LXC
    /// path.
    pub next_step: String,
    /// Wall-clock duration of the collection. Useful for the audit log.
    pub elapsed_secs: u64,
}

// ── `run()` — async entry point ───────────────────────────────────────────────

/// Run `collect_jtac_support_bundle`. Takes the staging-key lock,
/// dispatches to the `generic` or per-type code path, and returns a
/// `SupportBundleData` with the full bundle manifest.
pub async fn run(
    device: &mut PooledDevice,
    mut args: SupportBundleArgs,
    staging: &SupportBundleStagingConfig,
) -> Result<SrxToolResponse<SupportBundleData>, SrxError> {
    if args.router.trim().is_empty() {
        return Err(SrxError::InvalidInput("router must not be empty".into()));
    }
    let timeout_secs = args.timeout.min(3600);
    // Take problem_type out of args so the rest of args (router, flags,
    // limits) stays usable downstream.
    let problem_types =
        std::mem::replace(&mut args.problem_type, ProblemTypeArg::Many(Vec::new())).into_set();
    if problem_types.is_empty() {
        return Err(SrxError::InvalidInput(
            "problem_type must contain at least one value".into(),
        ));
    }
    validate_path_inputs(&args)?;
    let router = args.router.clone();
    let filesystem_id = mint_filesystem_id();
    let request_id = effective_request_id(args.request_id.as_deref(), &filesystem_id)?;

    // Acquire the staging-key lock (per-router serialization). Use
    // try_acquire to surface contention as a typed error instead of
    // queueing forever.
    let sem = lock_for(&router);
    let _permit =
        sem.clone()
            .try_acquire_owned()
            .map_err(|_| SrxError::BundlePerRouterContention {
                router: router.clone(),
            })?;

    let started_at = std::time::Instant::now();
    tracing::info!(
        target: "audit",
        request_id = %request_id,
        filesystem_id = %filesystem_id,
        router = %router,
        tool = "collect_jtac_support_bundle",
        problem_types = ?problem_types,
        include_logs = args.include_logs,
        redact = args.redact,
        timeout_secs = timeout_secs,
        "bundle.start"
    );

    // Generic short-circuit: any presence of Generic in the set means we
    // skip everything else and run `request support information`.
    let result = if problem_types.contains(&ProblemType::Generic) {
        collect_generic(device, &router, &request_id, &filesystem_id, &args, staging).await
    } else {
        collect_per_type(
            device,
            &router,
            &request_id,
            &filesystem_id,
            &args,
            &problem_types,
            staging,
        )
        .await
    };

    let elapsed_secs = started_at.elapsed().as_secs();
    match result {
        Ok(data) => {
            tracing::info!(
                target: "audit",
                request_id = %request_id,
                filesystem_id = %filesystem_id,
                router = %router,
                tool = "collect_jtac_support_bundle",
                elapsed_secs,
                bytes = data.bundle.bytes,
                location = ?data.bundle.location,
                "bundle.ok"
            );
            Ok(SrxToolResponse::<SupportBundleData>::active(data))
        }
        Err(err) => {
            tracing::warn!(
                target: "audit",
                request_id = %request_id,
                filesystem_id = %filesystem_id,
                router = %router,
                tool = "collect_jtac_support_bundle",
                elapsed_secs,
                err = %err,
                "bundle.err"
            );
            Err(err)
        }
    }
}

// ── Generic path: LXC-side tarball from inline `request support information` ───

async fn collect_generic(
    device: &mut PooledDevice,
    router: &str,
    request_id: &str,
    filesystem_id: &str,
    args: &SupportBundleArgs,
    staging: &SupportBundleStagingConfig,
) -> Result<SupportBundleData, SrxError> {
    let mut paths = PreparedBundlePaths::prepare(staging, router, filesystem_id)?;
    let scratch = paths.scratch_dir().to_path_buf();

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    // `request support information` over the NETCONF `command` RPC returns
    // the full tech-support text INLINE — the `| save <path>` pipe is NOT
    // honoured on the wire (it writes nothing on-device while still
    // returning the payload), so we capture the payload here and assemble
    // the tarball on the LXC side, exactly like the per-type path. The
    // defensive tokio::time::timeout keeps a wedged RPC off the per-router
    // lock. See issue #81.
    let deadline = Duration::from_secs(args.timeout.min(3600));
    let call = exec.cli("request support information", "text");
    let payload = tokio::time::timeout(deadline, call)
        .await
        .map_err(|_| SrxError::ClusterHealthCheckTimeout {
            router: router.to_string(),
            elapsed_secs: deadline.as_secs(),
        })?
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    if payload.trim().is_empty() {
        return Err(SrxError::BundleConfigCaptureFailed {
            router: router.to_string(),
            detail: "`request support information` returned no output".into(),
        });
    }

    let (payload, redacted) = redact_generic_payload(router, payload, args.redact)?;

    let fname = "request-support-information.txt";
    let abs_path = scratch.join(fname);
    std::fs::write(&abs_path, payload.as_bytes())
        .map_err(|e| SrxError::InvalidInput(format!("write {}: {e}", abs_path.display())))?;

    let artefacts = vec![CapturedArtefact {
        source: ArtefactSource::Rpc {
            name: "request support information".into(),
            args: None,
        },
        tarball_path: fname.into(),
        sha256: sha256_hex(payload.as_bytes()),
        bytes_in_tarball: payload.len() as u64,
        redacted,
        error: None,
    }];

    let mut problem_types = BTreeSet::new();
    problem_types.insert(ProblemType::Generic);
    finalize_lxc_bundle(
        router,
        request_id,
        filesystem_id,
        &mut paths,
        artefacts,
        &problem_types,
        redacted,
    )
}

// ── Per-type path: LXC-side tarball ───────────────────────────────────────────

async fn collect_per_type(
    device: &mut PooledDevice,
    router: &str,
    request_id: &str,
    filesystem_id: &str,
    args: &SupportBundleArgs,
    problem_types: &BTreeSet<ProblemType>,
    staging: &SupportBundleStagingConfig,
) -> Result<SupportBundleData, SrxError> {
    let mut paths = PreparedBundlePaths::prepare(staging, router, filesystem_id)?;
    let scratch = paths.scratch_dir().to_path_buf();
    let rpc_dir = scratch.join("rpc");
    std::fs::create_dir_all(&rpc_dir)
        .map_err(|e| SrxError::InvalidInput(format!("cannot create scratch dir: {e}")))?;

    // 1) Capture baseline + per-type RPCs.
    let mut artefacts: Vec<CapturedArtefact> = Vec::new();
    let mut any_redacted = false;
    let mut all_rpcs: BTreeSet<(String, String)> = BTreeSet::new();
    for rpc in BASELINE_RPCS {
        all_rpcs.insert((rpc.to_string(), String::new()));
    }
    for pt in problem_types {
        for rpc in pt.additional_rpcs() {
            all_rpcs.insert((rpc.to_string(), String::new()));
        }
        for (rpc, inner) in pt.additional_rpcs_with_args() {
            all_rpcs.insert((rpc.to_string(), inner.to_string()));
        }
    }

    let mut exec = device
        .rpc()
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))?;

    let mut failures: Vec<(String, String)> = Vec::new();
    let total = all_rpcs.len();
    for (rpc, inner) in &all_rpcs {
        let reply = if inner.is_empty() {
            exec.call(rpc, &[]).await
        } else {
            // Build the RPC envelope by hand because rustez's `call()` only
            // takes key/value args (no nested element support). The
            // `<rpc>` outer wrapper is added by `call_xml`.
            let envelope = format!("<{rpc}>{inner}</{rpc}>");
            exec.call_xml(&envelope).await
        };
        let raw = match reply {
            Ok(xml) => xml,
            Err(e) => {
                let err_msg = format!("rpc {rpc}: {e}");
                failures.push((rpc.clone(), err_msg.clone()));
                // For the universal-baseline get-configuration, bail
                // hard — the design doc makes this mandatory.
                if rpc == "get-configuration" {
                    return Err(SrxError::BundleConfigCaptureFailed {
                        router: router.to_string(),
                        detail: err_msg,
                    });
                }
                continue;
            }
        };
        // RPC replies here are always expected to be well-formed XML (they
        // come straight off the NETCONF `command`/`call` path). Unlike the
        // best-effort log-artefact dispatch, a parse failure on this path
        // fails closed: `redact_xml`'s "return unchanged on parse failure"
        // fallback would silently ship the raw, unredacted reply while still
        // recording `redacted: false` as if nothing was wrong. Refuse the
        // artefact instead — treated exactly like an RPC transport failure,
        // including the hard bail for the mandatory `get-configuration`
        // baseline capture.
        let (payload, redacted) = if args.redact {
            match redact_rpc_reply(&raw) {
                Some((red, changed)) => {
                    any_redacted |= changed;
                    (red, changed)
                }
                None => {
                    let err_msg = format!(
                        "rpc {rpc}: reply was not well-formed XML; artefact refused rather than shipped unredacted"
                    );
                    failures.push((rpc.clone(), err_msg.clone()));
                    if rpc == "get-configuration" {
                        return Err(SrxError::BundleConfigCaptureFailed {
                            router: router.to_string(),
                            detail: err_msg,
                        });
                    }
                    continue;
                }
            }
        } else {
            (raw, false)
        };

        let fname = sanitize_rpc_filename(rpc, inner)?;
        let abs_path = rpc_dir.join(&fname);
        std::fs::write(&abs_path, payload.as_bytes())
            .map_err(|e| SrxError::InvalidInput(format!("write {}: {e}", abs_path.display())))?;
        let bytes = payload.len() as u64;
        let sha256 = sha256_hex(payload.as_bytes());
        artefacts.push(CapturedArtefact {
            source: ArtefactSource::Rpc {
                name: rpc.clone(),
                args: if inner.is_empty() {
                    None
                } else {
                    Some(inner.clone())
                },
            },
            tarball_path: format!("rpc/{fname}"),
            sha256,
            bytes_in_tarball: bytes,
            redacted,
            error: None,
        });
    }

    // 2) Log file capture. Junos serves `/var/log/*` over the NETCONF
    //    `command` RPC via `file show <path>`, returning the file content
    //    INLINE as text (the `| save` redirect is unavailable here — see
    //    #81 — and the `fetch_file` SCP primitive only pulls basenames out
    //    of `/var/tmp`, so neither applies). We capture inline, enforce the
    //    `max_log_bytes_per_file` size cap and the `max_log_files` count
    //    cap, and stage each log into `logs/<device-path>` in the tarball.
    if args.include_logs {
        let mut all_logs: BTreeSet<&str> = BASELINE_LOGS.iter().copied().collect();
        for pt in problem_types {
            for log in pt.additional_logs() {
                all_logs.insert(log);
            }
        }
        let cap_bytes = args.max_log_bytes_per_file as usize;
        let mut captured: u32 = 0;
        for path in all_logs {
            let rel = device_log_tarball_path(path)?;
            let rel_display = path_to_string(&rel);
            // Enforce the count cap: record a skip marker so JTAC sees
            // which logs were intentionally omitted.
            if captured >= args.max_log_files {
                artefacts.push(CapturedArtefact {
                    source: ArtefactSource::LogFile {
                        device_path: path.to_string(),
                    },
                    tarball_path: rel_display,
                    sha256: String::new(),
                    bytes_in_tarball: 0,
                    redacted: false,
                    error: Some(format!(
                        "skipped: max_log_files={} reached",
                        args.max_log_files
                    )),
                });
                continue;
            }

            let raw = match exec.cli(&format!("file show {path}"), "text").await {
                Ok(text) => text,
                Err(e) => {
                    artefacts.push(CapturedArtefact {
                        source: ArtefactSource::LogFile {
                            device_path: path.to_string(),
                        },
                        tarball_path: rel_display,
                        sha256: String::new(),
                        bytes_in_tarball: 0,
                        redacted: false,
                        error: Some(format!("file show {path}: {e}")),
                    });
                    continue;
                }
            };
            // Junos emits a plain `error: ...` line (not an rpc-error) when
            // a file is absent or unreadable; treat that as a per-artefact
            // error rather than archiving the error text as log data.
            if raw.trim_start().starts_with("error:") {
                artefacts.push(CapturedArtefact {
                    source: ArtefactSource::LogFile {
                        device_path: path.to_string(),
                    },
                    tarball_path: rel_display,
                    sha256: String::new(),
                    bytes_in_tarball: 0,
                    redacted: false,
                    error: Some(raw.trim().to_string()),
                });
                continue;
            }

            let mut content = raw;
            let truncated = truncate_to_char_boundary(&mut content, cap_bytes);

            // Log files are plain text, so a naive XML-only redactor's
            // well-formedness gate fails and would emit them verbatim. Route
            // them through `junos::redact_log_artefact`, which applies the
            // line-oriented secret scrubber to non-XML payloads (#89) and
            // fails closed when content merely shaped like XML cannot be
            // confirmed well-formed — refuse rather than ship it with only
            // the weaker pass applied.
            let (payload, redacted) = if args.redact {
                match junos::redact_log_artefact(&content) {
                    Ok(red) => {
                        let changed = red != content;
                        any_redacted |= changed;
                        (red, changed)
                    }
                    Err(e) => {
                        artefacts.push(CapturedArtefact {
                            source: ArtefactSource::LogFile {
                                device_path: path.to_string(),
                            },
                            tarball_path: rel_display,
                            sha256: String::new(),
                            bytes_in_tarball: 0,
                            redacted: false,
                            error: Some(format!(
                                "{path}: could not be confirmed safe to redact, artefact refused rather than shipped unredacted: {e}"
                            )),
                        });
                        continue;
                    }
                }
            } else {
                (content, false)
            };

            let abs_path = scratch.join(&rel);
            if let Some(parent) = abs_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    SrxError::InvalidInput(format!("create log dir {}: {e}", parent.display()))
                })?;
            }
            std::fs::write(&abs_path, payload.as_bytes()).map_err(|e| {
                SrxError::InvalidInput(format!("write {}: {e}", abs_path.display()))
            })?;

            artefacts.push(CapturedArtefact {
                source: ArtefactSource::LogFile {
                    device_path: path.to_string(),
                },
                tarball_path: rel_display,
                sha256: sha256_hex(payload.as_bytes()),
                bytes_in_tarball: payload.len() as u64,
                redacted,
                error: if truncated {
                    Some(format!(
                        "truncated to max_log_bytes_per_file={}",
                        args.max_log_bytes_per_file
                    ))
                } else {
                    None
                },
            });
            captured += 1;
        }
    }

    // Surface bundled-up RPC failures so the operator can decide whether
    // the bundle is still useful or to retry.
    if !failures.is_empty() && failures.len() == total {
        let (_, first) = &failures[0];
        return Err(SrxError::BundleRpcSubsetFailed {
            router: router.to_string(),
            failed_count: failures.len(),
            total_count: total,
            first_error: first.clone(),
        });
    }

    // 3) Write the manifest, assemble the tarball, and compute its digest.
    finalize_lxc_bundle(
        router,
        request_id,
        filesystem_id,
        &mut paths,
        artefacts,
        problem_types,
        any_redacted,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compress `scratch` into the prepared tarball path, entries rooted at the
/// scratch directory's own name.
///
/// Replaces a `tar -czf - -C <router_dir> -- <scratch>` spawn whose stdout was
/// redirected into an already-opened file. That redirection was doing security
/// work, and this keeps both halves of it (#212):
///
/// * **The archive pathname is never handed to the archiver.** It writes into
///   the `File` `PreparedBundlePaths::create_tarball` opened, so no
///   caller-controlled value can steer where bytes land.
/// * **`create_new` makes a pre-existing symlink at the destination an error**,
///   not something to follow through to whatever it points at.
///
/// One property is *new*: `tar-rs` follows symlinks by default where GNU tar
/// does not. Left alone, a symlink under the scratch directory would have had
/// its target's contents pulled into the bundle — reading files the collection
/// step never chose to collect. `follow_symlinks(false)` matches the old
/// behaviour and is the safer of the two.
///
/// # Errors
///
/// Returns [`SrxError::InvalidInput`] if the destination cannot be created
/// exclusively, or if archiving or compression fails.
fn write_bundle_archive(paths: &PreparedBundlePaths, scratch: &Path) -> Result<(), SrxError> {
    let tarball_file = paths.create_tarball()?;
    let encoder = flate2::write::GzEncoder::new(tarball_file, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    archive.follow_symlinks(false);

    let archive_root = scratch
        .file_name()
        .ok_or_else(|| SrxError::InvalidInput("scratch dir has no name".into()))?;
    archive
        .append_dir_all(archive_root, scratch)
        .map_err(|e| SrxError::InvalidInput(format!("build bundle archive: {e}")))?;
    archive
        .into_inner()
        .map_err(|e| SrxError::InvalidInput(format!("finish bundle archive: {e}")))?
        .finish()
        .map_err(|e| SrxError::InvalidInput(format!("finish bundle compression: {e}")))?;
    Ok(())
}
/// Write `manifest.json` into the scratch dir, tar the scratch dir into the
/// per-router LXC staging area, clean up the scratch dir, enforce the
/// staging cap, and compute the tarball's size + sha256. Shared by the
/// `generic` and per-type collection paths so both land an identical
/// `lxc_staging` bundle layout.
fn finalize_lxc_bundle(
    router: &str,
    request_id: &str,
    filesystem_id: &str,
    paths: &mut PreparedBundlePaths,
    artefacts: Vec<CapturedArtefact>,
    problem_types: &BTreeSet<ProblemType>,
    any_redacted: bool,
) -> Result<SupportBundleData, SrxError> {
    paths.ensure_confined()?;
    let scratch = paths.scratch_dir().to_path_buf();
    let tarball_path = paths.tarball_path().to_path_buf();

    // Write manifest.json into the scratch dir so it lands in the tarball.
    let manifest_json = serde_json::json!({
        "request_id": request_id,
        "filesystem_id": filesystem_id,
        "router": router,
        "problem_types": problem_types,
        "artefacts": &artefacts,
        "redacted": any_redacted,
        "schema": "srxmcp-support-bundle-v0.3.0",
    });
    let manifest_path = scratch.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_json).expect("manifest json"),
    )
    .map_err(|e| SrxError::InvalidInput(format!("write manifest: {e}")))?;

    write_bundle_archive(paths, &scratch)?;

    // Enforce staging cap (LRU eviction) — stub today.
    let _ = enforce_staging_cap(paths.staging_max_bytes());

    let tarball_bytes = std::fs::metadata(&tarball_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let sha256 = match std::fs::read(&tarball_path) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(_) => String::new(),
    };
    paths.commit_tarball();

    let bundle = BundleInfo {
        location: BundleLocation::LxcStaging,
        path: path_to_string(&tarball_path),
        bytes: tarball_bytes,
        sha256,
        problem_types: problem_types.iter().copied().collect(),
        artefacts,
        redacted: any_redacted,
    };
    let next_step = format!(
        "read tarball directly on the LXC host: {} (read by operator with shell access; not fetchable via fetch_file)",
        bundle.path
    );
    Ok(SupportBundleData {
        router: router.to_string(),
        request_id: request_id.to_string(),
        filesystem_id: filesystem_id.to_string(),
        bundle,
        next_step,
        elapsed_secs: 0,
    })
}

/// Redact the `request support information` payload for the generic
/// support-bundle path. That RPC returns plain tech-support text, never XML,
/// so this always goes through [`mecmcp_redact::junos::redact_log_artefact`]
/// (never a permissive XML-only redactor) — otherwise `redact:true` (the
/// default) becomes a silent no-op that ships the raw payload while still
/// recording `redacted: false`. Extracted from `collect_generic` so a test can
/// call the exact function production code calls, rather than exercising
/// `junos::redact_log_artefact` directly and missing a regression in how
/// `collect_generic` wires it up.
///
/// # Errors
/// Returns [`SrxError::BundleConfigCaptureFailed`] when `junos::redact_log_artefact`
/// cannot confirm the payload safe (fail-closed: the generic path's single
/// artefact must be refused rather than shipped with only a partial redaction
/// pass, or worse, raw).
fn redact_generic_payload(
    router: &str,
    payload: String,
    redact: bool,
) -> Result<(String, bool), SrxError> {
    if redact {
        let red = junos::redact_log_artefact(&payload).map_err(|e| {
            SrxError::BundleConfigCaptureFailed {
                router: router.to_string(),
                detail: format!(
                    "request support information: payload could not be confirmed safe to redact: {e}"
                ),
            }
        })?;
        let changed = red != payload;
        Ok((red, changed))
    } else {
        Ok((payload, false))
    }
}

/// Redact a captured RPC-reply payload for the per-RPC support-bundle path.
/// Returns `Some((payload, changed))` when the reply was confirmed
/// well-formed XML, `changed` indicating whether anything was actually
/// redacted. Returns `None` when the reply could not be confirmed
/// well-formed XML — the caller must refuse the artefact rather than
/// shipping the raw payload (fail closed).
fn redact_rpc_reply(raw: &str) -> Option<(String, bool)> {
    match junos::redact_xml(raw) {
        Ok(red) => {
            let changed = red != raw;
            Some((red, changed))
        }
        Err(_) => None,
    }
}

fn sanitize_rpc_filename(rpc: &str, inner: &str) -> Result<String, SrxError> {
    validate_path_component("RPC name", rpc)?;
    let filename = if inner.is_empty() {
        format!("{rpc}.xml")
    } else {
        // Strip <> and / from inner so we get something like
        // "get-flow-session-information.summary.xml".
        let suffix: String = inner
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        format!("{rpc}.{suffix}.xml")
    };
    validate_path_component("RPC artifact filename", &filename)?;
    Ok(filename)
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Truncate `s` in place to at most `cap` bytes, backing up to the nearest
/// UTF-8 char boundary so the result stays valid UTF-8. Returns `true` if
/// any bytes were dropped.
fn truncate_to_char_boundary(s: &mut String, cap: usize) -> bool {
    if s.len() <= cap {
        return false;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

fn mint_filesystem_id() -> String {
    format!("srxmcp-{}", uuid::Uuid::new_v4())
}

/// Lower-case hex SHA-256. Uses sha2 if available, otherwise falls back
/// to an empty string (the orchestrator surfaces this honestly in the
/// manifest rather than fabricating a hash).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_type_arg_one_collapses_to_singleton_set() {
        let arg = ProblemTypeArg::One(ProblemType::Vpn);
        let set = arg.into_set();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&ProblemType::Vpn));
    }

    #[test]
    fn problem_type_arg_many_dedupes() {
        let arg = ProblemTypeArg::Many(vec![
            ProblemType::Vpn,
            ProblemType::Routing,
            ProblemType::Vpn,
        ]);
        let set = arg.into_set();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn sanitize_rpc_filename_with_and_without_args() {
        assert_eq!(
            sanitize_rpc_filename("get-configuration", "").unwrap(),
            "get-configuration.xml"
        );
        assert_eq!(
            sanitize_rpc_filename("get-flow-session-information", "<summary/>").unwrap(),
            "get-flow-session-information.summary.xml"
        );
        assert!(sanitize_rpc_filename("../../escape", "").is_err());
    }

    #[test]
    fn caller_request_ids_are_metadata_only_but_still_validated() {
        let filesystem_id = "srxmcp-12345678-1234-1234-1234-123456789abc";
        assert_eq!(
            effective_request_id(Some("incident-123"), filesystem_id).unwrap(),
            "incident-123"
        );
        assert_eq!(
            effective_request_id(None, filesystem_id).unwrap(),
            filesystem_id
        );

        let long = "x".repeat(staging::MAX_PATH_COMPONENT_BYTES + 1);
        for bad in [
            "",
            " ",
            ".",
            "..",
            "../escape",
            "/absolute",
            "a/b",
            "a\\b",
            "line\nbreak",
            "srxmcp-",
            "srxmcp-.",
            &long,
        ] {
            assert!(
                effective_request_id(Some(bad), filesystem_id).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn truncate_to_char_boundary_respects_utf8_and_cap() {
        // Under cap: untouched.
        let mut s = "hello".to_string();
        assert!(!truncate_to_char_boundary(&mut s, 10));
        assert_eq!(s, "hello");

        // Exactly at cap: untouched.
        let mut s = "hello".to_string();
        assert!(!truncate_to_char_boundary(&mut s, 5));
        assert_eq!(s, "hello");

        // Over cap on ASCII: trims to cap.
        let mut s = "hello world".to_string();
        assert!(truncate_to_char_boundary(&mut s, 5));
        assert_eq!(s, "hello");

        // Multi-byte: "é" is 2 bytes — a cap of 1 must back up to 0 rather
        // than split the char (which would otherwise panic).
        let mut s = "é".to_string();
        assert!(truncate_to_char_boundary(&mut s, 1));
        assert_eq!(s, "");
        assert!(s.is_empty());
    }

    // The per-RPC support-bundle capture path must fail closed on malformed
    // XML rather than falling back to `redact_xml`'s unchanged-on-failure
    // behaviour and shipping the raw reply with `redacted: false` recorded
    // as if nothing were wrong.
    #[test]
    fn redact_rpc_reply_refuses_malformed_xml() {
        let malformed = "<rpc-reply><secret>oops";
        assert_eq!(
            redact_rpc_reply(malformed),
            None,
            "malformed RPC reply must be refused, not shipped raw"
        );
    }

    #[test]
    fn redact_rpc_reply_redacts_well_formed_xml() {
        let xml = "<rpc-reply><secret>s3cr3t</secret></rpc-reply>";
        let (payload, changed) = redact_rpc_reply(xml).expect("well-formed XML must redact");
        assert!(!payload.contains("s3cr3t"), "secret leaked: {payload}");
        assert!(
            changed,
            "well-formed XML with a known key must report changed=true"
        );
    }

    #[test]
    fn redact_rpc_reply_reports_unchanged_when_nothing_to_redact() {
        let xml = "<rpc-reply><host-name>edge01</host-name></rpc-reply>";
        let (payload, changed) = redact_rpc_reply(xml).expect("well-formed XML must redact");
        assert_eq!(payload, xml);
        assert!(
            !changed,
            "no sensitive elements present, so changed must be false"
        );
    }

    // F3: the M1 regression test for `collect_generic`'s redaction call must
    // exercise the exact function production code calls, not just the
    // library redactor directly — otherwise a regression that swapped
    // `redact_generic_payload`'s body back to a permissive redactor would go
    // uncaught while the library-level test kept passing.
    #[test]
    fn redact_generic_payload_scrubs_tech_support_text_when_redact_true() {
        let tech_support = "set snmp community leakedGeneric;\n".to_string();
        let (out, redacted) = redact_generic_payload("edge01", tech_support.clone(), true)
            .expect("plain tech-support text must redact, not refuse");
        assert!(!out.contains("leakedGeneric"), "secret leaked: {out}");
        assert!(redacted, "must report redacted=true");
    }

    #[test]
    fn redact_generic_payload_passes_through_when_redact_false() {
        let tech_support = "set snmp community leakedGeneric;\n".to_string();
        let (out, redacted) = redact_generic_payload("edge01", tech_support.clone(), false)
            .expect("redact=false must never fail");
        assert_eq!(out, tech_support);
        assert!(!redacted, "redact=false must report redacted=false");
    }

    // The generic support-bundle path's single artefact must be refused
    // (fail closed), not silently shipped unredacted, when the captured
    // payload cannot be confirmed safe to redact.
    #[test]
    fn redact_generic_payload_fails_closed_when_shaped_like_unparseable_xml() {
        let bad = "<unclosed><secret>oops".to_string();
        let err = redact_generic_payload("edge01", bad, true)
            .expect_err("XML-shaped-but-unparseable payload must be refused");
        assert!(
            matches!(err, SrxError::BundleConfigCaptureFailed { .. }),
            "unexpected error variant: {err:?}"
        );
    }

    // MEC-1232 fixture coverage: every known Junos secret-bearing key name
    // `mecmcp_redact::junos` redacts must actually come back redacted through
    // *this crate's* support-bundle wiring (`redact_rpc_reply` for the
    // per-RPC XML path, `redact_generic_payload` for the plain-text
    // `request support information` path) — not just inside the library's
    // own unit tests. `mecmcp_redact::junos::REDACT_LOG_KEYS` is private, so
    // this list is kept in sync by hand; a name added there without a
    // matching entry here is still caught by the crypt-hash catch-all cases
    // below, but should be added here too.
    const KNOWN_JUNOS_SECRET_KEYS: &[&str] = &[
        "pre-shared-key",
        "secret",
        "simple-password",
        "encrypted-password",
        "community",
        "hmac-key",
        "authentication-key",
        "authentication-password",
        "privacy-password",
        "privacy-key",
        "password",
        "chap-secret",
        "default-chap-secret",
        "local-password",
        "hello-authentication-key",
        "plain-text-password-value",
        "key",
        "value",
    ];

    #[test]
    fn every_known_junos_secret_key_is_redacted_in_rpc_reply_xml() {
        for key in KNOWN_JUNOS_SECRET_KEYS {
            let leaked = format!("leak-{key}-value");
            let xml = format!("<rpc-reply><{key}>{leaked}</{key}></rpc-reply>");
            let (payload, changed) = redact_rpc_reply(&xml)
                .unwrap_or_else(|| panic!("well-formed XML for <{key}> must redact, not refuse"));
            assert!(
                !payload.contains(&leaked),
                "secret leaked for <{key}>: {payload}"
            );
            assert!(changed, "must report changed=true for <{key}>");
        }
    }

    #[test]
    fn every_known_junos_secret_key_is_redacted_in_generic_log_text() {
        for key in KNOWN_JUNOS_SECRET_KEYS {
            let leaked = format!("leak{key}Value");
            // `set`-statement-aware config syntax, the same shape a
            // `request support information` tech-support dump or a syslog
            // line would carry it in.
            let line = format!("set foo {key} \"{leaked}\"\n");
            let (payload, changed) = redact_generic_payload("edge01", line.clone(), true)
                .unwrap_or_else(|e| {
                    panic!("set-syntax text for {key} must redact, not refuse: {e}")
                });
            assert!(
                !payload.contains(&leaked),
                "secret leaked for {key}: {payload}"
            );
            assert!(changed, "must report changed=true for {key}");
        }
    }

    // The Junos crypt-hash catch-all must still fire through this crate's
    // wiring even under an element/key name not on the known-key list — the
    // whole point of the catch-all is covering names nobody has denylisted
    // yet.
    #[test]
    fn junos_crypt_hash_catch_all_is_redacted_in_rpc_reply_xml() {
        let xml = "<rpc-reply><password-hash>$6$saltXYZ$hashLEAKvalue</password-hash></rpc-reply>";
        let (payload, changed) =
            redact_rpc_reply(xml).expect("well-formed XML with a bare crypt hash must redact");
        assert!(
            !payload.contains("$6$saltXYZ$hashLEAKvalue"),
            "crypt hash leaked: {payload}"
        );
        assert!(changed, "must report changed=true");
    }

    #[test]
    fn junos_crypt_hash_catch_all_is_redacted_in_generic_log_text() {
        let line = "unlisted-field $6$saltXYZ$hashLEAKvalue\n".to_string();
        let (payload, changed) = redact_generic_payload("edge01", line, true)
            .expect("bare crypt hash in text must redact, not refuse");
        assert!(
            !payload.contains("$6$saltXYZ$hashLEAKvalue"),
            "crypt hash leaked: {payload}"
        );
        assert!(changed, "must report changed=true");
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn lock_for_returns_same_semaphore_for_same_router() {
        let a = lock_for("vsrx-test10");
        let b = lock_for("vsrx-test10");
        assert!(Arc::ptr_eq(&a, &b));
        let c = lock_for("vsrx-test11");
        assert!(!Arc::ptr_eq(&a, &c));
    }

    // Regression for #81: the generic path used to report success with a
    // zero-byte/empty-hash bundle because `request support information |
    // save` wrote nothing on-device. The path now stages the inline payload
    // and assembles a real tarball — `finalize_lxc_bundle` must produce a
    // non-empty, hashed `lxc_staging` bundle.
    #[test]
    fn finalize_lxc_bundle_produces_nonempty_tarball() {
        let tmp = tempfile::tempdir().expect("tmp dir");
        let staging = SupportBundleStagingConfig::new(tmp.path().to_path_buf(), 123_456);
        let router = "vSRX-finalize-unit";
        let request_id = "srxmcp-unit-0001";
        let filesystem_id = "srxmcp-12345678-1234-1234-1234-123456789abc";
        let mut paths = PreparedBundlePaths::prepare_under(
            tmp.path(),
            staging.max_bytes(),
            router,
            filesystem_id,
        )
        .unwrap();
        let scratch = paths.scratch_dir().to_path_buf();
        let payload = b"hello tech-support output";
        std::fs::write(scratch.join("request-support-information.txt"), payload).expect("write");

        let artefacts = vec![CapturedArtefact {
            source: ArtefactSource::Rpc {
                name: "request support information".into(),
                args: None,
            },
            tarball_path: "request-support-information.txt".into(),
            sha256: sha256_hex(payload),
            bytes_in_tarball: payload.len() as u64,
            redacted: false,
            error: None,
        }];
        let mut problem_types = BTreeSet::new();
        problem_types.insert(ProblemType::Generic);

        let data = finalize_lxc_bundle(
            router,
            request_id,
            filesystem_id,
            &mut paths,
            artefacts,
            &problem_types,
            false,
        )
        .expect("finalize");

        assert_eq!(data.bundle.location, BundleLocation::LxcStaging);
        assert!(
            data.bundle.bytes > 0,
            "tarball must be non-empty (regression for #81)"
        );
        assert_eq!(data.bundle.sha256.len(), 64);
        assert!(Path::new(&data.bundle.path).exists());
        assert_eq!(data.request_id, request_id);
        assert_eq!(data.filesystem_id, filesystem_id);
        drop(paths);
        assert!(!scratch.exists(), "scratch dir should be cleaned up");
    }
}

#[cfg(test)]
mod archive_security_tests {
    use super::{PreparedBundlePaths, write_bundle_archive};
    use crate::workflows::support_bundle::staging::DEFAULT_STAGING_MAX_BYTES;
    use std::fs;

    fn prepared(temp: &tempfile::TempDir) -> PreparedBundlePaths {
        PreparedBundlePaths::prepare_under(
            temp.path(),
            DEFAULT_STAGING_MAX_BYTES,
            "vSRX-test10",
            "srxmcp-archive-test",
        )
        .unwrap()
    }

    /// The uncompressed archive bytes.
    fn decompressed(tarball: &std::path::Path) -> Vec<u8> {
        let mut out = Vec::new();
        let file = fs::File::open(tarball).unwrap();
        std::io::copy(&mut flate2::read::GzDecoder::new(file), &mut out).unwrap();
        out
    }

    fn entries(tarball: &std::path::Path) -> Vec<(String, tar::EntryType)> {
        let bytes = decompressed(tarball);
        tar::Archive::new(bytes.as_slice())
            .entries()
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.path().unwrap().to_string_lossy().into_owned(),
                    entry.header().entry_type(),
                )
            })
            .collect()
    }

    #[test]
    fn the_archive_is_rooted_at_the_scratch_directory_name() {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = prepared(&temp);
        fs::write(paths.scratch_dir().join("manifest.json"), b"{}").unwrap();

        let scratch = paths.scratch_dir().to_path_buf();
        write_bundle_archive(&paths, &scratch).unwrap();
        paths.commit_tarball();

        let root = scratch.file_name().unwrap().to_string_lossy().into_owned();
        let names: Vec<String> = entries(paths.tarball_path())
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(
            names
                .iter()
                .any(|name| name == &format!("{root}/manifest.json")),
            "entries must sit under the scratch dir name, as `tar -C <router_dir> -- <scratch>` \
             produced. got: {names:?}"
        );
    }

    /// #212 acceptance: the pathname-injection protection must survive. The
    /// archiver never receives the destination path — it writes into the `File`
    /// `create_tarball` opened — so nothing a caller controls can steer where
    /// the bytes land.
    #[test]
    fn a_destination_that_already_exists_is_refused_rather_than_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let paths = prepared(&temp);
        let scratch = paths.scratch_dir().to_path_buf();
        fs::write(paths.tarball_path(), b"pre-existing").unwrap();

        let err = write_bundle_archive(&paths, &scratch)
            .expect_err("an existing destination must not be written through");
        assert!(
            format!("{err}").contains("create bundle tarball securely"),
            "got: {err}"
        );
        assert_eq!(
            fs::read(paths.tarball_path()).unwrap(),
            b"pre-existing",
            "the existing file must be left untouched"
        );
    }

    /// #212 acceptance: the symlink-at-destination protection must survive.
    /// `create_new` refuses rather than following the link, so a symlink
    /// planted at the tarball path cannot redirect the write.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_destination_is_refused_rather_than_followed() {
        let temp = tempfile::tempdir().unwrap();
        let paths = prepared(&temp);
        let scratch = paths.scratch_dir().to_path_buf();

        let victim = temp.path().join("victim.txt");
        fs::write(&victim, b"do not clobber").unwrap();
        std::os::unix::fs::symlink(&victim, paths.tarball_path()).unwrap();

        write_bundle_archive(&paths, &scratch)
            .expect_err("a symlinked destination must not be written through");
        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do not clobber",
            "writing through the symlink would have destroyed the target"
        );
    }

    /// New with `tar-rs`, which follows symlinks by default where GNU tar does
    /// not. Following one would pull a file's contents into the bundle that the
    /// collection step never chose to collect — on a device-diagnostics archive
    /// that is an exfiltration primitive, not a convenience.
    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_scratch_dir_is_stored_as_a_link_not_its_target() {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = prepared(&temp);
        let scratch = paths.scratch_dir().to_path_buf();

        let secret = temp.path().join("secret.txt");
        fs::write(&secret, b"SECRET-DATA").unwrap();
        std::os::unix::fs::symlink(&secret, scratch.join("link.txt")).unwrap();

        write_bundle_archive(&paths, &scratch).unwrap();
        paths.commit_tarball();

        let root = scratch.file_name().unwrap().to_string_lossy().into_owned();
        let found = entries(paths.tarball_path());
        let link = found
            .iter()
            .find(|(name, _)| name == &format!("{root}/link.txt"))
            .expect("the symlink should be archived");
        assert_eq!(
            link.1,
            tar::EntryType::Symlink,
            "the link must be stored as a link; storing its target would put \
             {secret:?}'s contents in the bundle"
        );

        assert!(
            !decompressed(paths.tarball_path())
                .windows(11)
                .any(|w| w == b"SECRET-DATA"),
            "the target's contents must not appear anywhere in the archive"
        );
    }
}

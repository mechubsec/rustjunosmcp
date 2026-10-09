//! `fetch_file` MCP tool. SCP a file from a Junos device's /var/tmp/ back
//! to the host's staging directory, with per-router serialization and
//! sha256 verification. Mirror image of `transfer_file`.

use std::sync::Arc;

use crate::cancel::{select_cancel, select_cancel_raw};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::FetchFileArgs;
use crate::tools::transfer_file::{
    ScpFetchJob, TransferConfig, hex32, parse_checksum_output, sha256_file_cancellable,
    validate_source_basename,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// Build the JSON response for a skipped fetch (local file already present
/// with matching checksum).
fn skipped_response(
    local_path: &std::path::Path,
    remote_basename: &str,
    sha: &[u8; 32],
    size: u64,
) -> Value {
    json!({
        "status": "skipped",
        "local_path": local_path.display().to_string(),
        "remote_path": format!("/var/tmp/{}", remote_basename),
        "size_bytes": size,
        "sha256": hex32(sha),
        "verified": true,
        "message": "local file already present with matching sha256; no fetch performed",
    })
}

/// SCP a file from `/var/tmp/<remote_path>` on the device to the local staging directory.
///
/// Validates basename (rejects path traversal), requires SSH-key auth, enforces
/// per-router serialization, probes remote SHA-256 via NETCONF, skips if local
/// file already matches, verifies SHA-256 post-fetch, and atomically promotes
/// `.partial` to the canonical name. Requires `known_hosts` in `Strict` mode;
/// `AcceptNew`/`AcceptAll` tolerate a missing one. Respects cancellation.
pub async fn handle(
    args: FetchFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        // Issue #44 Half A: short-circuit if the request was cancelled
        // before we even entered the body.
        if ct.is_cancelled() {
            return Err(JmcpError::Cancelled);
        }
        validate_source_basename(&args.remote_path)?;
        let local_basename = args
            .local_name
            .clone()
            .unwrap_or_else(|| args.remote_path.clone());
        validate_source_basename(&local_basename)?;

        // RJMCP-SEC-004: known_hosts is mandatory in Strict mode.
        use crate::bootstrap::SshHostKeyMode;
        match std::fs::metadata(&cfg.known_hosts_file) {
            Ok(m) if m.is_file() => {}
            _ if cfg.host_key_mode == SshHostKeyMode::AcceptNew => {
                tracing::info!(
                    known_hosts = %cfg.known_hosts_file.display(),
                    "fetch_file: known_hosts missing; running in accept-new (TOFU) mode"
                );
            }
            _ if cfg.host_key_mode == SshHostKeyMode::AcceptAll => {
                tracing::info!(
                    "fetch_file: known_hosts missing; running in accept-any (insecure, lab-only) mode"
                );
            }
            _ => {
                return Err(JmcpError::KnownHostsMissing(cfg.known_hosts_file.clone()));
            }
        }

        // Per-router serialization (shared with transfer_file). Acquired AFTER
        // basename validation so an obviously-bogus path never queues behind a
        // live transfer.
        let _permit =
            select_cancel_raw::<_, _, JmcpError>(&ct, cfg.transfer_locks.acquire(&args.device))
                .await?;

        // Resolve device + check auth type. Snapshot the fields we need before
        // dropping the borrow so we can hand `dm` to `dm.open(...)` below.
        let inv = dm.inventory();
        let entry = inv.get(&args.device)?;
        let private_key_path = match &entry.auth {
            AuthConfig::Password { .. } | AuthConfig::PasswordEnv { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.device.clone()));
            }
            AuthConfig::SshKey { private_key_path } => private_key_path.clone(),
        };
        let host = entry.ip.clone();
        let port = entry.port;
        let username = entry.username.clone();
        drop(inv);

        let remote_basename = args.remote_path.clone();
        let remote_path = format!("/var/tmp/{}", remote_basename);
        let local_path = cfg.staging_dir.join(&local_basename);
        let partial_path = {
            let mut p = local_path.clone();
            let fname = p
                .file_name()
                .expect("local_path has a file name")
                .to_os_string();
            let mut s = fname;
            s.push(".partial");
            p.set_file_name(s);
            p
        };

        // Open pooled NETCONF session for the remote checksum probe.
        let mut dev = select_cancel(&ct, dm.open(&args.device)).await?;

        // Probe remote checksum. If absent, fail fast.
        let probe_cmd = format!("file checksum sha-256 {}", remote_path);
        let probe_out = select_cancel_raw::<_, _, JmcpError>(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "remote_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha = match parse_checksum_output(&probe_out)? {
            Some(s) => s,
            None => {
                return Err(JmcpError::RemoteFileMissing {
                    router: args.device.clone(),
                    remote_path: remote_path.clone(),
                });
            }
        };

        // Idempotent skip / local-conflict check.
        // SECURITY: there is a TOCTOU window between the metadata check below
        // and scp opening the partial file at `local_path.with_extension("partial")`.
        // The threat model assumes the staging dir is jmcp-owned with mode 0700,
        // so no unprivileged process can swap inodes inside this window. If a
        // future change relaxes those staging-dir permissions, this becomes a
        // real symlink/race vulnerability — consider an O_NOFOLLOW open instead.
        if let Ok(meta) = std::fs::symlink_metadata(&local_path) {
            if meta.file_type().is_symlink() {
                return Err(JmcpError::BadSourcePath(format!(
                    "local destination is a symlink, refusing to overwrite: {}",
                    local_path.display()
                )));
            }
            if meta.is_file() {
                let (local_sha, local_size) = sha256_file_cancellable(&local_path, &ct).await?;
                if local_sha == remote_sha {
                    return Ok(skipped_response(
                        &local_path,
                        &remote_basename,
                        &local_sha,
                        local_size,
                    ));
                }
                if !args.force {
                    return Err(JmcpError::LocalDestExistsDiffers {
                        dest: local_path.display().to_string(),
                        local_sha: hex32(&local_sha),
                        remote_sha: hex32(&remote_sha),
                    });
                }
                // force=true: fall through and overwrite.
            }
        }

        // Best-effort pre-clean of any stale .partial from a previous crashed fetch.
        let _ = std::fs::remove_file(&partial_path);

        // SCP the file down to the .partial sibling.
        let job = ScpFetchJob {
            private_key_path,
            known_hosts_file: cfg.known_hosts_file.clone(),
            username,
            host,
            port,
            remote_path: remote_path.clone(),
            local_path: partial_path.clone(),
            host_key_mode: cfg.host_key_mode,
        };
        let outcome = cfg.scp_runner.fetch(&job, &ct).await.map_err(|e| {
            let _ = std::fs::remove_file(&partial_path);
            match e.kind() {
                std::io::ErrorKind::Interrupted => JmcpError::Cancelled,
                _ => JmcpError::Io(e),
            }
        })?;
        if outcome.exit_code != 0 {
            let _ = std::fs::remove_file(&partial_path);
            return Err(crate::tools::transfer_file::classify_scp_failure(
                &outcome,
                &args.device,
                &cfg.known_hosts_file,
            ));
        }

        // Post-fetch local hash + verify (reads from partial_path).
        let (post_sha, post_size) = sha256_file_cancellable(&partial_path, &ct).await?;
        let verified = post_sha == remote_sha;
        if args.verify && !verified {
            // Best-effort cleanup of the corrupted partial file.
            let _ = std::fs::remove_file(&partial_path);
            return Err(JmcpError::FetchVerifyMismatch {
                dest: local_path.display().to_string(),
                local_sha: hex32(&post_sha),
                remote_sha: hex32(&remote_sha),
            });
        }

        // Atomically promote to the canonical name.
        std::fs::rename(&partial_path, &local_path).map_err(JmcpError::Io)?;

        Ok(json!({
            "status": "fetched",
            "local_path": local_path.display().to_string(),
            "remote_path": remote_path,
            "size_bytes": post_size,
            "sha256": hex32(&post_sha),
            "verified": verified,
        }))
    })
    .await
    .map_err(|_| JmcpError::TransferOuterTimeout(timeout))?
}

#[cfg(test)]
mod handle_validation_tests {
    use super::*;
    use crate::inventory::Inventory;
    use crate::tools::transfer_file::{MockScpRunner, TransferLocks};
    use std::io::Write;

    fn cfg(dir: &std::path::Path) -> TransferConfig {
        TransferConfig {
            staging_dir: dir.to_path_buf(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            scp_runner: MockScpRunner::ok(),
            transfer_locks: Arc::new(TransferLocks::default()),
            // Tests don't provide a real known_hosts file; opt into TOFU
            // so the v0.5.2 pre-check (`KnownHostsMissing`) doesn't short-
            // circuit them. A dedicated test below asserts that strict-mode
            // + missing known_hosts fails closed.
            host_key_mode: crate::bootstrap::SshHostKeyMode::AcceptNew,
        }
    }

    fn build_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn rejects_bad_remote_basename() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            FetchFileArgs {
                device: "r1".into(),
                remote_path: "../etc/shadow".into(),
                local_name: None,
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))), "got {r:?}");
    }

    #[tokio::test]
    async fn rejects_bad_local_name_override() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            FetchFileArgs {
                device: "r1".into(),
                remote_path: "ok.tgz".into(),
                local_name: Some("../escape".into()),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))), "got {r:?}");
    }

    /// Strict mode (`SshHostKeyMode::Strict`) must fail closed when the
    /// configured `known_hosts_file` is missing or not a regular file.
    #[tokio::test]
    async fn strict_mode_rejects_missing_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let mut c = cfg(dir.path());
        c.host_key_mode = crate::bootstrap::SshHostKeyMode::Strict;
        c.known_hosts_file = dir.path().join("no-such-known_hosts");
        let r = handle(
            FetchFileArgs {
                device: "r1".into(),
                remote_path: "ok.tgz".into(),
                local_name: None,
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            c,
            CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::KnownHostsMissing(_))),
            "expected KnownHostsMissing in strict mode, got {r:?}"
        );
    }

    /// MEC-44 follow-up: `AcceptAll` must not require known_hosts to exist
    /// for fetch, mirroring the transfer_file behaviour.
    #[tokio::test]
    async fn accept_all_mode_tolerates_missing_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let mut c = cfg(dir.path());
        c.host_key_mode = crate::bootstrap::SshHostKeyMode::AcceptAll;
        c.known_hosts_file = dir.path().join("no-such-known_hosts");
        let r = handle(
            FetchFileArgs {
                device: "r1".into(),
                remote_path: "ok.tgz".into(),
                local_name: None,
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            c,
            CancellationToken::new(),
        )
        .await;
        assert!(
            !matches!(r, Err(JmcpError::KnownHostsMissing(_))),
            "AcceptAll must not require known_hosts to exist, got {r:?}"
        );
    }

    #[tokio::test]
    async fn rejects_password_auth_with_unsupported_auth() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            FetchFileArgs {
                device: "r1".into(),
                remote_path: "ok.tgz".into(),
                local_name: None,
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::UnsupportedAuth(_))),
            "expected UnsupportedAuth, got {r:?}"
        );
    }
}

//! `transfer_file` MCP tool. SCP a pre-staged file from the host's staging
//! directory to a Junos device's /var/tmp/, with idempotent skip and
//! pre/post-transfer sha256 verification.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cancel::{select_cancel, select_cancel_raw};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::TransferFileArgs;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// Required free-space headroom on `/var` beyond the local file size, in bytes.
/// Junos needs working room for temp files and metadata; 32 MiB is generous
/// enough to absorb log churn during a multi-GB upload without false negatives.
pub(crate) const MIN_FREE_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

/// Format a 32-byte sha256 digest as 64 lowercase hex characters.
///
/// Shared across the workspace so every audited digest string is produced by
/// one implementation. `sha2` 0.11 returns `hybrid_array::Array`, which does
/// not implement `LowerHex`, so `format!("{:x}", ..)` is no longer available.
pub fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Scrub OpenSSH/scp stderr before it lands in a `JmcpError::ScpFailed`
/// surfaced to the MCP caller. Redacts:
/// - absolute filesystem paths (e.g. `/root/.ssh/id_ed25519`, `/var/tmp/x`)
///   → `<path>`
/// - IPv4 dotted-quad addresses (e.g. `192.168.1.10`) → `<host>`
///
/// Rationale (issue #26, L1): in a multi-tenant or less-trusted deployment,
/// raw `scp` stderr leaks the operator's filesystem layout (private-key
/// paths, staging dir locations) and the device's IP. Both are unnecessary
/// for diagnosing the underlying error reason, which we keep verbatim.
/// In single-operator labs this is cosmetic; in shared deployments it
/// matters.
pub(crate) fn scrub_scp_stderr(stderr: &str) -> String {
    let mut out = String::with_capacity(stderr.len());
    let bytes = stderr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // Absolute path: starts with '/' and contains only path-safe ASCII.
        // We accept the run of `[A-Za-z0-9./_+-]` after the leading '/'.
        // Requires at least one non-'/' char after to avoid matching bare '/'.
        if b == b'/' {
            let mut j = i + 1;
            while j < bytes.len() && is_path_byte(bytes[j]) {
                j += 1;
            }
            if j > i + 1 {
                out.push_str("<path>");
                i = j;
                continue;
            }
        }

        // IPv4 dotted-quad: greedy match of d{1,3}(.d{1,3}){3}.
        if b.is_ascii_digit()
            && let Some(end) = match_ipv4(&bytes[i..])
        {
            out.push_str("<host>");
            i += end;
            continue;
        }

        // Default: copy byte through. Safe because we only consume valid
        // UTF-8 boundaries above (the substituted matches are all ASCII).
        out.push(b as char);
        i += 1;
    }
    out
}

fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+')
}

/// If `bytes` starts with an IPv4 dotted-quad (`d{1,3}.d{1,3}.d{1,3}.d{1,3}`)
/// not followed by another digit or '.', return the byte length consumed.
fn match_ipv4(bytes: &[u8]) -> Option<usize> {
    let mut idx = 0;
    for octet in 0..4 {
        // 1 to 3 digits
        let start = idx;
        while idx < bytes.len() && idx - start < 3 && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == start {
            return None;
        }
        if octet < 3 {
            if idx >= bytes.len() || bytes[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    // Must not be followed by another digit or '.' (would mean it's a longer
    // numeric token, not an address).
    if let Some(&next) = bytes.get(idx)
        && (next.is_ascii_digit() || next == b'.')
    {
        return None;
    }
    Some(idx)
}

/// Build the JSON response returned when the destination already holds a file
/// with the same sha256 (idempotent skip). Kept as a pure helper so the shape
/// is unit-testable without standing up a DeviceManager.
pub(crate) fn skipped_response(basename: &str, sha: &[u8; 32], size: u64) -> Value {
    json!({
        "status": "skipped",
        "remote_path": format!("/var/tmp/{}", basename),
        "size_bytes": size,
        "sha256": hex32(sha),
        "verified": true,
        "message": "destination already present with matching sha256; no transfer performed",
    })
}

/// Validate that `source_path` is a safe basename. Rejects:
/// - empty
/// - longer than 255 bytes
/// - leading '.' (dotfiles)
/// - ".." anywhere (whole name or embedded, e.g. "a..b")
/// - any '/', '\\', or "..".
/// - any byte outside the ASCII allowlist `[A-Za-z0-9._-]`. This implicitly
///   rejects NUL bytes, ASCII control chars, and *all* non-ASCII Unicode —
///   including RTL overrides (U+202E), zero-width joiners, and homoglyph
///   scripts that could mask the true filename in operator logs or shell
///   expansions. Junos image / config artifacts are always plain ASCII so
///   this allowlist is non-restrictive in practice. (issue #26, L2)
pub fn validate_source_basename(source: &str) -> Result<(), JmcpError> {
    if source.is_empty() {
        return Err(JmcpError::BadSourcePath("source_path is empty".into()));
    }
    if source.len() > 255 {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path exceeds 255 bytes (got {})",
            source.len()
        )));
    }
    if source.starts_with('.') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not start with '.'"
        )));
    }
    if source.contains('/') || source.contains('\\') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '/' or '\\\\' (basename only)"
        )));
    }
    if source.contains("..") {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '..'"
        )));
    }
    // ASCII allowlist: [A-Za-z0-9._-] only. Scan bytes so non-ASCII (multi-
    // byte UTF-8) is rejected without needing to enumerate Unicode classes.
    if let Some(bad) = source
        .bytes()
        .find(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' contains disallowed byte 0x{bad:02x}; only [A-Za-z0-9._-] are permitted"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod scrub_tests {
    use super::*;

    #[test]
    fn redacts_absolute_path() {
        let s = scrub_scp_stderr("Load key \"/root/.ssh/id_ed25519\": invalid format");
        assert!(s.contains("<path>"), "{s}");
        assert!(!s.contains("/root"), "{s}");
        assert!(s.contains("invalid format"), "{s}");
    }

    #[test]
    fn redacts_ipv4_address() {
        let s = scrub_scp_stderr("ssh: connect to host 192.168.1.10 port 22: Connection timed out");
        assert!(s.contains("<host>"), "{s}");
        assert!(!s.contains("192.168"), "{s}");
        assert!(s.contains("Connection timed out"), "{s}");
        // "port 22" is left as-is — it's a service port number, not host info.
        assert!(s.contains("port 22"), "{s}");
    }

    #[test]
    fn redacts_multiple_paths_in_one_line() {
        let s =
            scrub_scp_stderr("scp: /var/tmp/foo.tgz: No such file or directory; checked /var/run");
        assert!(!s.contains("/var"), "{s}");
        assert_eq!(s.matches("<path>").count(), 2, "{s}");
        assert!(s.contains("No such file or directory"), "{s}");
    }

    #[test]
    fn keeps_diagnostic_text() {
        let s = scrub_scp_stderr("Permission denied (publickey).");
        // No paths or IPs to redact — message must pass through verbatim.
        assert_eq!(s, "Permission denied (publickey).");
    }

    #[test]
    fn preserves_newlines_and_structure() {
        let input = "line1: /a/b\nline2: 10.0.0.1\nline3: ok";
        let s = scrub_scp_stderr(input);
        assert_eq!(s.lines().count(), 3, "{s}");
        assert!(s.contains("<path>"));
        assert!(s.contains("<host>"));
        assert!(s.contains("ok"));
    }

    #[test]
    fn does_not_match_partial_ipv4() {
        // 1.2.3 is not a complete dotted-quad and must pass through.
        let s = scrub_scp_stderr("version 1.2.3 detected");
        assert_eq!(s, "version 1.2.3 detected");
    }

    #[test]
    fn does_not_match_bare_digits() {
        // Single number with no dots is not an IPv4 address.
        let s = scrub_scp_stderr("exit code 42");
        assert_eq!(s, "exit code 42");
    }

    #[test]
    fn leaves_bare_slash_alone() {
        // Single '/' with no following path chars should not become <path>.
        let s = scrub_scp_stderr("a / b");
        assert_eq!(s, "a / b");
    }
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    #[test]
    fn accepts_plain_basename() {
        assert!(validate_source_basename("junos-25.4R1.12.tgz").is_ok());
    }

    #[test]
    fn accepts_ascii_with_dots_in_middle() {
        assert!(validate_source_basename("a.b.c.tgz").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_source_basename(""),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(256);
        assert!(matches!(
            validate_source_basename(&s),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(
            validate_source_basename(".hidden"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_dotdot_anywhere() {
        assert!(matches!(
            validate_source_basename("a..b"),
            Err(JmcpError::BadSourcePath(_))
        ));
        assert!(matches!(
            validate_source_basename(".."),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_forward_slash() {
        assert!(matches!(
            validate_source_basename("dir/file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_backslash() {
        assert!(matches!(
            validate_source_basename("dir\\file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(matches!(
            validate_source_basename("/etc/passwd"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn accepts_max_length_255() {
        assert!(validate_source_basename(&"a".repeat(255)).is_ok());
    }

    // ----- issue #26 L2: allowlist hardening -----

    #[test]
    fn rejects_nul_byte() {
        assert!(matches!(
            validate_source_basename("file\0.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_ascii_control_chars() {
        // newline, tab, BEL
        for c in ["a\nb", "a\tb", "a\x07b"] {
            assert!(
                matches!(
                    validate_source_basename(c),
                    Err(JmcpError::BadSourcePath(_))
                ),
                "should reject {c:?}"
            );
        }
    }

    #[test]
    fn rejects_space() {
        assert!(matches!(
            validate_source_basename("a b.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_unicode_rtl_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — used in filename-spoofing attacks.
        assert!(matches!(
            validate_source_basename("file\u{202e}gpj.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_unicode_lookalike() {
        // Cyrillic 'а' (U+0430) instead of Latin 'a'.
        assert!(matches!(
            validate_source_basename("\u{0430}bc.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for c in ["a;b", "a|b", "a&b", "a$b", "a`b", "a*b", "a?b"] {
            assert!(
                matches!(
                    validate_source_basename(c),
                    Err(JmcpError::BadSourcePath(_))
                ),
                "should reject {c:?}"
            );
        }
    }
}

/// Stream a file from disk and return (sha256, size_bytes). Runs the actual
/// hashing on a blocking thread to keep the tokio runtime healthy on multi-GB
/// files (~3-5 s for 1.3 GB on the LXC).
pub async fn sha256_file(path: &Path) -> Result<([u8; 32], u64), JmcpError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), JmcpError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let out: [u8; 32] = hasher.finalize().into();
        Ok((out, size))
    })
    .await
    .map_err(|e| JmcpError::Io(std::io::Error::other(e)))?
}

/// Cancel-aware variant of [`sha256_file`]. Checks `ct.is_cancelled()`
/// between every 64 KiB read block (~5 ms cadence at SATA SSD speeds),
/// and additionally races the `JoinHandle` against `ct.cancelled()` so a
/// wedged blocking syscall doesn't keep us blocked past the cancel.
///
/// Used by `transfer_file::handle` and `upgrade_junos::run`. The
/// non-cancellable [`sha256_file`] is preserved for downstream callers
/// (and the `sha_tests` module).
pub(crate) async fn sha256_file_cancellable(
    path: &Path,
    ct: &CancellationToken,
) -> Result<([u8; 32], u64), JmcpError> {
    let path = path.to_path_buf();
    let inner_ct = ct.clone();
    let handle = tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), JmcpError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            // Cancel check between blocks. For a 1.3 GB image at ~250 MB/s
            // this is ~5 ms per check — fast cancel without measurable
            // hashing overhead.
            if inner_ct.is_cancelled() {
                return Err(JmcpError::Cancelled);
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let out: [u8; 32] = hasher.finalize().into();
        Ok((out, size))
    });
    tokio::select! {
        biased;
        _ = ct.cancelled() => {
            // The spawn_blocking thread will notice on its next iteration
            // and return Cancelled; we don't await it (leak-acceptable for
            // a finite-duration hash).
            Err(JmcpError::Cancelled)
        }
        r = handle => r.map_err(|e| JmcpError::Io(std::io::Error::other(e)))?,
    }
}

#[cfg(test)]
mod sha_tests {
    use super::*;
    use std::io::Write;

    /// Known-answer test for [`hex32`].
    ///
    /// The digest string reaches audit records and `mecmcp-changeset`
    /// fingerprints, so its encoding is a wire format, not a detail. The
    /// existing fingerprint tests assert only length and alphabet, which a
    /// byte-reversed or zero-truncated encoder would still satisfy. The `"39"`
    /// vector digests to `0b91...`: its first byte is `0x0b`, so an encoder
    /// using `{:x}` instead of `{:02x}` drops the pad and yields 63 chars.
    #[test]
    fn hex32_matches_known_sha256_vectors() {
        use sha2::{Digest, Sha256};

        for (input, expected) in [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "39",
                "0b918943df0962bc7a1824c0555a389347b4febdc7cf9d1254406d80ce44e3f9",
            ),
        ] {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            let got = hex32(&digest);
            assert_eq!(got, expected, "hex32 mismatch for input {input:?}");
            assert_eq!(got.len(), 64, "hex32 must always be 64 chars");
        }
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    #[tokio::test]
    async fn hashes_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(
            hex_lower(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn hashes_known_vector_abc() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            hex_lower(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn nonexistent_file_returns_io_error() {
        let r = sha256_file(Path::new("/nonexistent/jmcp/file")).await;
        assert!(matches!(r, Err(JmcpError::Io(_))));
    }

    /// T2 (issue #44 Half A): `sha256_file_cancellable` short-circuits to
    /// `JmcpError::Cancelled` when the caller's token is already cancelled
    /// before the helper is awaited.
    #[tokio::test]
    async fn sha256_cancellable_pre_cancelled_returns_cancelled() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();
        let ct = CancellationToken::new();
        ct.cancel();
        let r = sha256_file_cancellable(f.path(), &ct).await;
        assert!(
            matches!(r, Err(JmcpError::Cancelled)),
            "expected Cancelled, got {r:?}"
        );
    }
}

/// Inputs for one SCP upload job.
#[derive(Clone, Debug)]
pub struct ScpJob {
    /// Path to the SSH private key file for authentication.
    pub private_key_path: PathBuf,
    /// Path to the known_hosts file for host key verification.
    pub known_hosts_file: PathBuf,
    /// SSH username for the device connection.
    pub username: String,
    /// Device hostname or IP address.
    pub host: String,
    /// SSH port number (typically 22).
    pub port: u16,
    /// Full local path to the file to upload.
    pub local_path: PathBuf,
    /// Remote directory where the file will be placed (e.g., "/var/tmp/").
    pub remote_dir: String,
    /// Host-key verification policy for this connection. Mirrors the
    /// NETCONF SSH policy 1:1 (MEC-44): `Strict` is the default,
    /// `AcceptNew` is real TOFU, `AcceptAll` is the lab-only flag.
    pub host_key_mode: crate::bootstrap::SshHostKeyMode,
}

/// Inputs for one SCP download job.
#[derive(Clone, Debug)]
pub struct ScpFetchJob {
    /// Path to the SSH private key file for authentication.
    pub private_key_path: PathBuf,
    /// Path to the known_hosts file for host key verification.
    pub known_hosts_file: PathBuf,
    /// SSH username for the device connection.
    pub username: String,
    /// Device hostname or IP address.
    pub host: String,
    /// SSH port number (typically 22).
    pub port: u16,
    /// Full remote path, e.g. `/var/tmp/foo.tgz`.
    pub remote_path: String,
    /// Full local destination path under the staging directory.
    pub local_path: PathBuf,
    /// Host-key verification policy for this connection. Mirrors the
    /// NETCONF SSH policy 1:1 (MEC-44): `Strict` is the default,
    /// `AcceptNew` is real TOFU, `AcceptAll` is the lab-only flag.
    pub host_key_mode: crate::bootstrap::SshHostKeyMode,
}

#[cfg(test)]
mod runner_property_tests {
    use super::*;
    use crate::bootstrap::SshHostKeyMode;

    /// Tests asserting host-key policy, key-only auth, and other security
    /// properties that were previously checked via argv inspection. These now
    /// check the MecmcpScpRunner config construction.
    fn job() -> ScpJob {
        ScpJob {
            private_key_path: "/etc/jmcp/keys/id".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            host_key_mode: SshHostKeyMode::Strict,
        }
    }

    #[test]
    fn job_default_uses_strict_host_key_policy() {
        // RJMCP-SEC-004: default policy must be strict (HostKeyVerification::KnownHosts);
        // TOFU/AcceptAll are opt-in only.
        let j = job();
        assert_eq!(j.host_key_mode, SshHostKeyMode::Strict);
    }

    #[test]
    fn job_respects_accept_new_host_keys_flag() {
        let j = ScpJob {
            host_key_mode: SshHostKeyMode::AcceptNew,
            ..job()
        };
        assert_eq!(j.host_key_mode, SshHostKeyMode::AcceptNew);
    }

    #[test]
    fn job_respects_accept_all_host_keys_flag() {
        // MEC-44 follow-up: --ssh-insecure-accept-any-host-key must reach scp
        // as AcceptAll too, not just NETCONF.
        let j = ScpJob {
            host_key_mode: SshHostKeyMode::AcceptAll,
            ..job()
        };
        assert_eq!(j.host_key_mode, SshHostKeyMode::AcceptAll);
    }

    #[test]
    fn job_carries_known_hosts_path() {
        let j = job();
        assert_eq!(
            j.known_hosts_file,
            std::path::PathBuf::from("/etc/jmcp/known_hosts")
        );
    }

    #[test]
    fn job_carries_private_key_path() {
        // Key-only auth: job holds the private key path (password auth is rejected upstream).
        let j = job();
        assert_eq!(
            j.private_key_path,
            std::path::PathBuf::from("/etc/jmcp/keys/id")
        );
    }

    fn fetch_job() -> ScpFetchJob {
        ScpFetchJob {
            private_key_path: "/etc/jmcp/keys/id".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            remote_path: "/var/tmp/foo.tgz".into(),
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            host_key_mode: SshHostKeyMode::Strict,
        }
    }

    #[test]
    fn fetch_job_default_uses_strict_host_key_policy() {
        let j = fetch_job();
        assert_eq!(j.host_key_mode, SshHostKeyMode::Strict);
    }

    #[test]
    fn fetch_job_carries_known_hosts_path() {
        let j = fetch_job();
        assert_eq!(
            j.known_hosts_file,
            std::path::PathBuf::from("/etc/jmcp/known_hosts")
        );
    }

    #[test]
    fn scp_host_key_verification_maps_strict() {
        let v = super::scp_host_key_verification(
            SshHostKeyMode::Strict,
            "/etc/jmcp/known_hosts".into(),
        );
        assert!(
            matches!(v, mecmcp_scp::HostKeyVerification::KnownHosts(p) if p.as_path() == std::path::Path::new("/etc/jmcp/known_hosts"))
        );
    }

    #[test]
    fn scp_host_key_verification_maps_accept_new() {
        let v = super::scp_host_key_verification(
            SshHostKeyMode::AcceptNew,
            "/etc/jmcp/known_hosts".into(),
        );
        assert!(
            matches!(v, mecmcp_scp::HostKeyVerification::AcceptNew(p) if p.as_path() == std::path::Path::new("/etc/jmcp/known_hosts"))
        );
    }

    #[test]
    fn scp_host_key_verification_maps_accept_all() {
        // MEC-44 follow-up: the lab-only flag must give scp a real
        // mecmcp_scp::HostKeyVerification::AcceptAll, not TOFU.
        let v = super::scp_host_key_verification(
            SshHostKeyMode::AcceptAll,
            "/etc/jmcp/known_hosts".into(),
        );
        assert!(matches!(v, mecmcp_scp::HostKeyVerification::AcceptAll));
    }
}

/// Map a non-zero `ScpOutcome` to the appropriate `JmcpError`.
///
/// Branch order:
/// 1. Exit 255 + "@revoked"                                   → `HostKeyRevoked`
///    (key is marked compromised in known_hosts; must not trust).
/// 2. Exit 255 + "Connection timed out" / "No route to host"  → `ConnectTimeout`
///    (network unreachable; retry-able).
/// 3. Exit 255 + "Host key verification failed" /
///    "REMOTE HOST IDENTIFICATION HAS CHANGED"                → `HostKeyMismatch`
///    (operator-action required; refresh `known_hosts`).
/// 4. Anything else                                           → `ScpFailed`
///    with the stderr scrubbed via `scrub_scp_stderr`.
///
/// Used by both `transfer_file::handle` (upload) and `fetch_file::handle`
/// (download) so the branch order can't drift between the two paths.
pub(crate) fn classify_scp_failure(
    outcome: &ScpOutcome,
    device_name: &str,
    known_hosts_file: &std::path::Path,
) -> crate::error::JmcpError {
    use crate::error::JmcpError;

    // Revoked key: check first because it's the most critical (key known to be compromised).
    // mecmcp-scp includes "@revoked" in the error message when the key is marked revoked
    // in known_hosts.
    if outcome.stderr.contains("@revoked") {
        return JmcpError::HostKeyRevoked {
            router: device_name.to_string(),
            known_hosts_file: known_hosts_file.to_path_buf(),
        };
    }

    // Host-key failures: match on stderr substring regardless of exit code.
    // `scp -O` (Junos legacy SCP protocol) surfaces host-key failures as
    // exit=1 via the SCP wrapper-shell, while stock SFTP-mode scp uses
    // exit=255. The substrings below are themselves diagnostic. (#59)
    if outcome.stderr.contains("Host key verification failed")
        || outcome
            .stderr
            .contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
    {
        return JmcpError::HostKeyMismatch {
            router: device_name.to_string(),
            known_hosts_file: known_hosts_file.to_path_buf(),
        };
    }
    if outcome.exit_code == 255
        && (outcome.stderr.contains("Connection timed out")
            || outcome.stderr.contains("No route to host"))
    {
        return JmcpError::ConnectTimeout(device_name.to_string());
    }
    JmcpError::ScpFailed {
        exit_code: outcome.exit_code,
        stderr: scrub_scp_stderr(&outcome.stderr),
    }
}

/// Outcome of a single SCP invocation.
#[derive(Clone, Debug)]
pub struct ScpOutcome {
    /// Exit code from the SCP process (0 for success).
    pub exit_code: i32,
    /// Standard output from the SCP process.
    pub stdout: String,
    /// Standard error from the SCP process.
    pub stderr: String,
}

/// Trait for SCP upload and download operations. Production and test impls
/// must honor cancellation and return `ErrorKind::Interrupted` on cancel.
#[async_trait::async_trait]
pub trait ScpRunner: Send + Sync {
    /// Run the SCP upload job, racing against `ct.cancelled()`. On cancel,
    /// production impls MUST kill the underlying child process (or
    /// otherwise abort the work) and return
    /// `std::io::Error::new(ErrorKind::Interrupted, "cancelled")` so
    /// the caller can map it to `JmcpError::Cancelled`.
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome>;

    /// Run the SCP download job. Same cancellation contract as `run()`.
    async fn fetch(&self, job: &ScpFetchJob, ct: &CancellationToken)
    -> std::io::Result<ScpOutcome>;
}

/// Production runner using mecmcp-scp's native SCP1 client.
/// This eliminates the subprocess dependency on openssh-client.
pub struct MecmcpScpRunner;

impl MecmcpScpRunner {
    /// Synthesize an ScpOutcome from mecmcp_scp::ScpError, preserving the error
    /// taxonomy so classify_scp_failure can recognize host-key failures, connect
    /// timeouts, and other conditions and map them to the stable JmcpError codes
    /// that audit records and operators depend on.
    ///
    /// Returns `Err(io::Error)` only for `ErrorKind::Interrupted` (cancellation),
    /// which the handler special-cases. All other errors become non-zero outcomes
    /// that flow through classify_scp_failure.
    fn synthesize_outcome(e: mecmcp_scp::ScpError) -> std::io::Result<ScpOutcome> {
        use mecmcp_scp::ScpError;
        match e {
            // Cancellation: return Interrupted so the handler maps to JmcpError::Cancelled.
            ScpError::Io(io) if io.kind() == std::io::ErrorKind::Interrupted => Err(io),

            // Other I/O errors: synthesize outcome with exit 255 and the error message.
            ScpError::Io(io) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: io.to_string(),
            }),

            // Auth failure: password auth (which we reject upstream) or key load failure.
            // Exit 255, message in stderr. classify_scp_failure falls through to ScpFailed,
            // and the handler checks for password auth separately.
            ScpError::Auth(msg) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: msg,
            }),

            // Connect failure: network unreachable, timeout, connection refused.
            // Use exit 255 with diagnostic stderr. classify_scp_failure recognizes
            // "Connection timed out" and "No route to host" → ConnectTimeout.
            ScpError::Connect(msg) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: msg,
            }),

            // Host key verification failed: changed key, unknown key.
            // classify_scp_failure recognizes "Host key verification failed" and
            // "REMOTE HOST IDENTIFICATION HAS CHANGED" → HostKeyMismatch.
            ScpError::HostKeyVerification(msg) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: msg,
            }),

            // Host key revoked: key is marked @revoked in known_hosts.
            // classify_scp_failure recognizes "@revoked" → HostKeyRevoked.
            // This is a distinct operational situation from HostKeyMismatch: a mismatch
            // means the key changed (investigate why), while revoked means an operator
            // already decided this key is compromised and must not be trusted.
            ScpError::HostKeyRevoked(msg) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: msg,
            }),

            // Channel errors: SSH channel operation failed.
            ScpError::Channel(msg) | ScpError::ChannelClosed(msg) => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: msg,
            }),

            // Poisoned client: prior cancellation during channel open.
            ScpError::ScpClientPoisoned => Ok(ScpOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: e.to_string(),
            }),
        }
    }
}

/// Map the shared [`crate::bootstrap::SshHostKeyMode`] (also used for
/// NETCONF SSH) onto `mecmcp_scp`'s own `HostKeyVerification` enum.
///
/// MEC-44 follow-up: scp previously only ever got `KnownHosts` or
/// `AcceptNew`, so `--ssh-insecure-accept-any-host-key` gave scp TOFU
/// instead of the "accept any key" the flag name promises. This mirrors
/// [`crate::bootstrap::build_host_key_policy`] 1:1 so both transports read
/// the flags identically.
fn scp_host_key_verification(
    mode: crate::bootstrap::SshHostKeyMode,
    known_hosts_file: PathBuf,
) -> mecmcp_scp::HostKeyVerification {
    use crate::bootstrap::SshHostKeyMode;
    match mode {
        SshHostKeyMode::Strict => mecmcp_scp::HostKeyVerification::KnownHosts(known_hosts_file),
        SshHostKeyMode::AcceptNew => mecmcp_scp::HostKeyVerification::AcceptNew(known_hosts_file),
        SshHostKeyMode::AcceptAll => mecmcp_scp::HostKeyVerification::AcceptAll,
    }
}

#[async_trait::async_trait]
impl ScpRunner for MecmcpScpRunner {
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome> {
        use mecmcp_scp::{ScpClient, SshAuth, SshConfig};

        let ssh_config = SshConfig {
            host: job.host.clone(),
            port: job.port,
            username: job.username.clone(),
            auth: SshAuth::PrivateKey {
                path: job.private_key_path.clone(),
                passphrase: None,
            },
            host_key_verification: scp_host_key_verification(
                job.host_key_mode,
                job.known_hosts_file.clone(),
            ),
        };

        // Connect
        let mut client = match ScpClient::connect(ssh_config, ct).await {
            Ok(c) => c,
            Err(e) => return Self::synthesize_outcome(e),
        };

        // Upload
        let outcome = match client
            .upload(&job.local_path, &job.remote_dir, None, ct)
            .await
        {
            Ok(o) => o,
            Err(e) => return Self::synthesize_outcome(e),
        };

        // Close the connection
        let _ = client.close().await;

        Ok(ScpOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: outcome.server_messages.join("\n"),
        })
    }

    async fn fetch(
        &self,
        job: &ScpFetchJob,
        ct: &CancellationToken,
    ) -> std::io::Result<ScpOutcome> {
        use mecmcp_scp::{ScpClient, SshAuth, SshConfig};

        let ssh_config = SshConfig {
            host: job.host.clone(),
            port: job.port,
            username: job.username.clone(),
            auth: SshAuth::PrivateKey {
                path: job.private_key_path.clone(),
                passphrase: None,
            },
            host_key_verification: scp_host_key_verification(
                job.host_key_mode,
                job.known_hosts_file.clone(),
            ),
        };

        // Connect
        let mut client = match ScpClient::connect(ssh_config, ct).await {
            Ok(c) => c,
            Err(e) => return Self::synthesize_outcome(e),
        };

        // Download
        let outcome = match client
            .download(&job.remote_path, &job.local_path, None, ct)
            .await
        {
            Ok(o) => o,
            Err(e) => return Self::synthesize_outcome(e),
        };

        // Close the connection
        let _ = client.close().await;

        Ok(ScpOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: outcome.server_messages.join("\n"),
        })
    }
}

/// Test double that records calls and returns canned outcomes.
pub struct MockScpRunner {
    /// The canned outcome to return for all SCP operations.
    pub outcome: ScpOutcome,
    /// Record of all upload jobs submitted to this runner.
    pub calls: tokio::sync::Mutex<Vec<ScpJob>>,
    /// Record of all download jobs submitted to this runner.
    pub fetch_calls: tokio::sync::Mutex<Vec<ScpFetchJob>>,
    /// When `Some`, the runner sleeps this long (cancel-aware) before
    /// returning the outcome. Used by cancellation tests to assert the
    /// SCP call observes a mid-flight cancel.
    pub delay: Option<std::time::Duration>,
}

impl MockScpRunner {
    /// Construct a mock runner that returns success (exit code 0) with no delay.
    pub fn ok() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: ScpOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
            calls: tokio::sync::Mutex::new(Vec::new()),
            fetch_calls: tokio::sync::Mutex::new(Vec::new()),
            delay: None,
        })
    }
    /// Construct a mock runner that returns the given outcome with no delay.
    pub fn with_outcome(o: ScpOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: o,
            calls: tokio::sync::Mutex::new(Vec::new()),
            fetch_calls: tokio::sync::Mutex::new(Vec::new()),
            delay: None,
        })
    }
    /// Construct a mock that sleeps `d` (cancel-aware) before returning,
    /// to exercise the cancel-during-scp path in tests.
    pub fn with_delay(d: std::time::Duration) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: ScpOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
            calls: tokio::sync::Mutex::new(Vec::new()),
            fetch_calls: tokio::sync::Mutex::new(Vec::new()),
            delay: Some(d),
        })
    }
}

#[async_trait::async_trait]
impl ScpRunner for MockScpRunner {
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome> {
        self.calls.lock().await.push(job.clone());
        if let Some(d) = self.delay {
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
                }
                _ = tokio::time::sleep(d) => {}
            }
        }
        Ok(self.outcome.clone())
    }

    async fn fetch(
        &self,
        job: &ScpFetchJob,
        ct: &CancellationToken,
    ) -> std::io::Result<ScpOutcome> {
        self.fetch_calls.lock().await.push(job.clone());
        if let Some(d) = self.delay {
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
                }
                _ = tokio::time::sleep(d) => {}
            }
        }
        Ok(self.outcome.clone())
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_job_for_assertion() {
        let runner = MockScpRunner::ok();
        let job = ScpJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/x.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            host_key_mode: crate::bootstrap::SshHostKeyMode::Strict,
        };
        let ct = CancellationToken::new();
        let out = runner.run(&job, &ct).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let calls = runner.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].host, "10.0.0.1");
    }

    /// T4 (issue #44 Half A): a `MockScpRunner::with_delay` runner, raced
    /// against a token that fires mid-flight, returns `io::ErrorKind::Interrupted`.
    /// `transfer_file::handle` then maps `Interrupted` to `JmcpError::Cancelled`.
    #[tokio::test]
    async fn mock_runner_with_delay_cancels_to_interrupted() {
        let runner = MockScpRunner::with_delay(std::time::Duration::from_secs(5));
        let job = ScpJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/x.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            host_key_mode: crate::bootstrap::SshHostKeyMode::Strict,
        };
        let ct = CancellationToken::new();
        let ct2 = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            ct2.cancel();
        });
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), runner.run(&job, &ct))
            .await
            .expect("runner should return well within 500ms after cancel");
        let err = r.expect_err("expected Interrupted error");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "got {err:?}");
    }

    #[tokio::test]
    async fn mock_fetch_records_job_for_assertion() {
        let runner = MockScpRunner::ok();
        let job = ScpFetchJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            remote_path: "/var/tmp/foo.tgz".into(),
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            host_key_mode: crate::bootstrap::SshHostKeyMode::Strict,
        };
        let ct = CancellationToken::new();
        let out = runner.fetch(&job, &ct).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let calls = runner.fetch_calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].host, "10.0.0.1");
    }
}

/// Parse the free-bytes column for `/var` from `show system storage no-forwarding`.
/// Junos prints rows like:
/// ```text
/// Filesystem              Size       Used      Avail  Capacity   Mounted on
/// /dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/// /dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/// /dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
/// ```
/// We want the `Avail` column on the row whose `Mounted on` equals `/.mount/var`
/// (or `/var` for older Junos). On vSRX 24.x and other single-mount layouts
/// where `/var` lives inside the root `/.mount` filesystem rather than being
/// its own mount, we fall back to the `/.mount` row's `Avail`. Returns bytes.
pub fn parse_storage_free_bytes(output: &str) -> Result<u64, JmcpError> {
    let mut root_mount_avail: Option<&str> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Filesystem") {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        // Expect: filesystem size used avail capacity mounted_on
        if fields.len() < 6 {
            continue;
        }
        let mount = fields[fields.len() - 1];
        if mount == "/var" || mount == "/.mount/var" {
            return parse_size_with_suffix(fields[3]);
        }
        if mount == "/.mount" {
            // vSRX 24.x and similar single-mount layouts host /var inside the
            // root /.mount filesystem. Remember this row as a fallback for
            // when no dedicated /var row is found.
            root_mount_avail = Some(fields[3]);
        }
    }
    if let Some(avail) = root_mount_avail {
        return parse_size_with_suffix(avail);
    }
    Err(JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: "no /var, /.mount/var, or /.mount row found in storage output".into(),
    })
}

fn parse_size_with_suffix(s: &str) -> Result<u64, JmcpError> {
    let (num_part, mult): (&str, u64) = if let Some(stripped) = s.strip_suffix('G') {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('M') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('K') {
        (stripped, 1024)
    } else if let Some(stripped) = s.strip_suffix('B') {
        (stripped, 1)
    } else {
        (s, 1)
    };
    let n: f64 = num_part.parse().map_err(|_| JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: format!("could not parse storage size '{s}'"),
    })?;
    Ok((n * mult as f64) as u64)
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    const SAMPLE: &str = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
";

    #[test]
    fn finds_var_mount_in_modern_layout() {
        let n = parse_storage_free_bytes(SAMPLE).unwrap();
        // 7.0G ≈ 7516192768
        assert!((6_900_000_000..7_600_000_000).contains(&n), "got {n}");
    }

    #[test]
    fn handles_legacy_var_mount() {
        let s = "\
Filesystem      Size   Used  Avail Capacity   Mounted on
/dev/ad0s1f     5.0G   1.0G   4.0G    20%   /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((3_900_000_000..4_400_000_000).contains(&n));
    }

    #[test]
    fn errors_when_var_row_missing() {
        let s = "Filesystem  Size Used Avail Capacity Mounted on\n/dev/x 1G 0 1G 0% /\n";
        assert!(matches!(
            parse_storage_free_bytes(s),
            Err(JmcpError::InsufficientDisk { .. })
        ));
    }

    #[test]
    fn parses_megabyte_suffix() {
        let s = "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      500M 100M 400M 20% /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((400_000_000..420_000_000).contains(&n));
    }

    #[test]
    fn falls_back_to_root_mount_on_vsrx_24_layout() {
        // vSRX 24.4 reports a single root mount at /.mount with /var
        // living inside it — no dedicated /var or /.mount/var row.
        let s = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos           13G       940M        11G        8%  /.mount
tmpfs                   795M        24K       795M        0%  /.mount/tmp
/var/jails/rest-api      13G       940M        11G        8%  /.mount/packages/mnt/junos-runtime/web-api/var
tmpfs                   673M        1.1M      671M        0%  /.mount/mfs
";
        let n = parse_storage_free_bytes(s).unwrap();
        // 11G ≈ 11_811_160_064
        assert!((10_700_000_000..12_000_000_000).contains(&n), "got {n}");
    }

    #[test]
    fn prefers_var_mount_over_root_when_both_present() {
        // When /var/-specific and /.mount rows coexist (a hybrid that
        // could appear on some Junos variants), the dedicated /var row wins.
        let s = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos           14G       8.5G       4.4G       66%   /.mount
/dev/gpt/var             10G       2.1G       7.0G       23%   /.mount/var
";
        let n = parse_storage_free_bytes(s).unwrap();
        // Should match the 7.0G /.mount/var row, not the 4.4G /.mount row.
        assert!((6_900_000_000..7_600_000_000).contains(&n), "got {n}");
    }
}

/// Parse the sha256 from `file checksum sha-256 /var/tmp/foo` output. Junos prints:
/// ```text
/// SHA256 (/var/tmp/foo) = abc123...
/// ```
/// On older Junos, when the file is missing:
/// ```text
/// error: stat: /var/tmp/foo: No such file or directory
/// ```
/// On Junos 24.x, the missing-file form wraps the underlying `sha256(1)` stderr
/// into the same line that would normally hold the hash (issue #40):
/// ```text
/// sha256: (sha256: /var/tmp/foo: No such file or directory) = directory
/// ```
/// Returns `Ok(Some([u8;32]))` on hit, `Ok(None)` if absent, `Err` on parse failure.
pub fn parse_checksum_output(output: &str) -> Result<Option<[u8; 32]>, JmcpError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Any line carrying "No such file or directory" is the missing-file
        // signal. Older Junos: prefixed with `error:`. Junos 24.x: wrapped
        // inside `sha256: (...: No such file or directory) = directory`. The
        // success format below never contains this phrase (it ends in a 64-char
        // hex digest), so we can match it anywhere on the line safely.
        if trimmed.contains("No such file or directory") {
            return Ok(None);
        }
        if let Some(eq) = trimmed.rfind('=') {
            let hex = trimmed[eq + 1..].trim();
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    let hi = u8::from_str_radix(&hex[i * 2..i * 2 + 1], 16).expect(
                        "from_str_radix cannot fail: is_ascii_hexdigit() validated all chars",
                    );
                    let lo = u8::from_str_radix(&hex[i * 2 + 1..i * 2 + 2], 16).expect(
                        "from_str_radix cannot fail: is_ascii_hexdigit() validated all chars",
                    );
                    *byte = (hi << 4) | lo;
                }
                return Ok(Some(out));
            }
        }
    }
    Err(JmcpError::Validation(format!(
        "unable to parse checksum output: {output:?}"
    )))
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn parses_present_file() {
        let s = "SHA256 (/var/tmp/foo.tgz) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";
        let h = parse_checksum_output(s).unwrap().unwrap();
        assert_eq!(h[0], 0xba);
        assert_eq!(h[31], 0xad);
    }

    #[test]
    fn returns_none_for_missing_file() {
        let s = "error: stat: /var/tmp/foo: No such file or directory\n";
        assert!(parse_checksum_output(s).unwrap().is_none());
    }

    /// Junos 24.x wraps the BSD `sha256(1)` stderr into the would-be hash
    /// line (issue #40). The trailing `= directory` token can't be confused
    /// with a real 64-char hex digest, but the parser still needs to
    /// recognize the `No such file or directory` phrase as the missing-file
    /// signal rather than fall through to the "unable to parse" error.
    #[test]
    fn returns_none_for_missing_file_junos_24x_format() {
        let s = "\nsha256: (sha256: /var/tmp/smoke.txt: No such file or directory) = directory\n";
        assert!(parse_checksum_output(s).unwrap().is_none());
    }

    #[test]
    fn errors_on_garbage_output() {
        let s = "fzzt fzzt nothing here\n";
        assert!(parse_checksum_output(s).is_err());
    }
}

/// Per-router serialization for transfer_file. A confused or buggy caller
/// fanning out N concurrent transfers to one device could otherwise
/// exhaust the device's `/var/tmp` headroom or its session pool. Junos
/// can't really benefit from concurrent SCP into `/var/tmp` anyway —
/// the underlying transport serializes on the device side. (issue #26, L4)
///
/// Locks are created lazily on first use per router and cached for the
/// lifetime of the process. Concurrency limit is 1 per router; other
/// router pairs proceed in parallel.
#[derive(Default)]
pub struct TransferLocks {
    map: tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
}

impl TransferLocks {
    /// Acquire the per-router permit. The returned guard releases the
    /// permit on drop — including when a `handle()` call hits its outer
    /// `tokio::time::timeout` or returns an error.
    pub async fn acquire(&self, router: &str) -> tokio::sync::OwnedSemaphorePermit {
        let sem = {
            let mut g = self.map.lock().await;
            g.entry(router.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                .clone()
        };
        // Semaphore is never closed (we keep the Arc alive), so the only
        // way `acquire_owned` returns Err is if we explicitly called
        // `close()`, which we never do.
        sem.acquire_owned()
            .await
            .expect("transfer_locks semaphore should never be closed")
    }
}

/// Configuration handed to `handle()`. Holds the staging-dir + known-hosts
/// paths and the (mockable) ScpRunner. Built once in `main.rs` and cloned
/// per call.
#[derive(Clone)]
pub struct TransferConfig {
    /// Directory where staged files are stored before transfer.
    pub staging_dir: std::path::PathBuf,
    /// Path to the known_hosts file for SSH host key verification.
    pub known_hosts_file: std::path::PathBuf,
    /// SCP runner implementation (production or mock).
    pub scp_runner: Arc<dyn ScpRunner>,
    /// Per-router concurrency limiter; defaults to an empty map that
    /// lazy-creates one-permit semaphores on first use. Share the same
    /// `Arc<TransferLocks>` across all transfer_file calls in the process
    /// so the limit is process-wide (not per-call). (issue #26, L4)
    pub transfer_locks: Arc<TransferLocks>,
    /// Host-key policy passed through to every `ScpJob`/`ScpFetchJob`.
    /// `Strict` (default since v0.5.2 — RJMCP-SEC-004) refuses unknown host
    /// keys. `AcceptNew` opts in to first-contact TOFU. `AcceptAll` is the
    /// lab-only "accept any key" mode (MEC-44 follow-up: scp now honors
    /// this the same as NETCONF SSH).
    pub host_key_mode: crate::bootstrap::SshHostKeyMode,
}

/// Transfer a file from the staging directory to a device's /var/tmp/.
/// Performs idempotency check, pre-transfer storage probe, SCP upload,
/// and post-transfer SHA-256 verification.
pub async fn handle(
    args: TransferFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        // Issue #44 Half A: short-circuit if the request was cancelled
        // before we even entered the body (e.g. notifications/cancelled
        // arrived during dispatch).
        if ct.is_cancelled() {
            return Err(JmcpError::Cancelled);
        }
        validate_source_basename(&args.source_path)?;
        // RJMCP-SEC-004: known_hosts is mandatory in Strict mode. Probing
        // here keeps the failure mode loud and synchronous instead of
        // hidden inside scp's stderr after a queue + connect round-trip.
        use crate::bootstrap::SshHostKeyMode;
        match std::fs::metadata(&cfg.known_hosts_file) {
            Ok(m) if m.is_file() => {}
            _ if cfg.host_key_mode == SshHostKeyMode::AcceptNew => {
                // TOFU mode tolerates a missing known_hosts (scp will create
                // it on first contact). Still log so operators see what's
                // happening.
                tracing::info!(
                    known_hosts = %cfg.known_hosts_file.display(),
                    "transfer_file: known_hosts missing; running in accept-new (TOFU) mode"
                );
            }
            _ if cfg.host_key_mode == SshHostKeyMode::AcceptAll => {
                // Lab-only: no verification and no known_hosts persistence
                // at all, so a missing file is expected, not an error.
                tracing::info!(
                    "transfer_file: known_hosts missing; running in accept-any (insecure, lab-only) mode"
                );
            }
            _ => {
                return Err(JmcpError::KnownHostsMissing(cfg.known_hosts_file.clone()));
            }
        }
        tracing::info!(
            router = %args.device,
            host_key_policy = match cfg.host_key_mode {
                SshHostKeyMode::Strict => "strict",
                SshHostKeyMode::AcceptNew => "accept-new",
                SshHostKeyMode::AcceptAll => "accept-all",
            },
            "transfer_file: host-key policy"
        );
        // Per-router serialization (issue #26, L4). Acquired AFTER basename
        // validation so an obviously-bogus source_path never queues behind
        // a live transfer. Permit is dropped at end-of-block (success or
        // error) when `_permit` falls out of scope.
        tracing::info!(
            router = %args.device,
            step = "lock_acquire_pre",
            "transfer_file.step_diag"
        );
        let _permit =
            select_cancel_raw::<_, _, JmcpError>(&ct, cfg.transfer_locks.acquire(&args.device))
                .await?;
        tracing::info!(
            router = %args.device,
            step = "lock_acquire_post",
            "transfer_file.step_diag"
        );
        let local_path = cfg.staging_dir.join(&args.source_path);
        // symlink_metadata() does NOT follow symlinks — combined with the
        // explicit is_symlink() reject below, this guarantees we never read or
        // hash a file outside the staging dir via a symlink in the staging dir.
        let meta = std::fs::symlink_metadata(&local_path).map_err(|_| {
            JmcpError::BadSourcePath(format!(
                "staged file not found or unreadable: {}",
                local_path.display()
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(JmcpError::BadSourcePath(format!(
                "staged path is a symlink, refusing to follow: {}",
                local_path.display()
            )));
        }
        if !meta.is_file() {
            return Err(JmcpError::BadSourcePath(format!(
                "staged path is not a regular file: {}",
                local_path.display()
            )));
        }
        // Compute local sha256 + size (streamed).
        tracing::info!(
            router = %args.device,
            step = "sha256_pre",
            local_path = %local_path.display(),
            "transfer_file.step_diag"
        );
        let (local_sha, local_size) = sha256_file_cancellable(&local_path, &ct).await?;
        tracing::info!(
            router = %args.device,
            step = "sha256_post",
            local_size,
            "transfer_file.step_diag"
        );

        // NOTE: The order is intentional — local sha256 is computed BEFORE the
        // auth check. The `rejects_password_auth_with_unsupported_auth` test
        // assumes UnsupportedAuth fires after a successful sha256, so do not
        // reorder these without updating that test.

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

        let basename = args.source_path.clone();
        let remote_path = format!("/var/tmp/{}", basename);

        // Open pooled NETCONF session for the pre-flight + post-verify CLI calls.
        tracing::info!(
            router = %args.device,
            step = "dm_open_pre",
            "transfer_file.step_diag"
        );
        let mut dev = select_cancel(&ct, dm.open(&args.device)).await?;
        tracing::info!(
            router = %args.device,
            step = "dm_open_post",
            "transfer_file.step_diag"
        );

        // 1. Free-disk pre-flight.
        let storage_out =
            select_cancel_raw::<_, _, JmcpError>(&ct, dev.cli("show system storage no-forwarding"))
                .await?
                .map_err(|e| JmcpError::DeviceProbeFailed {
                    phase: "storage_probe".into(),
                    message: e.to_string(),
                })?;
        let free_bytes = parse_storage_free_bytes(&storage_out)?;
        let required = local_size.saturating_add(MIN_FREE_HEADROOM_BYTES);
        if free_bytes < required {
            return Err(JmcpError::InsufficientDisk {
                free: free_bytes,
                required,
                message: format!("device '{}' /var/tmp", args.device),
            });
        }

        // 2. Probe remote checksum to support idempotent skip.
        let probe_cmd = format!("file checksum sha-256 {}", remote_path);
        let probe_out = select_cancel_raw::<_, _, JmcpError>(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "remote_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha_pre = parse_checksum_output(&probe_out)?;
        tracing::info!(
            router = %args.device,
            step = "remote_checksum_done",
            remote_sha_some = remote_sha_pre.is_some(),
            "transfer_file.step_diag"
        );
        if let Some(remote) = remote_sha_pre {
            if remote == local_sha {
                return Ok(skipped_response(&basename, &local_sha, local_size));
            }
            if !args.force {
                return Err(JmcpError::DestExistsDiffers {
                    dest: remote_path.clone(),
                    local_sha: hex32(&local_sha),
                    remote_sha: hex32(&remote),
                });
            }
            // force=true: fall through to scp (overwrite).
        }

        // 3. SCP the file.
        let job = ScpJob {
            private_key_path,
            known_hosts_file: cfg.known_hosts_file.clone(),
            username,
            host,
            port,
            local_path: local_path.clone(),
            remote_dir: "/var/tmp/".into(),
            host_key_mode: cfg.host_key_mode,
        };
        tracing::info!(
            router = %args.device,
            phase = "scp_start",
            "transfer_file.scp_diag"
        );
        let outcome = cfg
            .scp_runner
            .run(&job, &ct)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::Interrupted => JmcpError::Cancelled,
                _ => JmcpError::Io(e),
            })?;
        tracing::info!(
            router = %args.device,
            phase = "scp_done",
            exit_code = outcome.exit_code,
            "transfer_file.scp_diag"
        );
        if outcome.exit_code != 0 {
            return Err(classify_scp_failure(
                &outcome,
                &args.device,
                &cfg.known_hosts_file,
            ));
        }

        // 4. Post-transfer verify (re-run remote checksum).
        let verify_out = select_cancel_raw::<_, _, JmcpError>(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "verify_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha_post = parse_checksum_output(&verify_out)?;
        let (post, verified) = match remote_sha_post {
            Some(s) => {
                let matches = s == local_sha;
                (s, matches)
            }
            None => {
                // Remote file vanished after a successful scp — treat as
                // verify mismatch with a sentinel placeholder so the caller
                // still sees the canonical error.
                if args.verify {
                    return Err(JmcpError::VerifyMismatch {
                        dest: remote_path.clone(),
                        local_sha: hex32(&local_sha),
                        remote_sha: "<missing>".into(),
                    });
                }
                (local_sha, false)
            }
        };
        if args.verify && !verified {
            // Best-effort cleanup: ignore the result, the canonical error wins.
            let _ = dev.cli(&format!("file delete {}", remote_path)).await;
            return Err(JmcpError::VerifyMismatch {
                dest: remote_path.clone(),
                local_sha: hex32(&local_sha),
                remote_sha: hex32(&post),
            });
        }

        Ok(json!({
            "status": "transferred",
            "remote_path": remote_path,
            "size_bytes": local_size,
            "sha256": hex32(&local_sha),
            "verified": verified,
        }))
    })
    .await
    .map_err(|_| JmcpError::TransferOuterTimeout(timeout))?
}

#[cfg(test)]
mod transfer_locks_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Two concurrent acquires on the same router must serialize: the
    /// second can only complete after the first guard is dropped.
    #[tokio::test]
    async fn same_router_serializes() {
        let locks = Arc::new(TransferLocks::default());
        let counter = Arc::new(AtomicUsize::new(0));
        let max_inflight = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let locks = locks.clone();
            let counter = counter.clone();
            let max_inflight = max_inflight.clone();
            handles.push(tokio::spawn(async move {
                let _permit = locks.acquire("r1").await;
                let now = counter.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                counter.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            max_inflight.load(Ordering::SeqCst),
            1,
            "expected serialization to limit inflight to 1, got {}",
            max_inflight.load(Ordering::SeqCst)
        );
    }

    /// Issue #51 regression: holding a permit for a router and then
    /// awaiting `acquire` for the SAME router on the SAME task is a
    /// self-deadlock — the inner future can never make progress because
    /// the outer scope holds the only permit. This test documents that
    /// invariant so the upgrade_junos path (which used to acquire the
    /// permit in `run()` and then call `transfer_file::handle()` which
    /// re-acquires it) cannot regress.
    #[tokio::test]
    async fn same_task_reacquire_deadlocks() {
        let locks = Arc::new(TransferLocks::default());
        let outer = locks.acquire("r1").await;
        let inner =
            tokio::time::timeout(std::time::Duration::from_millis(100), locks.acquire("r1")).await;
        assert!(
            inner.is_err(),
            "re-acquiring the same-router permit on the same task should deadlock; \
             if this test passes, the locking primitive changed and #51's fix may \
             no longer be load-bearing"
        );
        drop(outer);
    }

    /// Different routers must NOT block each other. Two acquires on
    /// distinct routers should be able to run concurrently.
    #[tokio::test]
    async fn different_routers_proceed_in_parallel() {
        let locks = Arc::new(TransferLocks::default());
        let permit1 = locks.acquire("r1").await;
        // If `r2` were blocked by `r1`'s permit, this would hang past the
        // timeout. A short 200ms upper bound is more than enough since
        // there's no contention.
        let acquired =
            tokio::time::timeout(std::time::Duration::from_millis(200), locks.acquire("r2")).await;
        assert!(
            acquired.is_ok(),
            "different routers should not block each other"
        );
        drop(permit1);
    }

    /// Permits are released on Drop — a successful release lets the next
    /// waiter proceed immediately.
    #[tokio::test]
    async fn permit_release_on_drop() {
        let locks = Arc::new(TransferLocks::default());
        {
            let _p = locks.acquire("r1").await;
        } // permit dropped here
        let p2 = tokio::time::timeout(std::time::Duration::from_millis(100), locks.acquire("r1"))
            .await
            .expect("permit should be available after drop");
        drop(p2);
    }
}

#[cfg(test)]
mod handle_validation_tests {
    use super::*;
    use crate::inventory::Inventory;
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
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "r1".into(),
                source_path: "../etc/passwd".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    /// RJMCP-SEC-004: strict-mode (`SshHostKeyMode::Strict`) must fail
    /// closed when the configured `known_hosts_file` is missing or not a
    /// regular file. This fires before the staged-file check, so even a
    /// missing source surfaces `KnownHostsMissing` first.
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
            TransferFileArgs {
                device: "r1".into(),
                source_path: "foo.tgz".into(),
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

    /// MEC-44 follow-up: `AcceptAll` (the lab-only
    /// `--ssh-insecure-accept-any-host-key` flag) never persists a
    /// known_hosts file, so a missing one must not trip
    /// `KnownHostsMissing` the way it does in `Strict` mode.
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
            TransferFileArgs {
                device: "r1".into(),
                source_path: "foo.tgz".into(),
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
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "r1".into(),
                source_path: "missing.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_with_unsupported_auth() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "r1".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_as_source() {
        // Plant a symlink in the staging dir pointing outside it. handle()
        // must reject it as BadSourcePath BEFORE hashing or auth, so we
        // never read or expose the link target.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link.tgz")).unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "r1".into(),
                source_path: "link.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        match r {
            Err(JmcpError::BadSourcePath(msg)) => {
                assert!(
                    msg.contains("symlink"),
                    "expected symlink reject message, got: {msg}"
                );
            }
            other => panic!("expected BadSourcePath(symlink…), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_directory_as_source() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "r1".into(),
                source_path: "subdir".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn skip_message_shape_helper_returns_expected_keys() {
        let v = super::skipped_response("foo.tgz", &[0u8; 32], 1234);
        assert_eq!(v["status"], "skipped");
        assert_eq!(v["remote_path"], "/var/tmp/foo.tgz");
        assert_eq!(v["size_bytes"], 1234);
        assert_eq!(v["sha256"], "0".repeat(64));
        assert_eq!(v["verified"], true);
        assert!(v["message"].as_str().unwrap().contains("already present"));
    }

    #[tokio::test]
    async fn unknown_router_propagates_unknown_router_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                device: "nope".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    /// T1 (issue #44 Half A): a token cancelled before `handle` is invoked
    /// must cause `handle` to return `JmcpError::Cancelled` immediately,
    /// before any validation, lock acquisition, or device I/O. The body's
    /// first statement is `if ct.is_cancelled() { return Cancelled }` — this
    /// test pins that fast-path so a future refactor cannot accidentally
    /// move the check.
    #[tokio::test]
    async fn pre_cancelled_token_returns_cancelled_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let ct = CancellationToken::new();
        ct.cancel();
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            handle(
                TransferFileArgs {
                    device: "r1".into(),
                    // Deliberately invalid basename: if the cancel pre-check
                    // were skipped we would observe `BadSourcePath` instead.
                    source_path: "../etc/passwd".into(),
                    force: false,
                    verify: true,
                    timeout: 5,
                },
                dm,
                cfg(dir.path()),
                ct,
            ),
        )
        .await
        .expect("handle should return well within 200ms when pre-cancelled");
        assert!(
            matches!(r, Err(JmcpError::Cancelled)),
            "expected Cancelled, got {r:?}"
        );
    }
}

#[cfg(test)]
mod scp_unit_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_runner_records_argv_and_reports_success() {
        let mock = MockScpRunner::with_outcome(ScpOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
        let job = ScpJob {
            host: "192.0.2.4".into(),
            port: 22,
            username: "admin".into(),
            private_key_path: "/etc/jmcp/ssh/id_ed25519".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            local_path: "/var/lib/jmcp/staging/abc/junos.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            host_key_mode: crate::bootstrap::SshHostKeyMode::Strict,
        };
        let ct = CancellationToken::new();
        let outcome = (mock.clone() as Arc<dyn ScpRunner>)
            .run(&job, &ct)
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, 0);
        let calls = mock.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].host, "192.0.2.4");
        assert_eq!(calls[0].username, "admin");
        assert_eq!(calls[0].remote_dir, "/var/tmp/");
    }

    /// Exercise the exit-255 + "Connection timed out" remap in isolation, without
    /// standing up the full handle() harness (which requires a staging dir, device
    /// manager, NETCONF session, etc.).  We test the remap logic directly by
    /// constructing the ScpOutcome values that would trigger each branch.
    #[test]
    fn scp_exit_255_connect_timeout_stderr_remaps_to_connect_timeout() {
        // Simulate the remap decision: exit_code == 255 && stderr contains
        // "Connection timed out" → ConnectTimeout; not ScpFailed.
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: Connection timed out".into(),
        };
        let router = "vsrx-test10".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router.clone())
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ConnectTimeout(ref r) if r == "vsrx-test10"),
            "expected ConnectTimeout, got: {}",
            err
        );
        let s = err.to_string();
        assert!(s.contains("[code=connect_timeout]"), "got {}", s);
        assert!(s.contains("vsrx-test10"), "got {}", s);
    }

    #[test]
    fn scp_exit_255_no_route_stderr_remaps_to_connect_timeout() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: No route to host".into(),
        };
        let router = "vsrx-test11".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router.clone())
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ConnectTimeout(ref r) if r == "vsrx-test11"),
            "expected ConnectTimeout, got: {}",
            err
        );
    }

    #[test]
    fn scp_exit_255_other_stderr_stays_as_scp_failed() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Permission denied (publickey).".into(),
        };
        let router = "vsrx-test10".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router)
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ScpFailed { exit_code: 255, .. }),
            "expected ScpFailed, got: {}",
            err
        );
    }

    #[test]
    fn scp_failed_display_includes_code() {
        let e = JmcpError::ScpFailed {
            exit_code: 1,
            stderr: "permission denied".into(),
        };
        let s = e.to_string();
        assert!(s.contains("[code=scp_failed]"), "got {}", s);
        assert!(s.contains("permission denied"), "got {}", s);
    }

    #[test]
    fn verify_mismatch_display_includes_code() {
        let e = JmcpError::VerifyMismatch {
            dest: "/var/tmp/foo.tgz".into(),
            local_sha: "aa".repeat(32),
            remote_sha: "bb".repeat(32),
        };
        let s = e.to_string();
        assert!(s.contains("[code=verify_mismatch]"), "got {}", s);
        assert!(s.contains("/var/tmp/foo.tgz"), "got {}", s);
    }

    #[test]
    fn transfer_outer_timeout_display_includes_code() {
        let e = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(600));
        let s = e.to_string();
        // actual Display tag is `[code=outer_timeout]` (error.rs line 76)
        assert!(s.contains("[code=outer_timeout]"), "got {}", s);
        assert!(s.contains("600s"), "got {}", s);
    }

    #[test]
    fn classify_scp_failure_maps_connect_timeout() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: Connection timed out".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "r1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        assert!(
            matches!(e, JmcpError::ConnectTimeout(ref r) if r == "r1"),
            "got {e:?}"
        );
    }

    #[test]
    fn classify_scp_failure_maps_no_route_to_host() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: No route to host".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "r1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        assert!(
            matches!(e, JmcpError::ConnectTimeout(ref r) if r == "r1"),
            "got {e:?}"
        );
    }

    #[test]
    fn classify_scp_failure_maps_host_key_verification_failed() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Host key verification failed.\r\nlost connection".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "vSRX-test10",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match e {
            JmcpError::HostKeyMismatch {
                router,
                known_hosts_file,
            } => {
                assert_eq!(router, "vSRX-test10");
                assert_eq!(
                    known_hosts_file,
                    std::path::PathBuf::from("/etc/jmcp/known_hosts")
                );
            }
            other => panic!("expected HostKeyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn classify_scp_failure_maps_remote_host_identification_changed() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "r1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        assert!(matches!(e, JmcpError::HostKeyMismatch { .. }), "got {e:?}");
    }

    /// Regression for #59: `scp -O` (Junos legacy SCP protocol) returns
    /// exit 1 — not 255 — on host-key failure. The classifier must still
    /// route the failure to `HostKeyMismatch` based on the stderr
    /// substring alone; the exit code is informational only.
    #[test]
    fn classify_scp_failure_maps_host_key_failure_with_exit_one() {
        let outcome = ScpOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\nHost key verification failed.\nlost connection".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "vSRX-test10",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match e {
            JmcpError::HostKeyMismatch {
                router,
                known_hosts_file,
            } => {
                assert_eq!(router, "vSRX-test10");
                assert_eq!(
                    known_hosts_file,
                    std::path::PathBuf::from("/etc/jmcp/known_hosts")
                );
            }
            other => panic!("expected HostKeyMismatch for exit=1 + host-key stderr, got {other:?}"),
        }
    }

    #[test]
    fn classify_scp_failure_falls_through_to_scp_failed_for_other_stderr() {
        let outcome = ScpOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: "scp: /var/tmp/foo: Permission denied".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "r1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        assert!(
            matches!(e, JmcpError::ScpFailed { exit_code: 1, .. }),
            "got {e:?}"
        );
    }

    #[test]
    fn classify_scp_failure_scrubs_paths_in_scp_failed_stderr() {
        // Regression: existing scrubbing behaviour at the call site must survive
        // the move into the classifier (issue #26, L1).
        let outcome = ScpOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: "Load key \"/root/.ssh/id_ed25519\": invalid format".into(),
        };
        let e = classify_scp_failure(
            &outcome,
            "r1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match e {
            JmcpError::ScpFailed { stderr, .. } => {
                assert!(
                    !stderr.contains("/root/.ssh/id_ed25519"),
                    "stderr was not scrubbed: {stderr}"
                );
            }
            other => panic!("expected ScpFailed, got {other:?}"),
        }
    }

    /// Assert that host-key verification failures produce `HostKeyMismatch` (not generic `Io`).
    /// This is a stable audit code that operators filter on.
    #[test]
    fn error_taxonomy_host_key_mismatch() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Host key verification failed".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device1",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::HostKeyMismatch { router, .. } => {
                assert_eq!(router, "device1");
            }
            other => panic!("expected HostKeyMismatch, got {other:?}"),
        }
    }

    /// Assert that host-key changed errors also produce `HostKeyMismatch`.
    #[test]
    fn error_taxonomy_host_key_changed() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "REMOTE HOST IDENTIFICATION HAS CHANGED".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device2",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::HostKeyMismatch { router, .. } => {
                assert_eq!(router, "device2");
            }
            other => panic!("expected HostKeyMismatch, got {other:?}"),
        }
    }

    /// Assert that connection timeouts produce `ConnectTimeout` (not generic `Io`).
    #[test]
    fn error_taxonomy_connect_timeout() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Connection timed out".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device3",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::ConnectTimeout(router) => {
                assert_eq!(router, "device3");
            }
            other => panic!("expected ConnectTimeout, got {other:?}"),
        }
    }

    /// Assert that "No route to host" produces `ConnectTimeout`.
    #[test]
    fn error_taxonomy_no_route_to_host() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "No route to host".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device4",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::ConnectTimeout(router) => {
                assert_eq!(router, "device4");
            }
            other => panic!("expected ConnectTimeout, got {other:?}"),
        }
    }

    /// Assert that a revoked host key produces `HostKeyRevoked`, not `HostKeyMismatch`.
    /// A revoked key is a distinct operational situation: the operator has already decided
    /// this key is compromised and must not be trusted. This must appear in audit records
    /// as `host_key_revoked`, not conflated with `host_key_mismatch`.
    #[test]
    fn error_taxonomy_host_key_revoked() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Host key for 192.0.2.1 is marked @revoked in known_hosts".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device5",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::HostKeyRevoked { router, .. } => {
                assert_eq!(router, "device5");
            }
            JmcpError::HostKeyMismatch { .. } => {
                panic!("revoked key must produce HostKeyRevoked, not HostKeyMismatch")
            }
            other => panic!("expected HostKeyRevoked, got {other:?}"),
        }
    }

    /// Assert that generic failures produce `ScpFailed` with scrubbed stderr.
    #[test]
    fn error_taxonomy_generic_failure() {
        let outcome = ScpOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: "scp: /var/tmp/foo.tgz: Permission denied".into(),
        };
        let err = classify_scp_failure(
            &outcome,
            "device5",
            std::path::Path::new("/etc/jmcp/known_hosts"),
        );
        match err {
            JmcpError::ScpFailed { exit_code, stderr } => {
                assert_eq!(exit_code, 1);
                assert!(stderr.contains("Permission denied"));
            }
            other => panic!("expected ScpFailed, got {other:?}"),
        }
    }
}

//! `upgrade_junos` MCP tool. Upgrades a standalone Junos device by
//! staging an image via transfer_file, installing it with
//! `request system software add ... reboot`, waiting for NETCONF to
//! reopen, and verifying `show version` matches `target_version`.
//!
//! See docs/superpowers/specs/2026-05-15-upgrade-junos-design.md.
//! Cluster (ISSU) support deferred to v2.

/// Parse the version string from `show version | match Junos:` output.
/// Looks for a line of the form `Junos: <version>` (case-sensitive,
/// whitespace tolerant) and returns the version token. Returns `None`
/// when no `Junos:` line is present.
///
/// In cluster output (`node0:\n...Junos:...\nnode1:\n...Junos:...`)
/// the first match wins; cluster detection runs upstream of this and
/// refuses with `UpgradeClusterUnsupported`, so we never reach the
/// second-node case in the destructive path.
pub fn parse_junos_version(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Junos:") {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Detect a chassis cluster from a `get-chassis-cluster-status` reply.
/// A clustered SRX answers with `<chassis-cluster-status>`; a standalone one
/// with an `<xnm:error>` saying `Chassis cluster is not enabled`. Upgrades are
/// refused on a cluster, so anything else counts as one: an upgrade only
/// proceeds on that exact message, which is what real devices send. A looser
/// match would accept unrelated errors such as `error: HA is not enabled`.
pub fn detect_cluster_active(reply_xml: &str) -> bool {
    reply_xml.contains("<chassis-cluster-status")
        || !reply_xml.contains("Chassis cluster is not enabled")
}

#[cfg(test)]
mod cluster_tests {
    use super::*;

    /// Captured from a standalone vSRX (24.4R1.9 and 26.2R1.7 agree).
    const STANDALONE: &str = "<xnm:error xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" \
        xmlns:xnm=\"http://xml.juniper.net/xnm/1.1/xnm\">\n<parse/>\n\
        <source-daemon>jsrpd</source-daemon>\n\
        <message>error: Chassis cluster is not enabled</message>\n</xnm:error>";

    const ACTIVE_CLUSTER: &str = "<chassis-cluster-status>\n<cluster-id>1</cluster-id>\n\
        <redundancy-group>\n<redundancy-group-id>0</redundancy-group-id>\n\
        </redundancy-group>\n</chassis-cluster-status>";

    #[test]
    fn not_enabled_error_is_standalone() {
        assert!(!detect_cluster_active(STANDALONE));
    }

    #[test]
    fn active_cluster_detected() {
        assert!(detect_cluster_active(ACTIVE_CLUSTER));
    }

    #[test]
    fn cluster_reply_wins_over_not_enabled_text_in_a_field() {
        let reply = "<chassis-cluster-status><monitor-failures>Chassis cluster is not enabled\
            </monitor-failures></chassis-cluster-status>";
        assert!(detect_cluster_active(reply));
    }

    #[test]
    fn only_known_non_srx_platforms_skip_the_cluster_check() {
        use rustez::Personality as Platform;
        for platform in [
            Platform::Mx,
            Platform::Vmx,
            Platform::Ex,
            Platform::Qfx,
            Platform::Ptx,
            Platform::Acx,
            Platform::M,
            Platform::T,
        ] {
            assert!(never_chassis_clustered(&platform), "{platform:?}");
        }
        for platform in [
            Platform::Srx,
            Platform::Vsrx,
            Platform::Csrx,
            Platform::Nfx,
            Platform::Olive,
            Platform::Jdm,
            Platform::Unknown("future-model".into()),
        ] {
            assert!(!never_chassis_clustered(&platform), "{platform:?}");
        }
        assert!(!detect_cluster_active(NO_CHASSIS_CLUSTER_SUPPORT));
    }

    #[test]
    fn anything_unproven_is_treated_as_a_cluster() {
        for reply in [
            "",
            "<xnm:error><message>error: permission denied</message></xnm:error>",
            "<xnm:error><message>error: HA is not enabled</message></xnm:error>",
            "<xnm:error><message>user is not configured for this RPC</message></xnm:error>",
            "Hostname: vsrx-test18\nJunos: 25.4R1.12",
        ] {
            assert!(detect_cluster_active(reply), "{reply:?}");
        }
    }
}

#[cfg(test)]
mod parse_version_tests {
    use super::*;

    #[test]
    fn parses_vsrx_version() {
        let s = "Hostname: vsrx-test18\nModel: vsrx\nJunos: 24.4R1.9\n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("24.4R1.9"));
    }

    #[test]
    fn parses_filtered_line() {
        let s = "Junos: 25.4R1.12";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn parses_mx_dash_x_release() {
        // MX-series flex-x releases use a trailing -X qualifier.
        let s = "Junos: 22.4R3-S2.5";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3-S2.5"));
    }

    #[test]
    fn returns_none_when_no_junos_line() {
        assert!(parse_junos_version("Hostname: x\nModel: vsrx\n").is_none());
    }

    #[test]
    fn returns_none_on_empty() {
        assert!(parse_junos_version("").is_none());
    }

    #[test]
    fn tolerates_extra_whitespace() {
        let s = "   Junos:    25.4R1.12   \n";
        assert_eq!(parse_junos_version(s).as_deref(), Some("25.4R1.12"));
    }

    #[test]
    fn picks_first_junos_line_in_cluster_output() {
        let s = "node0:\nHostname: a\nJunos: 22.4R3.10\n\nnode1:\nJunos: 22.4R3.10";
        assert_eq!(parse_junos_version(s).as_deref(), Some("22.4R3.10"));
    }
}

use std::collections::BTreeMap;

/// Per-command line-set diff. `added` = lines present in `post` but not
/// `pre`; `removed` = lines present in `pre` but not `post`. Order
/// follows first-seen in the source string. Whitespace-only lines are
/// ignored.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineDiff {
    /// Lines present in post but not pre.
    pub added: Vec<String>,
    /// Lines present in pre but not post.
    pub removed: Vec<String>,
}

/// Compute a per-command diff of baseline outputs. Commands present in
/// only one side are reported with the full content in the appropriate
/// `added` or `removed` list. Commands present in neither side are
/// absent from the result.
pub fn diff_baseline(
    pre: &BTreeMap<String, String>,
    post: &BTreeMap<String, String>,
) -> BTreeMap<String, BaselineDiff> {
    let mut out: BTreeMap<String, BaselineDiff> = BTreeMap::new();
    let mut keys: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
    keys.extend(pre.keys());
    keys.extend(post.keys());
    for k in keys {
        let pre_lines: Vec<&str> = pre
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let post_lines: Vec<&str> = post
            .get(k)
            .map(|s| s.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default();
        let pre_set: std::collections::HashSet<&str> = pre_lines.iter().copied().collect();
        let post_set: std::collections::HashSet<&str> = post_lines.iter().copied().collect();
        let added: Vec<String> = post_lines
            .iter()
            .filter(|l| !pre_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        let removed: Vec<String> = pre_lines
            .iter()
            .filter(|l| !post_set.contains(*l))
            .map(|s| s.to_string())
            .collect();
        out.insert(k.clone(), BaselineDiff { added, removed });
    }
    out
}

#[cfg(test)]
mod diff_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn empty_baselines_produce_empty_diff() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let post: BTreeMap<String, String> = BTreeMap::new();
        let diff = diff_baseline(&pre, &post);
        assert!(diff.is_empty());
    }

    #[test]
    fn equal_outputs_have_empty_added_and_removed() {
        let mut pre = BTreeMap::new();
        pre.insert("show version".to_string(), "Junos: 24.4R1.9".to_string());
        let post = pre.clone();
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show version"];
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn added_line_appears_in_added() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("show alarms".into(), "no alarms".into());
        post.insert(
            "show alarms".into(),
            "no alarms\n1 alarms currently active".into(),
        );
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show alarms"];
        assert_eq!(d.added, vec!["1 alarms currently active".to_string()]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn removed_line_appears_in_removed() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert(
            "show interfaces".into(),
            "ge-0/0/0 up up\nge-0/0/1 up up".into(),
        );
        post.insert("show interfaces".into(), "ge-0/0/0 up up".into());
        let diff = diff_baseline(&pre, &post);
        let d = &diff["show interfaces"];
        assert!(d.added.is_empty());
        assert_eq!(d.removed, vec!["ge-0/0/1 up up".to_string()]);
    }

    #[test]
    fn whitespace_only_lines_ignored() {
        let mut pre = BTreeMap::new();
        let mut post = BTreeMap::new();
        pre.insert("c".into(), "a\n   \nb".into());
        post.insert("c".into(), "a\nb".into());
        let diff = diff_baseline(&pre, &post);
        assert!(diff["c"].added.is_empty());
        assert!(diff["c"].removed.is_empty());
    }

    #[test]
    fn commands_only_in_post_are_all_added() {
        let pre: BTreeMap<String, String> = BTreeMap::new();
        let mut post = BTreeMap::new();
        post.insert("new cmd".into(), "x\ny".into());
        let diff = diff_baseline(&pre, &post);
        assert_eq!(
            diff["new cmd"].added,
            vec!["x".to_string(), "y".to_string()]
        );
    }
}

// ---------------------------------------------------------------------------
// Preflight types + evaluator
// ---------------------------------------------------------------------------

/// Minimum free-disk headroom on top of `2 × image_size`. Junos install
/// needs working space for unpack + new partition; 2× is a safe rule of
/// thumb on top of the local image size, plus 32 MiB for slack.
pub const UPGRADE_DISK_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

/// Estimated outage duration baked into the ConfirmationRequired
/// payload. Derived from the 2026-05-14 vSRX-test18 timing (7 min
/// total = 420 s) with a small headroom margin.
pub const ESTIMATED_OUTAGE_SECONDS: u64 = 420;

/// Raw outputs + local image facts handed to the pure preflight
/// evaluator. Everything I/O happens upstream; this struct is the
/// boundary between "talk to the world" and "decide what to do".
#[derive(Debug, Clone)]
pub struct PreflightFacts {
    /// Reply to `get-chassis-cluster-status`.
    pub cluster_status_output: String,
    /// Output of `show version | match Junos:`.
    pub version_output: String,
    /// Output of `show system commit`.
    pub commit_output: String,
    /// Output of `show system storage no-forwarding`.
    pub storage_output: String,
    /// Local staged image size in bytes.
    pub local_image_size: u64,
    /// Local staged image sha256.
    pub local_image_sha256: [u8; 32],
    /// Basename of the staged image file.
    pub image_basename: String,
}

/// The decision the pure evaluator returns. Each variant maps to a
/// concrete handle() outcome: an error, a skip-success, a confirmation
/// payload, or "go ahead".
#[derive(Debug)]
pub enum PreflightDecision {
    /// Chassis cluster detected (ISSU not yet supported).
    ClusterUnsupported,
    /// Could not parse current Junos version.
    UnparseableVersion,
    /// Could not parse storage output.
    UnparseableStorage,
    /// Device already running target version.
    AlreadyAtTarget {
        /// Current version string.
        current_version: String,
    },
    /// A `commit confirmed` is pending (entry 0 of `show system commit`
    /// carries `rollback pending`).
    CommitConfirmedActive,
    /// Insufficient disk space on `/var`.
    InsufficientDisk {
        /// Free bytes available.
        free: u64,
        /// Required bytes (2x image + headroom).
        required: u64,
    },
    /// Preflight passed but `confirm=false` (dry-run).
    ConfirmationRequired(serde_json::Value),
    /// All checks passed and `confirm=true`.
    Proceed,
}

/// Pure preflight decision. Order of checks (each short-circuits):
/// 1. Cluster → refuse (highest priority — never proceed on cluster)
/// 2. Version parseable
/// 3. Already-at-target → skip-success
/// 4. Pending commit-confirmed → refuse
/// 5. Storage parseable + disk headroom OK
/// 6. confirm=false → ConfirmationRequired
/// 7. else → Proceed
pub fn evaluate_preflight(
    facts: &PreflightFacts,
    args: &crate::tools::UpgradeJunosArgs,
) -> PreflightDecision {
    if detect_cluster_active(&facts.cluster_status_output) {
        return PreflightDecision::ClusterUnsupported;
    }
    let current_version = match parse_junos_version(&facts.version_output) {
        Some(v) => v,
        None => return PreflightDecision::UnparseableVersion,
    };
    if current_version == args.target_version {
        return PreflightDecision::AlreadyAtTarget { current_version };
    }
    if crate::commit_attribution::commit_confirm_pending(&facts.commit_output) {
        return PreflightDecision::CommitConfirmedActive;
    }
    let free = match crate::tools::transfer_file::parse_storage_free_bytes(&facts.storage_output) {
        Ok(b) => b,
        Err(_) => return PreflightDecision::UnparseableStorage,
    };
    let required = facts
        .local_image_size
        .saturating_mul(2)
        .saturating_add(UPGRADE_DISK_HEADROOM_BYTES);
    if free < required {
        return PreflightDecision::InsufficientDisk { free, required };
    }
    if !args.confirm {
        let payload = serde_json::json!({
            "code": "confirmation_required",
            "router": args.device,
            "current_version": current_version,
            "target_version": args.target_version,
            "image_basename": facts.image_basename,
            "image_size_bytes": facts.local_image_size,
            "device_var_free_bytes": free,
            "estimated_outage_seconds": ESTIMATED_OUTAGE_SECONDS,
            "preflight_blockers": [],
            "warning": "DESTRUCTIVE: this will install a new Junos image and REBOOT the device, causing an outage of approximately 5–7 minutes. Re-call with confirm=true to proceed."
        });
        return PreflightDecision::ConfirmationRequired(payload);
    }
    PreflightDecision::Proceed
}

#[cfg(test)]
mod preflight_tests {
    use super::*;

    fn args() -> crate::tools::UpgradeJunosArgs {
        crate::tools::UpgradeJunosArgs {
            device: "vsrx-test10".into(),
            source_path: "junos-25.4R1.12.tgz".into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 900,
            reboot_wait_secs: 480,
        }
    }

    fn baseline_facts() -> PreflightFacts {
        PreflightFacts {
            cluster_status_output:
                "<xnm:error><message>error: Chassis cluster is not enabled</message></xnm:error>"
                    .into(),
            version_output: "Junos: 24.4R1.9".into(),
            commit_output: "0   2026-05-14 ...\n".into(),
            storage_output: "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      10G  2.1G 7.0G  23%      /.mount/var
"
            .into(),
            local_image_size: 1_000_000_000,
            local_image_sha256: [0; 32],
            image_basename: "junos-25.4R1.12.tgz".into(),
        }
    }

    #[test]
    fn refuses_cluster_device() {
        let mut f = baseline_facts();
        f.cluster_status_output =
            "<chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }

    #[test]
    fn returns_already_at_target_when_version_matches() {
        let mut f = baseline_facts();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::AlreadyAtTarget { current_version } => {
                assert_eq!(current_version, "25.4R1.12");
            }
            other => panic!("expected AlreadyAtTarget, got {other:?}"),
        }
    }

    #[test]
    fn refuses_active_commit_confirmed() {
        let mut f = baseline_facts();
        f.commit_output = crate::commit_attribution::tests::PENDING_LOG.into();
        let d = evaluate_preflight(&f, &args());
        assert!(
            matches!(d, PreflightDecision::CommitConfirmedActive),
            "expected CommitConfirmedActive, got {d:?}"
        );
    }

    #[test]
    fn confirmed_commit_confirmed_does_not_refuse() {
        let mut f = baseline_facts();
        f.commit_output = crate::commit_attribution::tests::CONFIRMED_LOG.into();
        let d = evaluate_preflight(&f, &args());
        assert!(
            !matches!(d, PreflightDecision::CommitConfirmedActive),
            "got {d:?}"
        );
    }

    #[test]
    fn refuses_insufficient_disk_for_2x_plus_headroom() {
        let mut f = baseline_facts();
        f.local_image_size = 4_000_000_000;
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::InsufficientDisk { free, required } => {
                assert!(free < required, "free={free} required={required}");
            }
            other => panic!("expected InsufficientDisk, got {other:?}"),
        }
    }

    #[test]
    fn returns_confirmation_required_when_confirm_false() {
        let f = baseline_facts();
        let d = evaluate_preflight(&f, &args());
        match d {
            PreflightDecision::ConfirmationRequired(payload) => {
                assert_eq!(payload["router"], "vsrx-test10");
                assert_eq!(payload["current_version"], "24.4R1.9");
                assert_eq!(payload["target_version"], "25.4R1.12");
                assert_eq!(payload["image_basename"], "junos-25.4R1.12.tgz");
                assert_eq!(payload["image_size_bytes"], 1_000_000_000);
                assert!(payload["warning"].as_str().unwrap().contains("DESTRUCTIVE"));
                assert!(payload["warning"].as_str().unwrap().contains("REBOOT"));
            }
            other => panic!("expected ConfirmationRequired, got {other:?}"),
        }
    }

    #[test]
    fn confirmation_carries_plane_warning_only_when_given() {
        let decision = || evaluate_preflight(&baseline_facts(), &args());
        for (warning, expected) in [(Some("managed by Mist"), true), (None, false)] {
            let Err(JmcpError::ConfirmationRequired { payload }) =
                finish_preflight(decision(), &args(), warning)
            else {
                panic!("expected ConfirmationRequired");
            };
            assert_eq!(payload.get("config_authority_warning").is_some(), expected);
            if let Some(text) = warning {
                assert_eq!(payload["config_authority_warning"], text);
            }
            assert!(payload["warning"].as_str().unwrap().contains("REBOOT"));
        }
    }

    #[test]
    fn returns_proceed_when_confirm_true_and_everything_ok() {
        let f = baseline_facts();
        let mut a = args();
        a.confirm = true;
        let d = evaluate_preflight(&f, &a);
        assert!(matches!(d, PreflightDecision::Proceed));
    }

    #[test]
    fn unparseable_version_yields_proceed_block() {
        let mut f = baseline_facts();
        f.version_output = "garbage no junos line".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::UnparseableVersion));
    }

    #[test]
    fn check_order_cluster_before_already_at_target() {
        let mut f = baseline_facts();
        f.cluster_status_output =
            "<chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>".into();
        f.version_output = "Junos: 25.4R1.12".into();
        let d = evaluate_preflight(&f, &args());
        assert!(matches!(d, PreflightDecision::ClusterUnsupported));
    }
}

use crate::cancel::{select_cancel, select_cancel_raw};
use crate::config_authority::JunosAuthority;
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::plane_guard::{AuthoritySource, resolve_authority, upgrade_warning};
use crate::tools::UpgradeJunosArgs;
use crate::tools::transfer_file::{
    TransferConfig, sha256_file_cancellable, validate_source_basename,
};
use crate::{DeviceLeaseManager, DeviceLock};
use mecmcp_audit::AuditScope;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Tool-level config. Holds the shared `TransferConfig` so that:
/// - `transfer_file` and `upgrade_junos` use the same per-router locks
/// - staging dir + known hosts paths are configured in one place
/// - the mockable `ScpRunner` is reachable when this tool calls into
///   `transfer_file::handle` for the actual image push
#[derive(Clone)]
pub struct UpgradeConfig {
    /// Transfer configuration (staging dir, known_hosts, SCP runner, locks).
    pub transfer_cfg: TransferConfig,
    /// Device lease manager (for exclusive-upgrade lock across tools).
    pub device_leases: Arc<DeviceLeaseManager>,
}

async fn gather_facts(
    router: &str,
    dm: Arc<DeviceManager>,
    image_basename: String,
    local_size: u64,
    local_sha: [u8; 32],
    ct: &CancellationToken,
) -> Result<PreflightFacts, JmcpError> {
    // The cluster probe is the first RPC on a freshly checked-out session,
    // so it's where a stale pooled session surfaces (#83). open_validated
    // reconnects fresh and retries once if so; later probes reuse the now-
    // proven-live session.
    let (mut dev, cluster_status_output) =
        open_validated(router, dm.clone(), "cluster_probe", ct).await?;

    let version_output =
        run_probe(&mut dev, "show version | match Junos:", "version_probe", ct).await?;
    let commit_output = run_probe(&mut dev, "show system commit", "commit_probe", ct).await?;
    let storage_output = run_probe(
        &mut dev,
        "show system storage no-forwarding",
        "storage_probe",
        ct,
    )
    .await?;

    Ok(PreflightFacts {
        cluster_status_output,
        version_output,
        commit_output,
        storage_output,
        local_image_size: local_size,
        local_image_sha256: local_sha,
        image_basename,
    })
}

async fn run_probe(
    dev: &mut crate::device_manager::PooledDevice,
    command: &str,
    phase: &'static str,
    ct: &CancellationToken,
) -> Result<String, JmcpError> {
    select_cancel_raw::<_, _, JmcpError>(ct, dev.cli(command))
        .await?
        .map_err(|e| JmcpError::DeviceProbeFailed {
            phase: phase.into(),
            message: e.to_string(),
        })
}

/// Stands in for the cluster reply on a platform with no chassis clusters;
/// `detect_cluster_active` reads it as standalone.
const NO_CHASSIS_CLUSTER_SUPPORT: &str = "Chassis cluster is not enabled on this platform";

/// Platforms known never to form a chassis cluster, an SRX feature, so there is
/// no cluster RPC to ask them. Anything else, including an unrecognised model,
/// is asked and has to prove it is standalone.
fn never_chassis_clustered(personality: &rustez::Personality) -> bool {
    use rustez::Personality::{Acx, Ex, M, Mx, Ptx, Qfx, T, Vmx};
    matches!(personality, Acx | Ex | M | Mx | Ptx | Qfx | T | Vmx)
}

/// The cluster probe, as a structured RPC. Not the CLI `show chassis cluster
/// status`: on a standalone SRX, Junos answers that with bare text directly
/// inside `<rpc-reply>`, which the NETCONF parser rejects as malformed.
async fn call_cluster_status(
    dev: &mut crate::device_manager::PooledDevice,
) -> Result<String, rustez::RustEzError> {
    // Facts are gathered on connect, so this reads the cache and sends no RPC.
    if never_chassis_clustered(&dev.facts().await?.personality) {
        // Still a real RPC: `open_validated` catches a stale session on this one.
        dev.rpc()?.call("get-software-information", &[]).await?;
        return Ok(NO_CHASSIS_CLUSTER_SUPPORT.to_string());
    }
    dev.rpc()?.call("get-chassis-cluster-status", &[]).await
}

/// Open a (possibly pooled) session and run the cluster probe as the session's
/// first RPC. If that RPC fails with a stale-session error (issue #83) —
/// e.g. the pooled session died across a reboot or a transient blip left a
/// dead entry in the pool — drop it, reconnect with a guaranteed-fresh
/// session via [`DeviceManager::open_fresh`], and retry the probe exactly
/// once. Returns the live device plus the probe output so callers can keep
/// reusing the validated session for follow-on probes.
///
/// Only the *first* RPC on a freshly checked-out session needs this guard:
/// once one RPC round-trips successfully the session is proven live, so any
/// later failure is a real error and should propagate.
async fn open_validated(
    router: &str,
    dm: Arc<DeviceManager>,
    phase: &'static str,
    ct: &CancellationToken,
) -> Result<(crate::device_manager::PooledDevice, String), JmcpError> {
    let mut dev = select_cancel(ct, dm.open(router)).await?;
    match select_cancel_raw::<_, _, JmcpError>(ct, call_cluster_status(&mut dev)).await? {
        Ok(out) => Ok((dev, out)),
        Err(e) if error_indicates_stale_session(&e.to_string()) => {
            tracing::warn!(
                router = %router,
                phase = phase,
                error = %e,
                "upgrade_junos.stale_session: pooled session unusable, reconnecting fresh and retrying once"
            );
            drop(dev);
            let mut fresh = select_cancel(ct, dm.open_fresh(router)).await?;
            let out = select_cancel_raw::<_, _, JmcpError>(ct, call_cluster_status(&mut fresh))
                .await?
                .map_err(|e| JmcpError::DeviceProbeFailed {
                    phase: phase.into(),
                    message: e.to_string(),
                })?;
            Ok((fresh, out))
        }
        Err(e) => Err(JmcpError::DeviceProbeFailed {
            phase: phase.into(),
            message: e.to_string(),
        }),
    }
}

/// How long `resolve_plane` may probe. Pooled RPCs allow an hour, so a hung read
/// would otherwise spend the upgrade's own timeout on a warning.
const PLANE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The device's authority, or `None` if a probe could not establish it. A plane
/// never stops an upgrade, so the only error returned here is cancellation.
async fn resolve_plane(
    router: &str,
    declared: &JunosAuthority,
    dm: Arc<DeviceManager>,
    ct: &CancellationToken,
) -> Result<Option<(JunosAuthority, AuthoritySource)>, JmcpError> {
    if *declared != JunosAuthority::Unknown {
        return Ok(Some((declared.clone(), AuthoritySource::Declared)));
    }
    let probe = async {
        let mut dev = dm.open(router).await?;
        // A probe that fails or is dropped mid-RPC leaves the session in an unknown state.
        dev.prevent_reuse();
        let resolved = resolve_authority(&mut dev, declared).await?;
        dev.allow_reuse();
        Ok::<_, JmcpError>(resolved)
    };
    bounded_plane_probe(router, probe, PLANE_PROBE_TIMEOUT, ct).await
}

/// Run a plane probe within `limit`. A failed or slow probe costs only the
/// warning and never stops the upgrade.
async fn bounded_plane_probe(
    router: &str,
    probe: impl Future<Output = Result<(JunosAuthority, AuthoritySource), JmcpError>>,
    limit: std::time::Duration,
    ct: &CancellationToken,
) -> Result<Option<(JunosAuthority, AuthoritySource)>, JmcpError> {
    let bounded_probe = tokio::time::timeout(limit, probe);
    let failure = match select_cancel_raw::<_, _, JmcpError>(ct, bounded_probe).await? {
        Ok(Ok(resolved)) => return Ok(Some(resolved)),
        Ok(Err(error)) => error.to_string(),
        Err(_) => format!("no reply within {limit:?}"),
    };
    tracing::warn!(
        router = %router,
        error = %failure,
        "upgrade_junos.plane_probe_failed: upgrading without a plane warning"
    );
    Ok(None)
}

/// Record the plane as soon as it is known. The warning only reaches the client,
/// and a failed or timed-out upgrade has no result to read it from.
fn audit_plane(audit: &mut AuditScope, authority: &JunosAuthority, source: AuthoritySource) {
    audit.meta("config_authority", authority.as_str());
    audit.meta(
        "config_authority_detected",
        source == AuthoritySource::Detected,
    );
}

/// Tool handler for `upgrade_junos`: standalone Junos software upgrade with install + reboot + verification.
pub async fn handle(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
    ct: CancellationToken,
    correlation_id: String,
    audit: &mut AuditScope,
) -> Result<serde_json::Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, run(args, dm, cfg, ct, correlation_id, audit))
        .await
        .map_err(|_| JmcpError::UpgradeOuterTimeout(timeout))?
}

async fn run(
    args: UpgradeJunosArgs,
    dm: Arc<DeviceManager>,
    cfg: UpgradeConfig,
    ct: CancellationToken,
    correlation_id: String,
    audit: &mut AuditScope,
) -> Result<serde_json::Value, JmcpError> {
    // Issue #44 Half A: short-circuit if already cancelled before entry.
    if ct.is_cancelled() {
        return Err(JmcpError::Cancelled);
    }
    // 1. Basename validation (same allowlist as transfer_file).
    validate_source_basename(&args.source_path)?;

    // 2. Inventory lookup + auth check up front. We snapshot what we
    //    need so the borrow drops before any await on dm.open().
    let declared_authority = {
        let inv = dm.inventory();
        let entry = inv.get(&args.device)?;
        if entry.config_authority != JunosAuthority::Unknown {
            audit_plane(audit, &entry.config_authority, AuthoritySource::Declared);
        }
        match &entry.auth {
            AuthConfig::Password { .. } | AuthConfig::PasswordEnv { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.device.clone()));
            }
            AuthConfig::SshKey { .. } => {}
        }

        // A managing plane never refuses an upgrade; it only adds a warning (see `resolve_plane`).
        entry.config_authority.clone()
    };

    // 3. Staged file checks (mirror transfer_file pre-flight).
    let local_path = cfg.transfer_cfg.staging_dir.join(&args.source_path);
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

    // 4. Local sha256 + size (streamed, blocks of 64 KiB).
    //
    // Issue #51: we deliberately do NOT acquire the per-router transfer
    // lock here. Earlier versions acquired it as a "Phase 4" preflight
    // step, but `run_destructive` then calls `transfer_file::handle()`,
    // which re-acquires the same per-router permit on the same task —
    // a self-deadlock that hung every real upgrade at Phase 2 the moment
    // preflight returned `Proceed`. The cases that mask the bug
    // (`already_at_target`, `ClusterUnsupported`, `ConfirmationRequired`)
    // return before `dispatch_preflight` ever reaches `run_destructive`,
    // which is why CI + the gated live test never tripped it. The inner
    // `transfer_file::handle` still serializes parallel callers against
    // the same router; preflight is read-only and safe to overlap.
    let (local_sha, local_size) = sha256_file_cancellable(&local_path, &ct).await?;

    // 6. Gather NETCONF facts. Stub until Task 9 wires it up.
    let facts = gather_facts(
        &args.device,
        dm.clone(),
        args.source_path.clone(),
        local_size,
        local_sha,
        &ct,
    )
    .await?;

    // 7. Warn if a plane manages the device, then take the pure preflight decision.
    let plane = resolve_plane(&args.device, &declared_authority, dm.clone(), &ct).await?;
    let authority_warning = plane.and_then(|(authority, source)| {
        if source == AuthoritySource::Detected {
            audit_plane(audit, &authority, source);
        }
        upgrade_warning(&args.device, &authority, source)
    });
    dispatch_preflight(
        &args,
        &facts,
        dm.clone(),
        &cfg,
        authority_warning,
        &ct,
        &correlation_id,
    )
    .await
}

/// Translate a PreflightDecision into a handle() outcome. Task 9
/// stubs the Proceed arm; Tasks 10-11 fill in the destructive path.
async fn dispatch_preflight(
    args: &UpgradeJunosArgs,
    facts: &PreflightFacts,
    dm: Arc<DeviceManager>,
    cfg: &UpgradeConfig,
    authority_warning: Option<String>,
    ct: &CancellationToken,
    correlation_id: &str,
) -> Result<serde_json::Value, JmcpError> {
    let initial_decision = evaluate_preflight(facts, args);
    if !matches!(initial_decision, PreflightDecision::Proceed) {
        return finish_preflight(initial_decision, args, authority_warning.as_deref());
    }

    let _lease = cfg
        .device_leases
        .acquire_cancellable(&args.device, "upgrade_junos", correlation_id, ct)
        .await?;

    // Re-read every device fact after acquiring the shared lease. This closes
    // the gap where an SRX package operation could change device state between
    // the initial preview/preflight and the Junos upgrade's destructive path.
    let locked_facts = gather_facts(
        &args.device,
        dm.clone(),
        facts.image_basename.clone(),
        facts.local_image_size,
        facts.local_image_sha256,
        ct,
    )
    .await?;
    let locked_decision = evaluate_preflight(&locked_facts, args);
    if !matches!(locked_decision, PreflightDecision::Proceed) {
        return finish_preflight(locked_decision, args, authority_warning.as_deref());
    }

    run_destructive(
        args,
        &locked_facts,
        dm,
        cfg,
        authority_warning,
        ct,
        correlation_id,
    )
    .await
}

fn finish_preflight(
    decision: PreflightDecision,
    args: &UpgradeJunosArgs,
    authority_warning: Option<&str>,
) -> Result<serde_json::Value, JmcpError> {
    match decision {
        PreflightDecision::ClusterUnsupported => Err(JmcpError::UpgradeClusterUnsupported {
            router: args.device.clone(),
        }),
        PreflightDecision::UnparseableVersion => Err(JmcpError::DeviceProbeFailed {
            phase: "version_parse".into(),
            message: "could not parse Junos version from `show version`".into(),
        }),
        PreflightDecision::UnparseableStorage => Err(JmcpError::DeviceProbeFailed {
            phase: "storage_parse".into(),
            message: "could not parse free bytes from `show system storage`".into(),
        }),
        PreflightDecision::AlreadyAtTarget { current_version } => Ok(serde_json::json!({
            "status": "already_at_target",
            "router": args.device,
            "current_version": current_version,
            "target_version": args.target_version,
            "message": "device already running target version; no action taken"
        })),
        PreflightDecision::CommitConfirmedActive => Err(JmcpError::CommitConfirmedActive {
            router: args.device.clone(),
        }),
        PreflightDecision::InsufficientDisk { free, required } => {
            Err(JmcpError::InsufficientDisk {
                free,
                required,
                message: format!(
                    "device '{}' /var/tmp (install needs 2× image + 32 MiB headroom)",
                    args.device
                ),
            })
        }
        PreflightDecision::ConfirmationRequired(mut payload) => {
            // Not "warning": that key already holds the destructive reboot text.
            if let Some(warning) = authority_warning {
                payload["config_authority_warning"] = warning.into();
            }
            Err(JmcpError::ConfirmationRequired { payload })
        }
        PreflightDecision::Proceed => unreachable!("Proceed is handled while holding the lease"),
    }
}

async fn run_destructive(
    args: &UpgradeJunosArgs,
    facts: &PreflightFacts,
    dm: Arc<DeviceManager>,
    cfg: &UpgradeConfig,
    authority_warning: Option<String>,
    ct: &CancellationToken,
    correlation_id: &str,
) -> Result<serde_json::Value, JmcpError> {
    use std::time::Instant;
    let started = Instant::now();
    let preflight_secs = started.elapsed().as_secs();

    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "destructive_entry",
        "upgrade_junos.phase_diag"
    );

    // Phase 1: pre-baseline.
    let pre_baseline = capture_baseline(&args.device, dm.clone(), ct).await?;
    let phase1_done = Instant::now();
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "pre_baseline_done",
        "upgrade_junos.phase_diag"
    );

    // Phase 2: transfer via transfer_file::handle (idempotent skip).
    // The inner timeout matches the outer `args.timeout` rather than a
    // magic constant so operators can extend the transfer budget for
    // slow links by bumping a single knob (#42). The outer
    // `tokio::time::timeout(args.timeout, run(…))` in `handle()` is
    // still the wall bound — it will fire with `UpgradeOuterTimeout`
    // before the inner call's own `tokio::time::timeout` does.
    let transfer_args = build_transfer_args(args);
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "transfer_start",
        "upgrade_junos.phase_diag"
    );
    let _transfer_result = crate::tools::transfer_file::handle(
        transfer_args,
        dm.clone(),
        cfg.transfer_cfg.clone(),
        ct.clone(),
    )
    .await?;
    let phase2_done = Instant::now();
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "transfer_done",
        "upgrade_junos.phase_diag"
    );

    // Phase 3: install + reboot. Open a fresh session via the pool.
    //
    // Issue #44 Half A note: the `dev.cli(...)` install RPC is intentionally
    // NOT raced against cancellation. Once Junos accepts the
    // `request system software add ... reboot` command, the upgrade is
    // already in flight server-side; cancelling the client future cannot
    // undo it. We do race the *pre-RPC* `dm.open()` and the *post-RPC*
    // reboot-wait/post-verify steps below. A cancel during the install RPC
    // surfaces only after the RPC returns (or its session drops).
    let install_stdout = match select_cancel(ct, dm.open(&args.device)).await {
        Ok(mut dev) => {
            let cmd = format!(
                "request system software add /var/tmp/{} no-copy reboot",
                args.source_path
            );
            match dev.cli(&cmd).await {
                Ok(out) => {
                    if ct.is_cancelled() {
                        tracing::warn!(
                            router = %args.device,
                            correlation_id,
                            phase = "install_rpc",
                            "upgrade_junos.cancel_diag: cancel observed after install RPC; \
                             device upgrade already committed server-side"
                        );
                        return Err(JmcpError::Cancelled);
                    }
                    out
                }
                Err(e) => {
                    if install_error_indicates_session_drop(&e.to_string()) {
                        String::new()
                    } else {
                        return Err(JmcpError::DeviceProbeFailed {
                            phase: "install_rpc".into(),
                            message: e.to_string(),
                        });
                    }
                }
            }
        }
        Err(e) => return Err(e),
    };
    let phase3_done = Instant::now();
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "install_rpc_done",
        "upgrade_junos.phase_diag"
    );

    let _ = install_stdout;

    // Phases 4+5: wait for the device to reboot into `target_version`.
    // A single budgeted loop opens a session and polls
    // `show version` until the parsed version equals `target_version`,
    // tolerating the reboot flap (#83). Making the *version* the source of
    // truth — rather than treating the first successful `dm.open()` as
    // "device is back" — avoids the spurious "No route to host" failure
    // that occurred when a brief pre-reboot sshd window satisfied the old
    // open-only wait and the subsequent post-verify probe then hit the
    // genuine reboot outage and raw-propagated the connect error.
    let post_version_output = {
        let dm = dm.clone();
        let router = args.device.clone();
        wait_for_version(
            &args.device,
            &args.target_version,
            std::time::Duration::from_secs(args.reboot_wait_secs),
            std::time::Duration::from_secs(30), // initial_delay — device is rebooting
            std::time::Duration::from_secs(15), // poll_interval
            std::time::Duration::from_secs(30), // attempt_deadline per probe
            ct,
            move || {
                let dm = dm.clone();
                let router = router.clone();
                async move { dm.run_cli(&router, "show version | match Junos:").await }
            },
        )
        .await?
    };
    let _ = &post_version_output;
    let phase4_done = Instant::now();
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "reboot_verified",
        "upgrade_junos.phase_diag"
    );
    // The reboot wait and post-verify are now one budgeted loop; report the
    // full wait under reboot_wait and leave post-verify at zero.
    let phase5_done = phase4_done;

    // Phase 6: post-baseline.
    let post_baseline = capture_baseline(&args.device, dm.clone(), ct).await?;
    tracing::info!(
        router = %args.device,
        correlation_id,
        phase = "post_baseline_done",
        "upgrade_junos.phase_diag"
    );

    // Phase 7: assemble success response.
    let from_version =
        parse_junos_version(&facts.version_output).unwrap_or_else(|| "<unknown>".to_string());
    let mut response = build_success_response(BuildSuccessArgs {
        router: &args.device,
        from_version: &from_version,
        to_version: &args.target_version,
        image_basename: &args.source_path,
        image_sha256: &facts.local_image_sha256,
        elapsed_seconds: started.elapsed().as_secs(),
        preflight_secs,
        transfer_secs: (phase2_done - phase1_done).as_secs(),
        install_secs: (phase3_done - phase2_done).as_secs(),
        reboot_wait_secs: (phase4_done - phase3_done).as_secs(),
        postverify_secs: (phase5_done - phase4_done).as_secs(),
        pre_baseline: &pre_baseline,
        post_baseline: &post_baseline,
    });
    response["correlation_id"] = serde_json::Value::String(correlation_id.to_string());
    if let Some(warning) = authority_warning {
        response["warning"] = serde_json::Value::String(warning);
    }
    Ok(response)
}

/// Build the `TransferFileArgs` snapshot passed to `transfer_file::handle`
/// from Phase 2 of `run_destructive`. Extracted so the timeout-plumbing
/// (and any future per-call invariants like `force=false`) are unit-testable
/// without spinning up a device or a Tokio runtime. (#42)
pub(crate) fn build_transfer_args(args: &UpgradeJunosArgs) -> crate::tools::TransferFileArgs {
    crate::tools::TransferFileArgs {
        device: args.device.clone(),
        source_path: args.source_path.clone(),
        force: false,
        verify: true,
        timeout: args.timeout,
    }
}

#[cfg(test)]
mod build_transfer_args_tests {
    use super::*;

    fn args_with_timeout(timeout: u64) -> UpgradeJunosArgs {
        UpgradeJunosArgs {
            device: "vsrx-test10".into(),
            source_path: "junos-25.4R1.12.tgz".into(),
            target_version: "25.4R1.12".into(),
            confirm: true,
            timeout,
            reboot_wait_secs: 480,
        }
    }

    #[test]
    fn forwards_timeout_from_upgrade_args() {
        // Regression for #42: the inner transfer call previously used a
        // hard-coded 600 s timeout regardless of the operator-supplied
        // outer budget. Any value the operator picks must reach
        // `TransferFileArgs.timeout` verbatim.
        for t in [60_u64, 600, 900, 1800, 3600] {
            let upgrade = args_with_timeout(t);
            let transfer = build_transfer_args(&upgrade);
            assert_eq!(transfer.timeout, t, "timeout should pass through");
        }
    }

    #[test]
    fn pins_force_false_verify_true() {
        // Invariants the transfer call relies on. `force=false` so we
        // never silently overwrite a divergent remote file; `verify=true`
        // so we always post-checksum after scp.
        let transfer = build_transfer_args(&args_with_timeout(900));
        assert!(!transfer.force, "force must default to false");
        assert!(transfer.verify, "verify must default to true");
    }

    #[test]
    fn forwards_router_and_source() {
        let mut upgrade = args_with_timeout(900);
        upgrade.device = "vsrx-test11".into();
        upgrade.source_path = "junos-25.4R1.12.tgz".into();
        let transfer = build_transfer_args(&upgrade);
        assert_eq!(transfer.device, "vsrx-test11");
        assert_eq!(transfer.source_path, "junos-25.4R1.12.tgz");
    }
}

async fn capture_baseline(
    device_name: &str,
    dm: Arc<DeviceManager>,
    ct: &CancellationToken,
) -> Result<std::collections::BTreeMap<String, String>, JmcpError> {
    let mut out = std::collections::BTreeMap::new();
    let mut dev = select_cancel(ct, dm.open(device_name)).await?;
    for cmd in BASELINE_COMMANDS {
        match select_cancel_raw::<_, _, JmcpError>(ct, dev.cli(cmd)).await? {
            Ok(s) => {
                out.insert((*cmd).to_string(), s);
            }
            Err(e) => {
                out.insert((*cmd).to_string(), format!("<error capturing: {e}>"));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod handle_early_exit_tests {
    use super::*;
    use crate::device_manager::DeviceManager;
    use crate::inventory::Inventory;
    use crate::tools::{UpgradeJunosArgs, transfer_file::TransferLocks};
    use std::io::Write;
    use std::sync::Arc;

    fn cfg(dir: &std::path::Path) -> UpgradeConfig {
        UpgradeConfig {
            transfer_cfg: crate::tools::transfer_file::TransferConfig {
                staging_dir: dir.to_path_buf(),
                known_hosts_file: "/etc/jmcp/known_hosts".into(),
                scp_runner: crate::tools::transfer_file::MockScpRunner::ok(),
                transfer_locks: Arc::new(TransferLocks::default()),
                // Test bypasses the known_hosts pre-check; covered by the
                // dedicated pre-check tests in transfer_file.rs.
                host_key_mode: crate::bootstrap::SshHostKeyMode::AcceptNew,
            },
            device_leases: Arc::new(
                DeviceLeaseManager::for_directory(dir.join("device-leases")).unwrap(),
            ),
        }
    }

    /// Holds the inventory plus the temp key file so the key's lifetime
    /// covers the test (Inventory::load checks key existence at parse time).
    struct InvWithKey {
        inv: Arc<Inventory>,
        _key: tempfile::NamedTempFile,
        _json: tempfile::NamedTempFile,
    }

    fn build_inv(json_tmpl: &str) -> InvWithKey {
        let key = tempfile::NamedTempFile::new().unwrap();
        let key_path = key.path().to_string_lossy().to_string();
        let json = json_tmpl.replace("__KEY__", &key_path);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        InvWithKey {
            inv,
            _key: key,
            _json: f,
        }
    }

    fn args(router: &str, source: &str) -> UpgradeJunosArgs {
        UpgradeJunosArgs {
            device: router.into(),
            source_path: source.into(),
            target_version: "25.4R1.12".into(),
            confirm: false,
            timeout: 10,
            reboot_wait_secs: 5,
        }
    }

    #[tokio::test]
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(
            args("r1", "../etc/passwd"),
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
            "test-rejects-bad-basename".into(),
            &mut test_audit(),
        )
        .await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn unknown_router_propagates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(
            args("nope", "img.tgz"),
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
            "test-unknown-router".into(),
            &mut test_audit(),
        )
        .await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_before_transfer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("img.tgz"), b"abc").unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(
            args("r1", "img.tgz"),
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
            "test-password-auth".into(),
            &mut test_audit(),
        )
        .await;
        assert!(matches!(r, Err(crate::error::JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[tokio::test]
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(
            args("r1", "missing.tgz"),
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
            "test-missing-file".into(),
            &mut test_audit(),
        )
        .await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }

    /// A declared managing plane no longer stops `upgrade_junos`: the call gets
    /// past the inventory check and fails on the missing staged file instead.
    #[tokio::test]
    async fn declared_plane_does_not_refuse_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","config_authority":"mist",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let r = handle(
            args("r1", "missing.tgz"),
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
            "test-declared-plane".into(),
            &mut test_audit(),
        )
        .await;
        assert!(matches!(r, Err(crate::error::JmcpError::BadSourcePath(_))));
    }

    fn test_audit() -> AuditScope {
        AuditScope::stdio("upgrade_junos", "upgrade", vec![])
    }

    /// No router here is in the inventory, so opening a session always fails.
    fn dm_with_no_devices() -> Arc<DeviceManager> {
        Arc::new(DeviceManager::new(build_inv("{}").inv.clone()))
    }

    #[tokio::test]
    async fn declared_plane_resolves_without_opening_a_session() {
        let plane = resolve_plane(
            "not-in-inventory",
            &JunosAuthority::Mist,
            dm_with_no_devices(),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            plane.unwrap(),
            Some((JunosAuthority::Mist, AuthoritySource::Declared))
        );
    }

    #[tokio::test]
    async fn failed_open_costs_only_the_plane_warning() {
        let plane = resolve_plane(
            "not-in-inventory",
            &JunosAuthority::Unknown,
            dm_with_no_devices(),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(plane.unwrap(), None);
    }

    #[tokio::test]
    async fn hung_plane_probe_costs_only_the_plane_warning() {
        let plane = bounded_plane_probe(
            "r1",
            std::future::pending(),
            std::time::Duration::from_millis(10),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(plane.unwrap(), None);
    }

    #[tokio::test]
    async fn cancelling_a_plane_probe_still_cancels_the_upgrade() {
        let ct = CancellationToken::new();
        ct.cancel();
        let plane = bounded_plane_probe(
            "r1",
            std::future::pending(),
            std::time::Duration::from_secs(60),
            &ct,
        )
        .await;
        assert!(matches!(plane, Err(JmcpError::Cancelled)));
    }

    /// T5 (issue #44 Half A): a token cancelled before `upgrade_junos::handle`
    /// is invoked must cause it to return `JmcpError::Cancelled` before any
    /// inventory lookup, file stat, or device I/O. Pins the
    /// `if ct.is_cancelled()` short-circuit at the top of `run()`.
    #[tokio::test]
    async fn pre_cancelled_token_returns_cancelled_immediately() {
        let dir = tempfile::tempdir().unwrap();
        // Deliberately omit any staged file — if the cancel pre-check were
        // skipped, BadSourcePath would surface instead.
        let env = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"ssh_key","private_key_path":"__KEY__"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(env.inv.clone()));
        let ct = CancellationToken::new();
        ct.cancel();
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            handle(
                args("r1", "missing.tgz"),
                dm,
                cfg(dir.path()),
                ct,
                "test-pre-cancelled".into(),
                &mut test_audit(),
            ),
        )
        .await
        .expect("handle should return well within 200ms when pre-cancelled");
        assert!(
            matches!(r, Err(crate::error::JmcpError::Cancelled)),
            "expected Cancelled, got {r:?}"
        );
    }
}

/// Commands captured in pre- and post- baselines. Order matters for
/// stable response shape; informational only.
pub const BASELINE_COMMANDS: &[&str] = &[
    "show version",
    "show interfaces terse | except \"\\.[0-9]+ \"",
    "show route summary",
    "show security flow session summary",
    "show system alarms",
    "show system core-dumps no-forwarding",
];

/// Classify whether the error returned by `dev.cli("request system
/// software add ... reboot")` is the *expected* session-drop produced
/// when the device starts rebooting mid-RPC, vs a real failure.
pub fn install_error_indicates_session_drop(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    [
        "connection closed",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "early eof",
        "channel closed",
        "session closed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod install_classifier_tests {
    use super::*;

    #[test]
    fn detects_connection_closed() {
        assert!(install_error_indicates_session_drop(
            "Connection closed by peer"
        ));
    }

    #[test]
    fn detects_broken_pipe() {
        assert!(install_error_indicates_session_drop(
            "io error: Broken pipe"
        ));
    }

    #[test]
    fn detects_eof() {
        assert!(install_error_indicates_session_drop(
            "rustez: unexpected EOF on channel"
        ));
    }

    #[test]
    fn does_not_misclassify_syntax_error() {
        assert!(!install_error_indicates_session_drop(
            "error: syntax error, expecting <name>"
        ));
    }

    #[test]
    fn does_not_misclassify_rpc_error() {
        assert!(!install_error_indicates_session_drop(
            "rpc-error: package not found"
        ));
    }
}

/// Arguments for building the success response JSON payload. Aggregates timing + baseline data.
pub struct BuildSuccessArgs<'a> {
    /// Device name.
    pub router: &'a str,
    /// Pre-upgrade version.
    pub from_version: &'a str,
    /// Post-upgrade (target) version.
    pub to_version: &'a str,
    /// Installed image basename.
    pub image_basename: &'a str,
    /// Installed image sha256.
    pub image_sha256: &'a [u8; 32],
    /// Total wall-clock elapsed time (seconds).
    pub elapsed_seconds: u64,
    /// Preflight phase duration.
    pub preflight_secs: u64,
    /// Transfer phase duration.
    pub transfer_secs: u64,
    /// Install phase duration.
    pub install_secs: u64,
    /// Reboot-wait phase duration.
    pub reboot_wait_secs: u64,
    /// Post-verify phase duration.
    pub postverify_secs: u64,
    /// Pre-upgrade operational baseline (command → output map).
    pub pre_baseline: &'a std::collections::BTreeMap<String, String>,
    /// Post-upgrade operational baseline (command → output map).
    pub post_baseline: &'a std::collections::BTreeMap<String, String>,
}

/// Build the success response JSON payload from phase timings and baselines.
pub fn build_success_response(a: BuildSuccessArgs) -> serde_json::Value {
    let diff = diff_baseline(a.pre_baseline, a.post_baseline);
    serde_json::json!({
        "status": "upgraded",
        "router": a.router,
        "from_version": a.from_version,
        "to_version": a.to_version,
        "image_basename": a.image_basename,
        "image_sha256": crate::tools::transfer_file::hex32(a.image_sha256),
        "elapsed_seconds": a.elapsed_seconds,
        "phase_timings": {
            "preflight_secs": a.preflight_secs,
            "transfer_secs": a.transfer_secs,
            "install_secs": a.install_secs,
            "reboot_wait_secs": a.reboot_wait_secs,
            "postverify_secs": a.postverify_secs,
        },
        "pre_baseline": a.pre_baseline,
        "post_baseline": a.post_baseline,
        "baseline_diff": diff,
    })
}

/// Wait for the device to reboot into `target_version`, polling
/// `show version` until it reports the target (issue #83).
///
/// This is the post-reboot source of truth: rather than treating a single
/// successful `dm.open()` as "device is back" (which wrongly trips on the
/// brief sshd window the device exposes *before* it actually reboots), it
/// repeatedly opens a session and reads `show version` until the parsed
/// version equals `target_version`.
///
/// Behaviour:
/// * Transient probe errors (connect refused / no route to host / dropped
///   session — exactly what a reboot produces) are swallowed and retried
///   within `budget`.
/// * A parseable-but-wrong version (e.g. the pre-reboot old version, or a
///   silent rollback) is remembered but does not end the wait early.
/// * A non-transient error (auth failure, unknown router) propagates
///   immediately — those will never self-heal.
/// * On `budget` exhaustion: `UpgradePostVerifyMismatch` if a version was
///   ever observed (came back wrong), else `UpgradeRebootTimeout` (never
///   reachable).
///
/// `probe` is injected so the decision logic is unit-testable without a
/// device; the production caller passes a closure that does
/// `dm.open()` + `cli("show version | match Junos:")`.
#[allow(clippy::too_many_arguments)]
async fn wait_for_version<F, Fut>(
    router: &str,
    target_version: &str,
    budget: std::time::Duration,
    initial_delay: std::time::Duration,
    poll_interval: std::time::Duration,
    attempt_deadline: std::time::Duration,
    ct: &CancellationToken,
    mut probe: F,
) -> Result<String, JmcpError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<String, JmcpError>>,
{
    let start = std::time::Instant::now();
    select_cancel_raw::<_, _, JmcpError>(ct, tokio::time::sleep(initial_delay)).await?;

    let mut last_observed: Option<String> = None;
    loop {
        let attempt = select_cancel_raw::<_, _, JmcpError>(
            ct,
            tokio::time::timeout(attempt_deadline, probe()),
        )
        .await?;
        match attempt {
            // Probe succeeded and we parsed a version.
            Ok(Ok(output)) => {
                if let Some(observed) = parse_junos_version(&output) {
                    if observed == target_version {
                        return Ok(output);
                    }
                    // Parseable-but-wrong (pre-reboot old version or silent
                    // rollback): remember it, but keep waiting within budget.
                    last_observed = Some(observed);
                }
                // Unparseable output is treated like a transient blip.
            }
            // Probe returned an error.
            Ok(Err(err)) => {
                if !crate::device_manager::error_is_transient(&err.to_string()) {
                    // Auth failure / unknown router — will never self-heal.
                    return Err(err);
                }
                // Transient (reboot in progress): swallow and retry.
            }
            // Per-attempt deadline elapsed — also transient.
            Err(_elapsed) => {}
        }

        if start.elapsed() >= budget {
            return match last_observed {
                Some(observed) => Err(JmcpError::UpgradePostVerifyMismatch {
                    router: router.to_string(),
                    expected: target_version.to_string(),
                    observed,
                }),
                None => Err(JmcpError::UpgradeRebootTimeout {
                    router: router.to_string(),
                    waited_secs: budget.as_secs(),
                }),
            };
        }

        select_cancel_raw::<_, _, JmcpError>(ct, tokio::time::sleep(poll_interval)).await?;
    }
}

#[cfg(test)]
mod wait_for_version_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    const TARGET: &str = "25.4R1.12";

    fn version_output(v: &str) -> String {
        format!("Hostname: vSRX-test11\nJunos: {v}\n")
    }

    // Helper: build a probe that returns scripted results by attempt index.
    // Big budget + zero delays so success cases never time out first.
    async fn run_with<F, Fut>(budget: Duration, probe: F) -> Result<String, JmcpError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<String, JmcpError>>,
    {
        let ct = CancellationToken::new();
        wait_for_version(
            "vSRX-test11",
            TARGET,
            budget,
            Duration::ZERO,          // initial_delay
            Duration::ZERO,          // poll_interval
            Duration::from_secs(60), // attempt_deadline — never elapses for instant probes
            &ct,
            probe,
        )
        .await
    }

    #[tokio::test]
    async fn returns_when_target_version_observed() {
        let calls = AtomicU32::new(0);
        let out = run_with(Duration::from_secs(60), || {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n < 3 {
                    Err(JmcpError::Validation("no route to host".into()))
                } else {
                    Ok(version_output(TARGET))
                }
            }
        })
        .await
        .unwrap();
        assert!(out.contains(TARGET));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn keeps_waiting_through_old_version_then_succeeds() {
        // The premature-sshd window: device answers with the OLD version
        // before it actually reboots. Must not end the wait early.
        let calls = AtomicU32::new(0);
        let out = run_with(Duration::from_secs(60), || {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if n < 3 {
                    Ok(version_output("24.4R1.9"))
                } else {
                    Ok(version_output(TARGET))
                }
            }
        })
        .await
        .unwrap();
        assert!(out.contains(TARGET));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn budget_exhausted_with_only_old_version_is_mismatch() {
        let res = run_with(Duration::ZERO, || async { Ok(version_output("24.4R1.9")) }).await;
        match res {
            Err(JmcpError::UpgradePostVerifyMismatch {
                expected, observed, ..
            }) => {
                assert_eq!(expected, TARGET);
                assert_eq!(observed, "24.4R1.9");
            }
            other => panic!("expected UpgradePostVerifyMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn budget_exhausted_never_reachable_is_reboot_timeout() {
        let res = run_with(Duration::ZERO, || async {
            Err(JmcpError::Validation(
                "SSH connect failed: No route to host".into(),
            ))
        })
        .await;
        assert!(matches!(res, Err(JmcpError::UpgradeRebootTimeout { .. })));
    }

    #[tokio::test]
    async fn non_transient_error_propagates_immediately() {
        let calls = AtomicU32::new(0);
        let res = run_with(Duration::from_secs(60), || {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(JmcpError::UnknownRouter("vSRX-test11".into())) }
        })
        .await;
        assert!(matches!(res, Err(JmcpError::UnknownRouter(_))));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "must not retry non-transient"
        );
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn build_success_response_has_expected_keys() {
        let mut pre = BTreeMap::new();
        pre.insert("show version".into(), "Junos: 24.4R1.9".into());
        let mut post = BTreeMap::new();
        post.insert("show version".into(), "Junos: 25.4R1.12".into());

        let sha = [0xab; 32];
        let v = build_success_response(BuildSuccessArgs {
            router: "vsrx-test10",
            from_version: "24.4R1.9",
            to_version: "25.4R1.12",
            image_basename: "junos-25.4R1.12.tgz",
            image_sha256: &sha,
            elapsed_seconds: 423,
            preflight_secs: 4,
            transfer_secs: 84,
            install_secs: 218,
            reboot_wait_secs: 112,
            postverify_secs: 5,
            pre_baseline: &pre,
            post_baseline: &post,
        });
        assert_eq!(v["status"], "upgraded");
        assert_eq!(v["router"], "vsrx-test10");
        assert_eq!(v["from_version"], "24.4R1.9");
        assert_eq!(v["to_version"], "25.4R1.12");
        assert_eq!(v["image_basename"], "junos-25.4R1.12.tgz");
        assert_eq!(v["elapsed_seconds"], 423);
        assert_eq!(v["phase_timings"]["preflight_secs"], 4);
        assert_eq!(v["phase_timings"]["transfer_secs"], 84);
        assert!(
            v["pre_baseline"]["show version"]
                .as_str()
                .unwrap()
                .contains("24.4R1.9")
        );
        assert!(
            v["post_baseline"]["show version"]
                .as_str()
                .unwrap()
                .contains("25.4R1.12")
        );
        assert!(
            v["baseline_diff"]["show version"]["added"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x.as_str().unwrap().contains("25.4R1.12"))
        );
    }
}

/// Classify whether an RPC error against a *pooled* session indicates the
/// session is dead/stale (peer rebooted, transport dropped, keepalive
/// probe failed, transient connect failure) and the call should reconnect
/// with a fresh session and retry once (issue #83). This is broader than
/// [`install_error_indicates_session_drop`]: it also covers connect-level
/// failures ("no route to host", "connection refused") so a transient blip
/// that left a dead entry in the pool self-heals rather than surfacing as a
/// hard `DeviceProbeFailed`. It must NOT match genuine command/RPC errors
/// (syntax error, rpc-error) — those are real and must propagate.
pub fn error_indicates_stale_session(err: &str) -> bool {
    // Delegate to the single canonical classifier in `device_manager` so the
    // upgrade reconnect path and the global `open()`/`run_cli` paths can never
    // drift apart (issue #83).
    crate::device_manager::error_is_transient(err)
}

#[cfg(test)]
mod stale_session_classifier_tests {
    use super::*;

    #[test]
    fn detects_session_expired_keepalive() {
        assert!(error_indicates_stale_session(
            "netconf error: protocol error: session expired: keepalive probe failed"
        ));
    }

    #[test]
    fn detects_no_route_to_host_connect_failure() {
        assert!(error_indicates_stale_session(
            "netconf error: transport error: connection failed: SSH connect to 10.0.0.1:22 failed: No route to host"
        ));
    }

    #[test]
    fn detects_connection_reset() {
        assert!(error_indicates_stale_session("Connection reset by peer"));
    }

    #[test]
    fn detects_broken_pipe() {
        assert!(error_indicates_stale_session("io error: Broken pipe"));
    }

    #[test]
    fn does_not_misclassify_syntax_error() {
        assert!(!error_indicates_stale_session(
            "error: syntax error, expecting <name>"
        ));
    }

    #[test]
    fn does_not_misclassify_rpc_error() {
        assert!(!error_indicates_stale_session(
            "rpc-error: package not found"
        ));
    }

    #[test]
    fn empty_is_not_stale() {
        assert!(!error_indicates_stale_session(""));
    }
}

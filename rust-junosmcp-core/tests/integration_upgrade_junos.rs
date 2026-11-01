#![allow(clippy::unwrap_used)]
//! Live upgrade_junos smoke test. Gated behind three env vars; if any
//! is unset the test exits 0 (skipped). Expected runtime ~7-10 min.
//!
//! Requires a real Junos device reachable from the test host with
//! ssh_key auth.
//!
//! Run:
//!   JMCP_LIVE_UPGRADE_TARGET=vsrx-test18 \
//!   JMCP_LIVE_UPGRADE_IMAGE=junos-vsrx-x86-64-25.4R1.12.tgz \
//!   JMCP_LIVE_UPGRADE_TARGET_VERSION=25.4R1.12 \
//!   cargo test -p rust-junosmcp-core --test integration_upgrade_junos -- --nocapture

use rust_junosmcp_core::tools::UpgradeJunosArgs;
use rust_junosmcp_core::tools::transfer_file::{MecmcpScpRunner, TransferConfig, TransferLocks};
use rust_junosmcp_core::tools::upgrade_junos::{UpgradeConfig, handle};
use rust_junosmcp_core::{DeviceLeaseManager, DeviceManager, Inventory};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_upgrade_round_trip() {
    let Ok(router) = std::env::var("JMCP_LIVE_UPGRADE_TARGET") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_TARGET not set");
        return;
    };
    let Ok(image) = std::env::var("JMCP_LIVE_UPGRADE_IMAGE") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_IMAGE not set");
        return;
    };
    let Ok(target_version) = std::env::var("JMCP_LIVE_UPGRADE_TARGET_VERSION") else {
        eprintln!("skipping: JMCP_LIVE_UPGRADE_TARGET_VERSION not set");
        return;
    };
    let inventory_path = std::env::var("JMCP_LIVE_INVENTORY")
        .unwrap_or_else(|_| "/etc/jmcp/devices.json".to_string());
    let staging_dir =
        std::env::var("JMCP_LIVE_STAGING").unwrap_or_else(|_| "/var/lib/jmcp/staging".to_string());

    let inv = Arc::new(Inventory::load(std::path::Path::new(&inventory_path)).unwrap());
    let dm = Arc::new(DeviceManager::new(inv));
    let transfer_cfg = TransferConfig {
        staging_dir: staging_dir.into(),
        known_hosts_file: "/etc/jmcp/known_hosts".into(),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(TransferLocks::default()),
        // Integration test is `#[ignore]`-gated and runs against a real
        // lab device whose host key is pre-pinned; accept-new is safe.
        host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::AcceptNew,
    };
    let lease_dir = std::env::var("JMCP_DEVICE_LEASE_DIR")
        .unwrap_or_else(|_| "/var/lib/jmcp/device-leases".to_string());
    let cfg = UpgradeConfig {
        transfer_cfg,
        device_leases: Arc::new(DeviceLeaseManager::for_directory(lease_dir).unwrap()),
    };
    let args = UpgradeJunosArgs {
        device: router.clone(),
        source_path: image.clone(),
        target_version: target_version.clone(),
        confirm: true,
        timeout: 1800,         // 30 min ceiling
        reboot_wait_secs: 600, // 10 min reboot budget
    };
    let result = handle(
        args,
        dm,
        cfg,
        CancellationToken::new(),
        "live-upgrade-round-trip".into(),
        &mut mecmcp_audit::AuditScope::stdio("upgrade_junos", "upgrade", vec![]),
    )
    .await;
    eprintln!("upgrade result: {result:?}");
    let v = result.expect("upgrade should succeed end-to-end");
    assert_eq!(v["status"], "upgraded");
    assert_eq!(v["router"], router);
    assert_eq!(v["to_version"], target_version);
}

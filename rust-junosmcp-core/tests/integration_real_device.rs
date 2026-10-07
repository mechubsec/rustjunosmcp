#![allow(clippy::unwrap_used)]
//! Real-device integration tests. `#[ignore]`'d by default; run with:
//!
//! ```text
//! JMCP_TEST_HOST=10.0.0.1 JMCP_TEST_USER=admin JMCP_TEST_PASS=secret \
//!   cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored
//! ```
//!
//! Transfer-file tests additionally require:
//! ```text
//! TEST_DEVICE_NAME=vSRX-test10 TEST_INVENTORY_PATH=/etc/jmcp/devices.json \
//!   cargo test -p rust-junosmcp-core --test integration_real_device transfer_file -- --ignored
//! ```
//!
//! **Lab state:** these tests intentionally leave files at `/var/tmp/` on the
//! target device — `rt-1kb.bin`, `rt-200mb.bin`, and `collide.bin`
//! (the latter from `transfer_file_force_false_rejects_diff` whose negative
//! second push is rejected, leaving "version-A" on the remote). Operator is
//! responsible for any cleanup between runs.

use rust_junosmcp_core::{
    DeviceManager, Inventory, MecmcpScpRunner, TransferConfig,
    policy::Policy,
    tools::{
        ConfigDiffArgs, ExecuteBatchArgs, ExecuteCommandArgs, ExecutePfeArgs, GatherFactsArgs,
        GetConfigArgs, TransferFileArgs, batch, config_diff, execute_command, facts, get_config,
        pfe, router_list,
    },
};
use std::io::Write;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing env var {name}"))
}

fn build_inv() -> Arc<Inventory> {
    let host = env("JMCP_TEST_HOST");
    let user = env("JMCP_TEST_USER");
    let pass = env("JMCP_TEST_PASS");
    let json = format!(
        r#"{{
        "lab":{{"ip":"{host}","username":"{user}",
                "auth":{{"type":"password","password":"{pass}"}}}}
    }}"#
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    Arc::new(Inventory::load(f.path()).unwrap())
}

fn build_dm() -> Arc<DeviceManager> {
    Arc::new(DeviceManager::new(build_inv()))
}

#[tokio::test]
#[ignore]
async fn router_list_returns_lab() {
    // Inventory was built above; we exercise the handler against it.
    let inv = {
        let host = env("JMCP_TEST_HOST");
        let user = env("JMCP_TEST_USER");
        let pass = env("JMCP_TEST_PASS");
        let json = format!(
            r#"{{
            "lab":{{"ip":"{host}","username":"{user}",
                    "auth":{{"type":"password","password":"{pass}"}}}}
        }}"#
        );
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    };
    let v = router_list::handle(inv).await.unwrap();
    assert_eq!(v, serde_json::json!(["lab"]));
}

#[tokio::test]
#[ignore]
async fn execute_show_version() {
    let inv = build_inv();
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let v = execute_command::handle(
        ExecuteCommandArgs {
            device: "lab".into(),
            command: "show version".into(),
            timeout: 30,
            max_lines: None,
            max_bytes: None,
            tail: false,
        },
        dm,
        pol,
    )
    .await
    .unwrap();
    assert!(v.as_str().unwrap().contains("Junos") || v.as_str().unwrap().contains("Hostname"));
}

#[tokio::test]
#[ignore]
async fn get_running_config() {
    let dm = build_dm();
    let policy = Arc::new(rust_junosmcp_core::policy::Policy::build(&dm.inventory()).unwrap());
    let v = get_config::handle(
        GetConfigArgs {
            device: "lab".into(),
            timeout: 360,
            config_path: None,
            format: "text".into(),
            max_lines: None,
            max_bytes: None,
            tail: false,
        },
        dm.clone(),
        policy,
    )
    .await
    .unwrap();
    let body = v.as_str().unwrap();
    assert!(!body.is_empty());
    assert!(body.contains("system") || body.contains("version"));
}

#[tokio::test]
#[ignore]
async fn diff_against_rollback_1() {
    let dm = build_dm();
    let v = config_diff::handle(
        ConfigDiffArgs {
            device: "lab".into(),
            version: 1,
            timeout: 360,
        },
        dm,
    )
    .await
    .unwrap();
    assert!(v.is_string());
}

#[tokio::test]
#[ignore]
async fn gather_facts() {
    let dm = build_dm();
    let v = facts::handle(
        GatherFactsArgs {
            device: "lab".into(),
            timeout: 30,
        },
        dm,
    )
    .await
    .unwrap();
    assert!(v.get("hostname").is_some());
    assert!(v.get("version").is_some());
}

// --- Sub-project #3: PFE + batch ----------------------------------------

fn live_inv() -> Option<Arc<Inventory>> {
    let host = std::env::var("JMCP_TEST_HOST").ok()?;
    let user = std::env::var("JMCP_TEST_USER").ok()?;
    let pass = std::env::var("JMCP_TEST_PASS").ok()?;
    let json = format!(
        r#"{{"r1":{{"ip":"{host}","username":"{user}","auth":{{"type":"password","password":"{pass}"}}}}}}"#
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    Some(Arc::new(Inventory::load(f.path()).unwrap()))
}

#[tokio::test]
#[ignore]
async fn live_batch_show_version_one_router_one_command() {
    let inv = match live_inv() {
        Some(i) => i,
        None => {
            eprintln!("skipped: JMCP_TEST_HOST/USER/PASS not set");
            return;
        }
    };
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let args = ExecuteBatchArgs {
        devices: vec!["r1".into()],
        commands: vec!["show version".into()],
        command_timeout: 30,
        batch_timeout: Some(60),
        max_concurrent_devices: 1,
        max_lines: None,
        max_bytes: None,
        tail: false,
    };
    let v = batch::handle(args, dm, pol).await.unwrap();
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let cmds = arr[0].pointer("/commands").unwrap().as_array().unwrap();
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].get("ok"), Some(&serde_json::json!(true)));
    let value = cmds[0].get("value").and_then(|v| v.as_str()).unwrap();
    assert!(!value.trim().is_empty(), "expected non-empty CLI output");
}

#[tokio::test]
#[ignore]
async fn live_pfe_show_jnh_stats_packet() {
    let inv = match live_inv() {
        Some(i) => i,
        None => {
            eprintln!("skipped: JMCP_TEST_HOST/USER/PASS not set");
            return;
        }
    };
    let dm = Arc::new(DeviceManager::new(inv.clone()));
    let pol = Arc::new(Policy::build(&inv).unwrap());
    let args = ExecutePfeArgs {
        device: "r1".into(),
        fpc_target: std::env::var("JMCP_TEST_FPC").unwrap_or_else(|_| "fpc0".into()),
        pfe_command: "show jnh 0 stats packet".into(),
        timeout: 30,
        max_lines: None,
        max_bytes: None,
        tail: false,
    };
    let v = pfe::handle(args, dm, pol).await.unwrap();
    let output = v.get("output").and_then(|x| x.as_str()).unwrap();
    assert!(!output.trim().is_empty(), "expected non-empty PFE output");
}

#[tokio::test]
#[ignore]
async fn live_render_show_version_template_dry_run() {
    let host = std::env::var("JMCP_TEST_HOST").expect("JMCP_TEST_HOST set");
    let user = std::env::var("JMCP_TEST_USER").expect("JMCP_TEST_USER set");
    let pass = std::env::var("JMCP_TEST_PASS").expect("JMCP_TEST_PASS set");

    let inv_json = format!(
        r#"{{"r1":{{"ip":{host:?},"username":{user:?},"auth":{{"type":"password","password":{pass:?}}}}}}}"#
    );

    // Use tempfile + Inventory::load to be explicit about the path requirement.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(inv_json.as_bytes()).unwrap();
    let inv = Arc::new(rust_junosmcp_core::inventory::Inventory::load(f.path()).unwrap());
    let dm = Arc::new(rust_junosmcp_core::device_manager::DeviceManager::new(
        inv.clone(),
    ));
    let pol = Arc::new(rust_junosmcp_core::policy::Policy::build(&inv).unwrap());

    let args = rust_junosmcp_core::tools::TemplateArgs {
        template_content: "set system host-name {{ name }}".into(),
        vars_content: r#"{"name":"jmcp-test"}"#.into(),
        device_name: Some("r1".into()),
        device_names: None,
        apply_config: true,
        commit_comment: "rust-junosmcp template smoke".into(),
        dry_run: true,
        config_format: None,
        mode: "merge".into(),
        confirm_timeout_mins: None,
        timeout: 360,
    };

    let r = rust_junosmcp_core::tools::template::handle(args, dm, pol)
        .await
        .expect("handle ok");
    let row = &r["results"][0];
    assert_eq!(row["router"], "r1");
    assert!(row.get("diff").is_some(), "expected dry-run diff field");
    assert!(
        row.get("commit_comment").is_none(),
        "expected no commit_comment in dry-run"
    );
}

#[tokio::test]
#[ignore]
async fn live_add_device_persists_then_reload() {
    let host = env("JMCP_TEST_HOST");
    let user = env("JMCP_TEST_USER");
    let pass = env("JMCP_TEST_PASS");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    std::fs::write(&path, r#"{}"#).unwrap();

    let inv = Arc::new(Inventory::load(&path).unwrap());
    let hash = rust_junosmcp_core::inventory::hash_file(&path).unwrap();
    let dm = Arc::new(DeviceManager::with_path(
        inv,
        path.clone(),
        hash,
        false,
        true, // allow_password_auth_add=true for the live test
    ));

    let args = rust_junosmcp_core::tools::AddDeviceArgs {
        device_name: Some("live-test".into()),
        device_ip: Some(host.clone()),
        device_port: Some(22),
        username: Some(user.clone()),
        auth: Some(rust_junosmcp_core::inventory::AddDeviceAuth::Password {
            password: pass.clone(),
        }),
    };

    let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
        rust_junosmcp_core::Policy::build(&dm.inventory()).unwrap(),
    )));

    let r = rust_junosmcp_core::tools::add_device::handle(args, dm.clone(), policy.clone())
        .await
        .expect("add_device handle ok");
    assert_eq!(r["added"], "live-test");

    // Reload no-args; must observe the device.
    let r2 = rust_junosmcp_core::tools::reload_devices::handle(
        rust_junosmcp_core::tools::ReloadDevicesArgs::default(),
        dm.clone(),
        policy,
    )
    .await
    .expect("reload ok");
    assert_eq!(r2["new_router_count"], 1);
    assert!(dm.inventory().get("live-test").is_ok());
}

// --- Sub-project: transfer_file real-device round-trip tests ----------------
//
// Required env vars:
//   TEST_DEVICE_NAME   — name of an inventory entry that uses ssh_key auth
//   TEST_INVENTORY_PATH — absolute path to a devices.json with that entry
//
// These tests are #[ignore]'d and MUST NOT be run in CI without a live device.

/// Build a (DeviceManager, TransferConfig, device_name) triple from env vars.
///
/// Panics with a descriptive message if the required env vars are missing,
/// so operators see exactly what to set when running manually.
fn setup_real_transfer_env() -> (Arc<DeviceManager>, TransferConfig, String) {
    let device_name =
        std::env::var("TEST_DEVICE_NAME").expect("set TEST_DEVICE_NAME=<inventory-entry-name>");
    let inv_path = std::env::var("TEST_INVENTORY_PATH")
        .expect("set TEST_INVENTORY_PATH=<path-to-devices.json>");
    let inv_path = std::path::PathBuf::from(inv_path);

    let inv = Arc::new(Inventory::load(&inv_path).unwrap());
    let hash = rust_junosmcp_core::inventory::hash_file(&inv_path).unwrap();
    let dm = Arc::new(DeviceManager::with_path(inv, inv_path, hash, false, false));

    // Use a fresh temp dir as the staging area for each test suite invocation.
    // We use `into_path()` so the directory persists for the duration of the
    // test (the caller is responsible for cleanup; these are #[ignore]'d tests
    // against a real lab device so operator-owned state is acceptable).
    let staging_dir = tempfile::tempdir().unwrap().keep();

    let cfg = TransferConfig {
        staging_dir,
        known_hosts_file: std::path::PathBuf::from("/etc/jmcp/known_hosts"),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(
            rust_junosmcp_core::tools::transfer_file::TransferLocks::default(),
        ),
        // `#[ignore]`-gated real-device test; host key is pinned in the
        // operator's known_hosts. accept-new keeps first-contact runs
        // working when the file is fresh.
        host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::AcceptNew,
    };

    (dm, cfg, device_name)
}

#[tokio::test]
#[ignore = "real device — requires TEST_DEVICE_NAME + TEST_INVENTORY_PATH + ssh_key auth"]
async fn transfer_file_round_trip_1kb() {
    let (dm, cfg, device_name) = setup_real_transfer_env();

    // Write a 1 KB file into the staging dir.
    let filename = "rt-1kb.bin";
    let payload = vec![0xABu8; 1024];
    std::fs::write(cfg.staging_dir.join(filename), &payload).unwrap();

    // First push — must report "transferred".
    let result1 = rust_junosmcp_core::tools::transfer_file::handle(
        TransferFileArgs {
            device: device_name.clone(),
            source_path: filename.into(),
            force: false,
            verify: true,
            timeout: 120,
        },
        dm.clone(),
        cfg.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("first push should succeed");

    assert_eq!(result1["status"], "transferred", "first push: {result1}");
    assert_eq!(result1["size_bytes"], 1024_u64, "first push size_bytes");

    // Second push with identical content — must be idempotent ("skipped").
    let result2 = rust_junosmcp_core::tools::transfer_file::handle(
        TransferFileArgs {
            device: device_name.clone(),
            source_path: filename.into(),
            force: false,
            verify: true,
            timeout: 120,
        },
        dm.clone(),
        cfg.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("second push should succeed (idempotent skip)");

    assert_eq!(
        result2["status"], "skipped",
        "second push should be skipped: {result2}"
    );
    assert_eq!(
        result2["sha256"], result1["sha256"],
        "sha256 must match between pushes"
    );
}

#[tokio::test]
#[ignore = "real device — 200 MB transfer, slow"]
async fn transfer_file_round_trip_200mb() {
    let (dm, cfg, device_name) = setup_real_transfer_env();

    const SIZE: u64 = 200 * 1024 * 1024;
    let filename = "rt-200mb.bin";

    // Allocate and write a 200 MB file (all zeros — fast to generate).
    {
        use std::io::Write as _;
        let path = cfg.staging_dir.join(filename);
        let mut f = std::fs::File::create(&path).unwrap();
        let chunk = vec![0u8; 64 * 1024];
        let mut written: u64 = 0;
        while written < SIZE {
            let n = (SIZE - written).min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..n]).unwrap();
            written += n as u64;
        }
    }

    let result = rust_junosmcp_core::tools::transfer_file::handle(
        TransferFileArgs {
            device: device_name.clone(),
            source_path: filename.into(),
            force: true, // overwrite any previous run's leftover
            verify: true,
            timeout: 900, // 15 min — generous for a 200 MB SCP to a vSRX
        },
        dm.clone(),
        cfg.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("200 MB push should succeed");

    assert_eq!(result["status"], "transferred", "200 MB push: {result}");
    assert_eq!(result["size_bytes"], SIZE, "size_bytes must equal 200 MiB");
    assert_eq!(
        result["verified"], true,
        "post-transfer verification must pass"
    );
}

#[tokio::test]
#[ignore = "real device — requires TEST_DEVICE_NAME + TEST_INVENTORY_PATH + ssh_key auth"]
async fn transfer_file_force_false_rejects_diff() {
    let (dm, cfg, device_name) = setup_real_transfer_env();

    let filename = "collide.bin";

    // Push "version-A".
    std::fs::write(cfg.staging_dir.join(filename), b"version-A").unwrap();
    let r_a = rust_junosmcp_core::tools::transfer_file::handle(
        TransferFileArgs {
            device: device_name.clone(),
            source_path: filename.into(),
            force: true, // ensure a clean slate regardless of prior test runs
            verify: true,
            timeout: 120,
        },
        dm.clone(),
        cfg.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("version-A push should succeed");
    assert_eq!(r_a["status"], "transferred", "version-A push: {r_a}");

    // Overwrite local staging file with "version-B" (different content, same name).
    std::fs::write(cfg.staging_dir.join(filename), b"version-B").unwrap();

    // Second push with force=false — must reject with DestExistsDiffers.
    // The remote still holds "version-A" after the rejected B push.
    // This is expected lab state for an #[ignore]'d test; cleanup is the
    // operator's responsibility.
    let res = rust_junosmcp_core::tools::transfer_file::handle(
        TransferFileArgs {
            device: device_name.clone(),
            source_path: filename.into(),
            force: false,
            verify: true,
            timeout: 120,
        },
        dm.clone(),
        cfg.clone(),
        CancellationToken::new(),
    )
    .await;

    assert!(
        matches!(
            res,
            Err(rust_junosmcp_core::JmcpError::DestExistsDiffers { .. })
        ),
        "expected DestExistsDiffers, got: {res:?}"
    );
}

//! `reload_devices` — re-read the current inventory or swap to a new path.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::{Inventory, hash_file};
use crate::policy::Policy;
use crate::tools::ReloadDevicesArgs;
use arc_swap::ArcSwap;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

/// MCP-facing reload: re-read or swap the inventory file.
///
/// Rejects the call if inventory mutation is disabled (`--inventory-readonly`).
/// Takes the device manager write lock, validates the new path is within the
/// inventory directory (RJMCP-SEC-005: prevents symlink/traversal escapes),
/// checks the file exists and is non-empty, rebuilds the policy from the new
/// inventory, hashes and swaps the inventory and policy into memory together,
/// invalidates pooled sessions for removed/changed devices, and returns
/// added/removed/changed counts. The new inventory and the policy built from
/// it are validated together before either is swapped in: on any validation
/// failure this returns `Err` and leaves the previous inventory, policy, and
/// pooled sessions untouched.
pub async fn handle(
    args: ReloadDevicesArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<ArcSwap<Policy>>,
) -> Result<serde_json::Value, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    reload(args, dm, policy).await
}

/// Re-read the already-configured inventory path from trusted process code.
///
/// Unlike the MCP-facing [`handle`], this operation is allowed when inventory
/// mutation is disabled because it cannot select another path or write data.
/// It exists for process control paths such as SIGHUP configuration refresh.
pub async fn reload_current_from_disk(
    dm: Arc<DeviceManager>,
    policy: Arc<ArcSwap<Policy>>,
) -> Result<serde_json::Value, JmcpError> {
    reload(ReloadDevicesArgs::default(), dm, policy).await
}

async fn reload(
    args: ReloadDevicesArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<ArcSwap<Policy>>,
) -> Result<serde_json::Value, JmcpError> {
    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let prev_path = dm.inventory_path();
    let path: PathBuf = match args.file_name.as_deref() {
        None | Some("") => prev_path.clone(),
        Some(p) => {
            let candidate = PathBuf::from(p);
            // Reject path traversal (defense-in-depth — the canonicalize
            // check below also catches this, but failing early gives a
            // clearer error.)
            if candidate
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(JmcpError::InventoryInvalid(
                    "file_name must not contain '..' path components".into(),
                ));
            }
            // RJMCP-SEC-005: file_name must be a *relative* path inside the
            // inventory directory. Absolute paths are rejected outright.
            if candidate.is_absolute() {
                return Err(JmcpError::InventoryInvalid(
                    "file_name must be a relative path within the inventory directory".into(),
                ));
            }
            let parent = prev_path.parent().ok_or_else(|| {
                JmcpError::InventoryInvalid("current inventory path has no parent directory".into())
            })?;
            parent.join(&candidate)
        }
    };

    if !path.is_file() {
        return Err(JmcpError::InventoryRead(format!(
            "not a regular file: {}",
            path.display(),
        )));
    }

    // RJMCP-SEC-005: after the file is confirmed to exist, canonicalize
    // both the inventory directory and the candidate path and reject if
    // the candidate escapes the directory (covers symlink-out attacks).
    // Skip when the candidate equals the current inventory file — the
    // "no file_name" path needs no further restriction.
    if args.file_name.as_deref().is_some_and(|s| !s.is_empty()) {
        let inv_dir = prev_path
            .parent()
            .ok_or_else(|| {
                JmcpError::InventoryInvalid("current inventory path has no parent directory".into())
            })?
            .canonicalize()
            .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
        let resolved = path
            .canonicalize()
            .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
        if !resolved.starts_with(&inv_dir) {
            return Err(JmcpError::InventoryInvalid(format!(
                "file_name resolves outside inventory directory (resolved={}, inventory_dir={})",
                resolved.display(),
                inv_dir.display(),
            )));
        }
    }

    let new_inv = Inventory::load(&path).map_err(|e| JmcpError::InventoryParse(e.to_string()))?;
    if new_inv.is_empty() {
        return Err(JmcpError::EmptyInventory);
    }

    let prev = dm.inventory();
    let prev_count = prev.len();
    let new_count = new_inv.len();

    let prev_names: std::collections::BTreeSet<String> = prev.names().into_iter().collect();
    let new_names: std::collections::BTreeSet<String> = new_inv.names().into_iter().collect();
    let added: Vec<String> = new_names.difference(&prev_names).cloned().collect();
    let removed: Vec<String> = prev_names.difference(&new_names).cloned().collect();
    let mut changed: Vec<String> = Vec::new();
    for name in prev_names.intersection(&new_names) {
        if let (Ok(p), Ok(n)) = (prev.get(name), new_inv.get(name))
            && !inventory_entry_equal(p, n)
        {
            changed.push(name.clone());
        }
    }

    // Build the policy from the new inventory *before* anything is swapped
    // in. On failure, return without touching the inventory, the policy, or
    // the pool — the previous, known-good state keeps governing every
    // existing device.
    let new_policy = Policy::build(&new_inv)?;

    let new_hash = hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    tracing::info!(
        prev = %prev_path.display(),
        new = %path.display(),
        "reload_devices: inventory swapped"
    );
    dm.store_inventory(Arc::new(new_inv), path.clone(), new_hash);
    policy.store(Arc::new(new_policy));

    // Invalidate pooled sessions for removed or changed routers.
    let invalidate: Vec<String> = removed.iter().chain(changed.iter()).cloned().collect();
    if !invalidate.is_empty() {
        dm.invalidate_pool(&invalidate).await;
    }

    Ok(json!({
        "previous_router_count": prev_count,
        "new_router_count": new_count,
        "added": added,
        "removed": removed,
        "changed": changed,
        "inventory_path": path,
    }))
}

fn inventory_entry_equal(
    a: &crate::inventory::DeviceEntry,
    b: &crate::inventory::DeviceEntry,
) -> bool {
    a.ip == b.ip && a.port == b.port && a.username == b.username && a.auth == b.auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dm_at(path: &std::path::Path, readonly: bool) -> Arc<DeviceManager> {
        let inv = Arc::new(Inventory::load(path).unwrap());
        let hash = crate::inventory::hash_file(path).unwrap();
        Arc::new(DeviceManager::with_path(
            inv,
            path.to_path_buf(),
            hash,
            readonly,
            false,
        ))
    }

    fn test_policy(inv: &Inventory) -> Arc<ArcSwap<Policy>> {
        Arc::new(ArcSwap::from(Arc::new(Policy::build(inv).unwrap())))
    }

    fn write_file(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// Write two inventory files into the same tempdir and return
    /// `(dir, first_path, second_filename)` so callers can pass the second
    /// inventory's *basename* as `file_name` (required by the v0.5.2 path
    /// policy).
    fn paired_inventories(
        first_json: &str,
        second_json: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let dir = tempfile::TempDir::new().unwrap();
        let p1 = dir.path().join("inventory.json");
        let p2 = dir.path().join("inventory2.json");
        crate::helpers::write_restricted_fixture(&p1, first_json);
        crate::helpers::write_restricted_fixture(&p2, second_json);
        (dir, p1, "inventory2.json".to_string())
    }

    #[tokio::test]
    async fn reload_no_args_re_reads_current_path() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);

        // Edit the file externally.
        crate::helpers::write_restricted_fixture(
            f.path(),
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                 "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );

        let policy = test_policy(&dm.inventory());
        let r = handle(ReloadDevicesArgs::default(), dm.clone(), policy)
            .await
            .unwrap();
        assert_eq!(r["previous_router_count"], 1);
        assert_eq!(r["new_router_count"], 2);
        assert!(r["added"].as_array().unwrap().iter().any(|v| v == "r2"));
        assert!(dm.inventory().get("r2").is_ok());
    }

    #[tokio::test]
    async fn reload_with_file_name_swaps_inventory() {
        let (_dir, p1, name2) = paired_inventories(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            r#"{"r9":{"ip":"127.0.0.9","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(&p1, false);

        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(name2),
            },
            dm.clone(),
            policy,
        )
        .await
        .unwrap();

        assert_eq!(r["new_router_count"], 1);
        assert!(dm.inventory().get("r9").is_ok());
        assert!(dm.inventory().get("r1").is_err());
    }

    #[tokio::test]
    async fn reload_empty_inventory_rejected() {
        let (_dir, p1, name2) = paired_inventories(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            r#"{}"#,
        );
        let dm = dm_at(&p1, false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(name2),
            },
            dm,
            policy,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::EmptyInventory)));
    }

    #[tokio::test]
    async fn reload_inventory_readonly_rejected() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), true);
        let policy = test_policy(&dm.inventory());
        let r = handle(ReloadDevicesArgs::default(), dm, policy).await;
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[tokio::test]
    async fn trusted_current_path_reload_works_when_inventory_is_readonly() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), true);

        crate::helpers::write_restricted_fixture(
            f.path(),
            r#"{"r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );

        let policy = test_policy(&dm.inventory());
        let result = reload_current_from_disk(dm.clone(), policy).await.unwrap();
        assert_eq!(result["new_router_count"], 1);
        assert!(dm.inventory().get("r2").is_ok());
        assert!(dm.inventory().get("r1").is_err());
    }

    #[tokio::test]
    async fn reload_reports_added_removed_changed_diff() {
        let (_dir, p1, name2) = paired_inventories(
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "gone":{"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"v","auth":{"type":"password","password":"x"}},
                "new":{"ip":"10.0.0.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = dm_at(&p1, false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(name2),
            },
            dm,
            policy,
        )
        .await
        .unwrap();
        let added: Vec<String> = serde_json::from_value(r["added"].clone()).unwrap();
        let removed: Vec<String> = serde_json::from_value(r["removed"].clone()).unwrap();
        let changed: Vec<String> = serde_json::from_value(r["changed"].clone()).unwrap();
        assert_eq!(added, vec!["new"]);
        assert_eq!(removed, vec!["gone"]);
        assert_eq!(changed, vec!["mut"]);
    }

    #[tokio::test]
    async fn reload_rejects_path_traversal() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some("../../../etc/shadow".into()),
            },
            dm,
            policy,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(ref msg)) if msg.contains("..")));
    }

    #[tokio::test]
    async fn reload_detects_password_change() {
        let (_dir, p1, name2) = paired_inventories(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"old"}}}"#,
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"new"}}}"#,
        );
        let dm = dm_at(&p1, false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(name2),
            },
            dm,
            policy,
        )
        .await
        .unwrap();
        let changed: Vec<String> = serde_json::from_value(r["changed"].clone()).unwrap();
        assert_eq!(changed, vec!["r1"], "password change must be detected");
    }

    /// RJMCP-SEC-005: absolute paths are rejected outright.
    #[tokio::test]
    async fn reload_rejects_absolute_path() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some("/etc/passwd".into()),
            },
            dm,
            policy,
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::InventoryInvalid(ref msg)) if msg.contains("relative")),
            "expected absolute-path rejection, got {r:?}"
        );
    }

    /// RJMCP-SEC-005: a symlink inside the inventory dir that targets a
    /// file outside that dir is rejected at canonicalization.
    #[cfg(unix)]
    #[tokio::test]
    async fn reload_rejects_symlink_escape() {
        let inv_dir = tempfile::TempDir::new().unwrap();
        let inv_path = inv_dir.path().join("inventory.json");
        crate::helpers::write_restricted_fixture(
            &inv_path,
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );

        let outside_dir = tempfile::TempDir::new().unwrap();
        let outside_target = outside_dir.path().join("evil.json");
        crate::helpers::write_restricted_fixture(
            &outside_target,
            r#"{"r99":{"ip":"127.0.0.99","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );

        // Sibling symlink inside the inventory dir pointing outside.
        let escape = inv_dir.path().join("escape.json");
        std::os::unix::fs::symlink(&outside_target, &escape).unwrap();

        let dm = dm_at(&inv_path, false);
        let policy = test_policy(&dm.inventory());
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some("escape.json".into()),
            },
            dm,
            policy,
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::InventoryInvalid(ref msg)) if msg.contains("outside")),
            "expected symlink-escape rejection, got {r:?}"
        );
    }

    /// A reload whose new inventory parses but whose policy fails to build
    /// must fail closed on every axis — inventory, policy, and pool — not
    /// just the policy.
    #[tokio::test]
    async fn reload_with_file_name_rejected_when_new_policy_fails_to_build() {
        let (_dir, p1, name2) = paired_inventories(
            r#"{
                "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"request system reboot*"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
            r#"{
                "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"request system reboot*"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"2.2.2.2","username":"u","auth":{"type":"password","password":"x"},
                      "blocklist":{"commands":[{"action":"deny","pattern":"[unterminated"}]}}
            }"#,
        );
        let dm = dm_at(&p1, false);
        let policy = test_policy(&dm.inventory());
        let policy_before = policy.load_full();
        let hash_before = dm.inventory_hash();

        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(name2),
            },
            dm.clone(),
            policy.clone(),
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::BlocklistRuleInvalid { .. })),
            "expected BlocklistRuleInvalid, got {r:?}"
        );

        // (b) the in-memory inventory is unchanged: the new device never
        // appears, and the hash used for the next TOCTOU check is untouched.
        assert_eq!(dm.inventory().len(), 1);
        assert!(dm.inventory().get("r2").is_err());
        assert_eq!(dm.inventory_hash(), hash_before);

        // (c) a device still decided by the old policy *and* the old
        // inventory: r1's pre-existing deny rule is still enforced, proving
        // the old policy (not a half-built one) is what governs it.
        assert!(
            !policy
                .load()
                .check_command("r1", "request system reboot")
                .is_allowed(),
            "the old policy's deny rule must still be enforced after a failed reload"
        );
        assert!(
            Arc::ptr_eq(&policy.load_full(), &policy_before),
            "policy must not be swapped when the rebuild fails"
        );
    }

    /// (d) Same failure mode via the SIGHUP path
    /// ([`reload_current_from_disk`]), which has no caller to report `Err`
    /// to but must leave the same state untouched.
    #[tokio::test]
    async fn sighup_reload_rejected_when_new_policy_fails_to_build() {
        let f = write_file(
            r#"{
                "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"request system reboot*"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = dm_at(f.path(), false);
        let policy = test_policy(&dm.inventory());
        let policy_before = policy.load_full();
        let hash_before = dm.inventory_hash();

        // Mutate the file in place, as SIGHUP would re-read it.
        crate::helpers::write_restricted_fixture(
            f.path(),
            r#"{
                "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"request system reboot*"}]},
                "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"2.2.2.2","username":"u","auth":{"type":"password","password":"x"},
                      "blocklist":{"commands":[{"action":"deny","pattern":"[unterminated"}]}}
            }"#,
        );

        let r = reload_current_from_disk(dm.clone(), policy.clone()).await;
        assert!(
            matches!(r, Err(JmcpError::BlocklistRuleInvalid { .. })),
            "expected BlocklistRuleInvalid, got {r:?}"
        );

        assert_eq!(dm.inventory().len(), 1);
        assert!(dm.inventory().get("r2").is_err());
        assert_eq!(dm.inventory_hash(), hash_before);
        assert!(
            !policy
                .load()
                .check_command("r1", "request system reboot")
                .is_allowed(),
            "the old policy's deny rule must still be enforced after a failed SIGHUP reload"
        );
        assert!(
            Arc::ptr_eq(&policy.load_full(), &policy_before),
            "policy must not be swapped when the rebuild fails"
        );
    }
}

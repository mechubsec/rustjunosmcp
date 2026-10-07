//! `add_device` — validate, persist atomically, swap inventory.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
#[cfg(test)]
use crate::inventory::AddDeviceAuth;
use crate::inventory::AuthConfig;
use crate::inventory::validation::{
    is_valid_auth_path, is_valid_device_name, is_valid_ip_or_hostname, is_valid_ssh_username,
};
use crate::policy::Policy;
use crate::tools::AddDeviceArgs;
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Resolved and validated `add_device` arguments.
///
/// Produced by `validate()`. Contains only well-formed values that passed all
/// validation gates: device name does not exist, IP/hostname is valid, port is
/// in range, username satisfies the SSH naming constraints, and auth type is
/// allowed by the server's policy.
#[derive(Debug)]
pub struct ResolvedAdd {
    /// Validated device name (does not exist in inventory).
    pub device_name: String,
    /// Validated IP address or hostname.
    pub device_ip: String,
    /// Validated port (1..=65535, defaults to 22).
    pub device_port: u32,
    /// Validated SSH username (matches constraints, does not start with `-`).
    pub username: String,
    /// Validated auth config (SSH-key or password, if password auth is enabled).
    pub auth: AuthConfig,
}

/// Validate `add_device` arguments without touching disk or locks.
///
/// Pure function that checks: inventory is not readonly, all required fields
/// are present, device name is valid and does not already exist, IP/hostname
/// is valid, port is in range (1..=65535), username matches SSH constraints,
/// auth type is allowed, and paths do not start with `-`. Returns the resolved
/// bundle or the most specific error.
pub fn validate(args: &AddDeviceArgs, dm: &DeviceManager) -> Result<ResolvedAdd, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    let mut missing: Vec<String> = Vec::new();
    if args.device_name.is_none() {
        missing.push("device_name".into());
    }
    if args.device_ip.is_none() {
        missing.push("device_ip".into());
    }
    if args.username.is_none() {
        missing.push("username".into());
    }
    if args.auth.is_none() {
        missing.push("auth".into());
    }
    if !missing.is_empty() {
        return Err(JmcpError::MissingArguments(missing));
    }

    let device_name = args
        .device_name
        .clone()
        .expect("device_name is Some: validated by early return");
    if !is_valid_device_name(&device_name) {
        return Err(JmcpError::InvalidDeviceName(device_name));
    }
    let inv = dm.inventory();
    if inv.get(&device_name).is_ok() {
        return Err(JmcpError::DeviceExists(device_name));
    }

    let device_ip = args
        .device_ip
        .clone()
        .expect("device_ip is Some: validated by early return");
    if !is_valid_ip_or_hostname(&device_ip) {
        return Err(JmcpError::InvalidDeviceIp(device_ip));
    }

    let device_port = args.device_port.unwrap_or(22);
    if !(1..=65535).contains(&device_port) {
        return Err(JmcpError::InvalidDevicePort(device_port));
    }

    let auth: AuthConfig = args
        .auth
        .clone()
        .expect("auth is Some: validated by early return")
        .into();
    if matches!(auth, AuthConfig::Password { .. }) && !dm.allow_password_auth_add() {
        return Err(JmcpError::PasswordAuthDisabled);
    }
    if let AuthConfig::SshKey { private_key_path } = &auth
        && !is_valid_auth_path(private_key_path)
    {
        return Err(JmcpError::Validation(format!(
            "invalid private_key_path `{}`: must be non-empty and must not start with '-'",
            private_key_path.display()
        )));
    }

    let username = args
        .username
        .clone()
        .expect("username is Some: validated by early return");
    if !is_valid_ssh_username(&username) {
        return Err(JmcpError::Validation(format!(
            "invalid username `{username}`: must match ^[A-Za-z0-9_.-]{{1,64}}$ and must not start with '-'"
        )));
    }

    Ok(ResolvedAdd {
        device_name,
        device_ip,
        device_port,
        username,
        auth,
    })
}

/// Add a device to the inventory file atomically.
///
/// Validates arguments, takes the device manager write lock, reads the current
/// inventory from disk, checks the hash matches (TOCTOU guard), inserts the new
/// device entry, and stages it to a temp file. The staged inventory and the
/// policy built from it are validated together *before* anything durable
/// happens: on any validation failure, the staged file is discarded and this
/// returns `Err` without touching the on-disk inventory, the in-memory
/// inventory, or the policy. Only once both validate is the staged file
/// renamed into place and the device manager and policy swapped in together,
/// still under the write lock. Returns `{added, inventory_path, router_count}`.
pub async fn handle(
    args: AddDeviceArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<ArcSwap<Policy>>,
) -> Result<serde_json::Value, JmcpError> {
    let resolved = validate(&args, &dm)?;

    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let path = dm.inventory_path();
    if path.as_os_str().is_empty() {
        return Err(JmcpError::InventoryWrite(
            "inventory has no on-disk path; add_device requires --device-mapping to point at a writable file".into(),
        ));
    }

    // TOCTOU guard: re-read disk and verify hash.
    let on_disk_hash =
        crate::inventory::hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    if on_disk_hash != dm.inventory_hash() {
        return Err(JmcpError::InventoryDriftedOnDisk);
    }

    let raw = std::fs::read(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| JmcpError::InventoryParse(e.to_string()))?;

    let updated = crate::inventory::insert_device(
        &value,
        &resolved.device_name,
        &resolved.device_ip,
        resolved.device_port,
        &resolved.username,
        &resolved.auth,
    )?;

    let tmp = crate::inventory::stage_atomic(&path, &updated)
        .map_err(|e| JmcpError::InventoryWrite(e.to_string()))?;

    // Validate the staged content fully (parse + policy build) before this
    // mutation becomes visible anywhere. On failure, `tmp` is dropped here
    // and cleans up its own file; `path` and the device manager are
    // untouched.
    let staged_inv = crate::inventory::Inventory::load(tmp.path())
        .map_err(|e| JmcpError::InventoryParse(e.to_string()))?;
    let new_policy = Policy::build(&staged_inv)?;

    // Hash the staged file before persisting it, so the stored hash and
    // in-memory inventory are guaranteed to match the exact content just
    // validated above rather than whatever is at `path` by the time it is
    // read back.
    let new_hash = crate::inventory::hash_file(tmp.path())
        .map_err(|e| JmcpError::InventoryRead(e.to_string()))?;

    tmp.persist(&path)
        .map_err(|e| JmcpError::InventoryWrite(e.error.to_string()))?;

    dm.store_inventory(Arc::new(staged_inv), path.clone(), new_hash);
    policy.store(Arc::new(new_policy));

    Ok(serde_json::json!({
        "added": resolved.device_name,
        "inventory_path": path,
        "router_count": dm.inventory().len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm_with(json: &str, readonly: bool, allow_pw: bool) -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        Arc::new(DeviceManager::with_path(
            inv,
            f.path().to_path_buf(),
            crate::inventory::hash_file(f.path()).unwrap(),
            readonly,
            allow_pw,
        ))
    }

    fn test_policy(inv: &Inventory) -> Arc<ArcSwap<Policy>> {
        Arc::new(ArcSwap::from(Arc::new(Policy::build(inv).unwrap())))
    }

    fn args_full() -> AddDeviceArgs {
        AddDeviceArgs {
            device_name: Some("core-3".into()),
            device_ip: Some("10.0.0.3".into()),
            device_port: Some(22),
            username: Some("automation".into()),
            auth: Some(AddDeviceAuth::SshKey {
                private_key_path: "/etc/jmcp/keys/id".into(),
            }),
        }
    }

    #[test]
    fn rejects_when_inventory_readonly() {
        let dm = dm_with(r#"{}"#, true, false);
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[test]
    fn rejects_existing_device_name() {
        let dm = dm_with(
            r#"{"core-3":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            false,
            true,
        );
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::DeviceExists(ref n)) if n == "core-3"));
    }

    #[test]
    fn rejects_missing_required_fields_with_list() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = None;
        a.username = None;
        let r = validate(&a, &dm);
        match r {
            Err(JmcpError::MissingArguments(v)) => {
                assert!(v.contains(&"device_name".to_string()));
                assert!(v.contains(&"username".to_string()));
            }
            other => panic!("expected MissingArguments, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_name_with_shell_meta() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = Some("evil; rm -rf /".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceName(_))));
    }

    #[test]
    fn rejects_invalid_ip_garbage() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("not an ip or host".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceIp(_))));
    }

    #[test]
    fn accepts_hostname_form() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("router-3.example.net".into());
        let r = validate(&a, &dm).unwrap();
        assert_eq!(r.device_ip, "router-3.example.net");
    }

    #[test]
    fn rejects_out_of_range_port() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_port = Some(70_000);
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDevicePort(70_000))));
    }

    #[test]
    fn rejects_password_auth_when_flag_disabled() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.auth = Some(AddDeviceAuth::Password {
            password: "x".into(),
        });
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::PasswordAuthDisabled)));
    }

    #[test]
    fn accepts_password_auth_when_flag_enabled() {
        let dm = dm_with(r#"{}"#, false, true);
        let mut a = args_full();
        a.auth = Some(AddDeviceAuth::Password {
            password: "x".into(),
        });
        validate(&a, &dm).unwrap();
    }

    #[test]
    fn rejects_username_starting_with_dash() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.username = Some("-oProxyCommand=foo".into());
        let r = validate(&a, &dm);
        assert!(
            matches!(r, Err(JmcpError::Validation(ref s)) if s.contains("username")),
            "expected Validation error for dash-prefixed username, got {r:?}"
        );
    }

    #[test]
    fn rejects_username_with_space() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.username = Some("user with space".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::Validation(_))));
    }

    #[test]
    fn rejects_private_key_path_starting_with_dash() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.auth = Some(AddDeviceAuth::SshKey {
            private_key_path: "-evil".into(),
        });
        let r = validate(&a, &dm);
        assert!(
            matches!(r, Err(JmcpError::Validation(ref s)) if s.contains("private_key_path")),
            "expected Validation error for dash-prefixed key path, got {r:?}"
        );
    }

    #[test]
    fn accepts_typical_usernames() {
        let dm = dm_with(r#"{}"#, false, false);
        for name in ["admin", "netconf", "user.name", "user-name", "user_name"] {
            let mut a = args_full();
            a.username = Some(name.into());
            validate(&a, &dm).unwrap_or_else(|e| panic!("expected '{name}' accepted, got {e:?}"));
        }
    }

    #[tokio::test]
    async fn add_device_persists_to_disk_and_swaps_in_memory() {
        // Use a tempdir so the inventory file outlives dm_with's scope.
        let dir = tempfile::TempDir::new().unwrap();
        let inv_path = dir.path().join("devices.json");
        let json = r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#;
        crate::helpers::write_restricted_fixture(&inv_path, json);
        let inv = Arc::new(Inventory::load(&inv_path).unwrap());
        let hash = crate::inventory::hash_file(&inv_path).unwrap();
        let dm = Arc::new(DeviceManager::with_path(
            inv,
            inv_path.clone(),
            hash,
            false,
            true,
        ));

        let key = tempfile::NamedTempFile::new().unwrap();
        let mut args = args_full();
        args.auth = Some(AddDeviceAuth::SshKey {
            private_key_path: key.path().to_path_buf(),
        });
        let policy = test_policy(&dm.inventory());
        let r = handle(args, dm.clone(), policy.clone()).await.unwrap();
        assert_eq!(r["added"], "core-3");
        assert_eq!(dm.inventory().len(), 2);
        // Verify disk was updated.
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dm.inventory_path()).unwrap()).unwrap();
        assert!(on_disk.get("core-3").is_some());
        // key tempfile must stay alive until after handle() returns.
        drop(key);
    }

    /// If the post-add inventory can't produce a working policy, the add must
    /// fail closed: no on-disk write, no in-memory inventory swap, no policy
    /// swap.
    #[tokio::test]
    async fn add_device_rejected_when_resulting_policy_fails_to_build() {
        let dir = tempfile::TempDir::new().unwrap();
        let inv_path = dir.path().join("devices.json");
        let bad_json = r#"{
            "_blocklist_defaults": {"mode":"blocklist","commands":[{"action":"deny","pattern":"[unterminated"}]},
            "core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#;
        crate::helpers::write_restricted_fixture(&inv_path, bad_json);
        let inv = Arc::new(Inventory::load(&inv_path).unwrap());
        let hash = crate::inventory::hash_file(&inv_path).unwrap();
        let dm = Arc::new(DeviceManager::with_path(
            inv,
            inv_path.clone(),
            hash,
            false,
            true,
        ));

        // Stand-in for "the last policy that built successfully". This test
        // only asserts it is left in place on failure, not what it permits.
        let policy = test_policy(&Inventory::empty());
        let policy_before = policy.load_full();

        let key = tempfile::NamedTempFile::new().unwrap();
        let mut args = args_full();
        args.auth = Some(AddDeviceAuth::SshKey {
            private_key_path: key.path().to_path_buf(),
        });

        let r = handle(args, dm.clone(), policy.clone()).await;
        assert!(
            matches!(r, Err(JmcpError::BlocklistRuleInvalid { .. })),
            "expected BlocklistRuleInvalid, got {r:?}"
        );

        assert_eq!(
            dm.inventory().len(),
            1,
            "device must not be added to the in-memory inventory"
        );
        assert!(dm.inventory().get("core-3").is_err());
        assert_eq!(
            dm.inventory_hash(),
            hash,
            "in-memory hash must be unchanged"
        );
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&inv_path).unwrap()).unwrap();
        assert!(
            on_disk.get("core-3").is_none(),
            "on-disk inventory must not be mutated"
        );
        assert!(
            Arc::ptr_eq(&policy.load_full(), &policy_before),
            "policy must not be swapped when the rebuild fails"
        );
        drop(key);
    }

    #[tokio::test]
    async fn add_device_drift_check_rejects_external_edit() {
        // Use a tempdir so the inventory file stays alive after setup.
        let dir = tempfile::TempDir::new().unwrap();
        let inv_path = dir.path().join("devices.json");
        crate::helpers::write_restricted_fixture(&inv_path, r#"{}"#);
        let inv = Arc::new(Inventory::load(&inv_path).unwrap());
        let hash = crate::inventory::hash_file(&inv_path).unwrap();
        let dm = Arc::new(DeviceManager::with_path(
            inv,
            inv_path.clone(),
            hash,
            false,
            true,
        ));

        // Mutate the file from underneath us, but leave the in-memory hash stale.
        crate::helpers::write_restricted_fixture(
            dm.inventory_path(),
            r#"{"sneaky":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let policy = test_policy(&dm.inventory());
        let r = handle(args_full(), dm, policy).await;
        assert!(matches!(r, Err(JmcpError::InventoryDriftedOnDisk)));
    }
}

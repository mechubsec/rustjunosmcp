#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! A pooled or locked NETCONF session stays bound to the `(ip, port)` it
//! connected to, even when an inventory reload retargets the device name
//! (#602). Two loopback fakes stand in for the old and new device.
mod common;

use common::fake_netconf::{FakeNetconf, OK, Script, client_key_pem};
use common::write_restricted;
use mecmcp_changeset::DeviceTransaction;
use rust_junosmcp_core::junos_transaction::{ConfigPayloadSpec, JunosAction, JunosTransaction};
use rust_junosmcp_core::{DeviceManager, Inventory};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

fn script() -> Script {
    vec![
        ("show version", "<output>fake</output>".to_string()),
        ("<nc:lock>", OK.to_string()),
        ("<nc:unlock>", OK.to_string()),
        ("<nc:load-configuration", OK.to_string()),
        ("<load-configuration", OK.to_string()),
        (
            "outbound-ssh",
            "<output></output>".to_string(),
        ),
        (
            "compare=\"rollback\"",
            "<configuration-information><configuration-output></configuration-output></configuration-information>"
                .to_string(),
        ),
        // Facts the connect handshake gathers.
        (
            "get-software-information",
            "<software-information><host-name>fake</host-name><product-model>fake-srx</product-model></software-information>".to_string(),
        ),
        (
            "get-chassis-inventory",
            "<chassis-inventory><chassis><serial-number>FAKE1</serial-number></chassis></chassis-inventory>".to_string(),
        ),
        (
            "get-route-engine-information",
            "<route-engine-information><route-engine><slot>0</slot></route-engine></route-engine-information>".to_string(),
        ),
        ("close-session", OK.to_string()),
    ]
}

/// An inventory with `r1` pointing at `port` on loopback.
fn inventory_for(dir: &Path, key: &Path, port: u16) -> Arc<Inventory> {
    let path = dir.join(format!("devices-{port}.json"));
    let device = json!({
        "ip": "127.0.0.1",
        "port": port,
        "username": "netconf",
        "auth": { "type": "ssh_key", "private_key_path": key.to_str().unwrap() },
    });
    write_restricted(&path, &json!({ "r1": device }).to_string());
    Arc::new(Inventory::load(&path).unwrap())
}

struct Rig {
    old_device: FakeNetconf,
    new_device: FakeNetconf,
    manager: Arc<DeviceManager>,
    new_inventory: Arc<Inventory>,
    // Holds the key the sessions authenticate with.
    _dir: tempfile::TempDir,
}

fn rig() -> Rig {
    let old_device = FakeNetconf::start(script());
    let new_device = FakeNetconf::start(script());
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    write_restricted(&key, &client_key_pem());
    let old_inventory = inventory_for(dir.path(), &key, old_device.port);
    let new_inventory = inventory_for(dir.path(), &key, new_device.port);
    Rig {
        old_device,
        new_device,
        manager: Arc::new(DeviceManager::new(old_inventory)),
        new_inventory,
        _dir: dir,
    }
}

impl Rig {
    /// What `reload_devices` does: swap the inventory, then purge the pool.
    async fn retarget_r1(&self) {
        self.manager
            .store_inventory(self.new_inventory.clone(), Default::default(), [1; 32]);
        self.manager.invalidate_pool(&["r1".to_string()]).await;
    }
}

#[tokio::test]
async fn a_session_returned_after_a_retarget_is_not_reused() {
    let rig = rig();
    let held = rig.manager.open("r1").await.unwrap();
    assert_eq!(held.endpoint().1, rig.old_device.port);

    rig.retarget_r1().await;
    // The session was checked out during the reload, so it comes back after
    // the purge: `Drop` spawns the return.
    drop(held);
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }

    let mut fresh = rig.manager.open("r1").await.unwrap();
    assert_eq!(fresh.endpoint().1, rig.new_device.port);
    fresh.cli("show version").await.unwrap();

    assert!(rig.new_device.saw("show version"));
    assert!(!rig.old_device.saw("show version"));
}

#[tokio::test]
async fn stage_refuses_a_name_retargeted_after_lock() {
    let rig = rig();
    let transaction = JunosTransaction::new(rig.manager.clone(), "r1".to_string());
    transaction.lock("test").await.unwrap();

    rig.retarget_r1().await;

    let action = JunosAction {
        payload: Some(ConfigPayloadSpec {
            text: "set system host-name x".to_string(),
            format: Some("set".to_string()),
            mode: None,
        }),
        ..Default::default()
    };
    let error = transaction
        .stage(&[action])
        .await
        .err()
        .expect("a retargeted name must be refused");
    assert!(error.to_string().contains("retargeted"), "{error}");

    assert!(
        rig.new_device.requests().is_empty(),
        "{:?}",
        rig.new_device.requests()
    );
    assert!(
        !rig.old_device.saw("<nc:load-configuration") && !rig.old_device.saw("<load-configuration"),
        "{:?}",
        rig.old_device.requests()
    );
    // The old device's candidate was released: unlocked, or the session closed.
    assert!(
        rig.old_device.saw("<nc:unlock>") || rig.old_device.connection_closed(1),
        "{:?}",
        rig.old_device.requests()
    );
}

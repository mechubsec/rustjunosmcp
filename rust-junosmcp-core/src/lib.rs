//! Core logic for rust-junosmcp: inventory, device manager, and MCP tool handlers
//! built on top of [`rustez`].
//!
//! The binary crate `rust-junosmcp` wires this into the rmcp transport.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod bootstrap;
pub mod changeset_recovery;
pub mod config_authority;
pub mod device_manager;
pub mod error;
pub mod helpers;
pub mod inventory;
pub mod junos_commit_metadata;
pub mod junos_transaction;
pub mod output;
pub mod policy;
pub mod progress;
pub mod schema_alias;
pub mod tools;

// Re-export mecmcp-device primitives
pub use mecmcp_device::cancel;
pub use mecmcp_device::{DeviceLock, DeviceLockGuard, FlockDeviceLock};

/// Backward-compatibility alias for `FlockDeviceLock`.
///
/// Existing callers written against the v0.1 API may use this name. New code
/// should use `FlockDeviceLock` directly.
pub type DeviceLeaseManager = FlockDeviceLock;

/// Backward-compatibility alias for `DeviceLockGuard`.
///
/// Existing callers written against the v0.1 API may use this name. New code
/// should use `DeviceLockGuard` directly.
pub type DeviceLeaseGuard = DeviceLockGuard;

/// Default directory for flock-based device lease files.
///
/// Used by the device manager when no custom path is provided. Callers running
/// as the `jmcp` user must ensure this directory exists and is writable.
pub const DEFAULT_DEVICE_LEASE_DIR: &str = "/var/lib/jmcp/device-leases";

pub use device_manager::DeviceManager;
pub use error::JmcpError;
pub use inventory::{AuthConfig, DeviceEntry, Inventory};
pub use policy::Policy;
pub use rustez::HostKeyVerification;
pub use tools::transfer_file::{
    MecmcpScpRunner, MockScpRunner, ScpJob, ScpOutcome, ScpRunner, TransferConfig,
};
pub use tools::upgrade_junos::UpgradeConfig;

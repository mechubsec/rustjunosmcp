//! Configuration ownership tracking for Junos devices.
//!
//! Junos devices may be owned by different management planes (Mist, Security
//! Director Cloud, Security Director On-Prem, or local CLI/NETCONF), and writes
//! to a plane-owned device are transient — overwritten at the next push by the
//! owning plane. This module defines the authority type and integrates with
//! `mecmcp-inventory::ConfigAuthority` to track and audit which system owns a
//! device's configuration.

use serde::{Deserialize, Serialize};

/// Configuration authority for a Junos device.
///
/// Identifies which management plane owns the device's running configuration.
/// Writes made to a device not owned by this server may be overwritten at the
/// next push from the true owner, and the audit record must say so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum JunosAuthority {
    /// This server is the authoritative configuration source.
    Local,
    /// Juniper Mist cloud manages this device.
    Mist,
    /// Security Director Cloud manages this device.
    SecurityDirectorCloud,
    /// Security Director On-Prem manages this device.
    SecurityDirectorOnprem,
    /// Configuration authority is not declared in inventory.
    ///
    /// Treated as `Local` for behaviour (writes are not refused), but recorded
    /// distinctly so the audit trail can distinguish "nobody said" from "we own it".
    Unknown,
}

impl mecmcp_inventory::LocalAuthority for JunosAuthority {
    fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }
}

impl JunosAuthority {
    /// True when some management plane other than this server owns the
    /// device's running configuration (anything but `Local` or `Unknown`).
    ///
    /// The single predicate the rollback-depth guard (MEC-1879) is built on:
    /// every refusal in that guard is gated on this, not on a per-vendor list,
    /// so a new plane variant is covered automatically.
    pub fn is_plane_owned(&self) -> bool {
        !matches!(self, Self::Local | Self::Unknown)
    }

    /// Stable lowercase-kebab name for error messages and audit records.
    ///
    /// Matches the `#[serde(rename_all = "kebab-case")]` wire form exactly, so
    /// a human reading an error message sees the same string that appears in
    /// `devices.json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Mist => "mist",
            Self::SecurityDirectorCloud => "security-director-cloud",
            Self::SecurityDirectorOnprem => "security-director-onprem",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for JunosAuthority {
    /// Default authority when not specified in `devices.json`.
    ///
    /// Returns `Unknown` rather than `Local` so the audit trail distinguishes
    /// "unset" from "explicitly declared local". Devices with unset authority
    /// are treated as local for behaviour (writes are not refused), but the
    /// audit event records the distinction.
    fn default() -> Self {
        Self::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_inventory::LocalAuthority;

    #[test]
    fn only_local_reports_is_local_true() {
        assert!(JunosAuthority::Local.is_local());
        assert!(!JunosAuthority::Mist.is_local());
        assert!(!JunosAuthority::SecurityDirectorCloud.is_local());
        assert!(!JunosAuthority::SecurityDirectorOnprem.is_local());
        assert!(!JunosAuthority::Unknown.is_local());
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(JunosAuthority::default(), JunosAuthority::Unknown);
    }

    #[test]
    fn is_plane_owned_true_only_for_non_local_non_unknown() {
        assert!(!JunosAuthority::Local.is_plane_owned());
        assert!(!JunosAuthority::Unknown.is_plane_owned());
        assert!(JunosAuthority::Mist.is_plane_owned());
        assert!(JunosAuthority::SecurityDirectorCloud.is_plane_owned());
        assert!(JunosAuthority::SecurityDirectorOnprem.is_plane_owned());
    }

    #[test]
    fn as_str_matches_kebab_case_wire_form() {
        let cases = [
            (JunosAuthority::Local, "local"),
            (JunosAuthority::Mist, "mist"),
            (
                JunosAuthority::SecurityDirectorCloud,
                "security-director-cloud",
            ),
            (
                JunosAuthority::SecurityDirectorOnprem,
                "security-director-onprem",
            ),
            (JunosAuthority::Unknown, "unknown"),
        ];
        for (authority, expected) in cases {
            assert_eq!(authority.as_str(), expected);
        }
    }

    #[test]
    fn deserializes_from_kebab_case() {
        let cases = [
            ("\"local\"", JunosAuthority::Local),
            ("\"mist\"", JunosAuthority::Mist),
            (
                "\"security-director-cloud\"",
                JunosAuthority::SecurityDirectorCloud,
            ),
            (
                "\"security-director-onprem\"",
                JunosAuthority::SecurityDirectorOnprem,
            ),
            ("\"unknown\"", JunosAuthority::Unknown),
        ];
        for (json, expected) in cases {
            let parsed: JunosAuthority = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("failed to parse {json}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn serializes_to_kebab_case() {
        let cases = [
            (JunosAuthority::Local, "\"local\""),
            (JunosAuthority::Mist, "\"mist\""),
            (
                JunosAuthority::SecurityDirectorCloud,
                "\"security-director-cloud\"",
            ),
            (
                JunosAuthority::SecurityDirectorOnprem,
                "\"security-director-onprem\"",
            ),
            (JunosAuthority::Unknown, "\"unknown\""),
        ];
        for (val, expected_json) in cases {
            let serialized = serde_json::to_string(&val).expect("serialization failed");
            assert_eq!(serialized, expected_json);
        }
    }
}

//! Junos authorization vocabulary over the shared mecmcp auth core.
//!
//! Pure data plus HTTP glue; no async device work.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod tower;

pub use mecmcp_auth::{
    CallerCtx, FileError as TokenStoreError, KnownNames, NoGrant, OidcSubject, ScopeSet,
    StoreError, TokenDigest, TokenEntry as SharedTokenEntry, TokenError, TokenSecret,
    TokenStore as SharedStore, TokenStoreFile as SharedFile, filter_device_names,
};

/// Junos token entry. Write authority is not yet modelled per token.
pub type TokenEntry = SharedTokenEntry<NoGrant>;
/// Junos token store.
pub type TokenStore = SharedStore<NoGrant>;
/// Junos token file.
pub type TokenStoreFile = SharedFile<NoGrant>;

/// Generic Junos tool names. The server crate has a drift test that
/// compares its `#[tool]` surface against this registry.
pub const JUNOS_TOOLS: &[&str] = &[
    "add_device",
    "apply_junos_change_set",
    "approve_junos_change_set",
    "cancel_junos_change_set",
    "commit_check_config",
    "confirm_commit",
    "confirm_junos_change_set",
    "create_junos_change_set",
    "discard_candidate",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_device_list",
    "get_junos_candidate_fingerprint",
    "get_junos_change_set_status",
    "get_junos_config",
    "get_router_list",
    "junos_config_diff",
    "list_junos_change_sets",
    "list_staged_files",
    "load_and_commit_config",
    "reload_devices",
    "render_and_apply_j2_template",
    "rollback_config",
    "transfer_file",
    "upgrade_junos",
];

/// SRX workflow tool names. Kept separate so the unified registry can enforce
/// per-domain drift checks while using one token file.
pub const SRX_TOOLS: &[&str] = &[
    "check_srx_feature_license",
    "collect_jtac_support_bundle",
    "get_chassis_cluster_status",
    "get_srx_security_services_status",
    "manage_appid_signature_package",
    "manage_idp_security_package",
    "srx_flow_sessions",
    "srx_list_nat_rules",
    "srx_list_policies",
    "srx_policy_match",
    "srx_resolve_address",
    "srx_resolve_application",
    "srxmcp_status",
    "validate_chassis_cluster_health",
    "vpn_lifecycle_report",
];

/// Facade tool names, separate from the concrete endpoint registries.
pub const FACADE_TOOLS: &[&str] = &["execute"];

/// All tool names accepted in token scopes, kept globally alphabetized for
/// stable diagnostics. This must remain the exact union of [`JUNOS_TOOLS`],
/// [`SRX_TOOLS`], and [`FACADE_TOOLS`]; registry tests enforce that invariant.
pub const KNOWN_TOOLS: &[&str] = &[
    "add_device",
    "apply_junos_change_set",
    "approve_junos_change_set",
    "cancel_junos_change_set",
    "check_srx_feature_license",
    "collect_jtac_support_bundle",
    "commit_check_config",
    "confirm_commit",
    "confirm_junos_change_set",
    "create_junos_change_set",
    "discard_candidate",
    "execute",
    "execute_junos_command",
    "execute_junos_command_batch",
    "execute_junos_pfe_command",
    "fetch_file",
    "gather_device_facts",
    "get_chassis_cluster_status",
    "get_device_list",
    "get_junos_candidate_fingerprint",
    "get_junos_change_set_status",
    "get_junos_config",
    "get_router_list",
    "get_srx_security_services_status",
    "junos_config_diff",
    "list_junos_change_sets",
    "list_staged_files",
    "load_and_commit_config",
    "manage_appid_signature_package",
    "manage_idp_security_package",
    "reload_devices",
    "render_and_apply_j2_template",
    "rollback_config",
    "srx_flow_sessions",
    "srx_list_nat_rules",
    "srx_list_policies",
    "srx_policy_match",
    "srx_resolve_address",
    "srx_resolve_application",
    "srxmcp_status",
    "transfer_file",
    "upgrade_junos",
    "validate_chassis_cluster_health",
    "vpn_lifecycle_report",
];

/// Tools that a wildcard tool scope does NOT confer. Granting write authority
/// must always be an explicit, named decision.
pub const WRITE_TOOLS: &[&str] = &[
    "add_device",
    "apply_junos_change_set",
    "approve_junos_change_set",
    "confirm_commit",
    "confirm_junos_change_set",
    "create_junos_change_set",
    "discard_candidate",
    "execute",
    "load_and_commit_config",
    "manage_appid_signature_package",
    "manage_idp_security_package",
    "reload_devices",
    "render_and_apply_j2_template",
    "rollback_config",
    "transfer_file",
    "upgrade_junos",
];

/// Backwards-compatible alias. `filter_router_names` was the pre-extraction
/// name; the shared crate calls devices devices.
pub use mecmcp_auth::filter_device_names as filter_router_names;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn known_tools_is_alphabetized() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            KNOWN_TOOLS,
            sorted.as_slice(),
            "KNOWN_TOOLS must stay alphabetized for easy diff/audit"
        );
    }

    #[test]
    fn known_tools_is_exact_endpoint_and_facade_union() {
        let known: HashSet<&str> = KNOWN_TOOLS.iter().copied().collect();
        let endpoint_tools: HashSet<&str> = JUNOS_TOOLS
            .iter()
            .chain(SRX_TOOLS.iter())
            .chain(FACADE_TOOLS.iter())
            .copied()
            .collect();

        assert_eq!(
            known, endpoint_tools,
            "KNOWN_TOOLS must be the exact union of endpoint and facade registries"
        );
        assert_eq!(
            KNOWN_TOOLS.len(),
            JUNOS_TOOLS.len() + SRX_TOOLS.len() + FACADE_TOOLS.len(),
            "endpoint registries must not contain duplicate tool names"
        );
        assert_eq!(KNOWN_TOOLS.len(), 44);
    }

    #[test]
    fn execute_requires_an_explicit_tool_grant() {
        assert!(WRITE_TOOLS.contains(&"execute"));
        assert!(!ScopeSet::Wildcard.allows_tool("execute", WRITE_TOOLS));
        assert!(
            ScopeSet::Allowlist(vec!["execute".to_string()]).allows_tool("execute", WRITE_TOOLS)
        );
    }

    #[test]
    fn write_tools_exist_in_known_tools() {
        for tool in WRITE_TOOLS {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "WRITE_TOOLS entry '{tool}' not found in KNOWN_TOOLS"
            );
        }
    }
}

#[cfg(test)]
mod write_tool_registry_tests {
    use super::*;

    /// Every change-set tool that can alter the device must be a write tool.
    ///
    /// `WRITE_TOOLS` is what excludes a tool from a wildcard (`*`) scope, so a
    /// tool missing here is reachable by any token that asked for everything,
    /// without the operator ever granting it by name. `confirm_junos_change_set`
    /// was added to the other two registries and not this one, and nothing
    /// failed — a confirming commit makes a provisional change permanent, so
    /// that was a real gap (#239).
    #[test]
    fn change_set_mutations_are_write_tools() {
        for tool in [
            "create_junos_change_set",
            "approve_junos_change_set",
            "apply_junos_change_set",
            "confirm_junos_change_set",
        ] {
            assert!(
                WRITE_TOOLS.contains(&tool),
                "{tool} alters the device but is absent from WRITE_TOOLS, so a \
                 wildcard token can call it without an explicit grant"
            );
        }
    }

    /// A read-only tool in `WRITE_TOOLS` would be denied to wildcard tokens that
    /// legitimately should have it, so the boundary matters in both directions.
    #[test]
    fn read_only_change_set_tools_are_not_write_tools() {
        for tool in [
            "get_junos_change_set_status",
            "list_junos_change_sets",
            "get_junos_candidate_fingerprint",
        ] {
            assert!(!WRITE_TOOLS.contains(&tool), "{tool} only reads");
        }
    }
}

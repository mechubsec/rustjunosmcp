//! One module per Phase 1B tool. Each exposes a single public
//! `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

pub mod appid_package;
pub mod cluster_health;
pub mod cluster_status;
mod config_fetch;
pub mod feed_status;
pub mod flow_sessions;
pub mod idp_package;
pub mod license;
pub mod list_nat_rules;
pub mod list_policies;
pub mod policy_match;
mod resolve;
pub mod resolve_address;
pub mod resolve_application;
pub mod services_status;
pub mod signature_package;
pub mod support_bundle;
pub mod vpn_lifecycle;

#[cfg(test)]
mod schema_tripwire {
    use schemars::JsonSchema;

    /// The SRX argument types keep `router` as the canonical field name where
    /// the Junos tools use `device`, so they need their own alias transform.
    /// Pointing them at the wrong canonical name makes the transform a silent
    /// no-op: the schema still closes with `additionalProperties: false`, and
    /// `router_name` — accepted by the deserializer — vanishes from it. Nothing
    /// else fails when that happens, which is why this test exists.
    fn assert_closed_and_aliased<T: JsonSchema>(name: &str) {
        let schema = serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes");
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false)),
            "{name} must reject arguments it does not understand"
        );
        rust_junosmcp_core::schema_alias::assert_describes_keys(
            schema.as_object().expect("schema is an object"),
            name,
            &["router_name"],
        );
    }

    #[test]
    fn every_srx_argument_type_is_closed_and_describes_its_alias() {
        assert_closed_and_aliased::<super::cluster_health::ClusterHealthArgs>("ClusterHealthArgs");
        assert_closed_and_aliased::<super::cluster_status::ClusterStatusArgs>("ClusterStatusArgs");
        assert_closed_and_aliased::<super::feed_status::FeedStatusArgs>("FeedStatusArgs");
        assert_closed_and_aliased::<super::services_status::ServicesStatusArgs>(
            "ServicesStatusArgs",
        );
        assert_closed_and_aliased::<super::license::LicenseArgs>("LicenseArgs");
        assert_closed_and_aliased::<super::vpn_lifecycle::VpnLifecycleArgs>("VpnLifecycleArgs");
        assert_closed_and_aliased::<super::appid_package::AppidPackageArgs>("AppidPackageArgs");
        assert_closed_and_aliased::<super::idp_package::IdpPackageArgs>("IdpPackageArgs");
        assert_closed_and_aliased::<super::support_bundle::SupportBundleArgs>("SupportBundleArgs");
        assert_closed_and_aliased::<super::list_policies::PolicyListArgs>("PolicyListArgs");
        assert_closed_and_aliased::<super::resolve_address::AddressResolveArgs>(
            "AddressResolveArgs",
        );
        assert_closed_and_aliased::<super::resolve_application::ApplicationResolveArgs>(
            "ApplicationResolveArgs",
        );
        assert_closed_and_aliased::<super::list_nat_rules::NatRulesArgs>("NatRulesArgs");
        assert_closed_and_aliased::<super::flow_sessions::FlowSessionsArgs>("FlowSessionsArgs");
        assert_closed_and_aliased::<super::policy_match::PolicyMatchArgs>("PolicyMatchArgs");
    }
}

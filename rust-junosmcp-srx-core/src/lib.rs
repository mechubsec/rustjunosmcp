//! SRX workflows and shared types for `rust-junosmcp`.
//!
//! This crate is consumed by the unified `rust-junosmcp` binary. It owns the typed
//! tool response envelope (`SrxToolResponse<T>`), absence semantics
//! (`SrxState`), the multi-RE XML helper, the `SrxError` taxonomy, and
//! one `workflows::<tool>` module per Phase 1B tool.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod absence;
pub mod error;
pub mod protocol;
pub mod workflows;
pub mod xml;

pub use absence::{SrxState, SrxToolResponse};
pub use error::SrxError;
pub use protocol::Protocol;
pub use workflows::appid_package::{
    AppidAction, AppidCheckServerData, AppidCheckServerNode, AppidPackageArgs, AppidPackageResponse,
};
pub use workflows::cluster_health::{
    CHECK_IDS, ClusterHealthArgs, ClusterHealthData, Finding, Severity, Verdict,
};
pub use workflows::cluster_status::{
    ClusterNode, ClusterStatusArgs, ClusterStatusData, RedundancyGroup, RgMember,
};
pub use workflows::feed_status::{
    FeedKind, FeedStatus, FeedStatusArgs, FeedStatusData, NodeFeedStatus,
};
pub use workflows::flow_sessions::{FlowSession, FlowSessionQuery, FlowSessionsArgs, NodeSessions};
pub use workflows::idp_package::{
    DownloadAndInstallCompletedData, DownloadAndInstallResponse, IdpAction, IdpCheckServerData,
    IdpCheckServerNode, IdpPackageArgs, IdpPackageResponse, RollbackCompletedData,
    RollbackResponse,
};
pub use workflows::license::{
    LicenseArgs, LicenseCounts, LicenseData, LicenseRecord, SrxLicensedFeature,
};
pub use workflows::list_nat_rules::{
    DestinationNatRule, DestinationTranslation, NatMatch, NatRules, NatRulesArgs,
    NatZoneOrInterface, SourceNatRule, SourceTranslation, StaticNatRule, StaticTranslation,
};
pub use workflows::list_policies::{
    PolicyAction, PolicyListArgs, PolicyListData, PolicyLog, SecurityPolicy,
};
pub use workflows::policy_match::{
    DefaultAction, FiveTuple, MatchVerdict, MatchedPolicy, PolicyMatchArgs, PolicyMatchResult,
};
pub use workflows::resolve_address::{
    AddressKind, AddressResolution, AddressResolveArgs, AddressScope, AddressValue, ResolvedAddress,
};
pub use workflows::resolve_application::{
    ApplicationKind, ApplicationResolution, ApplicationResolveArgs, PortRange, ResolvedApplication,
};
pub use workflows::services_status::{
    AppIdInfo, AtpCloudInfo, IdpInfo, NodeServicesStatus, SecIntelInfo, ServicesStatusArgs,
    ServicesStatusData, SubServiceStatus, UtmAvInfo,
};
pub use workflows::support_bundle::{
    ArtefactSource, BASELINE_LOGS, BASELINE_RPCS, BundleInfo, BundleLocation, CapturedArtefact,
    DEFAULT_STAGING_DIR, DEFAULT_STAGING_MAX_BYTES, ProblemType, ProblemTypeArg, SupportBundleArgs,
    SupportBundleData,
};
pub use workflows::vpn_lifecycle::{
    IkeSa, IpsecSa, NodeVpnReport, VpnCorrelation, VpnLifecycleArgs, VpnLifecycleData,
};

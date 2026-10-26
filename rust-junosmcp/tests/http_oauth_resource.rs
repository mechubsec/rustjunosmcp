#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! OAuth resource-server mode (mecmcp#498) through the Junos HTTP router:
//! discovery metadata, the 401 challenge, and static tokens still working.
//! No JWT is presented, so the IdP is never contacted.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_changeset::ChangesetCoordinator;
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource};
use mecmcp_runtime::cli::OAuthResourceArgs;
use mecmcp_transport::LimitsConfig;
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_auth::{KNOWN_TOOLS, KnownNames, ScopeSet, TokenStoreFile};
use rust_junosmcp_core::{DeviceManager, MecmcpScpRunner, Policy, TransferConfig, UpgradeConfig};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const ISSUER: &str = "https://idp.lab.example/realms/lab";
const RESOURCE: &str = "https://junos.lab.example/mcp";

fn test_handler() -> JmcpHandler {
    let inventory = rust_junosmcp_core::Inventory::empty();
    let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
        Policy::build(&inventory).unwrap(),
    )));
    let dev_manager = Arc::new(DeviceManager::new(Arc::new(inventory)));
    let transfer_cfg = TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp"),
        known_hosts_file: std::path::PathBuf::from("/dev/null"),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(Default::default()),
        host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
    };
    let lease_dir = tempfile::tempdir().unwrap();
    let upgrade_cfg = UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases: Arc::new(
            rust_junosmcp_core::DeviceLeaseManager::for_directory(lease_dir.path()).unwrap(),
        ),
    };
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None,
            mecmcp_changeset::OperationLimits::default(),
            std::time::Duration::from_secs(300),
            false,
        )
        .unwrap(),
    );
    JmcpHandler::new(
        dev_manager,
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator,
        false,
        false,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
}

/// Serve an authenticated router with OAuth on; returns `(base_url, static_token, shutdown)`.
async fn start(oauth_on: bool, port: u16) -> (String, String, CancellationToken) {
    // Leaked on purpose: the server task outlives this function.
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let tokens = dir.path().join("tokens.json");
    let static_token = TokenStoreFile::add(
        &tokens,
        "probe",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &KnownNames {
            devices: None,
            tools: KNOWN_TOOLS,
        },
    )
    .unwrap();
    let store = Arc::new(TokenStoreFile::load(&tokens).unwrap());

    let map = dir.path().join("scopes.json");
    std::fs::write(
        &map,
        r#"{"version":1,"scopes":{"junos:read":{"tools":["get_router_list"],"devices":["*"]}}}"#,
    )
    .unwrap();
    // 0.29.1 refuses a scope map looser than 0640.
    std::fs::set_permissions(&map, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
    let oauth = if oauth_on {
        let args = OAuthResourceArgs {
            oauth_issuer: Some(ISSUER.into()),
            oauth_resource: Some(RESOURCE.into()),
            oauth_scope_map: Some(map),
            ..OAuthResourceArgs::default()
        };
        rust_junosmcp::http_transport::build_oauth_resource(
            &args,
            Arc::new(DeviceManager::new(Arc::new(
                rust_junosmcp_core::Inventory::empty(),
            ))),
        )
        .unwrap()
    } else {
        None
    };

    // mecmcp-http's key source needs a process-wide provider (main installs it).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let shutdown = CancellationToken::new();
    let plan = rust_junosmcp::http_transport::build_http_router(
        test_handler(),
        Some(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown.clone(),
        None,
        oauth,
    )
    .unwrap();
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(async move {
        mecmcp_transport::serve_router(plan, addr, None, std::time::Duration::from_secs(5))
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    (
        format!("http://127.0.0.1:{port}"),
        static_token.expose_secret().to_owned(),
        shutdown,
    )
}

#[tokio::test]
async fn oauth_on_serves_metadata_challenges_and_keeps_static_tokens() {
    let (base, static_token, shutdown) = start(true, 18931).await;
    let client = reqwest::Client::new();

    // (a) RFC 9728 metadata names the configured resource and issuer.
    let metadata = client
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap();
    assert_eq!(metadata.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&metadata.text().await.unwrap()).unwrap();
    assert_eq!(body["resource"], RESOURCE);
    assert_eq!(body["authorization_servers"][0], ISSUER);

    // (b) No credential: 401 whose challenge points at the metadata.
    let unauth = client
        .post(format!("{base}/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
    let challenge = unauth.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(challenge.contains("resource_metadata="), "{challenge}");

    // (c) A static token still authenticates: past the boundary, rmcp answers
    // 406 to a probe lacking `Accept: text/event-stream`.
    let with_static = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&static_token)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(with_static.status(), 406);

    shutdown.cancel();
}

#[tokio::test]
async fn oauth_off_serves_no_metadata_route() {
    let (base, _, shutdown) = start(false, 18932).await;
    let client = reqwest::Client::new();
    let metadata = client
        .get(format!("{base}/.well-known/oauth-protected-resource/mcp"))
        .send()
        .await
        .unwrap();
    assert_ne!(metadata.status(), 200);
    let unauth = client
        .post(format!("{base}/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), 401);
    let challenge = unauth.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(!challenge.contains("resource_metadata"), "{challenge}");
    shutdown.cancel();
}

/// `--oauth-max-token-lifetime-secs` must reach the resource config (mecmcp#400).
/// Limitation: this pins the wiring only; no signed JWT is minted here, so the
/// refusal itself (`token_lifetime_exceeded`) is covered by mecmcp's own tests.
#[test]
fn oauth_max_token_lifetime_reaches_the_resource_config() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let map = dir.path().join("scopes.json");
    std::fs::write(
        &map,
        r#"{"version":1,"scopes":{"junos:read":{"tools":["get_router_list"],"devices":["*"]}}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&map, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
    let build = |ceiling| {
        let args = OAuthResourceArgs {
            oauth_issuer: Some(ISSUER.into()),
            oauth_resource: Some(RESOURCE.into()),
            oauth_scope_map: Some(map.clone()),
            oauth_max_token_lifetime_secs: ceiling,
            ..OAuthResourceArgs::default()
        };
        rust_junosmcp::http_transport::build_oauth_resource(
            &args,
            Arc::new(DeviceManager::new(Arc::new(
                rust_junosmcp_core::Inventory::empty(),
            ))),
        )
        .unwrap()
        .unwrap()
        .config()
        .max_token_lifetime()
    };
    assert_eq!(build(Some(900)), Some(std::time::Duration::from_secs(900)));
    assert_eq!(build(None), None);
}

/// Serves one signing key from memory; no socket to an IdP is opened.
struct FixtureSource(JwkSet);

#[async_trait::async_trait]
impl KeySource for FixtureSource {
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        Ok(DiscoveryDocument {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/jwks"),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: Vec::new(),
            id_token_signing_alg_values_supported: Vec::new(),
        })
    }
    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        Ok(self.0.clone())
    }
}

/// End to end (mecmcp#400 phase 2): devices.json `attributes` -> `DeviceManager` ->
/// `build_oauth_resource` -> a signed token authenticated with a `device_selectors` scope
/// grants only the matching inventory devices. The JWKS is an in-memory fixture.
#[tokio::test]
async fn device_selectors_grant_only_matching_inventory_devices() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let pw = r#""username":"a","auth":{"type":"password","password":"x"}"#;
    let devices = dir.path().join("devices.json");
    std::fs::write(
        &devices,
        format!(
            r#"{{"lab-a":{{"ip":"10.0.0.1",{pw},"attributes":{{"site":"lab-1"}}}},
                "emea-a":{{"ip":"10.0.0.2",{pw},"attributes":{{"site":"emea-lon"}}}},
                "bare":{{"ip":"10.0.0.3",{pw}}}}}"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        &devices,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let map = dir.path().join("scopes.json");
    std::fs::write(
        &map,
        r#"{"version":1,"scopes":{"junos:lab":{"tools":["get_router_list"],"devices":["*"],
            "device_selectors":["site=lab-*"]}}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&map, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
    let manager = Arc::new(DeviceManager::new(Arc::new(
        rust_junosmcp_core::Inventory::load(&devices).unwrap(),
    )));

    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = pair.as_der().unwrap();
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref().to_vec()));
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(pem_text.as_bytes()).unwrap();
    let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256).unwrap();
    jwk.common.key_id = Some("k1".to_owned());
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k1".to_owned());
    let token = jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": ISSUER, "sub": "alice", "aud": RESOURCE, "exp": now + 3600,
            "iat": now - 10, "jti": "j1", "client_id": "odysseus", "scope": "junos:lab",
        }),
        &encoding_key,
    )
    .unwrap();

    let args = OAuthResourceArgs {
        oauth_issuer: Some(ISSUER.into()),
        oauth_resource: Some(RESOURCE.into()),
        oauth_scope_map: Some(map),
        ..OAuthResourceArgs::default()
    };
    let resource = rust_junosmcp::http_transport::build_oauth_resource_with_keys(
        &args,
        manager,
        Some(Arc::new(FixtureSource(JwkSet { keys: vec![jwk] }))),
    )
    .unwrap()
    .unwrap();
    let caller = resource.authenticate(&token).await.unwrap();
    assert!(caller.devices.allows("lab-a"));
    assert!(!caller.devices.allows("emea-a"));
    assert!(!caller.devices.allows("bare"));
}

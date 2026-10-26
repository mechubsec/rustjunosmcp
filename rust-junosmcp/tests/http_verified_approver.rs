#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Verified-approver step-up (mecmcp#400) through the real Junos HTTP router:
//! a fresh IdP assertion in `Mecmcp-Approver-Assertion` is what lets a bound
//! human token approve a change set. The IdP is an in-memory fixture (signed
//! ephemeral keys, no network), driven the way mecmcp's own
//! `approver_assertion` test drives it.

mod common;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_auth::ApproverPolicy;
use mecmcp_changeset::{ApprovalDigestKey, ChangesetCoordinator, OperationLimits, OwnerSubject};
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource, OidcConfig, TokenVerifier};
use mecmcp_transport::{ApproverAssertionVerifier, LimitsConfig};
use rust_junosmcp::server::JmcpHandler;
use rust_junosmcp_core::{DeviceManager, MecmcpScpRunner, Policy, TransferConfig, UpgradeConfig};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "junos-mcp";
const KID: &str = "approver-test-key";
const APPROVE: &str = "approve_junos_change_set";
const HEADER: &str = "Mecmcp-Approver-Assertion";
static PORT: AtomicU16 = AtomicU16::new(18950);

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

fn generate_key() -> TestKey {
    let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = pair.as_der().unwrap();
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", der.as_ref().to_vec()));
    let encoding_key = EncodingKey::from_rsa_pem(pem_text.as_bytes()).unwrap();
    let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256).unwrap();
    jwk.common.key_id = Some(KID.to_owned());
    TestKey { encoding_key, jwk }
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// A fresh approver assertion for `subject`; `jti` must be unique per request.
fn assertion(key: &TestKey, subject: &str, jti: &str) -> String {
    let claims = json!({
        "sub": subject, "iss": ISSUER, "aud": AUDIENCE,
        "exp": now() + 3600, "iat": now() - 10,
        "groups": ["approver"], "jti": jti,
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, &claims, &key.encoding_key).unwrap()
}

/// Serves the key set from memory, or fails like an unreachable IdP.
struct FixtureSource {
    jwks: Option<JwkSet>,
}

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
        match &self.jwks {
            Some(jwks) => Ok(jwks.clone()),
            None => Err(FetchError::HttpStatus {
                what: "jwks",
                status: 503,
            }),
        }
    }
}

/// Mint a token through the shipped `token add` CLI, so the ONBOARDING
/// binding flags are exercised as written (tool and device names aside).
fn mint(tokens: &std::path::Path, name: &str, tools: &str, subject: Option<&str>) -> String {
    let mut command = std::process::Command::new(common::binary_path());
    command
        .args(["token", "add", "--tokens-file"])
        .arg(tokens)
        .args(["--name", name, "--actor-type", "human", "--tools", tools])
        .args(["--devices", "*"]);
    if let Some(subject) = subject {
        command.args(["--oidc-issuer", ISSUER, "--oidc-subject", subject]);
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

struct Rig {
    base: String,
    coordinator: Arc<ChangesetCoordinator>,
    alice: String,
    key: TestKey,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

/// Which parts of the step-up are configured on the server under test.
#[derive(Clone, Copy)]
struct Setup {
    verifier: bool,
    strict: bool,
    idp_up: bool,
}

async fn rig(setup: Setup) -> Rig {
    rig_with_store(setup, None).await
}

/// `replay_store` is the durable `jti` store, as `--approver-replay-store` sets it.
async fn rig_with_store(setup: Setup, replay_store: Option<&std::path::Path>) -> Rig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();

    let tokens = dir.path().join("tokens.json");
    let tools = format!("{APPROVE},get_router_list");
    let alice = mint(&tokens, "alice", &tools, Some("alice"));
    let store = Arc::new(rust_junosmcp_auth::TokenStoreFile::load(&tokens).unwrap());

    let inventory = common::write_inv(
        r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}}"#,
    );
    let inventory = rust_junosmcp_core::Inventory::load(inventory.path()).unwrap();
    let policy = Arc::new(arc_swap::ArcSwap::from(Arc::new(
        Policy::build(&inventory).unwrap(),
    )));
    let device_manager = Arc::new(DeviceManager::new(Arc::new(inventory)));
    let transfer_cfg = TransferConfig {
        staging_dir: std::path::PathBuf::from("/tmp"),
        known_hosts_file: std::path::PathBuf::from("/dev/null"),
        scp_runner: Arc::new(MecmcpScpRunner),
        transfer_locks: Arc::new(Default::default()),
        host_key_mode: rust_junosmcp_core::bootstrap::SshHostKeyMode::Strict,
    };
    let upgrade_cfg = UpgradeConfig {
        transfer_cfg: transfer_cfg.clone(),
        device_leases: Arc::new(
            rust_junosmcp_core::DeviceLeaseManager::for_directory(dir.path()).unwrap(),
        ),
    };

    let digest_key = dir.path().join("approval-digest.key");
    common::write_restricted(&digest_key, &"ab".repeat(32));
    let coordinator = Arc::new(
        ChangesetCoordinator::load_with_key(
            None,
            OperationLimits::default(),
            Duration::from_secs(300),
            false,
            Some(ApprovalDigestKey::load_from_file(&digest_key).unwrap()),
        )
        .unwrap()
        .with_require_verified_approver(setup.strict),
    );
    let handler = JmcpHandler::new(
        device_manager,
        policy,
        transfer_cfg,
        upgrade_cfg,
        coordinator.clone(),
        false,
        false,
        mecmcp_audit::DirectCommitPolicy::new(false),
    );

    let verifier = setup.verifier.then(|| {
        let jwks = setup.idp_up.then(|| JwkSet {
            keys: vec![key.jwk.clone()],
        });
        let verifier = TokenVerifier::new(
            OidcConfig::new(ISSUER, AUDIENCE, "groups"),
            Arc::new(FixtureSource { jwks }),
        );
        let verifier = ApproverAssertionVerifier::new(
            Arc::new(verifier),
            ISSUER,
            ApproverPolicy {
                approver_role: "approver".into(),
                max_age: Duration::from_secs(300),
                require_auth_time: false,
            },
        );
        Arc::new(match replay_store {
            Some(path) => verifier.with_replay_store(path).unwrap(),
            None => verifier,
        })
    });

    let shutdown = CancellationToken::new();
    let plan = rust_junosmcp::http_transport::build_http_router(
        handler,
        Some(store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown.clone(),
        verifier,
        None,
    )
    .unwrap();
    let port = PORT.fetch_add(1, Ordering::Relaxed);
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(async move {
        mecmcp_transport::serve_router(plan, addr, None, Duration::from_secs(5))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Rig {
        base: format!("http://127.0.0.1:{port}"),
        coordinator,
        alice,
        key,
        shutdown,
        _dir: dir,
    }
}

impl Rig {
    /// Propose a change set as `bob`, an owner bound to his own IdP subject.
    async fn propose(&self) -> (String, String) {
        let fingerprint = format!("sha256:{}", "0".repeat(64));
        let output = self
            .coordinator
            .create_change_set(
                "r1".into(),
                vec![json!({"payload": "set system host-name x"})],
                "bob".into(),
                fingerprint,
                "junos-default-v1".into(),
                Some(OwnerSubject {
                    issuer: ISSUER.into(),
                    subject: "bob".into(),
                }),
            )
            .await
            .unwrap();
        (output.change_set_id, output.digest)
    }

    async fn post(&self, session: Option<&str>, assertion: Option<&str>, body: Value) -> Reply {
        let mut request = reqwest::Client::new()
            .post(format!("{}/mcp", self.base))
            .bearer_auth(&self.alice)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        if let Some(session) = session {
            request = request.header("Mcp-Session-Id", session);
        }
        if let Some(assertion) = assertion {
            request = request.header(HEADER, assertion);
        }
        let response = request.body(body.to_string()).send().await.unwrap();
        let status = response.status().as_u16();
        let session_id = response
            .headers()
            .get("Mcp-Session-Id")
            .map(|v| v.to_str().unwrap().to_owned());
        let text = response.text().await.unwrap();
        Reply {
            status,
            session_id,
            text,
        }
    }

    async fn session(&self) -> String {
        let init = self.post(None, None, common::init_body()).await;
        assert_eq!(init.status, 200, "{}", init.text);
        let session = init.session_id.unwrap();
        let ack = self
            .post(
                Some(&session),
                None,
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            )
            .await;
        assert!(matches!(ack.status, 200 | 202), "{}", ack.text);
        session
    }

    async fn approve(
        &self,
        session: &str,
        assertion: Option<&str>,
        id: &str,
        digest: &str,
    ) -> Reply {
        self.post(
            Some(session),
            assertion,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name": APPROVE,
                "arguments": {"change_set_id": id, "device": "r1", "expected_digest": digest}}}),
        )
        .await
    }
}

struct Reply {
    status: u16,
    session_id: Option<String>,
    text: String,
}

impl Reply {
    /// Whether the tool call itself succeeded (HTTP 200 and no tool error).
    fn approved(&self) -> bool {
        self.status == 200 && self.text.contains("change set approved")
    }
}

const STRICT: Setup = Setup {
    verifier: true,
    strict: true,
    idp_up: true,
};

#[tokio::test]
async fn a_valid_assertion_lets_a_bound_human_token_approve() {
    let rig = rig(STRICT).await;
    let (id, digest) = rig.propose().await;
    let session = rig.session().await;
    let jwt = assertion(&rig.key, "alice", "jti-ok");
    let reply = rig.approve(&session, Some(&jwt), &id, &digest).await;
    assert!(reply.approved(), "{} {}", reply.status, reply.text);
    rig.shutdown.cancel();
}

#[tokio::test]
async fn strict_mode_refuses_approval_without_an_assertion() {
    let rig = rig(STRICT).await;
    let (id, digest) = rig.propose().await;
    let session = rig.session().await;
    let reply = rig.approve(&session, None, &id, &digest).await;
    assert!(!reply.approved(), "{}", reply.text);
    assert!(reply.text.contains("verified approver"), "{}", reply.text);
    // The refusal changed nothing: the same change set still approves with one.
    let jwt = assertion(&rig.key, "alice", "jti-after");
    let retry = rig.approve(&session, Some(&jwt), &id, &digest).await;
    assert!(retry.approved(), "{} {}", retry.status, retry.text);
    rig.shutdown.cancel();
}

/// A used assertion stays refused after a restart (a second server over the same
/// replay store), which the in-memory set alone cannot give.
#[tokio::test]
async fn a_used_assertion_is_refused_after_a_restart_with_a_replay_store() {
    let state = tempfile::tempdir().unwrap();
    let store = state.path().join("approver-replay.log");
    {
        let first = rig_with_store(STRICT, Some(&store)).await;
        let jwt = assertion(&first.key, "alice", "jti-once");
        let (id, digest) = first.propose().await;
        let session = first.session().await;
        let reply = first.approve(&session, Some(&jwt), &id, &digest).await;
        assert!(reply.approved(), "{} {}", reply.status, reply.text);
        first.shutdown.cancel();
    }
    // Restart: new coordinator, verifier and listener; only the store file survives.
    let second = rig_with_store(STRICT, Some(&store)).await;
    let (id, digest) = second.propose().await;
    let session = second.session().await;
    // The fixture key is regenerated per rig, so re-sign the same jti with the new key.
    let replayed = assertion(&second.key, "alice", "jti-once");
    let reply = second
        .approve(&session, Some(&replayed), &id, &digest)
        .await;
    assert_eq!(reply.status, 401, "{}", reply.text);
    assert!(!reply.approved(), "{} {}", reply.status, reply.text);
    let fresh = assertion(&second.key, "alice", "jti-fresh");
    let retry = second.approve(&session, Some(&fresh), &id, &digest).await;
    assert!(retry.approved(), "{} {}", retry.status, retry.text);
    second.shutdown.cancel();
}

#[tokio::test]
async fn an_assertion_for_another_subject_is_refused() {
    let rig = rig(STRICT).await;
    let (id, digest) = rig.propose().await;
    let session = rig.session().await;
    // Valid signature, valid claims, but not the subject alice's token is bound to.
    let jwt = assertion(&rig.key, "mallory", "jti-wrong-subject");
    let reply = rig.approve(&session, Some(&jwt), &id, &digest).await;
    // The boundary rejects the bearer+assertion pair itself: 401, never a tool result.
    assert_eq!(reply.status, 401, "{}", reply.text);
    assert!(!reply.approved(), "{} {}", reply.status, reply.text);
    let jwt = assertion(&rig.key, "alice", "jti-right-subject");
    let retry = rig.approve(&session, Some(&jwt), &id, &digest).await;
    assert!(retry.approved(), "{} {}", retry.status, retry.text);
    rig.shutdown.cancel();
}

#[tokio::test]
async fn an_unreachable_idp_refuses_approvals_but_not_reads() {
    let rig = rig(Setup {
        idp_up: false,
        ..STRICT
    })
    .await;
    let (id, digest) = rig.propose().await; // proposals do not touch the IdP
    let session = rig.session().await;
    let jwt = assertion(&rig.key, "alice", "jti-idp-down");
    let reply = rig.approve(&session, Some(&jwt), &id, &digest).await;
    // The boundary rejects the bearer+assertion pair itself: 401, never a tool result.
    assert_eq!(reply.status, 401, "{}", reply.text);
    assert!(!reply.approved(), "{} {}", reply.status, reply.text);

    let read = rig
        .post(
            Some(&session),
            None,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                   "params":{"name":"get_router_list","arguments":{}}}),
        )
        .await;
    assert_eq!(read.status, 200, "{}", read.text);
    assert!(read.text.contains("r1"), "{}", read.text);
    rig.shutdown.cancel();
}

/// Not configured (the default): nothing about approval changes, and an
/// assertion header is refused outright rather than silently ignored.
#[tokio::test]
async fn without_a_verifier_approval_is_unchanged() {
    let rig = rig(Setup {
        verifier: false,
        strict: false,
        idp_up: true,
    })
    .await;
    let (id, digest) = rig.propose().await;
    let session = rig.session().await;

    let jwt = assertion(&rig.key, "alice", "jti-unconfigured");
    let with_header = rig.approve(&session, Some(&jwt), &id, &digest).await;
    assert_eq!(with_header.status, 400, "{}", with_header.text);

    let plain = rig.approve(&session, None, &id, &digest).await;
    assert!(plain.approved(), "{} {}", plain.status, plain.text);
    rig.shutdown.cancel();
}

/// Every approver identity must come from `ApproverIdentity::from_attribution`:
/// a hand-built `TokenAsserted` would let a call site claim a human approver
/// the transport never verified. (`OidcVerified` cannot be named outside
/// mecmcp-changeset; this pins the other variant.)
#[test]
fn approver_identities_are_never_built_by_hand() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut stack = vec![
        root.join("rust-junosmcp/src"),
        root.join("rust-junosmcp-core/src"),
        root.join("rust-junosmcp-srx-core/src"),
    ];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("ApproverIdentity::TokenAsserted")
                    && !text.contains("ApproverIdentity::OidcVerified"),
                "{} builds an ApproverIdentity by hand; use from_attribution",
                path.display()
            );
        }
    }
}

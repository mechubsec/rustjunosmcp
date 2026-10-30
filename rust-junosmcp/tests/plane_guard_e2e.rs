#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! The plane guard end to end through the real binary against a loopback fake
//! NETCONF device: authority is declared or detected from the outbound-ssh
//! stanza, and a refusal never reaches the commit while the revert and unlock
//! still happen.
mod common;

use common::fake_netconf::{FakeNetconf, OK, Script, client_key_pem};
use common::{
    Server, StdioChild, call_tool, http_post, initialize, spawn_stdio_server_with_protocol,
    spawn_with_auth_args, write_restricted,
};
use serde_json::{Value, json};

const MIST_STANZA: &str =
    "<output>\nclient mist {\n    device-conn-retry 5;\n    services netconf;\n}</output>";
const SDC_STANZA: &str = "<output>\nclient EMS-srx.sdcloud.juniperclouds.net {\n    \
    srx.sdcloud.juniperclouds.net port 7804;\n    services netconf;\n}</output>";
const NO_STANZA: &str = "<output></output>";

fn diff_reply(diff: &str) -> String {
    format!(
        "<configuration-information><configuration-output>{diff}</configuration-output></configuration-information>"
    )
}

/// Open-session facts replies, then the config RPCs a candidate transaction
/// sends. Anything else is an `<rpc-error>`, so a surprise RPC fails loudly.
fn script(outbound_ssh_reply: &str, diff: &str) -> Script {
    vec![
        ("outbound-ssh", outbound_ssh_reply.to_string()),
        ("compare=\"rollback\"", diff_reply(diff)),
        ("<nc:lock>", OK.to_string()),
        ("<nc:unlock>", OK.to_string()),
        ("<nc:load-configuration", OK.to_string()),
        ("<nc:validate", OK.to_string()),
        ("<nc:commit", OK.to_string()),
        ("<commit-configuration", OK.to_string()),
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

/// Spawn the binary with the fake as its only device; `authority` is the
/// declared `config_authority` (None leaves it `unknown`).
fn start(
    script: Script,
    authority: Option<&str>,
    extra_args: &[&str],
) -> (FakeNetconf, StdioChild, tempfile::TempDir) {
    let fake = FakeNetconf::start(script);
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    write_restricted(&key, &client_key_pem());
    let known_hosts = dir.path().join("known_hosts");
    write_restricted(&known_hosts, fake.known_hosts_line());
    let mut device = json!({
        "ip": "127.0.0.1",
        "port": fake.port,
        "username": "netconf",
        "auth": { "type": "ssh_key", "private_key_path": key.to_str().unwrap() },
    });
    if let Some(authority) = authority {
        device["config_authority"] = json!(authority);
    }
    let inventory = dir.path().join("devices.json");
    write_restricted(&inventory, &json!({ "fake": device }).to_string());
    let mut args = vec![
        "-f",
        inventory.to_str().unwrap(),
        "--known-hosts-file",
        known_hosts.to_str().unwrap(),
        "--allow-direct-commit",
    ];
    args.extend_from_slice(extra_args);
    let server = spawn_stdio_server_with_protocol(&args, "2025-06-18");
    (fake, server, dir)
}

fn load_and_commit(server: &mut StdioChild) -> Value {
    call_tool(
        server,
        "load_and_commit_config",
        json!({ "device": "fake", "config_text": "set system host-name x", "config_format": "set" }),
    )
}

fn position(requests: &[String], needle: &str) -> usize {
    requests
        .iter()
        .position(|request| request.contains(needle))
        .unwrap_or_else(|| panic!("never sent {needle}: {requests:?}"))
}

const SECURITY_DIFF: &str = "[edit security nat source]\n+   rule-set rs1;";
const INTERFACE_DIFF: &str = "[edit interfaces ge-0/0/0]\n+   description x;";

#[test]
fn detected_mist_is_refused_before_any_lock_or_load() {
    let (fake, mut server, _dir) = start(script(MIST_STANZA, INTERFACE_DIFF), None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("plan_mist_change"), "{resp}");
    assert!(fake.saw("outbound-ssh"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:lock>"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:load-configuration"), "{:?}", fake.requests());
}

#[test]
fn declared_sdc_security_diff_is_refused_reverted_and_unlocked() {
    let (fake, mut server, _dir) = start(
        script(NO_STANZA, SECURITY_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("prepare_sdc_nat_write"), "{resp}");
    let requests = fake.requests();
    // Declared authority wins: the device is never asked.
    assert!(!fake.saw("outbound-ssh"), "{requests:?}");
    assert!(!fake.saw("<nc:commit"), "{requests:?}");
    let diff = position(&requests, "compare=\"rollback\"");
    let revert = position(&requests, r#"<nc:load-configuration rollback="0"/>"#);
    let unlock = position(&requests, "<nc:unlock>");
    assert!(diff < revert && revert < unlock, "{requests:?}");
}

#[test]
fn declared_sdc_interface_diff_commits() {
    let (fake, mut server, _dir) = start(
        script(NO_STANZA, INTERFACE_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp["success"], json!(true), "{resp}");
    assert!(resp.get("warning").is_none(), "{resp}");
    assert!(fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn detected_sdc_security_diff_is_refused_and_says_how_it_was_detected() {
    let (fake, mut server, _dir) = start(script(SDC_STANZA, SECURITY_DIFF), None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(
        resp.to_string()
            .contains("detected from system services outbound-ssh"),
        "{resp}"
    );
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn allow_flag_turns_the_mist_refusal_into_a_warning() {
    let (fake, mut server, _dir) = start(
        script(MIST_STANZA, INTERFACE_DIFF),
        None,
        &["--allow-plane-owned-writes"],
    );
    let resp = load_and_commit(&mut server);
    assert_eq!(resp["success"], json!(true), "{resp}");
    assert!(
        resp["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("overwritten and erased")),
        "{resp}"
    );
    assert!(fake.saw("<nc:commit"), "{:?}", fake.requests());
}

// ---- change-set lifecycle (HTTP, lab mode: approval waived, owner applies) ----

const CANDIDATE_CONFIG: &str =
    "<configuration><system><host-name>fake</host-name></system></configuration>";

/// `script()` plus the candidate read the change-set fingerprint is taken from.
fn changeset_script(outbound_ssh_reply: &str, diff: &str) -> Script {
    let mut entries = script(outbound_ssh_reply, diff);
    // After the `compare` entry, which is also a get-configuration.
    entries.push(("database=\"candidate\"", CANDIDATE_CONFIG.to_string()));
    entries
}

struct ChangeSetRig {
    fake: FakeNetconf,
    server: Server,
    secret: String,
    session: String,
    _dir: tempfile::TempDir,
}

/// Spawn the binary over HTTP in `--lab-mode` against the fake device.
fn start_changeset(script: Script, authority: Option<&str>, extra_args: &[&str]) -> ChangeSetRig {
    let fake = FakeNetconf::start(script);
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    write_restricted(&key, &client_key_pem());
    let known_hosts = dir.path().join("known_hosts");
    write_restricted(&known_hosts, fake.known_hosts_line());
    let mut device = json!({
        "ip": "127.0.0.1",
        "port": fake.port,
        "username": "netconf",
        "auth": { "type": "ssh_key", "private_key_path": key.to_str().unwrap() },
    });
    if let Some(authority) = authority {
        device["config_authority"] = json!(authority);
    }
    let inventory = dir.path().join("devices.json");
    write_restricted(&inventory, &json!({ "fake": device }).to_string());
    let tokens = dir.path().join("tokens.json");
    let output = std::process::Command::new(common::binary_path())
        .args(["token", "add", "--tokens-file"])
        .arg(&tokens)
        .args([
            "--name",
            "owner",
            "--tools",
            "create_junos_change_set,apply_junos_change_set,get_junos_candidate_fingerprint,get_junos_change_set_status",
            "--devices",
            "*",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let secret = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let mut args = vec![
        "--known-hosts-file",
        known_hosts.to_str().unwrap(),
        "--lab-mode",
    ];
    args.extend_from_slice(extra_args);
    let server = spawn_with_auth_args(&inventory, &tokens, &args);
    let session = initialize(server.port, &secret);
    ChangeSetRig {
        fake,
        server,
        secret,
        session,
        _dir: dir,
    }
}

impl ChangeSetRig {
    /// Call a tool; returns `(is_error, text)` of the first content block.
    fn call(&self, name: &str, arguments: Value) -> (bool, String) {
        let response = http_post(
            self.server.port,
            Some(&self.secret),
            Some(&self.session),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
                   "params":{"name":name,"arguments":arguments}}),
        );
        assert_eq!(response.code, 200, "{name}: {:?}", response.body);
        let result = &response.body["result"];
        (
            result["isError"] == json!(true),
            result["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
        )
    }

    /// Fingerprint, create, then apply a one-payload change set. Returns the
    /// create result and the apply result.
    fn create_and_apply(&self) -> ((bool, String), (bool, String)) {
        self.create_and_apply_actions(
            json!([{"payload": {"text": "set system host-name x", "format": "set"}}]),
        )
    }

    /// Fingerprint, create, then apply a change set with `actions`.
    fn create_and_apply_actions(&self, actions: Value) -> ((bool, String), (bool, String)) {
        let (_, text) = self.call("get_junos_candidate_fingerprint", json!({"device": "fake"}));
        let fingerprint = serde_json::from_str::<Value>(&text).unwrap()["candidate_fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("no fingerprint in {text}"))
            .to_owned();
        let created = self.call(
            "create_junos_change_set",
            json!({"device": "fake", "expected_fingerprint": fingerprint, "actions": actions}),
        );
        if created.0 {
            return (created, (false, String::new()));
        }
        let body: Value = serde_json::from_str(&created.1).unwrap();
        let applied = self.call(
            "apply_junos_change_set",
            json!({"change_set_id": body["change_set_id"], "device": "fake",
                   "expected_digest": body["plan_digest"], "expected_fingerprint": fingerprint}),
        );
        (created, applied)
    }
}

#[test]
fn changeset_declared_sdc_security_diff_is_refused_reverted_and_unlocked() {
    let rig = start_changeset(
        changeset_script(NO_STANZA, SECURITY_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let (created, (apply_error, apply_text)) = rig.create_and_apply();
    assert!(!created.0, "{created:?}");
    assert!(apply_error, "{apply_text}");
    assert!(apply_text.contains("prepare_sdc_nat_write"), "{apply_text}");
    // Returned typed, not stringified by the coordinator: a refusal, not bad input.
    assert!(
        apply_text.starts_with("refused: apply_junos_change_set"),
        "{apply_text}"
    );
    assert!(!apply_text.contains("staging failed"), "{apply_text}");
    // The refusal fails the change set rather than leaving it Approved.
    let id = serde_json::from_str::<Value>(&created.1).unwrap()["change_set_id"].clone();
    let (_, status) = rig.call(
        "get_junos_change_set_status",
        json!({"change_set_id": id, "device": "fake"}),
    );
    assert!(status.contains(r#""state": "failed""#), "{status}");
    let requests = rig.fake.requests();
    assert!(!rig.fake.saw("outbound-ssh"), "{requests:?}");
    assert!(!rig.fake.saw("<nc:commit"), "{requests:?}");
    assert!(!rig.fake.saw("<commit-configuration"), "{requests:?}");
    let diff = position(&requests, "compare=\"rollback\"");
    let revert = position(&requests, r#"<nc:load-configuration rollback="0"/>"#);
    // A dirtied candidate is released by closing the session, not by <unlock>.
    let release = position(&requests, "<nc:close-session/>");
    assert!(diff < revert && revert < release, "{requests:?}");
}

#[test]
fn changeset_declared_sdc_interface_diff_applies() {
    let rig = start_changeset(
        changeset_script(NO_STANZA, INTERFACE_DIFF),
        Some("security-director-cloud"),
        &[],
    );
    let (_, (apply_error, apply_text)) = rig.create_and_apply();
    assert!(!apply_error, "{apply_text}");
    assert!(
        rig.fake.saw("<commit-configuration"),
        "{:?}",
        rig.fake.requests()
    );
}

#[test]
fn changeset_detected_mist_is_refused_before_any_load() {
    let rig = start_changeset(changeset_script(MIST_STANZA, INTERFACE_DIFF), None, &[]);
    let (created, (apply_error, apply_text)) = rig.create_and_apply();
    assert!(
        !created.0,
        "unknown authority is allowed at create: {created:?}"
    );
    assert!(apply_error, "{apply_text}");
    assert!(apply_text.contains("plan_mist_change"), "{apply_text}");
    let requests = rig.fake.requests();
    assert!(rig.fake.saw("outbound-ssh"), "{requests:?}");
    assert!(!rig.fake.saw("<nc:load-configuration"), "{requests:?}");
    assert!(!rig.fake.saw("<nc:commit"), "{requests:?}");
    assert!(!rig.fake.saw("<commit-configuration"), "{requests:?}");
}

/// A detected plane gets the same rollback-depth guard as a declared one: the
/// interface-only diff would pass the plane guard, so only the depth guard can
/// refuse this.
#[test]
fn changeset_detected_sdc_rollback_depth_two_is_refused() {
    let rig = start_changeset(changeset_script(SDC_STANZA, INTERFACE_DIFF), None, &[]);
    let (created, (apply_error, apply_text)) =
        rig.create_and_apply_actions(json!([{"rollback_source": 2}]));
    assert!(!created.0, "{created:?}");
    assert!(apply_error, "{apply_text}");
    assert!(
        apply_text.contains("would roll back 2 commit(s)"),
        "{apply_text}"
    );
    assert!(!rig.fake.saw("rollback=\"2\""), "{:?}", rig.fake.requests());
    assert!(
        !rig.fake.saw("<commit-configuration"),
        "{:?}",
        rig.fake.requests()
    );
}

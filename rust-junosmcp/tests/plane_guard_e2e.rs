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

// ---- upgrade_junos: warns, never refuses ----

/// `get-chassis-cluster-status` on a standalone SRX, as captured from a vSRX.
const STANDALONE_CLUSTER_REPLY: &str = "<xnm:error xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" \
    xmlns:xnm=\"http://xml.juniper.net/xnm/1.1/xnm\">\n<parse/>\n\
    <source-daemon>jsrpd</source-daemon>\n\
    <message>error: Chassis cluster is not enabled</message>\n</xnm:error>";

/// `script()` plus the probes `upgrade_junos` preflight runs; the device
/// reports 24.4R1.9 with 7 GiB free, so a different target reaches the
/// confirmation prompt.
fn upgrade_script(outbound_ssh_reply: &str) -> Script {
    upgrade_script_with_cluster(outbound_ssh_reply, STANDALONE_CLUSTER_REPLY)
}

fn upgrade_script_with_cluster(outbound_ssh_reply: &str, cluster_reply: &str) -> Script {
    let mut entries = script(outbound_ssh_reply, INTERFACE_DIFF);
    entries.push(("get-chassis-cluster-status", cluster_reply.to_string()));
    let cli_replies = [
        (
            "show version | match Junos:",
            "<output>\nJunos: 24.4R1.9\n</output>",
        ),
        (
            "show system commit",
            "<output>\n0   2026-05-14 09:12:31 UTC by netconf via netconf\n</output>",
        ),
        (
            "show system storage no-forwarding",
            "<output>\nFilesystem  Size Used Avail Capacity Mounted on\n/dev/x      10G  2.1G 7.0G  23%      /.mount/var\n</output>",
        ),
    ];
    for (command, reply) in cli_replies {
        entries.push((command, reply.to_string()));
    }
    entries
}

/// Stage a small image, run the binary, and call `upgrade_junos` with
/// `confirm=false`; returns the fake, the response and the temp dirs.
fn preview_upgrade(
    script: Script,
    authority: Option<&str>,
) -> (FakeNetconf, Value, tempfile::TempDir, tempfile::TempDir) {
    preview_upgrade_repeatedly(script, authority, 1)
}

fn preview_upgrade_repeatedly(
    script: Script,
    authority: Option<&str>,
    previews: usize,
) -> (FakeNetconf, Value, tempfile::TempDir, tempfile::TempDir) {
    let staging = tempfile::tempdir().unwrap();
    std::fs::write(
        staging.path().join("junos-25.4R1.12.tgz"),
        b"not a real image",
    )
    .unwrap();
    let (fake, mut server, dir) = start(
        script,
        authority,
        &["--staging-dir", staging.path().to_str().unwrap()],
    );
    let mut resp = Value::Null;
    for _ in 0..previews {
        resp = call_tool(
            &mut server,
            "upgrade_junos",
            json!({
                "device": "fake",
                "source_path": "junos-25.4R1.12.tgz",
                "target_version": "25.4R1.12",
                "confirm": false,
            }),
        );
    }
    (fake, resp, staging, dir)
}

/// The upgrade reached its confirmation prompt and changed nothing.
fn assert_unrefused_preview(fake: &FakeNetconf, text: &str) {
    assert!(text.contains("confirmation_required"), "{text}");
    assert!(text.contains("REBOOT"), "{text}");
    // Junos answers the CLI form with bare text in <rpc-reply>, which the parser rejects.
    assert!(
        !fake.saw("show chassis cluster status"),
        "{:?}",
        fake.requests()
    );
    assert!(!fake.saw("load-configuration"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
    assert!(!fake.saw("<commit-configuration"), "{:?}", fake.requests());
}

#[test]
fn upgrade_on_detected_mist_warns_and_is_not_refused() {
    let (fake, resp, _staging, _dir) = preview_upgrade(upgrade_script(MIST_STANZA), None);
    let text = resp.to_string();
    assert_unrefused_preview(&fake, &text);
    assert!(text.contains("config_authority_warning"), "{text}");
    assert!(text.contains("Juniper Mist"), "{text}");
    assert!(
        text.contains("detected from system services outbound-ssh"),
        "{text}"
    );
}

#[test]
fn upgrade_on_detected_sdc_names_security_director_cloud() {
    let (fake, resp, _staging, _dir) = preview_upgrade(upgrade_script(SDC_STANZA), None);
    let text = resp.to_string();
    assert_unrefused_preview(&fake, &text);
    assert!(text.contains("Security Director Cloud"), "{text}");
}

#[test]
fn upgrade_on_declared_mist_warns_without_probing() {
    let (fake, resp, _staging, _dir) = preview_upgrade(upgrade_script(NO_STANZA), Some("mist"));
    let text = resp.to_string();
    assert_unrefused_preview(&fake, &text);
    assert!(text.contains("config_authority_warning"), "{text}");
    assert!(
        text.contains("declared in devices.json config_authority"),
        "{text}"
    );
    assert!(!fake.saw("outbound-ssh"), "{:?}", fake.requests());
}

#[test]
fn upgrade_on_unmanaged_device_has_no_plane_warning() {
    let (fake, resp, _staging, _dir) = preview_upgrade(upgrade_script(NO_STANZA), None);
    let text = resp.to_string();
    assert_unrefused_preview(&fake, &text);
    assert!(!text.contains("config_authority_warning"), "{text}");
}

/// Preview against `cluster_reply` and assert the cluster refusal itself, not
/// just any failure: a reply the parser rejects would also skip the prompt.
fn assert_refused_as_cluster(cluster_reply: &str) {
    let (_fake, resp, _staging, _dir) =
        preview_upgrade(upgrade_script_with_cluster(NO_STANZA, cluster_reply), None);
    let text = resp.to_string();
    assert!(!text.contains("confirmation_required"), "{text}");
    assert!(text.contains("code=cluster_unsupported"), "{text}");
}

#[test]
fn upgrade_on_a_chassis_cluster_is_still_refused() {
    assert_refused_as_cluster(
        "<chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>",
    );
}

#[test]
fn upgrade_is_refused_when_the_device_does_not_prove_it_is_standalone() {
    assert_refused_as_cluster(
        &STANDALONE_CLUSTER_REPLY.replace("Chassis cluster is not enabled", "HA is not enabled"),
    );
}

#[test]
fn upgrade_on_a_non_srx_router_skips_the_cluster_check() {
    let unsupported = common::fake_netconf::rpc_error("syntax error");
    let mut script = upgrade_script_with_cluster(NO_STANZA, &unsupported);
    script.insert(
        0,
        (
            "get-software-information",
            "<software-information><host-name>fake</host-name><product-model>mx204</product-model></software-information>".to_string(),
        ),
    );
    let (fake, resp, _staging, _dir) = preview_upgrade(script, None);
    assert_unrefused_preview(&fake, &resp.to_string());
    assert!(
        !fake.saw("get-chassis-cluster-status"),
        "{:?}",
        fake.requests()
    );
}

#[test]
fn upgrade_proceeds_without_warning_when_the_plane_probe_fails() {
    let failing_probe = common::fake_netconf::rpc_error("probe refused");
    let (fake, resp, _staging, _dir) = preview_upgrade(upgrade_script(&failing_probe), None);
    let text = resp.to_string();
    assert_unrefused_preview(&fake, &text);
    assert!(fake.saw("outbound-ssh"), "{:?}", fake.requests());
    assert!(!text.contains("config_authority_warning"), "{text}");
}

#[test]
fn session_with_a_failed_plane_probe_is_not_reused() {
    let failing_probe = common::fake_netconf::rpc_error("probe refused");
    let (fake, _resp, _staging, _dir) =
        preview_upgrade_repeatedly(upgrade_script(&failing_probe), None, 5);
    let requests = fake.requests_by_connection();
    for (index, (connection, rpc)) in requests.iter().enumerate() {
        if !rpc.contains("outbound-ssh") {
            continue;
        }
        let reused = requests[index + 1..]
            .iter()
            .any(|(later, rpc)| later == connection && !rpc.contains("close-session"));
        assert!(!reused, "connection {connection} reused: {requests:?}");
    }
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

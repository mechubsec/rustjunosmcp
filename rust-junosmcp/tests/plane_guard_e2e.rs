#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! The plane guard end to end through the real binary against a loopback fake
//! NETCONF device: authority is declared or detected from the outbound-ssh
//! stanza, and a refusal never reaches the commit while the revert and unlock
//! still happen.
mod common;

use common::fake_netconf::{FakeNetconf, NO_REPLY, OK, Script, client_key_pem, rpc_error};
use common::{
    Server, StdioChild, call_tool, http_post, initialize, spawn_stdio_server_with_protocol,
    spawn_with_auth_args, write_restricted,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

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
        // The pending-commit-confirmed guard reads this before any commit check.
        (
            "show system commit",
            "<output>\n0   2026-05-14 09:12:31 UTC by netconf via netconf\n</output>".to_string(),
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

/// `script` with `inheritance_reply` answering the piped probe ahead of the
/// plain `outbound-ssh` entry, which keeps answering the plain command.
fn script_with_inheritance_reply(
    inheritance_reply: String,
    plain_reply: &str,
    diff: &str,
) -> Script {
    let mut entries = script(plain_reply, diff);
    entries.insert(0, ("display inheritance", inheritance_reply));
    entries
}

fn assert_refused_as_mist(fake: &FakeNetconf, resp: &Value) {
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(resp.to_string().contains("plan_mist_change"), "{resp}");
    assert!(!fake.saw("<nc:lock>"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn client_kept_in_a_group_is_detected_through_display_inheritance() {
    let script = script_with_inheritance_reply(MIST_STANZA.to_string(), NO_STANZA, INTERFACE_DIFF);
    let (fake, mut server, _dir) = start(script, None, &[]);
    let resp = load_and_commit(&mut server);
    assert_refused_as_mist(&fake, &resp);
    assert!(fake.saw("| display inheritance"), "{:?}", fake.requests());
}

#[test]
fn release_rejecting_the_pipe_falls_back_to_the_plain_command() {
    let script = script_with_inheritance_reply(
        rpc_error("syntax error, expecting &lt;command&gt;"),
        MIST_STANZA,
        INTERFACE_DIFF,
    );
    let (fake, mut server, _dir) = start(script, None, &[]);
    let resp = load_and_commit(&mut server);
    assert_refused_as_mist(&fake, &resp);
    let requests = fake.requests();
    let plain = requests
        .iter()
        .filter(|request| request.contains("outbound-ssh") && !request.contains("inheritance"));
    assert_eq!(plain.count(), 1, "{requests:?}");
    assert!(fake.saw("| display inheritance"), "{requests:?}");
}

#[test]
fn denied_pipe_refuses_the_write_without_falling_back() {
    let script =
        script_with_inheritance_reply(rpc_error("permission denied"), NO_STANZA, INTERFACE_DIFF);
    let (fake, mut server, _dir) = start(script, None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    let requests = fake.requests();
    let plain = requests
        .iter()
        .filter(|request| request.contains("outbound-ssh") && !request.contains("inheritance"));
    assert_eq!(plain.count(), 0, "{requests:?}");
    assert!(!fake.saw("<nc:lock>"), "{requests:?}");
    assert!(!fake.saw("<nc:commit"), "{requests:?}");
}

#[test]
fn both_probes_failing_refuses_the_write_and_commits_nothing() {
    let script = script_with_inheritance_reply(
        rpc_error("syntax error"),
        &rpc_error("probe refused"),
        INTERFACE_DIFF,
    );
    let (fake, mut server, _dir) = start(script, None, &[]);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(!fake.saw("<nc:lock>"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
}

#[test]
fn dead_session_does_not_fall_back_to_the_plain_command() {
    let (fake, mut server, _dir) = start(script(MIST_STANZA, INTERFACE_DIFF), None, &[]);
    // Connecting sends three facts RPCs, so the piped probe is the fourth.
    fake.hang_up_on_rpc(4);
    let resp = load_and_commit(&mut server);
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    let requests = fake.requests();
    let plain = requests
        .iter()
        .filter(|request| request.contains("outbound-ssh") && !request.contains("inheritance"));
    assert_eq!(plain.count(), 0, "{requests:?}");
    assert!(fake.saw("| display inheritance"), "{requests:?}");
    assert!(!fake.saw("<nc:commit"), "{requests:?}");
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
    let (fake, mut server, staging, dir) = start_upgrade(script, authority, &[]);
    let mut resp = Value::Null;
    for _ in 0..previews {
        resp = call_preview(&mut server);
    }
    (fake, resp, staging, dir)
}

/// The binary with a small image staged, ready for `call_preview`.
fn start_upgrade(
    script: Script,
    authority: Option<&str>,
    extra_args: &[&str],
) -> (
    FakeNetconf,
    StdioChild,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let staging = tempfile::tempdir().unwrap();
    std::fs::write(
        staging.path().join("junos-25.4R1.12.tgz"),
        b"not a real image",
    )
    .unwrap();
    let mut args = vec!["--staging-dir", staging.path().to_str().unwrap()];
    args.extend_from_slice(extra_args);
    let (fake, server, dir) = start(script, authority, &args);
    (fake, server, staging, dir)
}

fn call_upgrade(server: &mut StdioChild, confirm: bool) -> Value {
    call_tool(
        server,
        "upgrade_junos",
        json!({
            "device": "fake",
            "source_path": "junos-25.4R1.12.tgz",
            "target_version": "25.4R1.12",
            "confirm": confirm,
        }),
    )
}

fn call_preview(server: &mut StdioChild) -> Value {
    call_upgrade(server, false)
}

/// Run one upgrade call and return the fields of its audit record.
fn audited_upgrade(script: Script, authority: Option<&str>, confirm: bool) -> Value {
    let audit_dir = tempfile::tempdir().unwrap();
    let audit_log = audit_dir.path().join("audit.jsonl");
    let (_fake, mut server, _staging, _dir) = start_upgrade(
        script,
        authority,
        &[
            "--audit-log-file",
            audit_log.to_str().unwrap(),
            "--audit-format",
            "json",
        ],
    );
    call_upgrade(&mut server, confirm);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(&audit_log).unwrap_or_default();
        let record = contents
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|record| record["fields"]["tool"] == "upgrade_junos");
        if let Some(record) = record {
            return record["fields"].clone();
        }
        assert!(Instant::now() < deadline, "no audit record: {contents}");
        std::thread::sleep(Duration::from_millis(20));
    }
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

/// A standalone MX, which answers the cluster RPC with a syntax error.
fn mx_script() -> Script {
    let unsupported = common::fake_netconf::rpc_error("syntax error");
    let mut script = upgrade_script_with_cluster(NO_STANZA, &unsupported);
    script.insert(
        0,
        (
            "get-software-information",
            "<software-information><host-name>fake</host-name><product-model>mx204</product-model></software-information>".to_string(),
        ),
    );
    script
}

#[test]
fn upgrade_on_a_non_srx_router_skips_the_cluster_check() {
    let (fake, resp, _staging, _dir) = preview_upgrade(mx_script(), None);
    assert_unrefused_preview(&fake, &resp.to_string());
    assert!(
        !fake.saw("get-chassis-cluster-status"),
        "{:?}",
        fake.requests()
    );
}

#[test]
fn stale_session_on_a_non_srx_router_reconnects() {
    let (fake, mut server, _staging, _dir) = start_upgrade(mx_script(), Some("local"), &[]);
    // Connecting sends three facts RPCs, so this is the upgrade's first.
    fake.hang_up_on_rpc(4);
    assert_unrefused_preview(&fake, &call_preview(&mut server).to_string());
    let requests = fake.requests_by_connection();
    assert!(
        requests[3].1.contains("<get-software-information/>"),
        "{requests:?}"
    );
    let last_connection = requests.iter().map(|(connection, _)| *connection).max();
    assert_eq!(last_connection, Some(2), "{requests:?}");
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
fn audit_records_a_declared_plane() {
    let fields = audited_upgrade(upgrade_script(NO_STANZA), Some("mist"), false);
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(metadata.contains("config_authority=mist "), "{fields}");
    assert_eq!(metadata.matches("config_authority=").count(), 1, "{fields}");
    assert!(
        metadata.ends_with("config_authority_detected=false"),
        "{fields}"
    );
}

#[test]
fn audit_records_a_detected_plane() {
    let fields = audited_upgrade(upgrade_script(MIST_STANZA), None, false);
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(metadata.contains("config_authority=mist "), "{fields}");
    assert!(
        metadata.ends_with("config_authority_detected=true"),
        "{fields}"
    );
}

#[test]
fn audit_records_an_unmanaged_device_as_probed() {
    let fields = audited_upgrade(upgrade_script(NO_STANZA), None, false);
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(metadata.contains("config_authority=unknown "), "{fields}");
    assert!(
        metadata.ends_with("config_authority_detected=true"),
        "{fields}"
    );
}

/// An upgrade that fails after preflight never produces a result to read the
/// plane from, and this is the record an operator needs most.
#[test]
fn audit_keeps_the_plane_when_a_confirmed_upgrade_fails() {
    let fields = audited_upgrade(upgrade_script(NO_STANZA), Some("mist"), true);
    assert_eq!(fields["result"], "error", "{fields}");
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(metadata.contains("config_authority=mist "), "{fields}");
}

#[test]
fn audit_records_a_declared_plane_when_preflight_fails() {
    let refused = common::fake_netconf::rpc_error("permission denied");
    let script = upgrade_script_with_cluster(NO_STANZA, &refused);
    let fields = audited_upgrade(script, Some("mist"), false);
    assert_eq!(fields["result"], "error", "{fields}");
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(metadata.contains("config_authority=mist "), "{fields}");
}

/// Detection comes after preflight, so a failed preflight has nothing to record.
#[test]
fn audit_omits_an_undeclared_plane_when_preflight_fails() {
    let refused = common::fake_netconf::rpc_error("permission denied");
    let script = upgrade_script_with_cluster(MIST_STANZA, &refused);
    let fields = audited_upgrade(script, None, false);
    assert_eq!(fields["result"], "error", "{fields}");
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(!metadata.contains("config_authority"), "{fields}");
}

#[test]
fn audit_omits_the_plane_when_the_probe_fails() {
    let failing_probe = common::fake_netconf::rpc_error("probe refused");
    let fields = audited_upgrade(upgrade_script(&failing_probe), None, false);
    let metadata = fields["metadata"].as_str().unwrap();
    assert!(!metadata.contains("config_authority"), "{fields}");
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

#[test]
fn unanswered_close_is_abandoned_at_the_cleanup_budget() {
    let failing_probe = common::fake_netconf::rpc_error("probe refused");
    let mut script = upgrade_script(&failing_probe);
    script.insert(0, ("close-session", NO_REPLY.to_string()));
    let (fake, mut server, _staging, _dir) =
        start_upgrade(script, None, &["--cleanup-timeout-secs", "1"]);
    call_preview(&mut server);
    // The probe may open a new connection or reuse the upgrade's, so follow the close.
    let closed = || {
        fake.requests_by_connection()
            .iter()
            .any(|(connection, rpc)| {
                rpc.contains("close-session") && fake.connection_closed(*connection)
            })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !closed() {
        assert!(
            std::time::Instant::now() < deadline,
            "close never gave up: {:?}",
            fake.requests_by_connection()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
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

// ---- pending commit confirmed (#632) ----

/// Captured from a lab vSRX on Junos 24.4R1.9: the fixture `PENDING_LOG` in
/// `rust-junosmcp-core/src/commit_attribution.rs`, closed for the reply.
const PENDING_COMMIT_LOG: &str = "\
<output xmlns:junos=\"http://xml.juniper.net/junos/24.4R1.9/junos\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">
0   2026-11-10 23:57:00 UTC by netconf via netconf commit confirmed, rollback in 3mins
    rollback pending
1   2026-11-09 16:05:55 UTC by netconf via netconf
    rotate root password [REDACTED]
</output>";

/// `script` where the device reports a commit confirmed still pending.
fn pending_script(script: Script) -> Script {
    let mut entries = script;
    entries.insert(0, ("show system commit", PENDING_COMMIT_LOG.to_string()));
    entries
}

#[test]
fn commit_check_is_refused_while_a_commit_confirmed_is_pending() {
    let (fake, mut server, _dir) = start(
        pending_script(script(NO_STANZA, INTERFACE_DIFF)),
        Some("local"),
        &[],
    );
    let resp = call_tool(
        &mut server,
        "commit_check_config",
        json!({ "device": "fake", "config_text": "set system host-name x", "config_format": "set" }),
    );
    assert_eq!(resp.get("isError"), Some(&json!(true)), "{resp}");
    assert!(
        resp.to_string().contains("commit_confirmed_active"),
        "{resp}"
    );
    assert!(fake.saw("show system commit"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:validate"), "{:?}", fake.requests());
    assert!(!fake.saw("<nc:commit"), "{:?}", fake.requests());
    assert!(!fake.saw("<commit-configuration"), "{:?}", fake.requests());
}

#[test]
fn changeset_apply_is_refused_while_a_commit_confirmed_is_pending() {
    let rig = start_changeset(
        pending_script(changeset_script(NO_STANZA, INTERFACE_DIFF)),
        Some("local"),
        &[],
    );
    let (created, (apply_error, apply_text)) = rig.create_and_apply();
    assert!(!created.0, "{created:?}");
    assert!(apply_error, "{apply_text}");
    assert!(
        apply_text.contains("commit_confirmed_active"),
        "{apply_text}"
    );
    let requests = rig.fake.requests();
    assert!(!rig.fake.saw("<nc:validate"), "{requests:?}");
    assert!(!rig.fake.saw("<nc:commit"), "{requests:?}");
    assert!(!rig.fake.saw("<commit-configuration"), "{requests:?}");
}

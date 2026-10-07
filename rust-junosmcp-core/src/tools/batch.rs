//! `execute_junos_command_batch` — N devices x M commands, parallel across devices.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use async_trait::async_trait;
use std::sync::Arc;

/// Trait for an open device CLI session used by the batch runner.
/// Abstracting this allows test doubles that don't require real Junos devices.
#[async_trait]
pub trait RouterSession: Send {
    /// Execute a single CLI command and return its output.
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError>;
    /// Close the session gracefully.
    async fn close(&mut self) -> Result<(), JmcpError>;
}

/// Trait for opening device sessions. Production uses `DeviceManager`; tests inject stubs.
#[async_trait]
pub trait BatchRunner: Send + Sync {
    /// Open a CLI session to the named device, returning a boxed `RouterSession`.
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError>;
}

/// Production `RouterSession` wrapping a `PooledDevice` from `DeviceManager`.
struct RustEzSession(crate::device_manager::PooledDevice);

#[async_trait]
impl RouterSession for RustEzSession {
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError> {
        Ok(self.0.cli(command).await?)
    }
    async fn close(&mut self) -> Result<(), JmcpError> {
        // PooledDevice returns to pool on drop — no explicit close needed.
        Ok(())
    }
}

/// Production `BatchRunner` using `DeviceManager` to open real device sessions.
pub struct DeviceManagerRunner(pub Arc<DeviceManager>);

#[async_trait]
impl BatchRunner for DeviceManagerRunner {
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError> {
        let dev = self.0.open(router).await?;
        Ok(Box::new(RustEzSession(dev)))
    }
}

use crate::policy::{Policy, enforce_decision};
use crate::tools::ExecuteBatchArgs;
use serde::Serialize;
use serde_json::Value;

/// Outcome of a single command execution within a batch: either success with output or failure with an error message.
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct CommandOutcome {
    /// The command that was executed.
    pub command: String,
    /// Whether the command succeeded.
    pub ok: bool,
    /// Command output (when `ok=true`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Error message (when `ok=false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Per-device batch result: device name plus the ordered outcomes for each command.
#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct RouterResult {
    /// Device name.
    pub router: String,
    /// Ordered list of command outcomes (matches the input command order).
    pub commands: Vec<CommandOutcome>,
}

/// Production entry point for `execute_junos_command_batch` using `DeviceManager`.
pub async fn handle(
    args: ExecuteBatchArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
) -> Result<Value, JmcpError> {
    let runner: Arc<dyn BatchRunner> = Arc::new(DeviceManagerRunner(dm.clone()));
    handle_with_runner(args, dm, policy, runner).await
}

/// Core batch handler accepting an injectable `BatchRunner`. Used by tests and by `handle()`.
pub async fn handle_with_runner(
    args: ExecuteBatchArgs,
    dm: Arc<DeviceManager>,
    policy: Arc<Policy>,
    runner: Arc<dyn BatchRunner>,
) -> Result<Value, JmcpError> {
    crate::helpers::validate_output_caps(args.max_lines, args.max_bytes)?;

    if args.devices.is_empty() {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: devices must be non-empty".into(),
        ));
    }
    if args.commands.is_empty() {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: commands must be non-empty".into(),
        ));
    }
    if args.max_concurrent_devices == 0 {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: max_concurrent_devices must be > 0".into(),
        ));
    }
    if args.devices.len() > 100 {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: devices list exceeds maximum of 100".into(),
        ));
    }
    if args.commands.len() > 50 {
        return Err(JmcpError::InventoryInvalid(
            "execute_junos_command_batch: commands list exceeds maximum of 50".into(),
        ));
    }

    // Pre-flight 1: partition devices into valid (in inventory) and unknown.
    let inventory = dm.inventory();
    let mut valid_indices = Vec::new();
    let mut preflight_results: Vec<Option<RouterResult>> =
        (0..args.devices.len()).map(|_| None).collect();

    for (idx, r) in args.devices.iter().enumerate() {
        if inventory.get(r).is_err() {
            tracing::warn!(
                tool = "execute_junos_command_batch",
                router = %r,
                "device not found in device mapping, skipping",
            );
            preflight_results[idx] = Some(RouterResult {
                router: r.clone(),
                commands: args
                    .commands
                    .iter()
                    .map(|c| CommandOutcome {
                        command: c.clone(),
                        ok: false,
                        value: None,
                        error: Some(format!("device '{}' not found in device mapping", r)),
                    })
                    .collect(),
            });
        } else {
            valid_indices.push(idx);
        }
    }
    drop(inventory);

    // Pre-flight 2: blocklist check on every (valid device, command) pair.
    // Security boundary — remains strict: one denied pair aborts the batch.
    for &idx in &valid_indices {
        let r = &args.devices[idx];
        for c in &args.commands {
            enforce_decision(
                policy.check_command(r, c),
                "execute_junos_command_batch",
                r,
                c,
            )?;
        }
    }

    let permits = Arc::new(tokio::sync::Semaphore::new(
        args.max_concurrent_devices as usize,
    ));
    let cmd_timeout = std::time::Duration::from_secs(args.command_timeout);
    let mut joinset: tokio::task::JoinSet<(usize, RouterResult)> = tokio::task::JoinSet::new();

    for &idx in &valid_indices {
        let device_name = args.devices[idx].clone();
        let permits = permits.clone();
        let runner = runner.clone();
        let commands = args.commands.clone();
        joinset.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore not closed");
            let rr = run_device(&*runner, device_name, commands, cmd_timeout).await;
            (idx, rr)
        });
    }

    let mut results = preflight_results;

    let collect = async {
        let mut js = joinset;
        while let Some(j) = js.join_next().await {
            if let Ok((idx, rr)) = j {
                results[idx] = Some(rr);
            }
        }
        js
    };

    if let Some(bt) = args.batch_timeout {
        let bt_dur = std::time::Duration::from_secs(bt);
        match tokio::time::timeout(bt_dur, collect).await {
            Ok(_drained) => {}
            Err(_) => {
                // batch timed out; tasks still in flight have been canceled
                // by dropping the JoinSet inside the timeout future.
            }
        }
    } else {
        let _ = collect.await;
    }

    let mut final_results: Vec<RouterResult> = args
        .devices
        .iter()
        .enumerate()
        .map(|(idx, name)| match results[idx].take() {
            Some(rr) => rr,
            None => RouterResult {
                router: name.clone(),
                commands: args
                    .commands
                    .iter()
                    .map(|c| CommandOutcome {
                        command: c.clone(),
                        ok: false,
                        value: None,
                        error: Some("batch timeout".into()),
                    })
                    .collect(),
            },
        })
        .collect();

    // Apply per-command output post-processing (pipe honoring + caps).
    for rr in &mut final_results {
        for co in &mut rr.commands {
            if let Some(v) = co.value.take() {
                co.value = Some(crate::output::process_output(
                    &co.command,
                    v,
                    args.max_lines,
                    args.max_bytes,
                    args.tail,
                ));
            }
        }
    }
    Ok(serde_json::to_value(final_results)?)
}

async fn run_device(
    runner: &dyn BatchRunner,
    device_name: String,
    commands: Vec<String>,
    cmd_timeout: std::time::Duration,
) -> RouterResult {
    let mut session = match runner.open(&device_name).await {
        Ok(s) => s,
        Err(e) => {
            return RouterResult {
                router: device_name,
                commands: commands
                    .iter()
                    .map(|c| CommandOutcome {
                        command: c.clone(),
                        ok: false,
                        value: None,
                        error: Some(format!("connect failed: {e}")),
                    })
                    .collect(),
            };
        }
    };
    let mut outs = Vec::with_capacity(commands.len());
    for cmd in &commands {
        let outcome = match tokio::time::timeout(cmd_timeout, session.cli(cmd)).await {
            Ok(Ok(out)) => CommandOutcome {
                command: cmd.clone(),
                ok: true,
                value: Some(out),
                error: None,
            },
            Ok(Err(e)) => CommandOutcome {
                command: cmd.clone(),
                ok: false,
                value: None,
                error: Some(format!("transport error: {e}")),
            },
            Err(_) => CommandOutcome {
                command: cmd.clone(),
                ok: false,
                value: None,
                error: Some("command timeout".into()),
            },
        };
        outs.push(outcome);
    }
    let _ = session.close().await;
    RouterResult {
        router: device_name,
        commands: outs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    use crate::policy::Policy;
    use crate::tools::ExecuteBatchArgs;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn routers_alias_still_deserializes() {
        // Prove that JSON with `"routers":` still works via serde alias.
        let json = r#"{"routers":["r1","r2"],"commands":["show version"]}"#;
        let args: ExecuteBatchArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.devices, vec!["r1", "r2"]);
    }

    #[tokio::test]
    async fn router_alias_still_deserializes() {
        // Prove that JSON with `"router":` (singular string → vec) still works.
        let json = r#"{"router":"r1","commands":["show version"]}"#;
        let args: ExecuteBatchArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.devices, vec!["r1"]);
    }

    #[tokio::test]
    async fn router_name_alias_still_deserializes() {
        // Prove that JSON with `"router_name":` still works.
        let json = r#"{"router_name":"r1","commands":["show version"]}"#;
        let args: ExecuteBatchArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.devices, vec!["r1"]);
    }

    #[tokio::test]
    async fn unknown_router_in_list_produces_inline_error() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"mode":"blocklist"},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, _) = stub_runner(vec![("r1", OpenBehavior::Ok(Duration::from_millis(10)))]);
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into(), "ghost".into()],
            commands: vec!["show version".into()],
            command_timeout: 5,
            batch_timeout: None,
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let v = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let results = parse_results(v);
        assert_eq!(results.len(), 2);
        // r1 should succeed
        assert_eq!(results[0].router, "r1");
        assert!(results[0].commands[0].ok);
        // ghost should have inline error
        assert_eq!(results[1].router, "ghost");
        assert!(!results[1].commands[0].ok);
        let err = results[1].commands[0].error.as_deref().unwrap();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn denied_command_anywhere_aborts_preflight() {
        let inv = inv_with(
            r#"{
                "_blocklist_defaults":{"commands":[{"action":"deny","pattern":"request system *"}]},
                "r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"203.0.113.2","port":1,"username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into(), "r2".into()],
            commands: vec!["show version".into(), "request system reboot".into()],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        match super::handle(args, dm, pol).await {
            Err(JmcpError::Denied { tool, pattern, .. }) => {
                assert_eq!(tool, "execute_junos_command_batch");
                assert_eq!(pattern, "request system *");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_routers_or_commands_is_rejected() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let args = ExecuteBatchArgs {
            devices: vec![],
            commands: vec!["show version".into()],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        assert!(super::handle(args, dm.clone(), pol.clone()).await.is_err());

        let args = ExecuteBatchArgs {
            devices: vec!["r1".into()],
            commands: vec![],
            command_timeout: 1,
            batch_timeout: None,
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        assert!(super::handle(args, dm, pol).await.is_err());
    }

    #[tokio::test]
    async fn device_manager_runner_propagates_unknown_router() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let runner = DeviceManagerRunner(Arc::new(DeviceManager::new(inv)));
        let r = runner.open("ghost").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Stub session: records each command, sleeps `cli_delay`, then returns
    /// either a value, an error, or times out by sleeping past the caller's
    /// `tokio::time::timeout`.
    struct StubSession {
        router: String,
        cli_delay: Duration,
        in_flight: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RouterSession for StubSession {
        async fn cli(&mut self, command: &str) -> Result<String, JmcpError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            let mut peak = self.peak_in_flight.load(Ordering::SeqCst);
            while now > peak {
                match self.peak_in_flight.compare_exchange(
                    peak,
                    now,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(observed) => peak = observed,
                }
            }
            tokio::time::sleep(self.cli_delay).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(format!("OUT:{}:{}", self.router, command))
        }
        async fn close(&mut self) -> Result<(), JmcpError> {
            Ok(())
        }
    }

    /// Open behavior: either succeed with a stub session or fail with a fixed message.
    enum OpenBehavior {
        Ok(Duration),
        Fail(&'static str),
    }

    struct StubRunner {
        behaviors: HashMap<String, OpenBehavior>,
        in_flight: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BatchRunner for StubRunner {
        async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError> {
            match self.behaviors.get(router) {
                Some(OpenBehavior::Ok(delay)) => Ok(Box::new(StubSession {
                    router: router.to_string(),
                    cli_delay: *delay,
                    in_flight: self.in_flight.clone(),
                    peak_in_flight: self.peak_in_flight.clone(),
                })),
                Some(OpenBehavior::Fail(msg)) => Err(JmcpError::InventoryInvalid((*msg).into())),
                None => Err(JmcpError::UnknownRouter(router.into())),
            }
        }
    }

    fn stub_inv(routers: &[&str]) -> Arc<Inventory> {
        // Explicit legacy `mode: blocklist` (fail-open, no rules) so these
        // transport/concurrency/ordering tests aren't affected by MEC-93's
        // new fail-closed allowlist default — they aren't testing policy.
        let mut entries = String::from(r#"{"_blocklist_defaults":{"mode":"blocklist"},"#);
        for (i, r) in routers.iter().enumerate() {
            if i > 0 {
                entries.push(',');
            }
            entries.push_str(&format!(
                r#""{r}":{{"ip":"203.0.113.{}","port":1,"username":"u","auth":{{"type":"password","password":"x"}}}}"#,
                i + 1
            ));
        }
        entries.push('}');
        inv_with(&entries)
    }

    fn stub_runner(behaviors: Vec<(&str, OpenBehavior)>) -> (Arc<StubRunner>, Arc<AtomicUsize>) {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));
        let mut map = HashMap::new();
        for (k, v) in behaviors {
            map.insert(k.to_string(), v);
        }
        (
            Arc::new(StubRunner {
                behaviors: map,
                in_flight,
                peak_in_flight: peak_in_flight.clone(),
            }),
            peak_in_flight,
        )
    }

    fn parse_results(v: Value) -> Vec<RouterResult> {
        serde_json::from_value(v).unwrap()
    }

    #[tokio::test]
    async fn result_ordering_matches_input() {
        let inv = stub_inv(&["r1", "r2"]);
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, _) = stub_runner(vec![
            ("r2", OpenBehavior::Ok(Duration::from_millis(10))),
            ("r1", OpenBehavior::Ok(Duration::from_millis(50))),
        ]);
        let args = ExecuteBatchArgs {
            devices: vec!["r2".into(), "r1".into()],
            commands: vec!["c2".into(), "c1".into()],
            command_timeout: 5,
            batch_timeout: None,
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let v = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let results = parse_results(v);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].router, "r2");
        assert_eq!(results[1].router, "r1");
        assert_eq!(results[0].commands[0].command, "c2");
        assert_eq!(results[0].commands[1].command, "c1");
        assert_eq!(results[0].commands[0].value.as_deref(), Some("OUT:r2:c2"));
    }

    #[tokio::test]
    async fn concurrency_cap_is_respected() {
        let inv = stub_inv(&["r1", "r2", "r3", "r4"]);
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, peak) = stub_runner(vec![
            ("r1", OpenBehavior::Ok(Duration::from_millis(80))),
            ("r2", OpenBehavior::Ok(Duration::from_millis(80))),
            ("r3", OpenBehavior::Ok(Duration::from_millis(80))),
            ("r4", OpenBehavior::Ok(Duration::from_millis(80))),
        ]);
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into(), "r2".into(), "r3".into(), "r4".into()],
            commands: vec!["show version".into()],
            command_timeout: 5,
            batch_timeout: None,
            max_concurrent_devices: 2,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let _ = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let observed = peak.load(Ordering::SeqCst);
        assert!(observed <= 2, "peak in-flight {observed} exceeded cap of 2");
        assert!(observed >= 1, "expected at least one cli call");
    }

    #[tokio::test]
    async fn command_timeout_records_inline_and_continues() {
        let inv = stub_inv(&["r1"]);
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, _) = stub_runner(vec![("r1", OpenBehavior::Ok(Duration::from_millis(200)))]);
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into()],
            commands: vec!["c1".into(), "c2".into()],
            command_timeout: 0,
            batch_timeout: None,
            max_concurrent_devices: 1,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let v = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let results = parse_results(v);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].commands.len(), 2);
        for c in &results[0].commands {
            assert!(!c.ok);
            assert_eq!(c.error.as_deref(), Some("command timeout"));
        }
    }

    #[tokio::test]
    async fn batch_timeout_marks_remaining_as_timeout() {
        let inv = stub_inv(&["r1", "r2"]);
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, _) = stub_runner(vec![
            ("r1", OpenBehavior::Ok(Duration::from_millis(20))),
            ("r2", OpenBehavior::Ok(Duration::from_secs(10))),
        ]);
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into(), "r2".into()],
            commands: vec!["c1".into()],
            command_timeout: 30,
            batch_timeout: Some(0),
            max_concurrent_devices: 4,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let v = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let results = parse_results(v);
        assert_eq!(results.len(), 2);
        let r2 = results.iter().find(|r| r.router == "r2").unwrap();
        assert_eq!(r2.commands.len(), 1);
        assert!(!r2.commands[0].ok);
        assert_eq!(r2.commands[0].error.as_deref(), Some("batch timeout"));
    }

    #[tokio::test]
    async fn connect_failure_yields_one_row_per_command() {
        let inv = stub_inv(&["r1"]);
        let dm = Arc::new(DeviceManager::new(inv.clone()));
        let pol = Arc::new(Policy::build(&inv).unwrap());
        let (runner, _) = stub_runner(vec![("r1", OpenBehavior::Fail("boom"))]);
        let args = ExecuteBatchArgs {
            devices: vec!["r1".into()],
            commands: vec!["c1".into(), "c2".into(), "c3".into()],
            command_timeout: 5,
            batch_timeout: None,
            max_concurrent_devices: 1,
            max_lines: None,
            max_bytes: None,
            tail: false,
        };
        let v = super::handle_with_runner(args, dm, pol, runner)
            .await
            .unwrap();
        let results = parse_results(v);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].commands.len(), 3);
        for c in &results[0].commands {
            assert!(!c.ok);
            let err = c.error.as_deref().unwrap_or("");
            assert!(err.starts_with("connect failed:"), "got: {err}");
        }
    }
}

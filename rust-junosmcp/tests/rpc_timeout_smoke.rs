#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Smoke test: the MCP-side per-call `tokio::time::timeout(args.timeout, ...)`
//! wrapper around `dm.open(...) + dev.cli(...)` returns a clean error within
//! the requested bound, end-to-end through the tool dispatch path.
//!
//! Context: while running a live Junos upgrade on 2026-05-14 we discovered
//! `rustez::Device` has a hidden `DEFAULT_RPC_TIMEOUT = 30s` that wraps every
//! post-handshake RPC. The fix in `device_manager.rs` raises that cap to 1 h
//! via `POOL_RPC_TIMEOUT`, leaving the MCP-side per-call timeout as the sole
//! user-visible bound (verified by the unit test
//! `device_manager::tests::pool_rpc_timeout_is_at_least_one_hour` and by the
//! manual real-device check in plan Task 5).
//!
//! What this test actually exercises: the request goes all the way through
//! `execute_junos_command`'s `tokio::time::timeout(...)` wrapper against an
//! unreachable IP (TEST-NET-1, RFC 5737), and the MCP returns `isError=true`
//! within the requested 5 s. It does NOT distinguish the T2 fix being applied
//! vs reverted — the rustez `connect()` (TCP + SSH + NETCONF hello) is not
//! covered by `rpc_timeout`, only post-handshake RPCs are, so against an
//! unreachable host the MCP outer timeout always fires first regardless. A
//! true regression test for the rustez cap would need a local SSH/NETCONF
//! mock that completes the handshake then stalls on an RPC; out of scope here.

mod common;

use common::{
    call_tool, spawn_stdio_server_with_args, write_fake_netconf_key_temp, write_inventory_temp,
};
use serde_json::json;
use std::time::Instant;

#[test]
fn execute_junos_command_outer_timeout_fires_before_rustez_cap() {
    // Inventory points at TEST-NET-1 (RFC 5737) — guaranteed unreachable,
    // so the connect attempt will hang until *something* times out.
    // Use a fake key file — connection will fail at the TCP layer long
    // before key parsing matters, but startup now requires a real,
    // 0600-moded regular file for every private_key_path named here.
    let key = write_fake_netconf_key_temp();
    let inv_path = write_inventory_temp(&[(
        "unreachable",
        "192.0.2.1",
        22,
        "netconf",
        key.path().to_str().expect("key path is utf8"),
    )]);

    let mut child = spawn_stdio_server_with_args(&["-f", inv_path.path().to_str().unwrap()]);

    let start = Instant::now();
    let resp = call_tool(
        &mut child,
        "execute_junos_command",
        json!({
            "router_name": "unreachable",
            "command": "show version",
            "timeout": 5,
        }),
    );
    let elapsed = start.elapsed();

    // Two observable properties:
    // 1. The MCP-side `tokio::time::timeout(args.timeout, ...)` returns an
    //    error within the requested bound (~5 s). The 25 s ceiling allows
    //    generous slack for CI jitter and process spawn tail.
    assert!(
        elapsed.as_secs() < 25,
        "MCP outer timeout should fire within the requested bound (~5s); \
         got {:?}. If this exceeds 25s, the timeout wrapper around \
         dm.open + dev.cli has regressed.",
        elapsed
    );

    // 2. The response is an error (it must not silently succeed against
    //    an unreachable host).
    let is_error = resp
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    assert!(is_error, "expected isError=true, got: {resp:?}");
}

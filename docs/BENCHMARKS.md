# Benchmarks

How `rust-junosmcp` compares with the other open-source Junos MCP servers on
startup, per-call latency, memory and SSH connection reuse, and how to
reproduce every number on this page.

| Server | Version | Commit | Language / NETCONF stack |
|--------|---------|--------|--------------------------|
| rust-junosmcp | 0.27.2 | `864ca6c` | Rust, rustez / rustnetconf |
| [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server) | 1.1.1 | `0fe6354` | Python, PyEZ 2.7.4 / ncclient 0.6.15 |
| [shigechika/junos-mcp](https://github.com/shigechika/junos-mcp) | 0.18.0 | `ecec068` | Python, junos-ops 0.30.0 / PyEZ 2.8.2 / ncclient 0.7.0 |
| shigechika/junos-mcp | 0.22.0 | `af4f84a` | as 0.18.0, on MCP SDK 2.x |

The competitors are run exactly as published, from the pinned commits above.
Their code is not modified.

## Results

### Mock NETCONF target (2026-10-05)

This measures **server overhead only**. The target is a synthetic NETCONF
server on loopback ([`mock_netconf.py`](../scripts/bench/mock_netconf.py)) that
answers instantly, so these numbers show what each MCP server adds on top of
the device. They say nothing about device response time.

3 runs × 30 steady-state calls per operation per server, 0 failed calls out of
1,812. Each cell is the median across the 3 runs, with the min–max range in
brackets. Raw data: [`results/mock-2026-10-05/`](../scripts/bench/results/mock-2026-10-05/).

| Server | Cold start (ms) | First device call (ms) | Peak RSS (MiB) | SSH connections per run |
|---|---|---|---|---|
| rust-junosmcp 0.27.2 | 5.7 (5.5–6.0) | 91.3 (48.3–132.2) | 20.6 (20.6–20.7) | 1 |
| Juniper 1.1.1 | 250.7 (248.3–261.8) | 300.1 (299.7–300.6) | 88.6 (88.3–88.9) | 121 |
| shigechika 0.18.0 | 289.9 (278.8–302.1) | 200.6 (200.1–201.9) | 88.5 (88.5–88.6) | 1 |
| shigechika 0.22.0 | 392.2 (382.3–407.1) | 196.9 (195.3–198.9) | 95.1 (94.7–95.3) | 1 |

Steady-state latency, p50 / p95 in ms (median across runs):

| Server | router list | facts | `show version` | `show interfaces terse` | config |
|---|---|---|---|---|---|
| rust-junosmcp 0.27.2 | 0.1 / 0.2 | 0.2 / 0.3 | 0.4 / 1.2 | 0.4 / 0.8 | 3.1 / 3.9 |
| Juniper 1.1.1 | 1.3 / 1.9 | 1819.7 / 1827.0 | 297.0 / 299.7 | 296.8 / 300.1 | 297.1 / 300.7 |
| shigechika 0.18.0 | 1.5 / 2.1 | 1.5 / 2.8 | 98.1 / 99.7 | 101.1 / 102.3 | 101.8 / 103.3 |
| shigechika 0.22.0 | 1.1 / 1.4 | 1.4 / 2.0 | 98.5 / 100.2 | 101.1 / 102.3 | 102.0 / 103.0 |

The per-run p50/p95 ranges are in [`summary.md`](../scripts/bench/results/mock-2026-10-05/summary.md).

How to read it:

- **The Python servers' latencies come in steps of about 100 ms.** ncclient
  polls its SSH channel with `select(timeout=TICK)`, `TICK = 0.1`
  (`ncclient/transport/session.py`), so a reply waits for the next tick. On a
  real device that floor sits under the device's own response time.
- **Juniper opens a new SSH session for every device call.** 121 connections
  per run means 1 first call plus 4 device operations × 30 calls. The router
  list never touches the device. rust-junosmcp and shigechika each keep one
  pooled session for the whole run.
- **Facts are cached by rust-junosmcp and shigechika** after the first call
  in a session. Juniper gathers the full PyEZ fact set on a fresh connection
  for every call. That gap reflects different behaviour, not raw speed.
- **Cold start is warm-cache.** Bytecode is already compiled and the binaries
  are in the page cache. A first-ever launch of a fresh Python venv took about
  0.9–1.0 s for the Python servers in our setup runs; rust-junosmcp was
  unchanged.

### Lab device

Pending. The same workload will run against a vSRX 24.4 lab device, and the
results and raw CSV will be added here.

## Method

The harness lives in [`scripts/bench/`](../scripts/bench/).

- **Client.** `bench.py` is a minimal MCP client. It starts each server as a
  child process on the stdio transport, the way an MCP host does, and sends
  JSON-RPC over its stdin/stdout. Servers run one at a time, never in
  parallel. The order rotates on each run so drift over time does not favour
  one server.
- **Same target, same path.** Every server reaches the NETCONF target through
  a loopback TCP proxy inside the harness. The proxy forwards bytes unchanged
  and counts SSH connections. Every server pays the same extra loopback hop.
- **Workload.** Read-only, the same five operations on every server, mapped
  to each server's equivalent tool:

  | Operation | rust-junosmcp / Juniper | shigechika |
  |---|---|---|
  | router list | `get_router_list` | `get_router_list` |
  | facts | `gather_device_facts` | `get_device_facts` |
  | `show version` | `execute_junos_command` | `run_show_command` |
  | `show interfaces terse` | `execute_junos_command` | `run_show_command` |
  | config | `get_junos_config` | `get_config` |

  No tool that changes configuration is ever called. Write-path latency is
  not measured.
- **Correctness check.** A call counts only if it returns without a JSON-RPC
  or tool error and its text matches an expected pattern, such as a Junos
  version string for facts or `host-name` for config. The match runs in memory.
  Response bodies are never written anywhere. `raw.csv` holds latency, an ok
  flag, a fixed failure class and the reply size in bytes.
- **Metrics.**
  - *Cold start*: process spawn to the `initialize` result.
  - *First device call*: the first `show version`, which pays SSH and
    NETCONF session setup.
  - *Steady state*: 30 calls per operation, interleaved round-robin across
    the five operations.
  - *Percentiles*: nearest-rank p50/p95 over each run's 30 calls, then the
    median and min–max across 3 runs.
  - *Memory*: peak RSS (`VmHWM`) of the server process at the end of the run.
  - *Connection reuse*: SSH connections the proxy saw over the server's
    lifetime.
- **Configuration.** Each server gets a fresh temporary config directory and
  `HOME`, so no user SSH config or known_hosts file leaks into the run.
  rust-junosmcp verifies host keys strictly against a known_hosts file the
  harness writes, and gets an inventory allowlist containing exactly the
  workload's three CLI commands (it denies commands by default). The Python
  servers use PyEZ's defaults.
- **Lab safety.** `--target lab` connects only to a device named in
  `LAB_DEVICE_ALLOWLIST` (`bench.py`). The harness refuses to start unless
  all of these hold:
  - The credential file and private key are mode 0600 and owned by the user.
  - The entry has a pinned host key.
  - A pre-flight SSH login, made directly rather than through the proxy,
    verifies that pinned key.

  The Python servers do not verify host keys by default, so this pre-flight
  is what ties a lab run to the device it was granted. Server stderr goes to
  a temporary file that is deleted unread.

## Hardware and software

| | |
|---|---|
| CPU | AMD Ryzen AI Max+ 395 (32 logical CPUs) |
| Memory | 125 GiB |
| OS | Linux 7.2 (CachyOS) |
| Harness / Python servers | CPython 3.13.15 (uv-managed venvs) |
| rust-junosmcp build | rustc 1.98.0 (as pinned in `rust-toolchain.toml`), `--release --locked` |

The full environment record is in each results directory's `environment.json`.

## Reproduce

```sh
# Build every server at its pinned commit (refuses moved tags).
scripts/bench/setup.sh ~/bench-work

# Mock target: one invocation per run, then merge.
for i in 1 2 3; do
  ~/bench-work/venv-bench/bin/python scripts/bench/bench.py run --target mock \
    --servers ~/bench-work/servers.json --out scripts/bench/results/mock-$(date +%F) \
    --calls 30 --run-index "$i" --strict
done
~/bench-work/venv-bench/bin/python scripts/bench/bench.py summarize \
  --out scripts/bench/results/mock-$(date +%F)
```

For a lab device, add `--target lab --lab-device <name> --lab-config <file>`.
`<name>` must be in `LAB_DEVICE_ALLOWLIST`, and `<file>` is a mode-0600 JSON
file:

```json
{"<name>": {"host": "…", "port": 830, "username": "…",
            "private_key_path": "…", "host_key": "ssh-ed25519 AAAA…"}}
```

Use a read-only Junos login class. Results never contain the device's
address or name: every server sees the target as `bench` on `127.0.0.1`.

Dependency locks for the harness and shigechika are in
[`scripts/bench/requirements/`](../scripts/bench/requirements/). Juniper is
installed from its own `uv.lock`.

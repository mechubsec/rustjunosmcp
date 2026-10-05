#!/usr/bin/env python3
"""MCP server benchmark harness: rust-junosmcp vs other Junos MCP servers.

Drives each server as an MCP client over stdio, the way an MCP host does, and
runs the same read-only workload against the same NETCONF target. All servers
reach the target through a loopback TCP proxy that counts SSH connections.

What it records (never response bodies, never device output):
  - cold start: process spawn -> `initialize` result
  - first call: first device call, which pays SSH + NETCONF session setup
  - per-op latency of N steady-state calls per op
  - peak RSS (VmHWM) of the server process
  - SSH connections opened over the server's lifetime

Targets:
  mock  synthetic NETCONF server (mock_netconf.py) on loopback; measures
        server overhead only.
  lab   a lab device named in LAB_DEVICE_ALLOWLIST, with credentials from an
        operator-supplied JSON file. The workload is read-only: no tool that
        changes configuration is ever called.

Usage:
  bench.py run --target mock --servers servers.json --out results/x --run-index 1
  bench.py summarize --out results/x
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import platform
import re
import shutil
import signal
import stat
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The only lab devices this harness will ever connect to. Adding a device here
# needs an explicit grant on the tracking task; nothing else widens it.
LAB_DEVICE_ALLOWLIST = frozenset({"vsrx-ci"})

# Alias every server uses for the target. Never the device's real name.
DEVICE_ALIAS = "bench"

CALL_TIMEOUT_S = 120.0
INIT_TIMEOUT_S = 60.0
PROTOCOL_VERSION = "2025-03-26"

# Read-only workload. Each op maps to a tool per server flavour, plus a regex
# the response text must match for the call to count as ok. The match is done
# in memory; the text is then dropped.
JUNOS_VERSION_RE = r"\b\d{2}\.\d+[RXI]\d"
OPS = ["router_list", "facts", "show_version", "interfaces_terse", "config"]
FLAVOURS = {
    "rustjunosmcp": {
        "router_list": ("get_router_list", {}, DEVICE_ALIAS),
        "facts": ("gather_device_facts", {"router_name": DEVICE_ALIAS}, JUNOS_VERSION_RE),
        "show_version": ("execute_junos_command", {"router_name": DEVICE_ALIAS, "command": "show version"},
                    r"Junos:"),
        "interfaces_terse": ("execute_junos_command", {"router_name": DEVICE_ALIAS, "command": "show interfaces terse"},
                    r"ge-0/0/0|fxp0"),
        "config": ("get_junos_config", {"router_name": DEVICE_ALIAS}, r"host-name"),
    },
    "juniper": {
        "router_list": ("get_router_list", {}, DEVICE_ALIAS),
        "facts": ("gather_device_facts", {"router_name": DEVICE_ALIAS}, JUNOS_VERSION_RE),
        "show_version": ("execute_junos_command", {"router_name": DEVICE_ALIAS, "command": "show version"},
                    r"Junos:"),
        "interfaces_terse": ("execute_junos_command", {"router_name": DEVICE_ALIAS, "command": "show interfaces terse"},
                    r"ge-0/0/0|fxp0"),
        "config": ("get_junos_config", {"router_name": DEVICE_ALIAS}, r"host-name"),
    },
    "shigechika": {
        "router_list": ("get_router_list", {}, DEVICE_ALIAS),
        "facts": ("get_device_facts", {"hostname": DEVICE_ALIAS}, JUNOS_VERSION_RE),
        "show_version": ("run_show_command", {"hostname": DEVICE_ALIAS, "command": "show version"},
                    r"Junos:"),
        "interfaces_terse": ("run_show_command", {"hostname": DEVICE_ALIAS, "command": "show interfaces terse"},
                    r"ge-0/0/0|fxp0"),
        "config": ("get_config", {"hostname": DEVICE_ALIAS}, r"host-name"),
    },
}


def die(msg: str) -> None:
    print(f"bench: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Target: mock or lab
# --------------------------------------------------------------------------


@dataclass
class Target:
    kind: str
    host: str
    port: int
    username: str
    private_key_path: str
    host_key: str  # "<type> <base64>"
    junos_version: str = ""
    cleanup: list = field(default_factory=list)


def _require_private(path: Path, what: str) -> None:
    st = path.stat()
    if st.st_uid != os.getuid():
        die(f"{what} is not owned by the current user; refusing")
    if stat.S_IMODE(st.st_mode) & 0o077:
        die(f"{what} is readable by group or others; chmod 600 it first")


def load_lab_target(device: str, config_path: str) -> Target:
    """Fail closed before any network I/O unless every guard passes."""
    if device not in LAB_DEVICE_ALLOWLIST:
        die(f"device {device!r} is not in LAB_DEVICE_ALLOWLIST; refusing")
    path = Path(config_path).expanduser()
    if not path.is_file():
        die("lab config file not found")
    _require_private(path, "lab config file")
    try:
        entry = json.loads(path.read_text())[device]
    except (json.JSONDecodeError, KeyError, TypeError):
        die(f"lab config has no usable entry for {device!r}")
    missing = [k for k in ("host", "port", "username", "private_key_path", "host_key") if not entry.get(k)]
    if missing:
        die(f"lab config entry is missing: {', '.join(missing)} (a pinned host_key is required)")
    key = Path(entry["private_key_path"]).expanduser()
    if not key.is_file():
        die("private key file not found")
    _require_private(key, "private key file")
    if len(entry["host_key"].split()) < 2:
        die("host_key must be '<type> <base64>'")
    return Target("lab", entry["host"], int(entry["port"]), entry["username"], str(key), entry["host_key"])


async def start_mock(workdir: Path) -> Target:
    import asyncssh  # harness venv only

    hk = asyncssh.generate_private_key("ssh-ed25519")
    ck = asyncssh.generate_private_key("ssh-ed25519")
    (workdir / "mock_host_key").write_bytes(hk.export_private_key())
    (workdir / "mock_client_key").write_bytes(ck.export_private_key())
    (workdir / "mock_client_key.pub").write_bytes(ck.export_public_key())
    os.chmod(workdir / "mock_host_key", 0o600)
    os.chmod(workdir / "mock_client_key", 0o600)
    port_file = workdir / "mock_port"
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(HERE / "mock_netconf.py"),
        "--host-key", str(workdir / "mock_host_key"),
        "--authorized-key", str(workdir / "mock_client_key.pub"),
        "--port-file", str(port_file),
        stderr=open(workdir / "mock.log", "wb"),
    )
    for _ in range(200):
        if port_file.exists() and port_file.read_text():
            break
        await asyncio.sleep(0.05)
    else:
        proc.kill()
        die("mock NETCONF server did not start")
    host_key = hk.export_public_key("openssh").decode().split()
    t = Target("mock", "127.0.0.1", int(port_file.read_text()), "bench",
               str(workdir / "mock_client_key"), f"{host_key[0]} {host_key[1]}")
    t.cleanup.append(proc)
    return t


async def preflight_host_key(target: Target) -> None:
    """Authenticate once against the pinned host key, directly (not via the
    proxy). The Python competitors do not verify host keys, so this is the
    check that a lab run is talking to the device it was granted."""
    import asyncssh

    known = asyncssh.import_known_hosts(f"[{target.host}]:{target.port} {target.host_key}\n"
                                        if target.port != 22 else f"{target.host} {target.host_key}\n")
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            target.host, target.port, username=target.username,
            client_keys=[target.private_key_path], known_hosts=known,
            config=None, agent_path=None, preferred_auth="publickey"), 30)
    except Exception as e:  # noqa: BLE001 - report class only, never the message
        die(f"pre-flight SSH to target failed ({type(e).__name__}); not running")
    conn.close()
    await conn.wait_closed()


# --------------------------------------------------------------------------
# Loopback counting proxy
# --------------------------------------------------------------------------


class CountingProxy:
    def __init__(self, target: Target):
        self.target = target
        self.connections = 0
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(self.target.host, self.target.port), 15)
        except (OSError, asyncio.TimeoutError):
            cw.close()
            return

        async def pump(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    w.close()
                except Exception:  # noqa: BLE001
                    pass

        await asyncio.gather(pump(cr, uw), pump(ur, cw))


# --------------------------------------------------------------------------
# Server launch configs
# --------------------------------------------------------------------------


def write_server_config(flavour: str, spec: dict, proxy_port: int, target: Target,
                        d: Path) -> tuple[list[str], dict, str]:
    """Return (argv, extra_env, cwd) for one server, writing its config into d."""
    key = target.private_key_path
    if flavour in ("rustjunosmcp", "juniper"):
        inv = {DEVICE_ALIAS: {"ip": "127.0.0.1", "port": proxy_port, "username": target.username,
                              "auth": {"type": "ssh_key", "private_key_path": key}}}
        if flavour == "rustjunosmcp":
            # rust-junosmcp denies commands by default; allow exactly the workload.
            inv["_blocklist_defaults"] = {"mode": "allowlist", "allow": [
                "show version", "show interfaces terse", "show configuration"]}
        if flavour == "juniper":
            # An empty ssh_config keeps the user's ~/.ssh/config out of the run.
            (d / "ssh_config").write_text("")
            inv[DEVICE_ALIAS]["ssh_config"] = str(d / "ssh_config")
        (d / "devices.json").write_text(json.dumps(inv))
        os.chmod(d / "devices.json", 0o600)
    if flavour == "rustjunosmcp":
        (d / "known_hosts").write_text(f"[127.0.0.1]:{proxy_port} {target.host_key}\n")
        for sub in ("staging", "leases", "bundles"):
            (d / sub).mkdir(exist_ok=True)
        argv = [spec["bin"], "--transport", "stdio", "--device-mapping", str(d / "devices.json"),
                "--known-hosts-file", str(d / "known_hosts"), "--staging-dir", str(d / "staging"),
                "--device-lease-dir", str(d / "leases"), "--state-file", str(d / "changeset-state.json"),
                "--support-bundle-staging-dir", str(d / "bundles"), "--inventory-readonly"]
        return argv, {}, str(d)
    if flavour == "juniper":
        return [spec["python"], str(Path(spec["src"]) / "jmcp.py"), "-f", str(d / "devices.json"),
                "-t", "stdio"], {}, spec["src"]
    if flavour == "shigechika":
        (d / "config.ini").write_text(
            f"[{DEVICE_ALIAS}]\nhost = 127.0.0.1\nport = {proxy_port}\nid = {target.username}\n"
            f"pw = \nsshkey = {key}\nssh_config = {d / 'ssh_config'}\n")
        (d / "ssh_config").write_text("")
        os.chmod(d / "config.ini", 0o600)
        return [spec["python"], "-m", "junos_mcp"], {"JUNOS_OPS_CONFIG": str(d / "config.ini")}, str(d)
    die(f"unknown server flavour {flavour!r}")


# --------------------------------------------------------------------------
# Minimal MCP stdio client
# --------------------------------------------------------------------------


class McpClient:
    def __init__(self, proc: asyncio.subprocess.Process):
        self.proc = proc
        self.next_id = 0

    async def _send(self, msg: dict) -> None:
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()

    async def request(self, method: str, params: dict, timeout: float) -> tuple[dict, int]:
        self.next_id += 1
        rid = self.next_id
        await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})

        async def read_reply() -> tuple[dict, int]:
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    raise ConnectionError("server closed stdout")
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue  # stray non-protocol output; ignore
                if msg.get("id") == rid and ("result" in msg or "error" in msg):
                    return msg, len(line)
                if "method" in msg and "id" in msg:
                    # Server-to-client request (e.g. elicitation, roots): decline.
                    await self._send({"jsonrpc": "2.0", "id": msg["id"],
                                      "error": {"code": -32601, "message": "not supported by bench client"}})

        return await asyncio.wait_for(read_reply(), timeout)

    async def notify(self, method: str, params: dict | None = None) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})


def result_text(msg: dict) -> tuple[bool, str]:
    if "error" in msg:
        return False, ""
    res = msg.get("result") or {}
    parts = []
    for c in res.get("content") or []:
        if c.get("type") == "text":
            parts.append(c.get("text", ""))
    if res.get("structuredContent") is not None:
        parts.append(json.dumps(res["structuredContent"]))
    return not res.get("isError", False), "\n".join(parts)


def classify(msg: dict, marker: str) -> str:
    """'' if ok, otherwise a fixed failure class. Never returns response text."""
    ok, text = result_text(msg)
    if "error" in msg:
        return "jsonrpc_error"
    if not ok:
        return "tool_error"
    if not re.search(marker, text):
        return "no_marker"
    return ""


def vm_hwm_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


# --------------------------------------------------------------------------
# One server, one run
# --------------------------------------------------------------------------


async def bench_server(name: str, spec: dict, target: Target, calls: int, run: int,
                       raw: list, debug_dir: Path | None) -> dict:
    flavour = spec["flavour"]
    ops = FLAVOURS[flavour]
    proxy = CountingProxy(target)
    await proxy.start()
    workdir = Path(tempfile.mkdtemp(prefix=f"bench-{name}-"))
    os.chmod(workdir, 0o700)
    argv, extra_env, cwd = write_server_config(flavour, spec, proxy.port, target, workdir)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(workdir), "LANG": "C.UTF-8",
           "RUST_LOG": "warn", **extra_env}
    stderr_path = workdir / "server.stderr"
    row = {"run": run, "server": name, "cold_start_ms": "", "tools_list_ms": "", "first_call_ms": "",
           "peak_rss_mib": "", "ssh_conns": "", "steady_ssh_conns": "", "calls": 0, "failed": 0}

    t0 = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=cwd, env=env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=open(stderr_path, "wb"), limit=64 * 1024 * 1024)
    client = McpClient(proc)
    try:
        await client.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                            "clientInfo": {"name": "rustjunosmcp-bench", "version": "1"}},
                             INIT_TIMEOUT_S)
        row["cold_start_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        await client.notify("notifications/initialized")

        t = time.perf_counter()
        tl, _ = await client.request("tools/list", {}, INIT_TIMEOUT_S)
        row["tools_list_ms"] = round((time.perf_counter() - t) * 1000, 2)
        have = {tool["name"] for tool in (tl.get("result") or {}).get("tools", [])}
        missing = sorted({ops[o][0] for o in OPS} - have)
        if missing:
            raise RuntimeError(f"{name}: server does not expose {missing}")

        async def call(op: str, seq: int, record_as: str | None = None) -> float:
            tool, args, marker = ops[op]
            t = time.perf_counter()
            fail = ""
            nbytes = 0
            try:
                msg, nbytes = await client.request("tools/call", {"name": tool, "arguments": args}, CALL_TIMEOUT_S)
                fail = classify(msg, marker)
                if not fail and op == "facts" and not target.junos_version:
                    # Keep only the matched version string; the text is dropped.
                    m = re.search(JUNOS_VERSION_RE + r"[\w.-]*", result_text(msg)[1])
                    target.junos_version = m.group(0) if m else ""
                if fail and debug_dir is not None:
                    # Debug aid for mock bring-up only; see run --debug-dir.
                    (debug_dir / f"{name}-{op}-{seq}.json").write_text(json.dumps(msg)[:20000])
            except asyncio.TimeoutError:
                fail = "timeout"
            except (ConnectionError, OSError):
                fail = "transport"
            ms = round((time.perf_counter() - t) * 1000, 3)
            raw.append({"run": run, "server": name, "op": record_as or op, "seq": seq,
                        "latency_ms": ms, "ok": 0 if fail else 1, "fail_class": fail, "resp_bytes": nbytes})
            row["calls"] += 1
            row["failed"] += 1 if fail else 0
            return ms

        row["first_call_ms"] = await call("show_version", 0, record_as="first_call")
        conns_before = proxy.connections
        for seq in range(1, calls + 1):
            for op in OPS:
                await call(op, seq)
        row["steady_ssh_conns"] = proxy.connections - conns_before
        row["peak_rss_mib"] = round(vm_hwm_kib(proc.pid) / 1024, 1)
    finally:
        try:
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), 10)
        except (asyncio.TimeoutError, ProcessLookupError, ConnectionError):
            try:
                proc.send_signal(signal.SIGTERM)
                await asyncio.wait_for(proc.wait(), 5)
            except (asyncio.TimeoutError, ProcessLookupError):
                proc.kill()
                await proc.wait()
        await proxy.stop()
        row["ssh_conns"] = proxy.connections
        # Server stderr may carry device output; it is never copied anywhere.
        shutil.rmtree(workdir, ignore_errors=True)
    return row


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def host_environment(servers: dict, target: Target) -> dict:
    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem_kib = 0
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal:"):
                mem_kib = int(line.split()[1])
    except OSError:
        pass
    return {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": target.kind,
        "target_junos_version": target.junos_version + (" (synthetic)" if target.kind == "mock" else ""),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "mem_gib": round(mem_kib / 1024 / 1024, 1),
        "kernel": platform.release(),
        "harness_python": platform.python_version(),
        "servers": {k: {kk: vv for kk, vv in v.items() if kk in ("flavour", "version", "commit")}
                    for k, v in servers.items()},
    }


async def cmd_run(args: argparse.Namespace) -> int:
    servers = json.loads(Path(args.servers).read_text())
    if args.only:
        servers = {k: v for k, v in servers.items() if k in args.only}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    debug_dir = Path(args.debug_dir) if args.debug_dir else None
    if debug_dir and args.target != "mock":
        die("--debug-dir stores responses and is only allowed with --target mock")
    if debug_dir:
        debug_dir.mkdir(parents=True, exist_ok=True)

    mock_dir = None
    if args.target == "lab":
        target = load_lab_target(args.lab_device, args.lab_config)
    else:
        mock_dir = Path(tempfile.mkdtemp(prefix="bench-mock-"))
        target = await start_mock(mock_dir)
    try:
        await preflight_host_key(target)
        names = list(servers)
        # Rotate the order each run so drift over time does not favour one server.
        k = (args.run_index - 1) % len(names)
        order = names[k:] + names[:k]
        raw: list = []
        rows = []
        for name in order:
            print(f"bench: run {args.run_index} {name} ...", file=sys.stderr, flush=True)
            r = await bench_server(name, servers[name], target, args.calls, args.run_index, raw, debug_dir)
            print(f"bench:   cold={r['cold_start_ms']}ms first={r['first_call_ms']}ms "
                  f"rss={r['peak_rss_mib']}MiB conns={r['ssh_conns']} failed={r['failed']}/{r['calls']}",
                  file=sys.stderr, flush=True)
            rows.append(r)
        write_csv(out / f"raw-run{args.run_index}.csv", raw)
        write_csv(out / f"runs-run{args.run_index}.csv", rows)
        env_path = out / "environment.json"
        if not env_path.exists():
            if args.junos_version:
                target.junos_version = args.junos_version
            env_path.write_text(json.dumps(host_environment(servers, target), indent=2) + "\n")
        failed = sum(r["failed"] for r in rows)
        return 1 if (failed and args.strict) else 0
    finally:
        for p in target.cleanup:
            p.send_signal(signal.SIGTERM)
            await p.wait()
        if mock_dir:
            shutil.rmtree(mock_dir, ignore_errors=True)


def nearest_rank(xs: list[float], p: float) -> float:
    s = sorted(xs)
    import math
    return s[max(0, math.ceil(p / 100 * len(s)) - 1)]


def cmd_summarize(args: argparse.Namespace) -> int:
    out = Path(args.out)
    raw, runs = [], []
    for f in sorted(out.glob("raw-run*.csv")):
        raw += list(csv.DictReader(open(f)))
    for f in sorted(out.glob("runs-run*.csv")):
        runs += list(csv.DictReader(open(f)))
    if not raw:
        die("no raw-run*.csv files")
    write_csv(out / "raw.csv", raw)
    write_csv(out / "runs.csv", runs)
    for f in list(out.glob("raw-run*.csv")) + list(out.glob("runs-run*.csv")):
        f.unlink()
    env = json.loads((out / "environment.json").read_text())
    servers = list(dict.fromkeys(r["server"] for r in runs))
    run_ids = sorted({r["run"] for r in runs}, key=int)

    def agg(vals: list[float]) -> str:
        if not vals:
            return "n/a"
        if len(vals) == 1:
            return f"{vals[0]:.1f}"
        return f"{statistics.median(vals):.1f} ({min(vals):.1f}–{max(vals):.1f})"

    lines = [f"# Benchmark summary: {env['target']} target, {env['date_utc'][:10]}", "",
             f"Runs: {len(run_ids)}. Steady-state calls per op per run: "
             f"{max(int(r['seq']) for r in raw)}. Cells are the median across runs, with min–max "
             "in brackets. Latency percentiles are nearest-rank over each run's calls.", "",
             "## Startup, memory and connections", "",
             "| Server | Cold start (ms) | First device call (ms) | Peak RSS (MiB) "
             "| SSH connections / run | Failed calls |",
             "|---|---|---|---|---|---|"]
    for s in servers:
        rs = [r for r in runs if r["server"] == s]

        def f(k: str, rs: list = rs) -> list[float]:
            return [float(r[k]) for r in rs if r[k] not in ("", None)]

        calls = sum(int(r["calls"]) for r in rs)
        failed = sum(int(r["failed"]) for r in rs)
        lines.append(f"| {s} | {agg(f('cold_start_ms'))} | {agg(f('first_call_ms'))} | "
                     f"{agg(f('peak_rss_mib'))} | {agg(f('ssh_conns'))} | {failed}/{calls} |")
    for pct in (50, 95):
        lines += ["", f"## Per-op latency, p{pct} (ms)", "", "| Server | " + " | ".join(OPS) + " |",
                  "|---|" + "---|" * len(OPS)]
        for s in servers:
            cells = []
            for op in OPS:
                per_run = []
                for rid in run_ids:
                    xs = [float(r["latency_ms"]) for r in raw
                          if r["server"] == s and r["op"] == op and r["run"] == rid and r["ok"] == "1"]
                    if xs:
                        per_run.append(nearest_rank(xs, pct))
                cells.append(agg(per_run))
            lines.append(f"| {s} | " + " | ".join(cells) + " |")
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="rust-junosmcp MCP server benchmark harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one benchmark pass over every server")
    r.add_argument("--target", choices=["mock", "lab"], required=True)
    r.add_argument("--lab-device", default="", help="must be in LAB_DEVICE_ALLOWLIST")
    r.add_argument("--lab-config", default="", help="JSON credential file, mode 0600")
    r.add_argument("--servers", required=True, help="servers JSON (see servers.example.json)")
    r.add_argument("--only", nargs="*", help="subset of server names")
    r.add_argument("--out", required=True)
    r.add_argument("--run-index", type=int, default=1)
    r.add_argument("--calls", type=int, default=30, help="steady-state calls per op")
    r.add_argument("--junos-version", default="", help="recorded in environment.json for lab runs")
    r.add_argument("--strict", action="store_true", help="exit 1 if any call failed")
    r.add_argument("--debug-dir", help="mock only: keep failing responses here for bring-up")
    s = sub.add_parser("summarize", help="merge per-run CSVs and write summary.md")
    s.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "run":
        return asyncio.run(cmd_run(args))
    return cmd_summarize(args)


if __name__ == "__main__":
    sys.exit(main())

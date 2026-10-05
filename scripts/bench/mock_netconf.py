#!/usr/bin/env python3
"""Synthetic Junos NETCONF-over-SSH server for the benchmark harness.

Every reply is generated from fixed synthetic data: documentation-range
addresses (RFC 5737), a made-up hostname and serial, no secrets. It speaks
NETCONF 1.0 end-of-message framing on the ``netconf`` SSH subsystem and
answers the RPCs the three benchmarked servers send for the read workload.
Anything else gets an ``rpc-error``, so a client that strays outside the
workload fails visibly instead of being handed a guess.

It never forwards anything anywhere. Bind it to loopback.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import signal
import sys

import asyncssh

EOM = "]]>]]>"
BASE_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
JUNOS_NS = "http://xml.juniper.net/junos/24.4R0/junos"

HOSTNAME = "bench-mock-vsrx"
VERSION = "24.4R1.9"
SERIAL = "MOCK0000000001"

HELLO = f"""<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="{BASE_NS}">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
    <capability>http://xml.juniper.net/dmi/system/1.0</capability>
  </capabilities>
  <session-id>{{session_id}}</session-id>
</hello>
{EOM}"""


def _interfaces() -> list[tuple[str, str]]:
    out = [("fxp0", "198.51.100.10/24")]
    for i in range(8):
        out.append((f"ge-0/0/{i}", f"192.0.2.{i * 8 + 1}/29"))
    return out


SHOW_VERSION_TEXT = f"""Hostname: {HOSTNAME}
Model: vsrx
Junos: {VERSION}
JUNOS Software Release [{VERSION}]
"""

INTERFACES_TERSE_TEXT = "Interface               Admin Link Proto    Local                 Remote\n" + "".join(
    f"{name:<24}up    up\n{name + '.0':<24}up    up   inet     {addr}\n" for name, addr in _interfaces()
)


def _config_text() -> str:
    lines = [
        "## Last commit: 2026-01-01 00:00:00 UTC by bench",
        f"version {VERSION};",
        "system {",
        f"    host-name {HOSTNAME};",
        "    services { ssh; netconf { ssh; } }",
        "    syslog { file messages { any notice; } }",
        "}",
        "interfaces {",
    ]
    for name, addr in _interfaces():
        lines += [f"    {name} {{", f"        unit 0 {{ family inet {{ address {addr}; }} }}", "    }"]
    lines += ["}", "security {", "    policies {", "        from-zone trust to-zone untrust {"]
    for i in range(200):
        lines += [
            f"            policy bench-{i:03d} {{",
            "                match { source-address any; destination-address any; application junos-http; }",
            "                then { permit; }",
            "            }",
        ]
    lines += ["        }", "    }", "    zones {", "        security-zone trust { interfaces { ge-0/0/0.0; } }",
              "        security-zone untrust { interfaces { ge-0/0/1.0; } }", "    }", "}"]
    return "\n".join(lines) + "\n"


CONFIG_TEXT = _config_text()


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _config_xml() -> str:
    ifaces = "".join(
        f"<interface><name>{n}</name><unit><name>0</name><family><inet><address><name>{a}</name>"
        f"</address></inet></family></unit></interface>"
        for n, a in _interfaces()
    )
    return (
        f'<configuration junos:commit-seconds="1767225600" junos:commit-user="bench" xmlns:junos="{JUNOS_NS}">'
        f"<version>{VERSION}</version><system><host-name>{HOSTNAME}</host-name></system>"
        f"<interfaces>{ifaces}</interfaces></configuration>"
    )


SOFTWARE_XML = (
    f"<software-information><host-name>{HOSTNAME}</host-name><product-model>vsrx</product-model>"
    f"<product-name>vsrx</product-name><junos-version>{VERSION}</junos-version>"
    f"<package-information><name>junos</name><comment>JUNOS Software Release [{VERSION}]</comment>"
    f"</package-information></software-information>"
)

ROUTE_ENGINE_XML = (
    "<route-engine-information><route-engine><slot>0</slot><mastership-state>master</mastership-state>"
    "<status>OK</status><model>VSRX-RE</model><up-time seconds=\"86400\">1 day</up-time>"
    "<last-reboot-reason>Router rebooted after a normal shutdown.</last-reboot-reason>"
    "</route-engine></route-engine-information>"
)

CHASSIS_INV_XML = (
    f"<chassis-inventory><chassis><name>Chassis</name><serial-number>{SERIAL}</serial-number>"
    "<description>VSRX</description></chassis></chassis-inventory>"
)

SYSTEM_INFO_XML = (
    f"<system-information><hardware-model>vsrx</hardware-model><os-name>junos</os-name>"
    f"<os-version>{VERSION}</os-version><serial-number>{SERIAL}</serial-number>"
    f"<host-name>{HOSTNAME}</host-name></system-information>"
)

UPTIME_XML = (
    "<system-uptime-information><current-time><date-time seconds=\"1767225600\">2026-01-01 00:00:00 UTC"
    "</date-time></current-time><system-booted-time><date-time seconds=\"1767139200\">2025-12-31 00:00:00 UTC"
    "</date-time></system-booted-time></system-uptime-information>"
)

INTERFACES_TERSE_XML = "<interface-information>" + "".join(
    f"<physical-interface><name>{n}</name><admin-status>up</admin-status><oper-status>up</oper-status>"
    f"<logical-interface><name>{n}.0</name><admin-status>up</admin-status><oper-status>up</oper-status>"
    f"<address-family><address-family-name>inet</address-family-name><interface-address>"
    f"<ifa-local>{a}</ifa-local></interface-address></address-family></logical-interface></physical-interface>"
    for n, a in _interfaces()
) + "</interface-information>"


def _error(msg: str) -> str:
    return (
        "<rpc-error><error-type>protocol</error-type><error-tag>operation-not-supported</error-tag>"
        f"<error-severity>error</error-severity><error-message>{_esc(msg)}</error-message></rpc-error>"
    )


OK = "<ok/>"

# RPCs answered with a fixed body. Keys are the local name of the first child
# of <rpc>.
STATIC = {
    "get-software-information": SOFTWARE_XML,
    "get-route-engine-information": ROUTE_ENGINE_XML,
    "get-chassis-inventory": CHASSIS_INV_XML,
    "get-system-uptime-information": UPTIME_XML,
    "get-system-information": SYSTEM_INFO_XML,
    "get-interface-information": INTERFACES_TERSE_XML,
    "open-configuration": OK,
    "close-configuration": OK,
    "lock-configuration": OK,
    "unlock-configuration": OK,
    "lock": OK,
    "unlock": OK,
    "discard-changes": OK,
    "close-session": OK,
}

COMMANDS = {
    "show version": (SHOW_VERSION_TEXT, SOFTWARE_XML),
    "show interfaces terse": (INTERFACES_TERSE_TEXT, INTERFACES_TERSE_XML),
}

RPC_RE = re.compile(r"<(?:\w+:)?rpc\b([^>]*)>(.*)</(?:\w+:)?rpc>", re.S)
MSGID_RE = re.compile(r'message-id\s*=\s*"([^"]*)"')
FIRST_EL_RE = re.compile(r"<(?:\w+:)?([\w-]+)([^>]*?)(/?)>", re.S)
FORMAT_RE = re.compile(r'format\s*=\s*"([^"]*)"')


def reply(body_xml: str) -> str:
    rpc = RPC_RE.search(body_xml)
    attrs, inner = (rpc.group(1), rpc.group(2)) if rpc else ("", "")
    mid = MSGID_RE.search(attrs)
    mid_attr = f' message-id="{_esc(mid.group(1))}"' if mid else ""
    el = FIRST_EL_RE.search(inner)
    name = el.group(1) if el else ""
    fmt = (FORMAT_RE.search(el.group(2)) or [None, "xml"])[1] if el else "xml"

    if name in STATIC:
        body = STATIC[name]
    elif name == "command":
        cmd = re.sub(r"<[^>]+>", "", inner).strip()
        cmd = cmd.split("|", 1)[0].strip()
        if cmd == "show configuration":
            body = f"<output>{_esc(CONFIG_TEXT)}</output>" if fmt == "text" else _config_xml()
        elif cmd in COMMANDS:
            text, xml = COMMANDS[cmd]
            body = f"<output>{_esc(text)}</output>" if fmt == "text" else xml
        else:
            body = _error(f"unknown command in mock: {cmd[:40]}")
    elif name in ("get-configuration", "get-config"):
        if fmt == "text":
            body = f"<configuration-text>{_esc(CONFIG_TEXT)}</configuration-text>"
        else:
            body = _config_xml()
            if name == "get-config":
                body = f"<data>{body}</data>"
    else:
        body = _error(f"rpc not implemented in mock: {name[:40]}")

    return (
        f'<rpc-reply xmlns="{BASE_NS}" xmlns:junos="{JUNOS_NS}"{mid_attr}>\n{body}\n</rpc-reply>\n{EOM}'
    ), name == "close-session"


class Stats:
    sessions = 0
    rpcs = 0


async def netconf_session(process: asyncssh.SSHServerProcess) -> None:
    Stats.sessions += 1
    process.stdout.write(HELLO.replace("{session_id}", str(Stats.sessions)))
    buf = ""
    hello_done = False
    try:
        while True:
            chunk = await process.stdin.read(65536)
            if not chunk:
                break
            buf += chunk
            while EOM in buf:
                msg, buf = buf.split(EOM, 1)
                if not hello_done:
                    hello_done = True
                    continue
                Stats.rpcs += 1
                out, close = reply(msg)
                process.stdout.write(out)
                if close:
                    process.exit(0)
                    return
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, BrokenPipeError, ConnectionError):
        pass
    process.exit(0)


class Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return True


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    ap.add_argument("--host-key", required=True, help="server private host key file")
    ap.add_argument("--authorized-key", required=True, help="client public key file to accept")
    ap.add_argument("--port-file", help="write the bound port here once listening")
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        print("mock_netconf: refusing to bind a non-loopback address", file=sys.stderr)
        return 2

    server = await asyncssh.create_server(
        Server,
        args.host,
        args.port,
        server_host_keys=[args.host_key],
        authorized_client_keys=args.authorized_key,
        process_factory=netconf_session,
        allow_scp=False,
        line_editor=False,
        encoding="utf-8",
    )
    port = server.sockets[0].getsockname()[1]
    if args.port_file:
        with open(args.port_file, "w") as f:
            f.write(str(port))
    print(f"mock_netconf listening on {args.host}:{port}", file=sys.stderr, flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    server.close()
    print(f"mock_netconf: sessions={Stats.sessions} rpcs={Stats.rpcs}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

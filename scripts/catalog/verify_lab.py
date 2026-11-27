"""Verify the embedded Junos API catalog against the bench lab, read-only.

Run: cd ~/Projects/mechubbench && uv run python <repo>/scripts/catalog/verify_lab.py \
    <repo>/rust-junosmcp-core/catalog/data <repo>/scripts/catalog/lab-results \
    <repo>/rust-junosmcp/tests/fixtures/catalog-lab

Talks only to the bench MCP server (bearer token read from mechubbench's
.env.bench-setup-token, never printed or written) using `show ...` commands.
Per device: resolves family and train from `show version`, then for ten
catalog RPCs checks (a) `<cli> | display xml rpc` names that RPC and
(b) `<cli> | display xml` replies with the catalog output root. Check (b) is
reported "n/a" when the server's command path ignores the pipe.
"""

import datetime
import gzip
import json
import os
import re
import sys
from pathlib import Path

from mechubbench.runner import MCPClient

ENDPOINT = os.environ.get("BENCH_MCP_URL", "http://192.168.1.231:30030/mcp")
TOKEN_FILE = Path.home() / "Projects/mechubbench/.env.bench-setup-token"
DEVICES = ["bench-ex2300", "bench-srx1600", "bench-srx440", "bench-srx345", "bench-vsrx-inet", "bench-csrx"]
FIXTURE_DEVICES = {"bench-ex2300": "junos-ex", "bench-srx1600": "junos-es"}
COMMON = [
    "get-software-information", "get-interface-information", "get-arp-table-information",
    "get-route-information", "get-system-uptime-information", "get-chassis-inventory",
    "get-system-storage", "get-commit-information", "get-lldp-neighbors-information",
    "get-license-summary-information",
]
EX_ONLY = ["get-ethernet-switching-table-information", "get-vlan-information"]
SRX_ONLY = [
    "get-flow-session-information", "get-firewall-policies", "get-security-associations-information",
    "get-security-policies-hit-count",
]


def read_token():
    """Return the bearer token from a bare-token or KEY=VALUE file."""
    raw = TOKEN_FILE.read_text().strip()
    return raw.split("=", 1)[1].strip().strip("\"'") if re.match(r"^\w+=", raw) else raw


def redact(text):
    """Strip MACs, IPv4 addresses and serial-looking fields from captured text."""
    text = re.sub(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", "00:00:5e:00:53:xx", text)
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "192.0.2.1", text)
    return re.sub(r"(?i)(serial-number>)[^<]*", r"\1REDACTED", text)


def load_catalog(data_dir, family):
    """Return the rpc catalog dict for a family."""
    with gzip.open(Path(data_dir) / f"rpc-{family}.json.gz") as handle:
        return json.load(handle)


def first_element(xml):
    """Name of the first real element in a reply, skipping the <rpc> wrapper and <output> text."""
    names = [n for n in re.findall(r"<([A-Za-z][\w-]*)", xml) if n != "rpc"]
    return names[0] if names else None


def run(client, device, command):
    """Run a show command, returning (text, error)."""
    assert device.startswith("bench-"), f"refusing non-bench device {device!r}"
    try:
        return client.call_tool("execute_junos_command", {"router_name": device, "command": command}, truncate=False), None
    except Exception as error:  # report, never abort the sweep
        return None, str(error)[:200]


def identify(client, device):
    """Return (family, train, version) from `show version`."""
    text, error = run(client, device, "show version")
    if error or not isinstance(text, str):
        return None, None, None
    version = re.search(r"Junos: (\S+)", text)
    model = re.search(r"Model: (\S+)", text)
    if not version:
        return None, None, None
    family = "junos-ex" if model and model.group(1).lower().startswith("ex") else "junos-es"
    return family, ".".join(re.match(r"(\d+)\.(\d+)", version.group(1)).groups()), version.group(1)


def pick(catalog, family, train):
    """Choose up to ten (rpc, cli, output_roots) entries for the device class."""
    # Named RPCs first (lldp, license, class-specific), then fill to the cap.
    named = ["get-lldp-neighbors-information", "get-license-summary-information"]
    wanted = named + (EX_ONLY if family == "junos-ex" else SRX_ONLY[:3]) + COMMON
    picked = []
    for name in dict.fromkeys(wanted):
        for entry in catalog["families"][family].get(name, []):
            if train in entry["trains"] and entry["cli"].startswith("show "):
                picked.append((name, entry["cli"], sorted(catalog["outputs"][entry["output"]])))
                break
        if len(picked) == 10:  # duplicates in `wanted` are skipped below
            break
    return picked


def main():
    data_dir, results_dir, fixture_dir = map(Path, sys.argv[1:4])
    client = MCPClient(ENDPOINT, read_token())
    catalogs, report = {}, {}
    for device in DEVICES:
        family, train, version = identify(client, device)
        entry = report[device] = {"family": family, "version": version, "train": train, "checks": []}
        if family is None:
            entry["error"] = "could not resolve version"
            continue
        catalog = catalogs.setdefault(family, load_catalog(data_dir, family))
        for name, cli, roots in pick(catalog, family, train):
            reply, error = run(client, device, f"{cli} | display xml rpc")
            got = first_element(reply) if reply else None
            xml_reply, xml_error = run(client, device, f"{cli} | display xml")
            xml_root = first_element(xml_reply) if xml_reply else None
            if xml_root in ("output", None):
                xml_state = "n/a (pipe ignored)"
            else:
                xml_state = "ok" if xml_root in roots else f"mismatch ({xml_root})"
            unsupported = bool(error) and bool(re.search(r"syntax error|not valid on", error))
            entry["checks"].append({
                "unsupported_on_device": unsupported,
                "rpc": name, "cli": cli, "catalog_output_roots": roots,
                "rpc_name_ok": got == name, "rpc_name_got": got if got != name else None,
                "rpc_error": error, "display_xml": xml_state if not xml_error else f"error: {xml_error}",
            })
            if device in FIXTURE_DEVICES and name == "get-software-information" and reply:
                fixture_dir.mkdir(parents=True, exist_ok=True)
                (fixture_dir / f"{FIXTURE_DEVICES[device]}-display-xml-rpc-show-version.xml").write_text(redact(reply))
    print(f"{'device':16}{'ver':26}{'rpc':44}{'(a)':5}(b)")
    for device, entry in report.items():
        for check in entry["checks"]:
            print(f"{device:16}{str(entry['version']):26}{check['rpc']:44}{'ok' if check['rpc_name_ok'] else ('N/A' if check['unsupported_on_device'] else 'FAIL'):5}{check['display_xml'][:30]}")
        if entry.get("error"):
            print(f"{device:16}{entry['error']}")
    results_dir.mkdir(parents=True, exist_ok=True)
    out = results_dir / f"{datetime.date.today()}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("wrote", out)


if __name__ == "__main__":
    main()

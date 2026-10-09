<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-junosmcp</h1>

<p align="center"><strong>One MCP server for Juniper Junos and SRX devices, in Rust</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This repository is an independent, community-driven project. It is not affiliated with, endorsed by, sponsored by, or supported by Hewlett Packard Enterprise or Juniper Networks. "HPE", "Juniper", "SRX", "JUNOS", "Security Director" and "Juniper Mist" are trademarks of their respective owners and are used here only to describe what this software interoperates with. Please direct support and licensing questions about those products to the respective vendors.

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper Junos
and SRX devices, written in Rust. The single `rust-junosmcp` process exposes
the core Junos tools and, by default, the SRX security workflows through one
tool registry and endpoint. It is drop-in compatible with
[Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server) on the
inventory format and core tool surface, but built on async Rust
([rustEZ](https://github.com/mechubsec/rustez) +
[rustnetconf](https://github.com/mechubsec/rustnetconf)) instead of PyEZ.

## Beyond Juniper/junos-mcp-server

Drop-in on `devices.json` and the core tools — plus a lot the Python/PyEZ server doesn't have:

- **Safer config** — `commit_check_config` (validate, never commit), confirmed commits with auto-rollback, and `discard_candidate` to unstick a dirty candidate.
- **Device lifecycle** — staged `upgrade_junos` (image → install → reboot → verify), SCP `transfer_file`/`fetch_file`, PFE commands.
- **Scale & UX** — parallel session-pooled batch (~1.7× faster), `| last N`/`| count` + `max_lines`/`max_bytes` output caps, `router`/`router_name` aliases, Jinja2 templates.
- **Transport & auth** — streamable-HTTP with per-token router/tool scopes, TLS, and a `Host` allowlist; upstream is stdio-only.
- **SRX tools** (enabled by the default `srx` feature) — IDP & Application-ID **signature-package updates** (check/download/install/rollback), chassis-cluster health, license & security-services status, JTAC bundle with secret redaction, and read-only security-policy / address-book / application / NAT-rule inspection.

## Performance

Benchmarked on 2026-10-05 against [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server)
1.1.1 and [shigechika/junos-mcp](https://github.com/shigechika/junos-mcp) 0.18.0 / 0.22.0
with the same read-only workload on a vSRX lab device (Junos 26.2R1.7), 3 runs × 30 calls per operation, 0 failed calls.
Medians across runs:

| | rust-junosmcp 0.27.2 | Juniper 1.1.1 | shigechika 0.22.0 |
|---|---|---|---|
| Cold start | 6 ms | 264 ms | 392 ms |
| Peak memory (RSS) | 20 MiB | 129 MiB | 98 MiB |
| SSH connections per run | 1 | 121 | 1 |
| `show version`, p50 | 216 ms | 878 ms | 228 ms |
| config RPC (access-denied reply¹), p50 | 11 ms | 776 ms | 21 ms |

¹ the read-only bench login has no configuration view, so this measures a
round trip with a ~400-byte reply, not a full config fetch. See
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

Full results, the mock-target overhead numbers, method and reproduction steps:
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

> ## v0.10.0 released — read before upgrading
>
> Two **breaking** authorization changes, both requiring operator action:
> a wildcard tool scope (`"tools": ["*"]`) no longer confers the 15 **write-capable**
> tools, and `tokens.json` must be mode `0600` or the server refuses to start.
> The new **`token set-scope`** command changes a token's scopes without
> reissuing its secret, so you can narrow scopes on the running 0.9.x server
> before swapping the binary. See
> [Upgrading to v0.10](#upgrading-to-v010) for the procedure.
>
> Security: the auth stack is now `unsafe`-free — `rust-junosmcp-auth` consumes
> the shared [`mecmcp-auth`](https://github.com/mechubsec/mecmcp) crate,
> which replaces hand-rolled secret zeroing with `zeroize` and `libc::getuid`
> with `rustix`. A malformed token entry also no longer takes the whole store
> offline at load.
>
> Current tool surface: 44 tools by default (28 Junos-only with
> `--no-default-features`). See the
> [v0.10.0 release notes](https://github.com/mechubsec/rustjunosmcp/releases/tag/v0.10.0)
> for the authorization changes above.

## Feature scope

### v0.1 (released)

- 6 tools: `get_router_list`, `gather_device_facts`, `execute_junos_command`,
  `get_junos_config`, `junos_config_diff`, `load_and_commit_config`.
- stdio transport only.
- `devices.json` drop-in compatible (`auth.type` ∈ {`password`, `ssh_key`}).
- Docker image (distroless) and LXC release tarball with systemd unit.

### v0.2 (released)

- streamable-http transport (with optional rustls TLS).
- bearer-token auth with per-token router/tool scopes.
- SIGHUP hot-reload of the token store.

### v0.2 follow-up: PFE + batch (released)

- `execute_junos_pfe_command` — single PFE-shell call against an explicit FPC target.
- `execute_junos_command_batch` — N routers x M operational CLI commands, parallel across routers, per-command and optional whole-batch timeouts. Pre-flight blocklist + unknown-router checks; continue-on-error after pre-flight.
- New `pfe_commands` rule list under `_blocklist_defaults` and per-device `blocklist`. Independent from `commands`.

### v0.2 follow-up: Templates (released)

- `render_and_apply_j2_template` — render a Jinja2 template (inline `template_content`) with a JSON `vars_content` object. Supports single (`router_name`) or multiple routers (`router_names`), dry-run, and full commit. Reuses the same blocklist + format gating as `load_and_commit_config`.
- Vars must be a top-level JSON object. **YAML is no longer accepted** as of v0.5.2 (RJMCP-SEC-002): the `serde_yml` / `libyml` advisory chain (RUSTSEC-2025-0067/-0068) was reachable from MCP input, so the YAML branch was removed.
- Size caps: `template_content` and `vars_content` are each bounded at 64 KiB.
- Strict-undefined: missing variables fail with the variable name rather than rendering empty.
- Auto-format detection: leading `<` → `xml`, any `set ` / `delete ` line → `set`, otherwise `text`. Override via `config_format`.
- Result shape: one row per router with `rendered_template`, `config_format`, and either `diff` (dry-run), `commit_comment` (apply-mode echo of the supplied comment — rustez does not return a server-issued commit id), or `error`.

### v0.2 follow-up: Inventory mutation (released)

- `add_device` — add a Junos device to the in-memory inventory and persist to `devices.json`. Atomic write (tempfile + rename), preserves `_blocklist_defaults`, per-device `blocklist`, and other top-level fields. SHA-256-based TOCTOU guard rejects calls that race with external edits.
- `reload_devices` — re-read the current `--device-mapping` (no args) or swap to a new inventory file (`file_name`). Reports added / removed / changed device names.
- New CLI flags: `--inventory-readonly` (rejects both tools unconditionally), `--allow-password-auth-add` (permits `auth.type=password` in `add_device`; mutually exclusive with `--inventory-readonly`).
- SIGHUP now also re-reads the inventory in addition to the token store.

**Documented sharp edge:** `add_device` does not modify the token store. If a token has `--routers 'edge-*'` and you `add_device` for `core-3`, the existing token will not see the new router. Mint a new token or rotate scopes after `add_device`.

### v0.3 (released)

- **NETCONF session pooling** — `PooledDevice` RAII guard with per-router single-slot pool (300s idle timeout, 30s SSH keepalive, background reaper). Eliminates SSH handshake overhead on sequential commands.
- **Tool reliability fixes** — XML wrapper stripping for `get_junos_config` and `junos_config_diff`, corrected `show configuration | compare rollback N` command, timeout now covers SSH connect + NETCONF handshake (not just CLI execution).
- **Batch partial results** — `execute_junos_command_batch` returns inline error rows for unknown or unreachable routers instead of aborting the entire batch. Blocklist violations remain strict.
- **Batch scope violations are not partial** — if any router in the request is outside the token's scope, the call is refused with HTTP 403 `insufficient_scope` and *no* router executes. This differs from the unreachable case above on purpose: a device being down is a runtime failure, whereas naming a device the caller may not touch is an authorization failure, and no part of an unauthorized request is honoured. Split the request or widen the token.
- **Confirmed commits** — `load_and_commit_config` gains `confirm_timeout_mins` parameter for `commit confirmed N` with auto-rollback safety net.
- **crates.io dependency** — `rustez` switched from path dep to crates.io 0.10.1; CI no longer requires sibling repo checkout.

### v0.4 (released)

- **`transfer_file`** — idempotent SCP push (`scp -O`, since Junos disables OpenSSH SFTP) of a host-staged file to `/var/tmp/<basename>` on a Junos device. Pre-flight free-space check on `/var` (`local_size + 32 MiB` headroom), SHA-256 verify, post-transfer checksum re-validation with delete-on-mismatch. SSH-key auth only — password-auth devices rejected with `[code=unsupported_auth]`.
- **`list_staged_files`** — lists host staging dir always, plus device `/var/tmp/` listing when `router_name` is supplied.
- **Stable error codes** — every transfer failure carries an LLM-readable `[code=...]` Display tag (`bad_source_path`, `insufficient_disk`, `unsupported_auth`, `dest_exists_differs`, `scp_failed`, `connect_timeout`, `host_key_mismatch`, `host_key_revoked`, `verify_mismatch`, `outer_timeout`, `device_probe_failed`).
- **New CLI flags** — `--staging-dir` (default `/var/lib/jmcp/staging`) and `--known-hosts-file` (default `/etc/jmcp/known_hosts`).
- **Packaging** — `install.sh` provisions the new on-disk surface owned by `jmcp:jmcp`. See the File transfers section below for details.
- Tool count: 11 → 13.

### v0.5 (released)

- **`upgrade_junos`** — two-call (stage then confirm) Junos software upgrade. Uploads the package via `transfer_file` semantics, runs `request system software add`, and reboots. Standalone-only; rejected if a session pool entry exists for the target router.
- Tool count: 13 → 14.

### v0.6 (released)

- **`fetch_file`** — downloads a file from `<device>:/var/tmp/<basename>` to the host staging dir. SHA-256-verified, idempotent skip if the local copy already matches, per-router serialization. Mirror of `transfer_file`.
- Tool count: 14 → 15.

### v0.7 (released)

- **`commit_check_config`** — validate a candidate config (`commit check`) without committing — loads, diffs, checks, then discards. Never activates config. Own token scope (least-privilege).
- **`discard_candidate`** — discard uncommitted candidate changes (`rollback 0`) to recover a candidate left dirty ("configuration database modified"). Never changes the running config. Own token scope (least-privilege).
- Tool count: 15 → 17.

### v0.8 (released)

- **Unified Junos/SRX server** — one binary, endpoint, process, inventory,
  device manager, lease manager, auth surface, and SIGHUP reload path. Default
  builds expose 26 tools; `--no-default-features` retains the 17-tool
  Junos-only surface.
- **Operational controls** — per-router concurrency, per-token session and RPS
  limits, strict global session admission, bounded Prometheus metrics, and
  optional native journald audit fan-out.
- **Security and packaging** — scoped router-list results, cross-process
  destructive-operation leases, container SCP support, non-root image runtime,
  process healthchecks, and package upgrade coverage.
- **Split-service migration** — upgrades remove `rust-srxmcp`, its systemd unit,
  and port 30032 while preserving support bundles. Deprecated `JMCP_SRX_*`
  aliases are accepted for v0.8.0 only.

### v0.9 (released)

- **`rollback_config` tool** — load a Junos rollback archive (rollback N, 0–49)
  into the candidate and preview (default) or commit it, with confirmed-commit
  support. Tool count: 26 → 27 (17 → 18 Junos-only).
- **Correct pipe filtering** — `| match` / `| except` are applied server-side;
  the `<command>` RPC silently dropped them, so filtered config queries had
  returned the full config (a silent audit false negative).
- **Safer config verbs** — `junos_config_diff` accepts `rollback 0`
  (candidate vs running); `commit_check_config` reports a three-way `outcome`
  (`valid` / `invalid` / `check_failed`) so an inconclusive multi-RE cluster
  check is never read as an invalid config; `discard_candidate` recovers a
  dirty candidate lock-free.
- **Clearer diagnostics** — SRX services-status reports a failed health-check
  RPC as `error`, not `not_configured`; router-resolution failures log whether
  a name is unknown or out-of-scope (client response unchanged).
- **Security** — SSH transport off prerelease RustCrypto (russh 0.62; `-rc`
  crypto crates 13 → 3).

### v0.10 (released)

- **Wildcard tool scopes exclude write tools (breaking)** — `"tools": ["*"]`
  reaches every read-only tool but none of the 15 write-capable tools; granting write
  authority is now always an explicit, named decision. See
  [Tool scopes and write tools](#tool-scopes-and-write-tools).
- **`tokens.json` must be mode `0600` (breaking)** — the server refuses to
  start on a group- or world-accessible token file and names the owner uid,
  mode, caller uid, and the `chmod` to run.
- **`token set-scope`** — rescope a token without reissuing its secret, so
  scopes can be narrowed ahead of a binary upgrade without a client outage.
- **Resilient token load** — scope names are validated on write rather than on
  load, so one stale entry no longer takes the whole store offline.
- **Security** — `rust-junosmcp-auth` is now a thin re-export of the shared
  [`mecmcp-auth`](https://github.com/mechubsec/mecmcp) crate and contains
  no `unsafe`; `zeroize` replaces hand-rolled secret zeroing and `rustix`
  replaces `libc::getuid`. Tool count unchanged (27 / 18).

### v0.11 (released)

- **Four new read-only SRX tools** — `srx_list_policies` (security policies
  by from-zone/to-zone context, including global policies and optional
  per-policy hit counts), `srx_resolve_address` and `srx_resolve_application`
  (address-book and application/application-set resolution, including
  `junos-*` predefined defaults, with recursive nested-set resolution and
  explicit reference-cycle rejection — never a loop or a silent partial
  answer), and `srx_list_nat_rules` (source, destination, and static NAT
  rules, each independently). Address-book and application resolution are
  configuration-sourced via a hand-built subtree-filtered `get-configuration`
  RPC, since `rustez`'s `call()` only supports flat key/value args. Names on
  policies and NAT rules (addresses, applications) are returned
  **unresolved** on purpose — `srx_resolve_address` /
  `srx_resolve_application` are a separate, explicit step. All four are
  paginated/capped with an explicit `truncated` flag rather than a silent
  cutoff. Tool count: 37 → 41 (9 → 13 SRX tools; Junos-only build unchanged
  at 27 / 18, since these are gated by the default `srx` feature).

### v0.12 (unreleased)

- **Commit-confirmed is on by default (breaking)** — `load_and_commit_config`,
  `rollback_config` (`commit=true`), `render_and_apply_j2_template`, and
  `apply_junos_change_set` now issue `commit confirmed` unless the caller
  explicitly opts out with `confirm_timeout_mins: 0`. Previously a plain,
  unconditional commit was the default; a model-drafted change that cut
  management access had nothing bringing the device back. See
  [Confirmed commits](#confirmed-commits-v03-default-on-since-v012).
- **`--commit-confirm-default-mins`** (default `10`) sets the server-wide
  window used when a call omits `confirm_timeout_mins`; a per-call value
  still overrides it.
- **`confirm_commit`** — new write tool that sends the confirming commit for
  any of the four paths above, cancelling the pending auto-rollback.
- Opting out is recorded in the audit event as `commit_confirmed=false`.
- Tool count: 43 → 44 (27 → 28 Junos-only).

## Blocklist guardrails (v0.2)

`devices.json` may carry an optional `_blocklist_defaults` block plus an
optional `blocklist` field on each device entry. Rules use simple globs
(`*`, `?`) and an `action` of `"deny"` or `"allow"`. Most-specific match
wins; per-device rules tiebreak top-level defaults. See
[`devices-template.json`](devices-template.json) for an example, and
[`docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md`](docs/superpowers/specs/2026-05-04-blocklist-guardrails-design.md)
for the full design.

The `pfe_commands` rule list is independent: a deny on `commands` does not gate `execute_junos_pfe_command` and vice versa. Use it to restrict PFE inputs (e.g. `set *`) without affecting the operational CLI.

The blocklist applies to `execute_junos_command` and `load_and_commit_config`.
For `load_and_commit_config`, `config_format` must be `set` whenever the
device has any effective config rules; `text` and `xml` payloads are
rejected pre-flight in that case.

> **Compat note:** files using `_blocklist_defaults` or per-device
> `blocklist` are not cross-compatible with Juniper/junos-mcp-server's
> inventory format. Files without these fields remain drop-in compatible.

### `execute_junos_command` authorization mode: allowlist (default) vs. blocklist

`_blocklist_defaults` (and, going forward, this key only — see the
per-device restriction below) may carry a `mode` of `"allowlist"` or
`"blocklist"`. This governs `execute_junos_command`,
`execute_junos_command_batch`, `execute_junos_pfe_command`, and also
`get_junos_config` (it runs `show configuration [path] [| display
<format>]` through the same `commands` allowlist/blocklist — see "Config
output format and load mode" below); the `config` domain used by
`load_and_commit_config` stays a fail-open blocklist regardless of `mode`.

- **`allowlist` (fail-closed, the default for new configs)** — a command is
  denied unless it matches a literal, whitespace-tokenized prefix in
  `allow` (globs are rejected at load time, not just ignored). Each stage
  after a `|` in the command must independently match a prefix in
  `allowed_pipes`, or the whole command is refused; forbidden shell
  metacharacters (`;`, redirects, backticks, newlines) are refused
  outright, before any prefix match. `allow`/`allowed_pipes` merge the same
  way `commands` deny rules do today: `_blocklist_defaults` ∪ the device's
  own list. A per-device `allow` addition never leaks to other devices —
  each device gets its own compiled allowlist policy.

  `execute_junos_pfe_command` is gated by its own, independent pair of
  keys: `pfe_allow`/`pfe_allowed_pipes`. They merge the same way as
  `allow`/`allowed_pipes` (defaults ∪ device), but an entry in `allow` does
  not allowlist anything for PFE commands and vice versa — the two domains
  never share state. A config that sets `allow` but not `pfe_allow` still
  refuses every PFE command under allowlist mode — that is fail-closed by
  default for an unconfigured domain, not a bug; add a `pfe_allow` list if
  you need `execute_junos_pfe_command`.
- **`blocklist` (fail-open, legacy)** — the pre-MEC-93 behavior: a command
  is denied only if it matches a `commands` (or `pfe_commands`) deny glob;
  everything else is allowed.

**Allowed characters (MEC-1337).** In allowlist mode, a command may only
use printable ASCII characters with the literal ASCII space (`U+0020`) as
the token separator. Any other character is refused outright
(`forbidden_metachar`), the same as the existing `;`/redirect/backtick/
newline check.

**Migration:** a `devices.json` with `commands`/`pfe_commands` deny rules
but no `mode` key loads as `blocklist` and logs one startup `WARN` that
blocklist mode is fail-open, with a pointer back to this section. A file
with no `_blocklist_defaults` at all, or a freshly generated sample
config, loads as `allowlist`. `mode` is only valid on
`_blocklist_defaults` — setting it on a per-device `blocklist` is a
load-time error, since the underlying policy engine picks one command mode
for the whole file and a per-device override would silently do nothing.

Every refusal — allowlist or blocklist — writes an audit record via the
existing audit path, tagged with a stable reason code
(`not_allowlisted`, `pipe_not_allowlisted`, `forbidden_metachar`, or the
legacy `blocked`).

A minimal read-only starter allowlist:

```json
"_blocklist_defaults": {
    "mode": "allowlist",
    "allow": [
        "show version",
        "show interfaces",
        "show route",
        "show security policies",
        "show chassis"
    ],
    "pfe_allow": [
        "show cos"
    ]
}
```

## Config output format and load mode

`get_junos_config` takes an optional `format`: `text` (default, unchanged),
`set`, `xml`, or `json`. Each is rendered device-side via the matching Junos
`| display <format>` CLI modifier, so output goes through the same policy
check, blocklist, and output-cap pipeline as `text` today — there is no
separate code path for the new formats.

```json
{ "router_name": "core-1", "config_path": "system services", "format": "set" }
```

**Under `mode: allowlist`, `get_junos_config` is governed by the
`commands` allowlist, not a separate rule.** The rendered command is
`show configuration [config_path] [| display set|xml|json]`, checked the
same way as any other `execute_junos_command` input: `show configuration`
must be a prefix in `allow`, and — if a `format` other than the default
`text` is requested — `display set`/`display xml`/`display json` must be
a prefix in `allowed_pipes`. The starter allowlist in
[`devices-template.json`](devices-template.json) does **not** include
`show configuration`, so copying it as-is refuses `get_junos_config`
entirely (fails closed, so it is safe, but easy to miss). Add
`"show configuration"` to `allow` (and the `display` variants you need to
`allowed_pipes`) to enable it — and note that doing so exposes the full
running configuration, including hashed secrets, to the model.

`load_and_commit_config`, `render_and_apply_j2_template`, and
`create_junos_change_set`'s per-action `payload` all take an optional
`mode`: `merge` (default, unchanged), `replace`, or `override`.

`override` replaces the *entire* candidate configuration — the highest
blast-radius operation this server exposes. `load_and_commit_config` and
`render_and_apply_j2_template` commit directly in the same call with no
second-principal review, so they refuse `override` outright. It is only
available through the change-set flow (`create_junos_change_set` →
`approve_junos_change_set` → `apply_junos_change_set`), which requires a
second principal to approve the plan before anything commits.

`config_format=set` (a `configuration-set`, i.e. a list of `set`/`delete`
commands) has no wire-level `override` action in Junos — that combination
is rejected before any RPC is sent, on every path, including change sets.

## Confirmed commits (v0.3, default-on since v0.12)

`load_and_commit_config`, `rollback_config` (with `commit=true`),
`render_and_apply_j2_template`, and `apply_junos_change_set` all commit via
Junos `commit confirmed` **by default** — the router auto-rolls back if
nothing confirms the change within the window, so a bad push that cuts
management access reverts itself instead of requiring a truck roll.

The default window is the server's `--commit-confirm-default-mins` flag
(default 10, same validation as the per-call parameter). A per-call
`confirm_timeout_mins` overrides it for that one commit:

```json
{
  "router_name": "core-1",
  "config_text": "set interfaces ge-0/0/0 description test",
  "confirm_timeout_mins": 10,
  "commit_comment": "safe change with rollback window"
}
```

Response:
```json
{
  "success": true,
  "diff": "[edit interfaces ge-0/0/0]\n+   description test;",
  "confirmed": true,
  "rollback_in_minutes": 10,
  "rollback_deadline_unix": 1780000600,
  "message": "Commit confirmed: auto-rollback in 10 minutes unless confirmed. Send another commit to confirm."
}
```

`apply_junos_change_set`'s status response reports the same
`rollback_deadline_unix`.

**Opt out** of commit-confirmed for a single call by passing
`confirm_timeout_mins: 0`; this issues a plain, unconditional commit and is
recorded in the audit event as `commit_confirmed=false` so the exception is
traceable after the fact.

**To confirm** a pending window (cancel the scheduled auto-rollback), call
the `confirm_commit` tool with the device name — it sends the confirming
commit the same way `confirm_junos_change_set` does for the change-set
path. Sending another `load_and_commit_config` (or `rollback_config` /
`render_and_apply_j2_template`) also confirms, since Junos treats any
commit against the candidate as confirmation regardless of which tool
issued it. While a commit-confirmed window is open, `upgrade_junos` refuses
to proceed (`commit_confirmed_active`) rather than reboot a device that
might still roll back its configuration underneath the new image.

## File transfers (`transfer_file` / `fetch_file` / `list_staged_files`)

`transfer_file` pushes a host-staged file to `/var/tmp/<basename>` on a Junos
device using `mecmcp-scp`'s native SCP1 client over the SSH exec channel — the
same wire protocol OpenSSH's `scp -O` forces, since Junos disables SFTP-over-SSH.
No external `scp` process is spawned (#212). It is **idempotent on SHA-256**:
if the remote file already exists with a matching digest the call returns
`status: "skipped"`. Pass `force: true` to overwrite when digests differ.

`fetch_file` is the mirror operation: it downloads `/var/tmp/<basename>` from a
Junos device to the host staging dir using the same native SCP1 path. It is
**idempotent on SHA-256** — if the local file already exists with a matching
digest the call returns `status: "skipped"`. Per-router serialization and
post-transfer SHA-256 re-verification apply identically to `transfer_file`.

**Auth:** SSH key only. Devices with `auth.type = "password"` are rejected with
`[code=unsupported_auth]`. Add an SSH key to the device and reference its path
via `auth.private_key_path` in `devices.json`.

**On-disk surface:**

| Path                          | Purpose                                       | Default mode | Owner       |
| ----------------------------- | --------------------------------------------- | ------------ | ----------- |
| `/var/lib/jmcp/staging/`      | Host-side stage for files awaiting transfer  | `0750`       | `jmcp:jmcp` |
| `/etc/jmcp/known_hosts`       | SSH `known_hosts` consulted for every push    | `0644`       | `jmcp:jmcp` |
| `/var/lib/jmcp/device-leases` | Shared Junos/SRX destructive-operation locks | `0700`       | `jmcp:jmcp` |

Override at startup with `--staging-dir <path>`, `--known-hosts-file <path>`,
and `--device-lease-dir <path>`. Junos and SRX services must use the same
device lease directory.

**Host-key policy (v0.5.2+):** host-key checking is strict by default —
unknown device host keys are refused. The `known_hosts` file must
exist before the first `transfer_file` / `upgrade_junos` call, otherwise the
tool errors with `[code=known_hosts_missing]`. Pre-populate it with the
bundled helper:

```bash
scripts/scan-known-hosts.sh --inventory /etc/jmcp/devices.json \
                            --known-hosts /etc/jmcp/known_hosts
```

For lab / first-contact use, pass `--ssh-accept-new-host-keys` to fall back
to OpenSSH's `accept-new` (TOFU) mode: unknown hosts are pinned to
`known_hosts` on first contact, and a host presenting a *different* key
afterward is still refused. This applies identically to `transfer_file` /
`upgrade_junos` (scp) and NETCONF SSH.

**`--ssh-insecure-accept-any-host-key` (lab-only):** skips
host-key verification entirely for both NETCONF SSH *and* scp
(`transfer_file` / `upgrade_junos`) — no known_hosts persistence,
no mismatch detection, no protection against a man-in-the-middle. Mutually
exclusive with `--ssh-accept-new-host-keys`. Logged loudly at startup and
recorded as an audit event. Never use this against production devices; use
`--ssh-accept-new-host-keys` instead, which gives TOFU semantics safely.

`list_staged_files` returns the contents of the host staging dir. If
`router_name` is supplied it also runs `file list /var/tmp/ detail` on the
device and includes those entries under `device_files`.

**Source path safety:** `source_path` must be a basename only (no `/`, no `\`,
no `..`, no leading dot, ≤ 255 bytes); it is resolved relative to
`--staging-dir` and never escapes it.

**Pre-flight checks:** before transferring, `transfer_file` runs
`show system storage no-forwarding` and refuses to push when free space on
`/var` is below `local_size + 32 MiB`.

**Post-verify:** unless `verify: false` is passed, the device-side checksum is
re-computed via `file checksum sha-256 /var/tmp/<basename>` and the file is
deleted on mismatch.

## Long-running operational commands

Each MCP tool exposes a per-call `timeout` parameter (default 360 s). This is
the **sole user-visible bound** on operation duration; the underlying
`rustez::Device` is configured with a 1-hour internal RPC timeout at
connection time, so commands that legitimately take many minutes
(`request system software add`, `request support information`,
`request system snapshot`, etc.) will not be silently truncated.

If you need to run an operation that exceeds 1 hour, split it into
phases or invoke the work fire-and-forget on the device and poll for
completion separately.

**Caveat:** when a long-running RPC is followed by a device reboot, the
NETCONF session will of course die. The session pool reconnects cleanly
on the next call.

## Security warning

This server lets an LLM run commands and push configuration changes against
your Junos devices. Read [Juniper/junos-mcp-server's security notice](https://github.com/Juniper/junos-mcp-server#important-security-notice)
before deploying. The same warnings apply.

- Prefer SSH key authentication over passwords.
- Review configurations before allowing commit tools to run.
- Restrict network access to the MCP server.
- Don't deploy to untrusted networks.
- Set `devices.json` permissions to `0600` — it contains SSH credentials.
- `get_junos_config`, `junos_config_diff`, and other tools returning device
  config or command output are redacted before the response reaches the
  caller: values matching known secret patterns — including Junos
  `## SECRET-DATA` values (`$9$...`-style strings, which are **reversibly
  encrypted** with Juniper's proprietary symmetric cipher, not hashed —
  anyone holding the device's master key/passphrase can recover the
  plaintext), IKE pre-shared-keys, RADIUS/TACACS secrets, and SNMP
  communities — are replaced with a marker while structure, hostnames, and
  non-secret values are preserved. This is a best-effort net (a denylist plus
  a value-shape catch-all), not a guarantee; still restrict this tool's scope
  to trusted tokens.
- `reload_devices` requires `file_name` to be a *relative* path resolving
  inside the original `--device-mapping` directory (since v0.5.2). Absolute
  paths, `..` traversal, and symlinks pointing outside the inventory
  directory are all rejected.
- Text input fields (`command`, `config_text`, `template_content`,
  `pfe_command`) are capped at 1 MB. Batch lists are capped at 100
  routers and 50 commands.

## `--lab-mode`

`--lab-mode` waives the second principal requirement for change sets,
intended for single-operator lab environments where two-person control is
impractical. **It is off by default and must not be enabled on servers
managing production devices.**

What it does and does not change:

- Change sets are approved automatically at creation. There is no separate
  approval step, and the flow stays plan → apply, identical to production.
- Planning, the plan digest, drift detection, and apply-time revalidation all
  still run. Lab mode removes the *second reviewer*, not the change record.
- **No approver is fabricated.** A waived change set records `approver: null`
  alongside `approval_waiver: "lab-mode"`. It is cryptographically
  distinguishable from a genuine two-person approval and cannot be relabelled
  afterwards — which matters if anyone later has to prove which changes had
  real separation of duties.
- The server warns loudly at startup whenever it is enabled.

If you want solo write-testing *without* waiving the control, minting two
tokens with different names and using one to plan and the other to approve
is weaker than it looks: both tokens belong to the same human, so
"two-person" review is really the same operator clicking approve on their
own plan under a different name. The principal is the token name and
self-approval is refused, so it exercises the plan→approve→apply API shape
honestly — but it is not a real second reviewer.

mecmcp 0.27.0 adds a verified human-approver flow (MEC-994/MEC-995) that
closes that gap by binding the *approver's* identity to a fresh IdP login
rather than a token name:

- Bind the owner token to an IdP identity at creation time:
  `token add --oidc-issuer https://idp.example.com --oidc-subject
  alice@example.com ...`.
- Start the server with `--oidc-issuer`, `--oidc-audience`, and
  `--require-verified-approver` (plus `--approval-digest-key-file`, which
  strict mode requires so the verified-approver fields are tamper-evident).
- Approve with [`mecmcp-approve`](https://github.com/mechubsec/mecmcp/tree/main/crates/mecmcp-approve),
  which drives a real OIDC login (PKCE by default) and attaches the
  resulting assertion as a `Mecmcp-Approver-Assertion` header:
  `mecmcp-approve --server-url https://junos01.example:8443/mcp
  --approve-tool approve_junos_change_set --oidc-issuer
  https://idp.example.com --oidc-client-id mecmcp-approve
  --arg change_set_id=... --arg device=... --arg expected_digest=...`.
- In strict mode, the coordinator refuses an approval whose verified subject
  matches the owner's bound subject — the same human cannot satisfy both
  sides of the two-person rule, no matter how many token names they hold.

The two-token workaround above still has a place for pure functional
testing of the plan→approve→apply flow when no IdP is available, but treat
it as what it is: one operator exercising the API shape, not an approval.

### Enabling it

Add `--lab-mode` to the service unit. On a package install, use a systemd
drop-in rather than editing the shipped unit, so an upgrade does not silently
drop it:

```console
sudo systemctl edit rust-junosmcp
```

Replacing `ExecStart` means restating it in full, so **copy the shipped
command and append the flag** rather than writing a shorter one. Dropping
other arguments would turn off structured auditing or HMAC redaction as a side
effect of enabling lab mode:

```ini
[Service]
# Clear the shipped ExecStart before replacing it; systemd appends otherwise.
ExecStart=
ExecStart=/usr/local/bin/rust-junosmcp \
    --device-mapping /etc/jmcp/devices.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30030 \
    --tokens-file /etc/jmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/jmcp/audit-hmac.key \
    --lab-mode
```

Check it against `packaging/systemd/rust-junosmcp.service` before applying it —
the shipped arguments are the authority, and this snippet is a copy that can
age.

```console
sudo systemctl daemon-reload && sudo systemctl restart rust-junosmcp
```

Confirm it took effect. The startup warning uses `target: "audit"`, so grep
the journal for the lab-mode text with enough privilege to see a system unit:

```console
sudo journalctl -u rust-junosmcp -b | grep -i "lab mode"
```

The expected output includes:

```
lab mode enabled: change sets are approved on creation with no second principal. Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

Silence means it is off. An unprivileged `journalctl` can also print nothing
here for lack of access rather than because the flag is unset, which is why the
command uses `sudo`.

## `--allow-direct-commit`

Four tools never create a change set at all: `load_and_commit_config`
unconditionally, and `render_and_apply_j2_template` (when it would actually
apply), `rollback_config` (with `commit=true`), and `upgrade_junos` (with
`confirm=true`) once past their read-only preview/pre-flight step. Each stages,
validates, and commits a device change in one call, so there is no
second-principal review by construction — there is no change set for a second
principal to approve. **Off by default**: without this flag, all four are
refused before the device is ever touched, over stdio exactly as over HTTP
(stdio carries no caller context at all, so it cannot be treated any more
leniently than an authenticated session).

**Residual risk.** `--allow-direct-commit` is an escape hatch, not a fix. An
operator who sets it has decided that, for these specific tools, running with
no independent review is an acceptable risk for this deployment. That decision
is:

- **Logged loudly at startup.** A `SECURITY:` warning names the risk every time
  the process starts with the flag on.
- **Audited on every call.** Each direct-commit call carries
  `direct_commit_allowed=true` in its audit record — a refusal is audited too,
  as `authorization=denied reason=direct_commit_disabled`.

It does not add a second-principal review; it only makes running without one
visible. Prefer the change-set flow (`create_junos_change_set` →
`approve_junos_change_set` → `apply_junos_change_set`) wherever your workflow
can use it, and reserve this flag for the specific tools that cannot.

### Enabling it

Same pattern as `--lab-mode` above: add `--allow-direct-commit` to the service
unit via a systemd drop-in, copying the shipped `ExecStart` in full rather than
writing a shorter one.

Confirm it took effect. Unlike the `--lab-mode` banner, this one is
deliberately **not** tagged `target: "audit"` — that stream has a fixed
per-call schema, and a startup banner has none of those fields — so grep the
plain message text instead:

```console
sudo journalctl -u rust-junosmcp -b | grep -i "allow-direct-commit is enabled"
```

Silence means it is off.

## Audit logging

`rust-junosmcp` emits structured audit events for every Junos and SRX tool invocation. Each event records the caller, tool, target routers, authorization decision, outcome, and duration. See [`docs/AUDIT.md`](docs/AUDIT.md) for the full schema and forwarding guidance.

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--audit-format` | `JMCP_AUDIT_FORMAT` | `text` | Output format: `text` or `json`. |
| `--audit-log-file` | `JMCP_AUDIT_LOG_FILE` | (none) | Optional file path to append JSON events to (in addition to stderr). |
| `--audit-journald` | `JMCP_AUDIT_JOURNALD` | `false` | Optional native journald fan-out for structured audit fields; fails startup when explicitly enabled but unavailable. |

## Quick start (local)

```bash
git clone https://github.com/mechubsec/rustjunosmcp.git
cd RustJunosMCP

# Build the default 44-tool Junos/SRX server with TLS.
cargo build --release

# Optional: build the 28-tool Junos-only server without TLS.
cargo build --release --no-default-features

# Optional: build Junos-only with TLS.
cargo build --release --no-default-features --features tls

# Configure devices.
cp devices-template.json devices.json
$EDITOR devices.json   # set ip / username / auth

# Run as MCP stdio server.
./target/release/rust-junosmcp -f devices.json
```

## Claude Desktop config

One registration exposes every tool enabled in the built binary (44 with the
default `srx` feature, or 28 in a Junos-only build):

```json
{
  "mcpServers": {
    "junos": {
      "command": "/path/to/rust-junosmcp",
      "args": ["-f", "/path/to/devices.json"]
    }
  }
}
```

## Docker

### Run with Docker

The catalog-friendly stdio invocation replaces the image's HTTP CMD with
`--transport stdio`. The ENTRYPOINT already supplies the inventory, state,
known-hosts, lease, and token-file paths, so do not repeat those flags here.
The state mount is a bind mount, so it starts out host-user-owned; it and
`tokens.json` inside it must be owned by UID/GID `65532:65532` before the
first start, with `tokens.json` at mode `0600`:

```bash
mkdir -p jmcp-state
cat > jmcp-state/tokens.json <<'EOF'
{
  "version": 1,
  "tokens": [
    {
      "name": "catalog",
      "digest": "sha256:REPLACE_WITH_TOKEN_ADD_OUTPUT",
      "devices": ["r1"],
      "tools": ["gather_device_facts"],
      "created_at": "2026-01-01T00:00:00Z"
    }
  ]
}
EOF
sudo chown -R 65532:65532 jmcp-state
sudo chmod 0700 jmcp-state
sudo chmod 0600 jmcp-state/tokens.json
sudo chown 65532:65532 devices.json
sudo chmod 0600 devices.json

docker run --rm -i \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/jmcp-state:/var/lib/jmcp" \
  ghcr.io/mechubsec/rustjunosmcp:latest \
  --transport stdio
```

On rootless Docker or a userns-remapped host, UID 65532 inside the container
maps to a different host UID; chown the mounts to whatever that mapped UID
is instead of `65532` directly.

For example, `devices.json` uses the server's inventory shape (replace the
placeholder secret before use):

```json
{
  "r1": {
    "ip": "192.0.2.10",
    "port": 22,
    "username": "netconf-user",
    "auth": {
      "type": "password",
      "password": "replace-with-device-password"
    }
  }
}
```

This invocation leaves HTTP and TLS off because replacing the image CMD also
removes its HTTP bind and TLS-related flags.

The server defaults to port 22, which reaches NETCONF over the device's
regular SSH service (`set system services ssh`). If you enable the dedicated
NETCONF listener with `set system services netconf ssh` (port 830 by
default) and want to use it, set `port` to 830 explicitly.

> Running the two-person and lab-mode pair as containers, including the
> published-vs-internal port trap that makes the allow-lists reject everything
> with 421, is written up in
> [`docs/HOW-TO-SETUP-DOCKER.md`](docs/HOW-TO-SETUP-DOCKER.md).

Prebuilt images are published to GHCR on every version tag. The package is
public — no `docker login` required. The runtime is `distroless` — no shell,
`apt`, or OpenSSH client (#201) — and runs as numeric UID/GID `65532:65532`.
`transfer_file`/`fetch_file` no longer spawn `scp`; they speak the SCP1 wire
protocol natively via `mecmcp-scp` over the SSH exec channel (#212).

Prepare read-only configuration/key mounts and one persistent writable state
directory. Private-key paths in `devices.json` must use their in-container
locations under `/etc/jmcp/keys`.

```bash
# Pull the prebuilt image (tags: latest, 0.25, 0.26, 0.27).
docker pull ghcr.io/mechubsec/rustjunosmcp:latest

# Prepare host paths. Review scanned host-key fingerprints against a trusted
# source before starting the server in strict mode.
mkdir -p keys jmcp-state/staging jmcp-state/device-leases
touch jmcp-state/known_hosts
./scripts/scan-known-hosts.sh \
  --inventory "$PWD/devices.json" \
  --known-hosts "$PWD/jmcp-state/known_hosts" \
  --replace

# The image's non-root process must own its writable state and be able to read
# the inventory and private keys. Keep all three private from other host users.
sudo chown -R 65532:65532 devices.json keys jmcp-state
sudo chmod 0600 devices.json keys/* jmcp-state/known_hosts
sudo chmod 0700 keys jmcp-state jmcp-state/device-leases
sudo chmod 0750 jmcp-state/staging

# Run with configuration/keys read-only and state persistent + writable.
docker run --rm -i \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/jmcp-state:/var/lib/jmcp" \
  ghcr.io/mechubsec/rustjunosmcp:latest
```

**Verifying the image signature:** every image pushed by the `Release image`
workflow is signed keylessly with [cosign](https://github.com/sigstore/cosign)
via GitHub Actions OIDC — there is no key pair anywhere. Verification pins the
signing identity to that exact workflow, so a signature from anywhere else
(a fork, a different repo, a local build) fails:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/mechubsec/rustjunosmcp/\.github/workflows/release-image\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/mechubsec/rustjunosmcp:latest
```

This is a regexp, not an exact `--certificate-identity`, because GitHub embeds
the ref that triggered the run into the certificate, and this workflow has two
legitimate triggers with two different refs: a normal tag push carries
`@refs/tags/vX.Y.Z` for that release's own tag — different for every version,
including for the `:latest` tag, since it is repushed and re-signed on every
release — and a `workflow_dispatch` backfill (see the `ref` input above)
typically carries `@refs/heads/main`, the branch the run was dispatched from.
Neither a pull request nor a push to any other branch can trigger this
workflow at all, so no other identity is possible. Pin the exact tag instead
of the version range if you are verifying one specific release rather than
"some release build of this workflow." Each signature also creates a public
entry in the [Rekor](https://docs.sigstore.dev/logging/overview/) transparency
log —
this is expected and does not disclose anything beyond what the image push
itself already made public.

Images published before 2026-09-29 were signed by the workflow under
`github.com/fastrevmd-lab/RustJunosMCP`, so verifying an older tag needs that
identity instead.

**Verifying the SBOM attestation:** on release, a CycloneDX SBOM of the Rust
dependency graph (not the image's distroless runtime base) is attached to the
GitHub release and also pushed as an in-toto attestation on the image, signed
keylessly the same way as above. This attestation is signed by the
`release-sbom.yml` workflow, a **different identity** from the image
signature's `release-image.yml` identity above, because it is a separate job
that runs after the image is already pushed:

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/mechubsec/rustjunosmcp/\.github/workflows/release-sbom\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/mechubsec/rustjunosmcp:<version>
```

The state mount holds staged upload/download files, the shared destructive
operation leases, and `known_hosts`. Do not delete its lease files while a
server is running. Strict host-key checking is the default. For an isolated lab
only, append `--ssh-accept-new-host-keys` to the `docker run` command; this lets
the server add first-seen keys to the writable state file, but does not
authenticate that first connection out of band.

> **Apple Silicon (M-series):** images are built for `linux/amd64` only, so
> they run under emulation on Apple Silicon. This works, but if you hit a
> platform-mismatch warning add `--platform linux/amd64` to both the `pull`
> and `run` commands.

Prefer to build locally instead:

```bash
docker build -t rust-junosmcp:local .

docker run --rm -i \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/jmcp-state:/var/lib/jmcp" \
  rust-junosmcp:local
```

## LXC (Proxmox)

> Building a container from nothing — including the two-person and lab-mode
> pair, the credential modes that must be right before first start, and how to
> verify the seccomp posture came from the shipped unit — is written up in
> [`docs/HOW-TO-SETUP-LXC.md`](docs/HOW-TO-SETUP-LXC.md).

```bash
# Build the tarball and checksum.
./scripts/package-lxc.sh

# Verify the checksum.
sha256sum -c dist/rust-junosmcp_0.27.2_amd64.tar.gz.sha256

# Push and install on VM 115. The installer copies the unified binary and unit
# from its extracted package root.
#
# The container MUST be Debian 13 (trixie). This is not a style preference:
# `package-lxc.sh` builds against the glibc of whatever host runs it, and the
# current published binary requires GLIBC_2.39. Debian 12 ships 2.36, so the
# service dies at start with a "GLIBC_2.39 not found" symbol error — after a
# clean build and a clean install, which is the worst place to discover it.
# Debian 13 ships 2.41. Check your own tarball with:
#   objdump -T dist/rust-junosmcp_*/usr/local/bin/rust-junosmcp \
#     | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -Vu | tail -1
#
# Debian 13 also matches docs/PACKAGING.md §2, the container runtime base, and
# rustpanosmcp — one distro generation to track CVEs against, not three.
pct push 115 dist/rust-junosmcp_0.27.2_amd64.tar.gz /tmp/jmcp.tar.gz
pct exec 115 -- bash -c "tar xzf /tmp/jmcp.tar.gz -C /tmp && /tmp/rust-junosmcp_0.27.2_amd64/install.sh"
```

**Downloading a prebuilt release tarball instead:** each GitHub release also
publishes the tarball, its `.sha256` checksum, and a keyless cosign signature
bundle (`.cosign.bundle`) for it, signed by the `Sign release tarball`
workflow the same way the container image is signed above — no key pair,
GitHub Actions OIDC only. Check the checksum *and* the signature; the checksum
alone only proves the download was not corrupted in transit, not that it came
from this repository's release workflow:

```bash
version=0.27.2
base="https://github.com/mechubsec/rustjunosmcp/releases/download/v${version}"
curl -LO "${base}/rust-junosmcp_${version}_amd64.tar.gz"
curl -LO "${base}/rust-junosmcp_${version}_amd64.tar.gz.sha256"
curl -LO "${base}/rust-junosmcp_${version}_amd64.tar.gz.cosign.bundle"

sha256sum -c "rust-junosmcp_${version}_amd64.tar.gz.sha256"

cosign verify-blob \
  --certificate-identity "https://github.com/mechubsec/mecmcp/.github/workflows/reusable-sign-release-tarball.yml@f927c820f39369b2601e11e31334cc5b504b1fd1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-repository "mechubsec/rustjunosmcp" \
  --certificate-github-workflow-trigger "release" \
  --bundle "rust-junosmcp_${version}_amd64.tar.gz.cosign.bundle" \
  "rust-junosmcp_${version}_amd64.tar.gz"
```

Unlike the image workflow above, the `sign` job in this repo's own
`release-sign-tarball.yml` delegates the actual signing to mecmcp's reusable
workflow, so the OIDC certificate subject is *that* workflow's path, pinned
to the exact commit SHA `release-sign-tarball.yml`'s `sign:` job currently
references via its `uses:` line — not this repo's own workflow file, and not
a branch ref. That pin moves whenever the `sign:` job is repinned to a newer
mecmcp SHA or tag, so don't trust this README's SHA to stay accurate forever;
check the `uses:` line in `.github/workflows/release-sign-tarball.yml` for
the current pin.

Because that reusable workflow lives in a public repo, any GitHub repository
can call it and get a certificate with the same identity, so the identity
alone does not prove the tarball came from *this* repo's release.
`--certificate-github-workflow-repository` and
`--certificate-github-workflow-trigger` close that gap: they check the
certificate's calling-repository and triggering-event fields, which must be
`mechubsec/rustjunosmcp` and `release`. Do not drop them.

`cosign verify-blob` exits non-zero on any mismatch — wrong identity, wrong
issuer, wrong calling repository or trigger, or a tarball that does not match
the bundle — so a failure here means do not install, not "probably fine."

**Edit the inventory:**

```bash
# Copy the example and configure your devices.
pct exec 115 -- cp /etc/jmcp/devices.json.example /etc/jmcp/devices.json
pct exec 115 -- $EDITOR /etc/jmcp/devices.json  # or edit via another method
pct exec 115 -- chown jmcp:jmcp /etc/jmcp/devices.json
pct exec 115 -- chmod 0600 /etc/jmcp/devices.json
```

**Mint a bearer token:**

```bash
# A wildcard tool scope grants read-only tools only; write tools must be named
# explicitly. See "Upgrading to v0.10" and "Tool scopes and write tools" below.
pct exec 115 -- runuser -u jmcp -- /usr/local/bin/rust-junosmcp token add \
  --tokens-file /etc/jmcp/tokens.json \
  --name ops \
  --routers '*' \
  --tools get_router_list,gather_device_facts,execute_junos_command,get_junos_config,commit_check_config,load_and_commit_config
```

**Start the service:**

```bash
pct exec 115 -- systemctl enable --now rust-junosmcp
```

The installer is idempotent: rerunning it upgrades binaries and units without
overwriting `devices.json`, `tokens.json`, or `known_hosts`. It validates the
complete archive before changing system state. The packaged server exposes all
enabled Junos and SRX tools at `127.0.0.1:30030/mcp` and requires bearer
authentication. Use an SSH tunnel or a TLS reverse proxy for remote clients.

> **Clearing a stuck operation:** `state resolve` settles an operation that is
> stuck in a non-terminal state after a failed apply. One such record blocks
> every later change on its device, and no tool can clear it — `cancel_junos_
> change_set` refuses a change set that is already terminal. **Stop the service
> first**, or the running server will overwrite the file from memory:
>
> ```bash
> systemctl stop rust-junosmcp
> runuser -u jmcp -- /usr/local/bin/rust-junosmcp state resolve \
>   --state-file /var/lib/jmcp/changeset-state.json \
>   --operation-id <64-hex-operation-id> \
>   --disposition discarded \
>   --confirmation "RESOLVED <64-hex-operation-id> AS DISCARDED"
> systemctl start rust-junosmcp
> ```
>
> The confirmation string must match exactly: it is the operator asserting they
> looked at the device and this is what is true. Use `committed` only when the
> device's own commit log proves the change landed.

> **Narrowing an existing token:** `token set-scope` changes a token's router or
> tool scopes **without reissuing its secret**, so clients keep working with the
> same bearer token. Useful for removing access without reconfiguring every
> client. See the [token management](#token-management) section for examples.

Upgrading from a split-server release removes the retired `rust-srxmcp`
executable, unit, and enabled-service link. It deliberately preserves existing
support bundles under `/var/lib/jmcp/srx-staging/bundles`.

## Remote transport + auth

### Mint a token

```bash
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts
```

`get_router_list` applies the same router scope as device tools. Authenticated
allowlist tokens receive only the current inventory names in their scope;
stale scope entries and excluded routers are omitted without counts or errors.
An empty allowlist or empty intersection returns `[]`. Wildcard tokens, local
stdio, and explicitly unauthenticated loopback mode retain the full inventory.

> **Note:** See [`tokens-template.json`](tokens-template.json) for the file
> shape. Use `token add` rather than editing the file by hand — the `digest`
> field must be a versioned SHA-256 of the secret, not the plaintext. Fields
> are canonically `digest` and `devices`; the older `hash` and `routers`
> spellings are still accepted as aliases, so existing files load unchanged.
> The CLI flag remains `--routers`.

> **`tokens.json` must be mode `0600`** (v0.10.0+). The server refuses to
> start on a group- or world-accessible token file, and the error names the
> file's owner uid, its mode, the calling process's uid, and the `chmod` to
> run. Every `token` subcommand writes `0600`, and the LXC installer sets it,
> so this only bites files created or copied by hand.

### Tool scopes and write tools

A tool scope is either the literal `*` or an explicit list of tool names. The
two cannot be mixed — `--tools '*',transfer_file` is rejected.

**A wildcard tool scope does not confer write tools** (v0.10.0+). `"tools":
["*"]` reaches every read-only tool but none of these 15 write-capable tools:

| Write tool | |
|---|---|
| `add_device` | `apply_junos_change_set` |
| `approve_junos_change_set` | `confirm_junos_change_set` |
| `create_junos_change_set` | `discard_candidate` |
| `execute` | `load_and_commit_config` |
| `manage_appid_signature_package` | `manage_idp_security_package` |
| `reload_devices` | `render_and_apply_j2_template` |
| `rollback_config` | `transfer_file` |
| `upgrade_junos` | |

Granting write authority is always an explicit, named decision: a token that
needs `load_and_commit_config` must list it, alongside every other tool it
calls. An explicit allowlist behaves exactly as before.

`execute` is a strict facade over the 40 concrete operations. A token
using it must explicitly name **both** `execute` and the selected concrete
operation; wildcard scope does not grant `execute`. The facade passes the
selected operation's arguments unchanged, so use the concrete operation's
exact argument names:

```json
{"operation":"gather_device_facts","arguments":{"device":"vsrx-ci"}}
```

Direct calls to all 40 concrete tools remain supported.

`tools/list` advertises only what the caller's token can invoke, so the list an
agent sees matches what it can actually call. A wildcard token is shown the
read-only tools and not the 15 write-capable tools; a token scoped to nothing is shown
an empty list.

> **Cached lists go stale.** A client that fetched `tools/list` before you
> re-scoped its token with `token set-scope` keeps the old view until it
> reconnects — the server does not currently emit
> `notifications/tools/list_changed` on SIGHUP reload. Authorization is
> unaffected: a call to a tool the token no longer has is refused regardless of
> what the client believes it can see.

Scope checks apply only to authenticated HTTP callers. Local stdio and the
`--allow-no-auth` loopback escape hatch carry no caller context and are not
scope-restricted.

> **Run token subcommands as the service user.** When the systemd unit runs
> the server as a dedicated user (e.g. `User=jmcp` in the packaged unit), the
> file `token add`/`revoke`/`rotate`/`set-scope` writes inherits the calling
> user's ownership. If you run them as `root`, the resulting `tokens.json`
> will be `root:root 0600` and the service user cannot read it — the server
> then crash-loops on startup with `Permission denied`. Either:
>
> ```bash
> # Preferred: run subcommands as the service user.
> sudo -u jmcp rust-junosmcp token add --tokens-file /etc/jmcp/tokens.json ...
>
> # Or fix ownership after running as root.
> rust-junosmcp token add --tokens-file /etc/jmcp/tokens.json ...
> chown jmcp:jmcp /etc/jmcp/tokens.json
> ```
>
> If the server hits this case on startup, the error message now reports the
> file's uid/mode and the caller's uid so the fix is obvious without trawling
> journald.

### Run with auth (streamable-http)

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 127.0.0.1 \
  -p 8765 \
  --tokens-file tokens.json
```

### Loopback escape hatch (no auth, local only)

```bash
cargo run -- --device-mapping devices.json --transport streamable-http \
  -H 127.0.0.1 -p 8765 --allow-no-auth
```

`--allow-no-auth` is refused if the bind address is not loopback.

### Non-loopback requires TLS

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 0.0.0.0 \
  -p 8765 \
  --tokens-file tokens.json \
  --tls-cert cert.pem \
  --tls-key key.pem
```

To bind off-loopback over plain HTTP (e.g., behind a TLS-terminating proxy on
the same host), add `--allow-insecure-bind`. This flag overrides the TLS
requirement and should be used with care — only when you have an external
guarantee of transport security.

### Host allowlist (DNS-rebinding guard)

The streamable-http transport validates the incoming `Host` header against an
allowlist (default: loopback only — `localhost`, `127.0.0.1`, `::1`). This
closes RUSTSEC-2026-0189 (DNS rebinding). Off-loopback clients must be
allowlisted with `--allowed-host <HOST>` (repeatable) or they are rejected
with HTTP 403, regardless of auth state:

```bash
cargo run -- \
  --device-mapping devices.json \
  --transport streamable-http \
  -H 0.0.0.0 \
  -p 8765 \
  --tokens-file tokens.json \
  --tls-cert cert.pem \
  --tls-key key.pem \
  --allowed-host jmcp.example.net
```

There is no way to turn the allowlist off. `--disable-host-check` was removed in
0.15.3 and is now rejected at startup. The allowlist is the DNS-rebinding guard
(RUSTSEC-2026-0189), and rebinding targets loopback-bound services specifically —
a browser resolves an attacker-controlled name to `127.0.0.1` and reaches the
server with a foreign `Host`. "Off" was therefore most dangerous exactly where it
looked safest. If a client sends an authority the server does not know, name it
with `--allowed-host`; the flag is repeatable.

### Hot reload

After revoking or rotating a token, the server reloads the token store without
restarting. Pass `--server-pid <pid>` to any write subcommand and the SIGHUP
is sent automatically after the file is written:

```bash
# Revoke — writes file, then signals the server.
cargo run -- token revoke --tokens-file tokens.json --name ops --server-pid <pid>

# Rotate (mints a new secret, preserves scopes) — same pattern.
cargo run -- token rotate --tokens-file tokens.json --name ops --server-pid <pid>

# Add a new token and signal in one step.
cargo run -- token add \
  --tokens-file tokens.json \
  --name ops2 \
  --routers '*' \
  --tools execute_junos_command,gather_device_facts \
  --server-pid <pid>
```

### Rescope a token without reissuing its secret

`token set-scope` changes an existing token's scopes in place. The digest,
`created_at`, and envelope version are all preserved, so clients holding the
secret keep working — this is the difference from `rotate`, which mints a new
secret and forces every consumer to be updated at once.

```bash
# Narrow tools; leave the router scope alone.
cargo run -- token set-scope \
  --tokens-file tokens.json \
  --name ops \
  --tools gather_device_facts,get_junos_config,load_and_commit_config \
  --server-pid <pid>

# Narrow routers; leave the tool scope alone.
cargo run -- token set-scope \
  --tokens-file tokens.json \
  --name ops \
  --routers edge-1,edge-2 \
  --server-pid <pid>
```

`--routers` and `--tools` are each optional and independent; whichever you
omit is left unchanged. Supplying neither is an error. The command prints the
resulting scopes to stderr, and `--server-pid` sends the usual SIGHUP once the
file is written. Unknown tool names are rejected; unknown device names warn
but are accepted, since token operations run before the inventory is loaded.

If you need to trigger a reload without a token change (e.g., after editing the
file by hand), send SIGHUP directly:

```bash
kill -HUP <pid>
```

### Refusal matrix

| Flags | Bind address | Result |
|---|---|---|
| _(none)_ | any | Refused — `--tokens-file` or `--allow-no-auth` required for streamable-http |
| `--allow-no-auth` only | non-loopback | Refused — `--allow-no-auth` is loopback-only |
| `--allow-no-auth` only | loopback | OK — but note: if you also supply `--tls-cert`/`--tls-key`, auth is still disabled; TLS gives confidentiality but any client that can reach the port has full tool access (foot-gun) |
| `--tokens-file` only | non-loopback, no TLS | Refused — add `--tls-cert`/`--tls-key` or `--allow-insecure-bind` |
| `--tokens-file --allow-insecure-bind` | non-loopback, no TLS | OK — tokens are checked; you are asserting external transport security |
| `--tokens-file --tls-cert cert.pem --tls-key key.pem` | any | OK |

### Canonical environment variables

The unified server uses one `JMCP_*` namespace. Command-line values take
precedence over environment values.

| Purpose | Canonical environment variable |
|---|---|
| Listener | `JMCP_HTTP_HOST`, `JMCP_HTTP_PORT` |
| Inventory and tokens | `JMCP_DEVICES_PATH`, `JMCP_TOKENS_PATH` |
| TLS | `JMCP_TLS_CERT`, `JMCP_TLS_KEY` |
| Destructive-operation leases | `JMCP_DEVICE_LEASE_DIR` |
| Support-bundle staging | `JMCP_SUPPORT_BUNDLE_STAGING_DIR`, `JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES` |
| Audit | `JMCP_AUDIT_FORMAT`, `JMCP_AUDIT_LOG_FILE`, `JMCP_AUDIT_JOURNALD`, `JMCP_AUDIT_REDACT`, `JMCP_AUDIT_HMAC_KEY_FILE` |
| Metrics | `JMCP_ENABLE_METRICS` |

For migration, legacy `JMCP_SRX_*` aliases are accepted with a warning in
`0.8.0` only when neither the corresponding command-line option nor canonical
variable is set. `JMCP_SRX_HTTP_PORT` is always ignored: the retired second
listener no longer exists. Move deployments to the canonical names now.

## Upgrading to v0.10

Two breaking authorization changes land in v0.10.0. Both are checked at
runtime by the new binary, so **do the preparation while 0.9.x is still
running** — otherwise the upgrade either fails to start or silently breaks
write-capable clients.

### 1. Fix token-file permissions

The new binary refuses to start on a group- or world-accessible
`tokens.json`. Check and fix before swapping the binary:

```bash
# On the server host, as the service user.
stat -c '%a %U:%G %n' /etc/jmcp/tokens.json
chmod 0600 /etc/jmcp/tokens.json
```

The LXC installer already sets `0600`, so packaged installs are almost
certainly fine. Files created by hand, copied between hosts, restored from a
backup, or written by configuration management are the ones to check. If the
server does hit this, the startup error names the file's owner uid, its mode,
the calling process's uid, and the exact `chmod` — it is not a silent failure.

### 2. Re-scope wildcard tokens that need write tools

A wildcard tool scope no longer confers the 15
[write-capable tools](#tool-scopes-and-write-tools). Any token with `"tools": ["*"]`
that calls one of them will start getting `ToolNotInScope` refusals after the
upgrade.

Find the affected tokens:

```bash
sudo -u jmcp rust-junosmcp token list --tokens-file /etc/jmcp/tokens.json
```

Every row showing `*` in the `TOOLS` column is a candidate. For each one,
decide whether it genuinely needs write access:

- **Read-only in practice** — leave it. A wildcard scope still reaches every
  read-only tool, and it is now safer than it was.
- **Needs write tools** — replace the wildcard with an explicit list naming
  every tool it calls, including the read-only ones. Scopes cannot mix `*`
  with names.

`token set-scope` does this without reissuing the secret, so clients keep
working across the change:

```bash
sudo -u jmcp rust-junosmcp token set-scope \
  --tokens-file /etc/jmcp/tokens.json \
  --name ops \
  --tools get_router_list,gather_device_facts,get_junos_config,junos_config_diff,commit_check_config,load_and_commit_config \
  --server-pid "$(systemctl show -p MainPID --value rust-junosmcp)"
```

`set-scope` exists in 0.10.0 and later. On 0.9.x, the equivalent is to edit
`tokens.json` by hand — change only the `tools` array, leave `hash`/`digest`
and `created_at` untouched — then `systemctl kill -s HUP rust-junosmcp`. Do
not use `rotate` for this: it mints a new secret and locks out every consumer
of that token at once.

### 3. Upgrade, then verify

After installing the new release, confirm the store loaded and the scopes are
what you expect:

```bash
systemctl status rust-junosmcp
sudo -u jmcp rust-junosmcp token list --tokens-file /etc/jmcp/tokens.json
```

Then exercise one write tool through an affected client. A refusal at this
point means that token's allowlist is missing the tool name.

> **Back up `tokens.json` before upgrading — rollback is not symmetric.**
> v0.10 *reads* the old `hash`/`routers` spellings, but any v0.10 token write
> (`add`, `rotate`, `revoke`, `set-scope`) rewrites the whole file in the
> canonical `digest`/`devices` spelling, and **0.9.x cannot parse that** — it
> requires `hash` and fails to load the store, so the rolled-back server will
> not start. Keep a copy:
>
> ```bash
> sudo -u jmcp cp -a /etc/jmcp/tokens.json /etc/jmcp/tokens.json.0.9-backup
> ```
>
> If you have not run a v0.10 token write, the file is byte-identical and
> rollback is clean. Otherwise restore the backup (secrets and scopes are
> unchanged by the upgrade itself), or rename the two fields back by hand.
> On Proxmox, an LXC snapshot of the container before install covers this
> along with everything else.

## Resource limits (streamable-HTTP)

The unified endpoint enforces configurable DoS guardrails. Most limits are enabled by
default with generous values; the optional per-token request-rate limiter is
disabled until both of its knobs are positive. A zero value disables an
individual limit, subject to the rate/burst pair rule below.

| Flag | Environment variable | Default | Effect |
|------|-------------------|---------|--------|
| `--max-request-body-bytes` | `JMCP_MAX_REQUEST_BODY_BYTES` | 10 MiB | Reject larger bodies with **413** before buffering |
| `--max-inflight-requests` | `JMCP_MAX_INFLIGHT_REQUESTS` | 64 | Global concurrency cap; over-limit → **503** |
| `--max-inflight-requests-per-token` | `JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN` | 16 | Per-token concurrency cap → **503** |
| `--max-requests-per-second-per-token` | `JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN` | 0 | Per-token refill rate; pair with burst (`0/0` disables) |
| `--max-request-burst-per-token` | `JMCP_MAX_REQUEST_BURST_PER_TOKEN` | 0 | Per-token immediate burst; pair with rate (`0/0` disables) |
| `--max-inflight-requests-per-router` | `JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER` | 4 | Per-router concurrency cap → **503** |
| `--max-sessions` | `JMCP_MAX_SESSIONS` | 128 | Session count cap → **503** |
| `--max-sessions-per-token` | `JMCP_MAX_SESSIONS_PER_TOKEN` | 16 | Per-bearer-token session cap → **503** |
| `--session-idle-timeout-secs` | `JMCP_SESSION_IDLE_TIMEOUT_SECS` | 300 | Idle sessions reaped |
| `--session-max-lifetime-secs` | `JMCP_SESSION_MAX_LIFETIME_SECS` | 3600 | Old sessions reaped |

The global session cap is enforced atomically during session creation. The
middleware rejects obvious saturation early, while the shared session manager
closes any concurrently created session that loses the final slot race before
returning the same `session_cap` 503 contract. Rejected initialization never
returns an `Mcp-Session-Id`, and closing or reaping an admitted session returns
its slot.

Per-token session accounting uses the exact authenticated token name. Successful
initialization binds the returned `Mcp-Session-Id`; explicit close and idle/lifetime
reaping return the slot. Saturation returns
`{"error":"overloaded","limit":"token_session_cap"}`. The cap is skipped in
explicit no-auth mode because no token identity exists.

Over-limit responses carry `Retry-After: 1`. Concurrency permits are released when
the response stream ends. A multi-router call holds one router slot for each unique
top-level `router`, `router_name`, `routers`, or `router_names` target.
Per-router saturation is identified by the response body
`{"error":"overloaded","limit":"router_concurrency"}`.

The per-router HTTP permit is acquired before a destructive workflow waits for its
cross-process device lease. A destructive call counts once while waiting for or
holding that lease; the HTTP cap bounds both reads and destructive waiters, while the
lease remains the authority that serializes destructive operations across processes.

Per-token request-rate limiting is an opt-in token bucket keyed by the exact
authenticated token name. Set both the requests-per-second rate and burst to
positive values to enable it; leave both at `0` to disable it. Supplying only
one positive value fails startup. Each authenticated `/mcp` HTTP request costs
one token. An exhausted bucket returns **429**, `Retry-After: 1`, and
`{"error":"rate_limited","limit":"token_rate"}` before concurrency or session
capacity is acquired. Explicit no-auth mode skips this per-token control.

Use the RPS limiter to absorb bursts of many cheap, short calls. Use concurrency
limits to bound simultaneous expensive NETCONF/SSH work and slow response
streams. They are independent and can be enabled together; rate checks run
first, while concurrency/session exhaustion retains the existing **503**
contract.

Prometheus export is opt-in with `--enable-metrics`
(`JMCP_ENABLE_METRICS`). It mounts an
unauthenticated `GET /metrics` beside `/mcp`; protect it with network controls.
See [Prometheus metrics](docs/METRICS.md) for scrape configuration, metric
names, labels, and PromQL examples.

## CLI

```
Junos MCP server (Rust)

Usage: rust-junosmcp [OPTIONS] [COMMAND]

Commands:
  token  Manage the bearer-token store
  help   Print this message or the help of the given subcommand(s)

Options:
  -f, --device-mapping <DEVICE_MAPPING>
          JSON file with device mapping (Juniper junos-mcp-server compatible) [default: devices.json]
  -t, --transport <TRANSPORT>
          Transport [default: stdio] [possible values: stdio, streamable-http]
  -H, --host <HOST>
          Bind host (streamable-http only) [default: 127.0.0.1]
  -p, --port <PORT>
          Bind port (streamable-http only) [default: 30030]
      --tokens-file <TOKENS_FILE>
          Bearer-token file. Required for streamable-http unless --allow-no-auth
      --tls-cert <TLS_CERT>
          PEM-encoded TLS cert (streamable-http only). Pair with --tls-key
      --tls-key <TLS_KEY>
          PEM-encoded TLS key (streamable-http only). Pair with --tls-cert
      --allow-no-auth
          Disable bearer-token auth. Refuses to bind off-loopback
      --allow-insecure-bind
          Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured
      --inventory-readonly
          Reject add_device and reload_devices unconditionally
      --allow-password-auth-add
          Permit add_device to accept auth.type=password (mutually exclusive
          with --inventory-readonly)
      --device-lease-dir <DEVICE_LEASE_DIR>
          Shared directory for cross-process destructive-operation leases
          [default: /var/lib/jmcp/device-leases]
      --allowed-host <HOST>
          Additional Host authorities to accept on the streamable-http
          endpoint, beyond the loopback defaults (localhost, 127.0.0.1, ::1).
          Repeatable
  -h, --help
          Print help
  -V, --version
          Print version
```

## Testing against a real device

```bash
JMCP_TEST_HOST=10.0.0.1 \
JMCP_TEST_USER=admin \
JMCP_TEST_PASS=secret \
cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture
```

## Audit forwarding to the event store

The audit trail does not stay on this host. This server follows the family
standard — [AUDIT-FORWARDING-STANDARD.md](https://github.com/mechubsec/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md).

An audit record that only exists on the machine that produced it is not an audit
trail: it is a log file on a box whose operator is the party the record is about.

### Emission (in effect now)

```
--audit-format json \
--audit-log-file /var/lib/jmcp/audit.jsonl
```

JSON is mandatory. The `text` format is for reading in a terminal and is not a
parse target. The file is the operator-facing artifact and must be rotated — the
server never truncates it.

### Transport (specified, not yet implemented)

Records are written directly into SSDF's `ssdf.audit` as **hash-chained** rows,
per SSDF's merged evidence contract, so that deleting or editing a row is
detectable. Tracked in [mecmcp#292](https://github.com/mechubsec/mecmcp/issues/292).

A cheaper syslog path was designed and rejected: it works, but the records are
unchained, and every other link here is tamper-evident by construction — plan
digests bind approvals, approvals name a distinct principal, and
`token_verified_fields` separates vouched-for provenance from asserted. An
unchained final hop would discard that guarantee exactly where an auditor needs
it. The reasoning is recorded in the standard.

### Reading the result

`token_verified_fields` names the provenance fields the **token** vouched for.
The rest of that group — `client_name`, `model_id`, `session_id` — is
client-asserted and authenticated by nothing. Do not read them as equivalent.

`request_id` correlates the transport event, the handler event, and (on Junos)
the device commit comment.

## License

Licensed under [MIT](LICENSE).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>

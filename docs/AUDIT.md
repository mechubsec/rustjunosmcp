# Audit Event Schema

`rust-junosmcp` emits a canonical structured `AuditScope` completion event for
every Junos and SRX MCP tool invocation. That event records the caller,
tool, target routers, authorization decision, outcome, and duration. Selected
SRX workflows also emit auxiliary audit events for package preflights, package
lifecycle phases, and support-bundle progress. Events are written to stderr
(or an optional append-only JSON file) and are machine-parseable for SIEM
ingestion.

## Canonical AuditScope schema

The canonical tool-completion event has `target="audit"`, tracing level `INFO`,
message `audit`, and the following fields (in order). This table is the stable
`AuditScope` schema; auxiliary SRX audit events use workflow-specific fields as
described under [Native field mapping](#native-field-mapping).

| Field | Type | Description |
|-------|------|-------------|
| `correlation_id` | string | Unique request identifier (`req-<nanos>` epoch-based). |
| `caller` | string | Bearer-token name, or `"stdio"` when unauthenticated. |
| `tool` | string | MCP tool name (e.g., `execute_junos_command`, `get_chassis_cluster_status`). |
| `routers` | string | Comma-separated list of target router names (empty for inventory/list tools). |
| `router_count` | u64 | Number of target routers. |
| `action` | string | Stable action category: `read`, `commit`, `add-device`, `upgrade`, `pfe`, `transfer`, `destructive`, etc. |
| `authorization` | enum | Authorization decision: `allowed`, `denied`, or `no_auth` (stdio caller). |
| `result` | enum | Outcome: `ok` (success), `error` (failure), `denied` (authorization rejected), or `unsettled` (client disconnect). |
| `duration_ms` | u64 | Elapsed time from handler entry to drop (milliseconds). |
| `error_kind` | string | Stable error category when `result=error` (e.g., `"timeout"`, `"lease_busy"`, `"transport"`). Empty otherwise. See [Error kinds](#error-kinds) for the full vocabulary. |
| `error` | string | Bounded error message when `result=error`; values longer than 512 bytes are cut at a UTF-8 boundary no later than byte 512, then suffixed with `…`. Empty otherwise. |
| `reason` | string | Denial reason when `result=denied` (see below). Empty otherwise. |
| `metadata` | string | Space-separated `key=value` pairs of allowlisted, non-secret tool-specific fields (e.g., `command_count=5 dry_run=true`). Empty if none. |

### Authorization values

- **`allowed`** — caller has required scopes; work proceeds.
- **`denied`** — caller lacks required scopes or context; work refused before execution.
- **`no_auth`** — stdio transport (no bearer token); treated as allowed.

### Result values

- **`ok`** — handler completed successfully.
- **`error`** — handler returned an error (see `error_kind` and `error`).
- **`denied`** — authorization check rejected the request (see `reason`).
- **`unsettled`** — guard dropped without an outcome (client disconnect or cancel).

### Denial reasons

| Reason | Meaning |
|--------|---------|
| `tool_scope` | Token lacks permission for the requested tool. |
| `router_scope` | Token lacks permission for one or more target routers. |
| `inventory_readonly` | Server started with `--inventory-readonly`; inventory mutations refused. |
| `missing_caller_context` | SRX tool invoked without caller context (stdio or unauthenticated HTTP). |

### Error kinds

When `result=error`, `error_kind` carries a stable category derived from the failing error variant (`JmcpError::audit_kind` / `SrxError::audit_kind`). The strings are a closed vocabulary — the mapping is an exhaustive match, so adding a new error variant forces a deliberate classification at compile time. Use these to alert on error *classes* (e.g. "> 10 `lease_busy` in 5 min") rather than parsing free-text `error`.

Emitted by the base Junos tools and inherited by SRX workflows through their
`Transport` variant:

| Kind | Meaning |
|------|---------|
| `unknown_router` | Target router is not present in the inventory. |
| `invalid_input` | Malformed or invalid arguments, formats, SSH config, or blocklist rules (client error). |
| `parse` | JSON, template, or config parse failure. |
| `not_found` | A required file/resource is missing (key file, `known_hosts`, remote file). |
| `unsupported` | Operation unsupported for this device/config (password auth, chassis cluster, etc.). |
| `conflict` | Destination/device/inventory state conflict (exists-differs, on-disk drift, already-exists). |
| `timeout` | Operation exceeded its time budget (connect, transfer, install, reboot, or outer timeout). |
| `cancelled` | Client cancelled the in-flight operation. |
| `lease_busy` | Device destructive-lease held by another workflow (contention). |
| `lease_error` | Lease acquisition or candidate cleanup failed. |
| `verify_mismatch` | Post-op checksum or version verification mismatch. |
| `host_key_mismatch` | SSH host-key verification rejected the device. |
| `host_key_revoked` | SSH host key is marked @revoked in known_hosts (key compromised). |
| `confirmation_required` | Operation needs re-call with `confirm=true`. |
| `commit_confirmed_active` | A pending commit-confirmed rollback window blocks the operation. |
| `insufficient_disk` | Not enough free space on the device. |
| `dependency_unavailable` | A required external tool (e.g. `scp`/openssh) is missing. |
| `scp_failed` | An `scp` transfer returned a non-zero exit. |
| `device_probe_failed` | A pre-flight device probe failed. |
| `blocked` | A blocklist rule denied the command or config. |
| `inventory_readonly` | Inventory mutation refused under `--inventory-readonly` (normally surfaces as a `denied`/`inventory_readonly` reason; see [Denial reasons](#denial-reasons)). |
| `inventory_empty` | Inventory contains no devices. |
| `transport` | NETCONF/SSH transport-layer error. |
| `io` | Filesystem / I/O error (including inventory file read/write). |

SRX workflow kinds:

| Kind | Meaning |
|------|---------|
| `rpc` | Device returned an RPC error. |
| `confirmation_token` | Confirmation token missing, invalid, drifted, or over capacity. |
| `license_inactive` | Required feature license is not active. |
| `unreachable` | Signature/AppID package server is unreachable. |
| `precondition_failed` | Required precondition missing (no rollback/uninstall target). |
| `cluster_desynced` | Chassis cluster is not synchronized. |
| `download_failed` | Signature/AppID package download failed. |
| `install_failed` | Signature/AppID package install failed. |
| `daemon_not_ready` | `idp-policy` daemon not initialized. |
| `timeout` | Poll or cluster-health-check budget exceeded. |
| `staging_full` | Support-bundle staging dir over cap even after LRU eviction. |
| `staging_evicted` | Requested bundle not present in staging (LRU evicted or never written). |
| `bundle_partial` | A subset of support-bundle RPCs failed. |
| `contention` | Another per-router workflow is already in flight. |
| `capture_failed` | Universal-baseline config-capture RPC failed. |

Server-level (not from an error enum):

| Kind | Meaning |
|------|---------|
| `serialize` | Response serialization failed (internal error). |

## JSON Event Format

When `--audit-format json` is set, events are emitted as line-delimited JSON. The `tracing` crate's JSON formatter nests field data under a `"fields"` object:

```json
{"timestamp":"2026-07-12T18:32:14.091234Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805534091123456","caller":"ci","tool":"execute_junos_command","routers":"vsrx-lab-01","router_count":1,"action":"read","authorization":"allowed","result":"ok","duration_ms":142,"error_kind":"","error":"","reason":"","metadata":"format=text"},"message":"audit"}
```

### Example: Success

```json
{"timestamp":"2026-07-12T18:32:15.001Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805535001000000","caller":"automation","tool":"load_and_commit_config","routers":"vsrx-lab-02","router_count":1,"action":"commit","authorization":"allowed","result":"ok","duration_ms":3456,"error_kind":"","error":"","reason":"","metadata":"config_bytes=1234 dry_run=false"},"message":"audit"}
```

### Example: Failure

```json
{"timestamp":"2026-07-12T18:32:16.500Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805536500000000","caller":"devops","tool":"execute_junos_command","routers":"vsrx-lab-03","router_count":1,"action":"read","authorization":"allowed","result":"error","duration_ms":5001,"error_kind":"timeout","error":"NETCONF session timed out after 5000ms","reason":"","metadata":"format=text"},"message":"audit"}
```

### Example: Denial

```json
{"timestamp":"2026-07-12T18:32:17.250Z","level":"INFO","target":"audit","fields":{"correlation_id":"req-1720805537250000000","caller":"readonly-token","tool":"load_and_commit_config","routers":"vsrx-lab-01","router_count":1,"action":"commit","authorization":"denied","result":"denied","duration_ms":0,"error_kind":"","error":"","reason":"tool_scope","metadata":""},"message":"audit"}
```

## Configuration

The unified `rust-junosmcp` binary uses one audit configuration for every tool:

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `--audit-format` | `JMCP_AUDIT_FORMAT` | `text` | Output format: `text` or `json`. |
| `--audit-log-file` | `JMCP_AUDIT_LOG_FILE` | (none) | Optional file path to append JSON events to (in addition to stderr). |
| `--audit-journald` | `JMCP_AUDIT_JOURNALD` | `false` | Also send `target="audit"` events directly to journald as native structured fields. Startup fails if journald is unavailable. |

## Retention & Forwarding

### journald

By default, services running under systemd write their normal text/JSON stderr
stream into the journal. Set `--audit-journald` (or `JMCP_AUDIT_JOURNALD`) to
add a second, native journal record for every
`target="audit"` event. The native target is disabled by default and does not
replace stderr or `--audit-log-file`.

Enabling the target probes `/run/systemd/journal/socket` during startup. A
missing or inaccessible socket aborts startup with `initializing audit tracing`
and the operating-system error; the service never silently claims that an
explicitly requested sink is active. The upstream tracing layer cannot return
per-event send failures after initialization, so stderr and the optional file
sink remain the fallback if journald later becomes unavailable.

When systemd also captures stderr, an audit operation can appear twice: once as
the formatted stderr `MESSAGE`, and once as the native entry with indexed
`AUDIT_*` fields. Select `TARGET=audit` to consume only native entries.

#### Native field mapping

The native layer derives standard journal fields from each tracing event:

| Journal field | Value |
|---------------|-------|
| `TARGET` | `audit` |
| `PRIORITY` | Derived from the tracing level: `INFO` becomes `5` (`NOTICE`) and `WARN` becomes `4` (`WARNING`). |
| `SYSLOG_IDENTIFIER` | `rust-junosmcp` |
| `MESSAGE` | The event message. The canonical `AuditScope` message is `audit`; auxiliary messages vary by workflow. |
| `CODE_FILE` | Rust source file containing the tracing emission callsite, when supplied by tracing metadata. |
| `CODE_LINE` | Rust source line of the tracing emission callsite, when supplied by tracing metadata. |

The following native fields are the stable mapping for the canonical
`AuditScope` schema:

| Journal field | Canonical AuditScope value |
|---------------|----------------------------|
| `AUDIT_CORRELATION_ID` | `correlation_id` |
| `AUDIT_CALLER` | `caller` |
| `AUDIT_TOOL` | `tool` |
| `AUDIT_ROUTERS` | `routers` |
| `AUDIT_ROUTER_COUNT` | `router_count` |
| `AUDIT_ACTION` | `action` |
| `AUDIT_AUTHORIZATION` | `authorization` |
| `AUDIT_RESULT` | `result` |
| `AUDIT_DURATION_MS` | `duration_ms` |
| `AUDIT_ERROR_KIND` | `error_kind` |
| `AUDIT_ERROR` | `error` |
| `AUDIT_REASON` | `reason` |
| `AUDIT_METADATA` | `metadata` |

Every structured field on any exact-`audit` event is preserved as a separate
native journal field. `tracing-journald` prefixes user fields with `AUDIT_`,
replaces dots with underscores, removes unsupported name characters, and
uppercases the result. For example, `request_id`, `service`, and `event` become
`AUDIT_REQUEST_ID`, `AUDIT_SERVICE`, and `AUDIT_EVENT`. The journal stores
values as byte strings; consumers do not parse the JSON formatter's nested
`fields` object. For canonical `AuditScope` events, its redaction policy is
applied before fan-out, so native fields match the already-redacted stderr and
file values. Auxiliary SRX producers emit directly to tracing: their fields are
forwarded as emitted and are not transformed by the `AuditScope` `routers` or
`metadata` redaction settings.

Current auxiliary SRX producers include the following representative events.
This is an operator guide, not a stable or exhaustive auxiliary schema; these
workflow-specific fields and messages may evolve independently of the
canonical `AuditScope` table above.

| Producer family | Tracing level / journal priority | Representative messages | Representative native fields |
|-----------------|----------------------------------|-------------------------|------------------------------|
| AppID and IDP package lifecycle | `INFO` / `5` (`NOTICE`) | `audit` | `AUDIT_SERVICE`, `AUDIT_PHASE`, `AUDIT_CURRENT_VERSION`, `AUDIT_TARGET_VERSION`, `AUDIT_ERROR_CODE`, `AUDIT_ERROR_DETAIL`, plus `AUDIT_REQUEST_ID` or `AUDIT_CORRELATION_ID` |
| AppID and IDP package preflight | `WARN` / `4` (`WARNING`) | `commit-confirmed window open; proceeding because sig-package install is op-mode` and corresponding uninstall/rollback variants | `AUDIT_EVENT=sigpkg_commit_confirmed_window_active`, `AUDIT_ROUTER` |
| JTAC support-bundle lifecycle | `INFO` / `5` (`NOTICE`) for start/success; `WARN` / `4` (`WARNING`) for failure | `bundle.start`, `bundle.ok`, `bundle.err` | `AUDIT_REQUEST_ID`, `AUDIT_FILESYSTEM_ID`, `AUDIT_ROUTER`, `AUDIT_PROBLEM_TYPES`, `AUDIT_ELAPSED_SECS`, `AUDIT_BYTES`, `AUDIT_LOCATION`, `AUDIT_ERR` as applicable |

Query native Junos and SRX audit entries with:

```bash
journalctl -t rust-junosmcp TARGET=audit
journalctl -t rust-junosmcp -o json | jq 'select(.TARGET == "audit")'
```

Direct RFC 5424 formatting and remote syslog transport are not implemented by
this option. Forward native journal fields with the host's journald/rsyslog or
SIEM integration when remote delivery is required.

### File sink

When `--audit-log-file` is set, JSON events are appended to the specified file. The server keeps the file handle `mecmcp_audit::init_tracing` returns and reopens it by path on `SIGHUP`, so rotation is lossless as long as the rotator renames the file and signals the process — the server never truncates it itself.

#### Rotation & retention

A ready-to-install fragment ships at [`packaging/logrotate/rust-junosmcp-audit`](../packaging/logrotate/rust-junosmcp-audit). Install it as `/etc/logrotate.d/rust-junosmcp-audit` (owned `root:root`, mode `0644`). It rotates `/var/lib/jmcp/audit.jsonl` daily, caps it at 100 MB, keeps 14 compressed generations, and matches the packaged systemd layout (`jmcp:jmcp`, files under `/var/lib/jmcp`). Tune `rotate`/`maxsize`/`daily` to your retention policy.

```
/var/lib/jmcp/audit.jsonl {
    daily
    rotate 14
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    su jmcp jmcp
    postrotate
        systemctl kill -s HUP rust-junosmcp.service >/dev/null 2>&1 || true
    endscript
}
```

**Rename + reopen, not `copytruncate`.** `SIGHUP` reopens the audit file by path alongside the existing `devices.json`/`tokens.json` hot reload, so `postrotate` renames the file and signals the process; every write after that lands in a fresh inode at the same path. Nothing written before the rename is truncated and nothing written after it is lost — `copytruncate` copies the file and then truncates it in place, which drops whatever is written in the gap between those two steps.

### Field redaction

Canonical `AuditScope` fields are emitted in cleartext by default. For
deployments that treat device identifiers as sensitive, an optional per-field
transform can `keep`, `drop`, or `hmac` a **closed set** of canonical fields.
Redaction is **off by default** — with no configuration the canonical output is
byte-for-byte unchanged.

| Flag | Environment variable | Meaning |
|------|-------------------|---------|
| `--audit-redact` | `JMCP_AUDIT_REDACT` | Comma-separated `field=transform` map. Empty = disabled. |
| `--audit-hmac-key-file` | `JMCP_AUDIT_HMAC_KEY_FILE` | Path to a file holding the HMAC key. Required if any field uses `hmac`. The key value is never a flag or env value. If the path is absent or the file is empty, the server generates a key there on startup, the same way `packaging/lxc/install.sh` does at install time — this is why the flag is safe to pass unconditionally, even before redaction is turned on. A non-empty file is never rotated. |

**Transforms:** `keep` (cleartext), `drop` (omit the field), `hmac` (emit `hmac:<hex>` = HMAC-SHA256 of the value under the key file's bytes). HMAC is deterministic, so a SIEM can still group events by a redacted identifier without learning it; it is keyed, so low-entropy values (IPs/hostnames) are not brute-force-reversible.

**Redactable canonical fields (only these; anything else is a startup error):**
`routers`, `host`, `name`, `basename`, `command`, `pfe_command`. The `routers`
field is transformed per router name and re-joined
(`hmac:<h1>,hmac:<h2>`); `router_count` stays cleartext. `caller` and all
structural fields (`result`, `duration_ms`, `error`, etc.) are never
redactable.

**Auxiliary-event limitation:** `--audit-redact` is an `AuditScope` rendering
policy, not a subscriber-wide tracing filter. Auxiliary SRX fields such as
`router`, `location`, `error_detail`, and `err` do not pass through it; stderr,
the JSON file, and native journald receive those values as the producer emitted
them. Operators must treat auxiliary fields as potentially sensitive and apply
appropriate journal/file access controls or downstream SIEM transformations.

**Example** — HMAC the canonical `AuditScope` router names and drop the device
IP recorded in its `add_device` metadata:

```
rust-junosmcp \
  --audit-redact 'routers=hmac,host=drop' \
  --audit-hmac-key-file /etc/jmcp/audit-hmac.key \
  ...
```

**Startup validation:** an unknown field, an unknown transform, a malformed entry, `hmac` without a key file, or an unreadable/empty key file all abort startup with a clear message — redaction never silently downgrades.

**Canonical limitation:** the free-text `error` field is bounded and
secret-free by construction but may legitimately contain an identifier (e.g.
`router 'r1' not found`). It is **not** field-redactable.

### SIEM / forwarding

Ingest via:

- **Filebeat / Fluentd / Vector** — tail the JSON log file or `journalctl` output.
- **Direct RFC 5424 syslog sink** — deferred; native journald forwarding is available above.

Filter on `target == "audit"` to separate audit events from operational logs.

## Deferred Items

The following capabilities are planned but not yet implemented:

1. **Direct RFC 5424 syslog sink** — native journald is implemented via `--audit-journald`, while direct RFC 5424 formatting and remote transport remain unimplemented and can be provided by the host's journald/rsyslog/SIEM integration.
2. **Built-in log rotation** — the server does not decide when to rotate; it only reopens the file on `SIGHUP` (see [Rotation & retention](#rotation--retention)). In-process size/age-triggered rotation remains out of scope by design; retention is handled by the shipped `logrotate` fragment.
3. **Per-field encryption** — sensitive canonical `AuditScope` metadata fields can be dropped or replaced with a keyed HMAC fingerprint via [Field redaction](#field-redaction). *Reversible* envelope encryption (recover the original from logs with a key) remains out of scope.

## Security & Privacy

- **Canonical secret exclusion** — `AuditScope` does not intentionally log
  credentials, private keys, or passwords. Its `metadata` field is allowlisted
  per tool (for example, `command_count`, `dry_run`, and `config_bytes`) and
  excludes secret material.
- **Canonical bounded errors** — the `AuditScope` `error` field is truncated at
  a UTF-8 boundary no later than 512 bytes, then an ellipsis (`…`) is appended,
  to prevent unbounded log growth from pathological failures.
- **Canonical caller attribution** — each `AuditScope` completion event records
  the bearer-token name or `"stdio"`, enabling per-caller audit trails even
  when multiple tokens share the same scope.
- **Auxiliary privacy boundary** — auxiliary AppID/IDP preflight and package
  events and support-bundle events may omit caller attribution. They may also
  carry direct, unbounded producer-rendered fields such as `err`,
  `error_detail`, and `location`; those fields can be sensitive and bypass both
  `AuditScope`'s `bounded_error` and its redaction policy. Restrict journal and
  audit-file access and apply appropriate downstream SIEM controls.

## Example Queries

### All denied requests in the last hour

```bash
journalctl -u rust-junosmcp.service --since "1 hour ago" --output=json \
  | jq -r 'select(.TARGET == "audit") | select(.AUDIT_RESULT == "denied")'
```

### Top 10 slowest successful commands

```bash
jq -r 'select(.target == "audit") | select(.fields.result == "ok") | "\(.fields.duration_ms) \(.fields.tool) \(.fields.routers)"' \
  /var/lib/jmcp/audit.jsonl \
  | sort -rn | head -10
```

### Failed commits by caller

```bash
jq -r 'select(.target == "audit") | select(.fields.action == "commit") | select(.fields.result == "error") | "\(.fields.caller) \(.fields.routers) \(.fields.error)"' \
  /var/lib/jmcp/audit.jsonl
```

# Feature scope

What each release added, oldest first. This is a summary; [CHANGELOG.md](CHANGELOG.md)
is the full record and is authoritative. Detail for the features named here is in
[docs/REFERENCE.md](docs/REFERENCE.md).

The current version is 2.6.1. The sections up to v0.12 below were written as the
roadmap was delivered and are kept as they were, with two corrections: the
v0.12 items shipped in 0.27.0 and 2.5.0, and cross-references now point into
docs/REFERENCE.md. From v0.13.0 on, each section is one released tag.

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
- **Packaging** — `install.sh` provisions the new on-disk surface owned by `jmcp:jmcp`. See the File transfers section of [docs/REFERENCE.md](docs/REFERENCE.md#file-transfers-transfer_file--fetch_file--list_staged_files) for details.
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
  [Tool scopes and write tools](docs/REFERENCE.md#tool-scopes-and-write-tools).
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

### v0.12 (released: commit-confirmed default and `confirm_commit` in 0.27.0, `get_srx_feed_status` in 2.5.0)

- **Commit-confirmed is on by default (breaking)** — `load_and_commit_config`,
  `rollback_config` (`commit=true`), `render_and_apply_j2_template`, and
  `apply_junos_change_set` now issue `commit confirmed` unless the caller
  explicitly opts out with `confirm_timeout_mins: 0`. Previously a plain,
  unconditional commit was the default; a model-drafted change that cut
  management access had nothing bringing the device back. See
  [Confirmed commits](docs/REFERENCE.md#confirmed-commits-v03-default-on-since-v012).
- **`--commit-confirm-default-mins`** (default `10`) sets the server-wide
  window used when a call omits `confirm_timeout_mins`; a per-call value
  still overrides it.
- **`confirm_commit`** — new write tool that sends the confirming commit for
  any of the four paths above, cancelling the pending auto-rollback.
- Opting out is recorded in the audit event as `commit_confirmed=false`.
- Tool count: 43 → 44 (27 → 28 Junos-only).
- **`get_srx_feed_status`** — new read-only SRX tool: status of the
  mecfeedmcp dynamic-address feeds an SRX pulls. No new write tool; see
  [mecfeedmcp feeds on SRX](docs/REFERENCE.md#mecfeedmcp-feeds-on-srx). Tool count: 44 → 45
  (15 → 16 SRX tools; Junos-only build unchanged at 28).

## Releases since v0.12

Summarised from [CHANGELOG.md](CHANGELOG.md). Routine dependency
and CI releases are omitted here; the CHANGELOG lists them. Tags that exist:
v0.13.0 through v0.28.1, v1.0.0, and v2.0.0 through v2.6.1.

### v0.13.0 and v0.13.1 (2026-07-29)

- **Confirmed commit on change sets** — `apply_junos_change_set` takes an
  optional `confirm_timeout_mins`; the device commits and rolls back
  automatically unless `confirm_junos_change_set` is called before the
  deadline. 0.13.1 made it reachable and registered
  `confirm_junos_change_set` as a write tool.
- **`get_junos_candidate_fingerprint`** exposes the candidate fingerprint the
  change-set flow checks.
- **`token add` provenance flags** such as `--provider` and `--provider-tier`.

### v0.14.0 (2026-07-29)

- **`--lab-mode`** for single-operator environments: change sets are approved
  on creation and record `approval_waiver: "lab-mode"`. See
  [`--lab-mode`](docs/REFERENCE.md#--lab-mode).
- Change-set flags renamed to match every other mecmcp server.

### v0.15.0 to v0.15.3 (2026-07-31 to 2026-08-05)

- **Progress notifications** for every tool call, and `--cleanup-timeout-secs`
  for the budget of each post-operation cleanup.
- `get_junos_config` honours `max_lines`, `max_bytes` and `tail`; output caps
  are now exact.
- A call the server refuses is now recorded in the audit log.
- `--disable-host-check` is removed and rejected at startup.

### v0.16.0 and v0.17.0 (2026-08-05 to 2026-08-07)

- rmcp 3.1.1 on mecmcp 0.5.0 (MCP 2026-07-28 support).
- **The container image has no shell, `apt` or `openssh-client`.** The runtime
  base is `gcr.io/distroless/cc-debian13:nonroot`. `transfer_file` and
  `fetch_file` no longer spawn `scp`; they use the SCP wire protocol natively.
- New stable error code `host_key_revoked`.

### v0.18.0 to v0.20.0 (2026-08-10 to 2026-08-13)

- mecmcp owns the HTTP transport assembly. `/metrics` is behind the Host
  allowlist, a disallowed `Host` returns 421, and an oversized request without
  a valid bearer returns 401.
- `systemctl restart` drains in-flight calls instead of dropping them.
- **`--web-enabled-approver`** exposes staged actions in status responses, and
  **configuration authority tracking** (`config_authority`) arrives for Junos
  devices (0.19.0).
- Commit comments carry `request.id=<uuid>` for provenance (0.20.0).

### v0.21.0 to v0.21.2 (2026-08-19)

- **`state resolve`** settles an operation stuck in a non-terminal state.
- The Junos commit comment names the approver and the change set.
- A change set whose apply fails past staging no longer reads `applied`, and a
  failed apply no longer wedges the device.
- `tools/list` carries the cache descriptor a 2026-07-28 client requires.

### v0.22.0 to v0.24.1 (2026-08-25 to 2026-09-06)

- `commit_check_config` reaches a verdict on a standalone SRX again.
- A crashed commit is re-probed against the device at startup, and
  `get_junos_change_set_status` tells a live commit from one the device
  reverted (0.24.0).
- The shipped systemd unit carries the seccomp posture, and cSRX devices work
  (0.24.1).

### v0.25.0 (2026-09-15)

- **`execute(operation, arguments)`**, an additive 37th tool over the existing
  36 concrete operations. It accepts only an exact operation name, and the
  concrete handler still validates the arguments. It is authorised against both
  the facade and the target operation, and is excluded from wildcard scopes
  because it is write-capable.

### v0.26.0 (2026-09-28)

- **`--allow-direct-commit`**, off by default: four tools that commit in one
  call are refused unless an operator opts in. See
  [`--allow-direct-commit`](docs/REFERENCE.md#--allow-direct-commit).
- `approve_junos_change_set` requires a human approver.
- `get_junos_config` gains a `format` parameter; the load tools gain a `mode`
  parameter.
- Two read-only SRX tools: `srx_flow_sessions` and `srx_policy_match`.
- The release image and tarball are signed keylessly with cosign.

### v0.27.0 to v0.27.5 (2026-09-29 to 2026-10-07)

- Device secrets are redacted from tool output (0.27.0).
- **Commit-confirmed is on by default** and `confirm_commit` is added (the
  v0.12 items above, shipped here).
- Container images publish to `ghcr.io/mechubsec/rustjunosmcp` (0.27.0) and
  to Docker Hub (0.27.5).
- `execute_junos_command` and `pfe_command` enforce an allowlist by default
  (0.27.2), with their own `pfe_allow` rules (0.27.3).
- The LXC release tarball is built and uploaded automatically (0.27.2).
- Official MCP Registry listing (0.27.4).
- stdio no longer requires a bearer-token store (0.27.5).

### v0.28.0 and v0.28.1 (2026-10-21)

- russh 0.64.1; plain-text and structured tool output go through
  vendor-scoped Junos redaction.
- Startup reports every credential-file mode problem in one pass, and LXC
  packages ship an honest `BUILD-INFO`.
- Tagged releases are published to the MCP Registry.

### v1.0.0 (2026-10-25)

- **No longer beta.** The surfaces covered by semantic versioning are listed in
  [Stability](docs/REFERENCE.md#stability).
- **Coded tool errors:** every tool error carries `{code, message, retryable}`
  for peers that negotiated MCP 2025-06-18 or later.
- Session-setup failures are classified by type, and `execute` validates its
  arguments before dispatch.
- **`--tool-mode full|compact`** (env `MCP_TOOL_MODE`) lists only `execute`
  and `get_router_list` in compact mode.
- Client config examples under `examples/`.

### v2.0.0 to v2.4.0 (2026-10-26)

- **2.0.0:** `tokens.json` token names starting with `oauth:` are reserved and
  fail to load; rename them before upgrading. Adds the forward-only audit
  evidence pipeline (`--audit-forward-endpoint`) and an optional OAuth 2.1
  resource-server mode behind the `oauth-resource` cargo feature (not in
  release images or the LXC package). Verified-approver step-up is covered
  end to end by tests.
- **2.1.0:** `--approver-replay-store`, an opt-in store of used approver
  assertion IDs so a restart cannot replay an unexpired assertion. Requires
  `--oidc-issuer`.
- **2.2.0:** `--oauth-max-token-lifetime-secs`, and a startup warning counting
  live `human` tokens without an `oidc_subject`.
- **2.3.0:** optional per-device `attributes` (`site`, `vendor`, `tags`) in
  `devices.json`.
- **2.4.0:** static-token `device_selectors`, `--require-verified-proposer`,
  and approver device-scope checks against every device in a change set.
  Snapshot the change-set state file before upgrading.

### v2.5.0 (2026-10-29)

- **`get_srx_feed_status`**, a read-only SRX tool for mecfeedmcp
  dynamic-address feeds. Tool count 44 to 45 (SRX 15 to 16).
- `get_device_list` takes an optional `include_blocklist` argument.
- SRX workflow failures settle the audit record once, and the list tools
  record a `count` audit field.

### v2.6.0 (2026-10-30)

- **Plane guard for Security Director and Mist-managed SRX.** A device's
  managing plane comes from `config_authority`, or is detected from
  `system services outbound-ssh` when it is `unknown`. Mist devices are
  read-only; Security Director devices refuse changes that touch `security`,
  `applications`, `schedulers` or `system services outbound-ssh`.
  `--allow-plane-owned-writes` turns the refusals into warnings. See
  [Security Director and Mist-managed SRX](docs/REFERENCE.md#security-director-and-mist-managed-srx).
- `load_and_commit_config` on a Security Director device now accepts changes
  outside the managed trees; before, it refused the whole device.

### v2.6.1 (2026-10-30)

Moves to russh 0.65 through rustnetconf 0.19.1, rustez 0.20.1 and mecmcp 0.32.0,
for CVE-2026-116794 and the client-side fixes in that release. No feature change.

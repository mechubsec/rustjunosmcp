# Changelog

All notable user-facing changes are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **LXC packages now ship an honest `BUILD-INFO`.** Skip-build
  (`JMCP_PACKAGE_SKIP_BUILD=1`) records `rustc=unknown (...)` instead of a
  local toolchain, and `binary_sha256` always matches the packed binary.
  Shared packaging conformance treats that provenance as fatal.
- **`Sign release tarball` can backfill a published tag.** The Debian 13
  container job trusts its workspace so packaging can read git metadata, and
  `workflow_dispatch` with a `tag` input rebuilds and uploads the tarball for
  an existing GitHub-verified signed tag that already has a published
  release.

## [0.27.5] - 2026-10-07

### Added

- **Release images are also published to Docker Hub** as
  `docker.io/mechub/rustjunosmcp` (same tags as GHCR: `X.Y.Z`, `X.Y`,
  `latest`), signed and attested the same way (#517, #518).
- **stdio no longer requires a bearer-token store**, and devices can take
  their credential from an environment variable (#504).
- mecmcp's verified-approver identity is wired through (MEC-995, #519).

### Changed

- Packaging emits an honest `BUILD-INFO` and treats provenance failures as
  fatal (#514).

## [0.27.4] - 2026-10-07

### Added

- **Official MCP Registry listing.** The image now carries
  `io.modelcontextprotocol.server.name="io.github.mechubsec/rustjunosmcp"`,
  which the registry uses to verify image ownership, and the repo ships a
  `server.json` describing the documented stdio container invocation.

### Changed

- Dependency and CI updates: distroless `cc-debian13` base image digest,
  `cargo-minor-patch` group, and pinned `mecmcp` reusable workflows.
- Docs: stdio container invocation and fwconfigsanitizer references.

## [0.27.3] - 2026-10-06

### Security

- **`mecmcp` bumped to 0.26.1**, picking up an upstream redaction-coverage
  fix in `mecmcp-redact`'s Junos profile. This repo's own support-bundle
  XML redaction test no longer needs to exclude any known Junos secret key
  from XML-pass coverage.

### Changed

- **`pfe_commands` now has its own `pfe_allow`/`pfe_allowed_pipes` config
  keys**, merged per-device the same way `allow`/`allowed_pipes` are for
  `commands` (MEC-1303). Previously the allowlist authorization mode
  (default since 0.27.2) had no dedicated allow-list for PFE commands and
  refused all of them unless a config pinned `mode: blocklist`; an
  inventory that wants `execute_junos_pfe_command` under allowlist mode
  should now add `pfe_allow` instead.

### Security

- **`rustnetconf` bumped to 0.18.1**, picking up its `russh >= 0.63.2, < 0.64`
  fix for CVE-2026-102823. This also drops the temporary
  `[patch.crates-io]` override for `HostKeyVerification::AcceptNew`
  (MEC-43 / rustnetconf#108), which has shipped in a tagged release since
  0.18.0.
- **`rustez` bumped to 0.19**, the published version whose own `rustnetconf`
  requirement moved to `^0.18` (0.18.0 still required `0.17`) — without this
  the resolved dependency graph kept a second, vulnerable `rustnetconf
  0.17.0` / `russh 0.62.7` pulled in transitively through `rustez`.

### Changed

- **The container image now pre-provisions its audit HMAC key.** The
  `rust-junosmcp` binary generates `--audit-hmac-key-file` on first run if
  it is absent or empty (mirroring `packaging/lxc/install.sh`'s own
  key-generation step), and the Dockerfile's `ENTRYPOINT` now always passes
  `--audit-hmac-key-file /var/lib/jmcp/audit-hmac.key`. Previously the
  container image ran with no HMAC key configured at all, unlike the LXC
  package of the same binary (mecmcp#376 / MEC-978). `--audit-redact`
  itself still defaults to empty — redaction stays opt-in — so this alone
  does not change what is logged; an operator who now turns on
  `=hmac` redaction no longer hits `HmacKeyUnreadable` on the first
  restart.

## [0.27.2] - 2026-09-30

### Changed

- **`execute_junos_command`/`pfe_command` now enforce an allowlist by
  default instead of a fail-open blocklist.** Command and PFE-command
  authorization is wired to `mecmcp-policy`'s `Policy<Action>`, compiled
  per device from `defaults.allow` merged with each device's own `allow`
  list. A device config with deny rules but no explicit `mode` key keeps
  loading as the legacy fail-open blocklist (with a startup warning); a
  config with no policy section at all now defaults to the new fail-closed
  allowlist. An explicit deny rule on top of a broader allow prefix (e.g.
  `allow: ["request system"]` plus a deny on `request system reboot*`) is
  now honored instead of being silently ignored. `pfe_command` has no
  dedicated allow-list config key yet, so it fails closed under the new
  default until a follow-up adds one (#465).

### Fixed

- **Release tarball now built and uploaded automatically.** The LXC release
  tarball used to be attached to a GitHub release by hand, after the tag push
  and the `Release image` workflow had already run; that manual step was
  skipped for v0.27.1, so the sign-tarball workflow failed with "no assets to
  download" and v0.27.1 shipped a GitHub release and a container image but no
  tarball, checksum, or signature. `release-sign-tarball.yml` now builds the
  Debian 13 LXC tarball itself and uploads it to the release before signing,
  so signing always has something to work with (#464).

## [0.27.1] - 2026-09-30

### Fixed

- **Release workflows now build.** `release-image.yml` and
  `release-sign-tarball.yml` pinned their `mecmcp` reusable workflow calls to
  `34bc01f`, a commit that only ever existed on a deleted branch from an
  abandoned mecmcp PR. GitHub silently rejects a workflow file that
  references an unreachable ref (the job list comes back empty), so v0.27.0
  tagged cleanly but published no GitHub release, no signed tarball, and no
  container image. Both workflows are repinned to `mecmcp` `main@e97d10b`,
  which is reachable and carries the same reusable workflow definitions
  (#456). No code, tool behavior, or crate API changed from 0.27.0 — this
  release exists solely to produce the artifacts 0.27.0 could not.

## [0.27.0] - 2026-09-29

### Security

- **Redact device secrets from tool output.** `get_junos_config` and
  `junos_config_diff` returned raw device configuration, including Junos
  `$9$`-style reversibly-encrypted values, PSKs, SNMP communities, and
  RADIUS/TACACS secrets, straight to the calling model (the README also
  wrongly called these values "hashed" — they are symmetrically encrypted
  and recoverable with the device's master key). Redaction is now applied
  at the two tool-specific call sites and, as a last-mile safety net, in a
  single `call_tool` post-processor covering every tool response, so a
  newly added tool cannot silently skip it. Tool descriptions and the
  README now say output is redacted (MEC-14).

### Added

- **`confirm_commit`** — new write tool that sends the confirming commit for
  a commit-confirmed window opened by `load_and_commit_config`,
  `rollback_config`, or `render_and_apply_j2_template`, cancelling the
  pending auto-rollback (MEC-45).

### Changed

- **Behaviour change: commit-confirmed is on by default.**
  `load_and_commit_config`, `rollback_config` (`commit=true`),
  `render_and_apply_j2_template`, and `apply_junos_change_set` now issue
  `commit confirmed <window>` unless the caller passes
  `confirm_timeout_mins: 0`. Previously these committed directly with no
  auto-rollback net unless the caller opted in. The window defaults to the
  new `--commit-confirm-default-mins` flag (default 10 minutes); a per-call
  `confirm_timeout_mins` overrides it. The opt-out is recorded in the audit
  event as `commit_confirmed=false`. The response and change-set status both
  report `rollback_deadline_unix` (MEC-45).
- **`--ssh-accept-new-host-keys` now gives real TOFU for NETCONF SSH, not
  no-verification-at-all.** Previously the flag pinned scp's known_hosts
  entries on first contact (`HostKeyVerification::AcceptNew`) but set NETCONF
  SSH to `HostKeyVerification::AcceptAll` — an operator reading the flag name
  had no reason to expect that NETCONF connections were left completely
  unverified. NETCONF now uses `AcceptNew` too: an unknown host's key is
  pinned on first contact, and a host that later presents a *different* key
  is refused, on both the scp and NETCONF paths, against the same
  `known_hosts` file (MEC-44).
  **Behaviour change for anyone relying on the old flag for key rotation:**
  a device that rotates its host key (reimage, RE swap) will now be refused
  on reconnect instead of being silently re-trusted. Re-run
  `scripts/scan-known-hosts.sh`, or delete the stale line from
  `known_hosts`, after a legitimate rotation.
- **New `--ssh-insecure-accept-any-host-key` flag**, lab-only, carries the
  old blanket `HostKeyVerification::AcceptAll` behavior for NETCONF SSH under
  an honestly-named opt-in. Mutually exclusive with
  `--ssh-accept-new-host-keys`. Logged loudly at startup and recorded as an
  audit event.
- **Container images now publish to `ghcr.io/mechubsec/rustjunosmcp`** —
  the repo moved to the mechubsec organization, and images are renamed to
  match. Older tags were copied from the previous name.

### Fixed

- **`--ssh-insecure-accept-any-host-key` now also disables host-key
  verification for scp (`transfer_file` / `upgrade_junos`), not just
  NETCONF SSH.** The MEC-44 landing (above) left scp on `AcceptNew` (TOFU)
  under this flag, so a device presenting a changed key was still refused
  over scp despite the flag's name promising to accept any key. Both
  transports now share one `SshHostKeyMode` end-to-end
  (`Strict` / `AcceptNew` / `AcceptAll`), so `--ssh-insecure-accept-any-host-key`
  means the same thing on both paths.
- **`srx_flow_sessions` fails closed on two more summary-parsing gaps**
  (MEC-745): a node reporting no error but also no recognised session-count
  element no longer has its missing count silently papered over by the
  other nodes' totals, and an early warning-severity `rpc-error` on a node
  can no longer mask a later error-severity one on the same node. Both
  previously risked understating the true session count.

## [0.26.0] - 2026-09-28

### Added

- **`--allow-direct-commit`, off by default.** `load_and_commit_config`, a
  committing `render_and_apply_j2_template`, `rollback_config`, and
  `upgrade_junos` stage, validate, and commit a device change in one call with
  no change set and no second-principal review. Without the flag, all four
  are refused before the device is touched, identically over stdio and HTTP.
  With it, the server logs loudly at startup and every call is audited
  (`direct_commit_allowed=true`; a refusal is audited too). See
  `--allow-direct-commit` in the README.
- **`approve_junos_change_set` now requires a human approver.** The mecmcp
  dependency's `ChangesetCoordinator::approve_change_set` gained an
  `approver_actor_type` argument and refuses anything but
  `mecmcp_audit::ActorType::Human` — an agent or an unattributed caller could
  already never propose and approve the same change set, but nothing
  previously stopped it from standing in as the second principal.

- **`get_junos_config` gains a `format` parameter** (`text` default, `set`,
  `xml`, or `json`), rendered device-side via the matching Junos
  `| display <format>` CLI modifier — the same mechanism
  `execute_junos_command` already passes through untouched. Output flows
  through the same policy check, XML-wrapper stripping, and output-cap
  pipeline as the existing `text` format; there is no new unredacted path.
  An unrecognized `format` is rejected before any device connection.

- **The load tools gain a `mode` parameter** (`merge` default, `replace`, or
  `override`) controlling the wire `action` for `<load-configuration>`:
  `load_and_commit_config`, `render_and_apply_j2_template`, and the
  change-set payload spec (`create_junos_change_set`'s `actions[].payload`).
  `override` replaces the entire candidate configuration — the highest
  blast-radius operation this server exposes — and is refused outright on
  `load_and_commit_config` and `render_and_apply_j2_template`, which commit
  directly with no second-principal review. It is permitted only through
  `create_junos_change_set` → `approve_junos_change_set` →
  `apply_junos_change_set`, which requires approval by a principal distinct
  from the creator before anything commits (MEC-12). `config_format=set`
  (configuration-set payloads) has no wire-level `override` action in Junos;
  that combination is rejected before any RPC is sent regardless of path.

- Raised MSRV to 1.89 (family-wide decision; enables mecmcp to drop aes pin)
- **Two new read-only SRX tools: `srx_flow_sessions`, `srx_policy_match`.**
  `srx_flow_sessions` queries active flow sessions with hard-capped result
  limits and node-aware summaries; `srx_policy_match` performs deterministic
  5-tuple policy matching against both zone-pair and global policies,
  returning the device's own verdict. Tool count: 37 → 39.
- **Four new read-only SRX tools: `srx_list_policies`, `srx_resolve_address`,
  `srx_resolve_application`, `srx_list_nat_rules`.** Security policies by
  zone pair (incl. global policies and optional hit counts), address-book and
  application/application-set resolution (including `junos-*` predefined
  defaults, with recursive nested-set resolution and explicit cycle
  rejection), and source/destination/static NAT rules. Address-book and
  application resolution are configuration-sourced via a hand-built
  subtree-filtered `get-configuration` RPC. Names on policies and NAT rules
  are returned unresolved by design — use `srx_resolve_address` /
  `srx_resolve_application` to expand them. Tool count: 39 → 43.
- **Release image and tarball are now signed keylessly with cosign** via
  GitHub Actions OIDC (no key pair, ever). The `Release image` workflow signs
  the pushed image by digest; a new `Sign release tarball` workflow signs the
  LXC tarball once it is attached to a published GitHub release. See the
  README's "Verifying the image signature" and "Downloading a prebuilt release
  tarball instead" sections for `cosign verify` / `verify-blob` recipes.

### Fixed

- **cSRX devices now work**. rustez 0.18 tolerates cSRX rejecting
  `<get-route-engine-information/>` during fact gathering
  (mechubsec/rustez#54). Previously every tool call on a cSRX device failed
  with `[OperationFailed] syntax error`.

## [0.25.0] - 2026-09-15

### Added

- **`execute(operation, arguments)` is an additive 37th MCP tool** over the
  existing 36 concrete Junos and SRX operations. It accepts only an exact
  concrete operation name; it never repairs names, translates argument keys,
  or supplies defaults. The selected concrete handler receives the original
  argument object, so its existing typed validation remains authoritative.
  Direct calls to all original 36 tools remain supported.

### Changed

- **Facade authorization is deliberately dual-scoped.** An authenticated HTTP
  token must explicitly grant both `execute` and the selected concrete tool;
  wildcard scope does not grant `execute`. The same preflight also applies the
  caller's device scope to every nested device selector before dispatch.

- **`execute` is conservatively write-capable.** It is excluded from wildcard
  tool scope, because it can dispatch a write-capable concrete operation.

- **Facade audit records retain both layers of attribution.** HTTP transport
  records the outer `execute` request, while the concrete handler emits the
  correlated operation record with the same request id; malformed and rejected
  facade calls remain bounded and do not log raw nested arguments.


## [0.24.1] - 2026-09-06

### Changed

- **Shipped systemd unit now carries the fleet seccomp posture** (mecmcp#354).
  Added a comment documenting why `SystemCallErrorNumber=EPERM` is load-bearing:
  without it, systemd's default applies and a denied syscall raises SIGSYS, killing
  the process mid-request (mecmcp#351). The comment also clarifies that EPERM denials
  are silent at the systemd layer — seccomp return actions have a precedence order
  and ERRNO outranks LOG, so such denials can only become visible if the application
  stops discarding the errno.

### Fixed

- **cSRX devices now work**. rustez 0.18 tolerates cSRX rejecting
  `<get-route-engine-information/>` during fact gathering
  (mechubsec/rustez#54). Previously every tool call on a cSRX device failed
  with `[OperationFailed] syntax error`.

- **Flaky test race in `timeout_budget_tests`**. Both tests mutated the same
  process-global `CLEANUP_TIMEOUT_SECS` and cargo ran them in parallel, so whichever
  test lost the race would read the value the other had just reset, causing spurious
  failures. Added a static mutex that both tests hold for their entire duration to
  serialize them.


## [0.24.0] - 2026-09-05

### Added

- **A crashed commit is now re-probed against the device at startup** (#370).
  `commit_operation` persists the caller's attribution -- including `request_id` -- immediately before
  the commit RPC is sent, and `format_attribution` puts that same id into the Junos commit comment as
  `request.id=<uuid>`. A process that dies between sending the commit and recording its result therefore
  leaves behind a record naming something the device can be asked about. On startup the server now asks:
  for every operation `ChangesetCoordinator::load` left `Indeterminate` that carries an attribution, it
  reads the device's commit log and settles the record `Committed` if the id is there.

  The selection is `Indeterminate` **plus an attribution**, not `Committing`. `load` rewrites every
  non-terminal operation to `Indeterminate` before any sweep could observe it, and attribution is written
  nowhere but `commit_operation` -- so its presence is what separates a crash during the commit from a
  crash during staging, which reaches the same state with no attribution.

  **Only a hit settles anything.** Junos keeps a bounded commit history, so an entry can age out, and a
  device can simply be unreachable at boot. Neither is evidence the commit did not happen, so both leave
  the record `Indeterminate` for `state resolve`. The sweep never writes `Failed`.

  **The commit-log hit settles the commit; the lock flag is cleared only when lock freedom was proven.**
  Finding the id in the log proves the commit landed, but not that the candidate lock was released — the
  process may have died between the commit and the unlock. So after finding a hit, the sweep probes lock
  freedom by taking and releasing the lock, matching the abandon path. `config_lock_held` is cleared only
  when that probe succeeds; if the lock cannot be taken, cannot be confirmed returned, or the probe times
  out or errors, the record is still settled `Committed` (the commit is proven) but the flag remains set
  and the `details` note that the lock state could not be verified.

  **A confirmed commit is not settled either.** Finding the id proves the provisional commit entered the
  log, not that its rollback was ever cancelled; settling it `Committed` would make the record terminal,
  freeing the device for an apply whose commit would cancel a rollback still armed, and would report as
  permanently live a change the device may yet revert. Junos marks these on the entry's *header*
  (`commit confirmed, rollback in Nmins`), so the match groups the log into entries rather than searching
  it flat, and a deadline already on the record is honoured even when the log is ambiguous.

  Known gap: a settle writes the record directly and emits no SSDF `result_receipt`, so a crash after the
  apply intent was spooled leaves that evidence chain unterminated even once the device has confirmed the
  outcome. Tracked separately.

  The sweep is detached rather than awaited: a candidate on an unreachable device costs 20s, longer than
  the readiness budget the test harness and package smoke allow, so blocking startup on it would turn a
  recoverable record into a server killed and retried on every boot. Nothing is lost by serving first --
  a non-terminal operation already blocks a new one on its device, so these records keep gating writes
  until the sweep settles them. Probing is bounded-concurrent (4 at a time) and the candidate order is
  rotated each run, so a prefix of unreachable devices in the coordinator's stable map order cannot
  starve a reachable candidate behind them -- either within one sweep or across every restart. 20s per
  device, 120s for the sweep. A provisional finding is reported but deliberately not written back: doing so
  would mean writing `Indeterminate` and the old deadline over a record a `confirm_junos_change_set` may
  have settled in between, un-confirming a commit the operator did confirm, and mecmcp has no
  compare-and-update for operations to make that check atomic. No rollback deadline is invented either: reconstructing one from the device's clock would be
  the same kind of unobserved claim the rest of this refuses to make. Because the sweep now runs alongside live traffic, the settle
  path re-reads the record and skips it if anything settled it while the probe was in flight; that path
  is safe from the remaining window by construction, since `committed` is only reached for a record that
  carried no deadline and so writes exactly what a concurrent confirm would have written. The candidate
  rotation is seeded per process rather than from the clock, because a wall-clock modulo is periodic --
  60 records restarted daily lands on `86400 % 60 == 0` and would reselect the same slow prefix forever.

  Verified on hardware (vSRX 24.4R1.9), not just offline: a real change-set commit was confirmed to stamp
  the full untruncated `request.id=` into the device's commit log; a record flipped to `Indeterminate` was
  settled `Committed` from that log after a restart; an id the device had never seen was left untouched;
  and an unreachable device timed out at 20s with the record untouched and the server still starting.


### Fixed

- **`get_junos_change_set_status` now distinguishes a live commit from one the device reverted** (#384).
  `apply_junos_change_set` with `confirm_timeout_mins` issues a Junos confirmed commit, which the
  device rolls back unless `confirm_junos_change_set` arrives before the deadline. Status reported
  `applied` either way. The cause is where `Applied` is written: `apply_change_set` sets it as soon as
  *staging* succeeds, before the commit is issued, and nothing rewrites it afterwards -- so the
  change-set state is settled before the device has been asked to do anything.

  The verdict now comes from the linked operation record, reached through `ChangeSetRecord::operation_id`:
  `awaiting_confirmation` while a rollback deadline is still in the future, `presumed_auto_reverted`
  once it passes with no confirmation recorded, `committed` once the operation reaches `Committed`, and
  `discarded` when one was reconciled by `state resolve`.

  A recorded deadline is the only evidence this server holds that a confirmed commit was issued, so it
  decides whether a verdict is owed at all, and it outlives a manual resolve. `resolve_persisted_operation`
  settles the state but leaves `rollback_deadline_unix` in place, and `state resolve ... AS COMMITTED`
  does not stop the device: reporting `committed` there would hide a rollback still counting down.
  `AS DISCARDED` is an operator saying the change is not on the device, which a timer only reinforces.
  An `AS COMMITTED` record whose window has since closed reports `indeterminate` rather than guessing:
  `state resolve` neither stops the device nor records when it ran, so that shape is either a confirm
  made out of band and then reconciled -- the remedy for a confirming commit whose durable write failed
  -- or a reconciliation made early on a timer that then fired. `committed` would hide a revert and
  `presumed_auto_reverted` would contradict a human who looked at the device, so the tool reports the
  uncertainty and sends the reader to the device.
  An operation with no deadline that is not `Committed` gets no verdict at all -- an ordinary failed
  apply terminalizes as `Discarded`, and that is not a confirmed-commit outcome.
  The response also carries `operation_id`, `operation_state` and `rollback_deadline_unix` so a reader
  can see the basis. All additions are additive -- no existing field or argument name changed.

  **`presumed_auto_reverted` is a presumption, not an observation.** It is the absence of a recorded
  confirmation, and it is wrong if a confirming commit was issued out of band on the device, if the
  server and device clocks disagree, or if `confirm_junos_change_set` reached the device but its
  durable write failed. Only the device settles it. Likewise `committed` cannot separate a confirmed
  commit from a plain one, because confirming clears the deadline -- both mean the configuration is
  live, which is the distinction that matters.

  The derivation keys on the deadline rather than on `LifecycleState::Committing`, because a restart
  rewrites every non-terminal operation to `Indeterminate` while leaving the deadline intact. Since the
  Junos rollback belongs to the device rather than the session, that window is still open and still
  confirmable; keying on `Committing` dropped the deadline from the response at exactly the moment an
  operator needed it.

## [0.23.0] - 2026-09-01

### Fixed

- **`add_device` corrupted a canonical-envelope inventory** (#374).
  `insert_device` always wrote the new device as a top-level key, so against an
  inventory shaped `{"version": 1, "devices": {...}}` the device landed beside
  `version` and `devices`. mecmcp-inventory 0.23 refuses unknown top-level keys
  once it has identified the shape, so the tool wrote the file, failed its
  reload, and left an inventory that would not load at the next start --
  reporting a failure having already broken the file on disk. The insert is now
  shape-aware: an envelope takes the device under `devices`, a bare map keeps
  taking a top-level key. An inventory whose `devices` is present but not an
  object -- the legacy array envelope the loader also accepts -- is refused
  outright rather than written, since it has no key-shaped slot to add to.
  Verified by sabotage: reverting the shape check fails the new tests, including
  a round-trip that loads the written file back.
- **Moved off the yanked `chacha20` 0.10.1.** The crate arrived through
  `rand -> rmcp -> mecmcp-server` and was yanked upstream; cargo-deny fails the
  advisories check on a yanked crate. 0.10.2 satisfies the same requirement, so
  this is a lockfile-only move.

### Added

- `JunosTransaction` declares `Atomicity::candidate_configuration()` rather than
  inheriting mecmcp 0.23.0's `nothing_guaranteed()` default. Junos stages into a
  candidate, `commit check`s it and rolls back exactly, so all three guarantees
  hold. Left inherited, an approval prompt keyed on this declaration would tell
  an operator that a Junos change offers no atomic apply, no dry run and no
  guaranteed rollback -- understating the change control this server provides.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.21.0` to `v0.23.0`, spanning two
  minors. No production code changed: `apply_change_set` already performs the
  `claim_change_set_for_apply` that 0.22.0 made the only legal
  `Approved -> Applying` route, and already writes `Applied` after staging, so
  `settle_change_set` still transitions from a legal `Applied`.
- Change-set fixtures seed through `seed_change_set_for_test`, since
  `insert_change_set` now creates `Planned` and nothing else.
- `ApprovalRecord` fixtures carry `digest_version: 4` and `ChangeSetRecord`
  fixtures carry `apply_without_handle: false`, both new required fields.
- **`quick-xml` 0.41 -> 0.42, with `rustez` 0.16 and `rustnetconf` 0.16** (#373).
  Resolves to one `quick-xml` version instead of two. `rustnetconf` 0.16 boxed
  `RpcError::ServerError`'s seven RFC 6241 fields into `RpcServerError` to
  reduce large-`Err` returns; six call sites moved (two pattern matches, one doc
  comment, three test constructions). The quick-xml change itself: the
  support-bundle redactor compares `local_name().as_ref()` against the name
  directly instead of `name.as_bytes()`, since 0.42 yields `&str`.
- **`sha2` -> 0.11 and `rand` -> 0.10.** sha2 0.11 returns
  `hybrid_array::Array`, which does not implement `LowerHex`, so
  `format!("{:x}", digest)` no longer compiles. All digest formatting now routes
  through the `hex32` helper rather than re-deriving an encoding, ensuring
  consistent wire format in audit records and change-set fingerprints. A
  known-answer test now pins `hex32` to published SHA-256 vectors. rand 0.10
  removes `OsRng` and `RngCore`; `SysRng` is the same OS entropy source, now
  exposed fallibly — the confirmation-token path keeps the old panic-on-failure
  semantics, since a dead CSPRNG must never silently downgrade to a weaker
  source for a destructive-workflow token.
- `uuid` 1.24.0 -> 1.25.0.
- `thiserror` 2.0.19 -> 2.0.20.
- **CI: Dependabot now ignores git-pinned `mecmcp` crates** (#375). The weekly
  cargo run was failing because Dependabot advanced the git ref from the pinned
  tag to the newest commit on mecmcp main, but the manifest also carries an
  exact version requirement, so cargo refused. The mecmcp version is deliberately
  moved by hand in dedicated PRs, so there is nothing for dependabot to do.

### Security

- **Fixed RUST_LOG turning off the audit trail** (via mecmcp 0.21.0). An
  operator who set `RUST_LOG` to debug one crate turned off this server's audit
  trail for the duration, while the operations it would have recorded still
  happened. The audit subscriber is now isolated from global `RUST_LOG`
  directives.

### Upgrading

- **A binary-only rollback to a build pinned at mecmcp v0.21.0 will refuse to
  start if any change set has been approved under this one.** 0.23.0 signs a
  genuine two-person approval with `digest_version: 5`, which binds the preview
  digest into the approval, and a record carrying one forces the change-set
  state file to schema 6. The v0.21.0 reader does not accept schema 6 and
  refuses the file rather than silently ignoring what it cannot verify -- which
  is the correct behaviour, but it means the state file is not backward
  compatible. Roll back the state file alongside the binary, or take a Proxmox
  snapshot of the guest before upgrading and restore that instead.

## [0.22.1] - 2026-08-25

### Fixed

- **Deleting an absent statement no longer fails the whole load.** Found by
  deploying 0.22.0 and retesting #358 against the physical SRX345: the
  `<ok/>`-sibling parse was fixed, and immediately exposed a second, distinct
  gap on the same device.

  Junos answers a delete of a statement that is not present with a *warning*
  `<rpc-error>` carrying only `error-severity` and `error-message` — no
  `error-type`, no `error-tag`, both of which RFC 6241 makes mandatory. The
  parser rejected the reply with `rpc-error is missing error-type`, so a benign
  warning sank the entire load and re-blocked `commit_check_config` and
  `apply_junos_change_set` on the very device 0.22.0 had just unblocked.

  Not SRX345-specific: any delete of an absent statement, on any Junos device,
  produces this shape.

  Fixed in `rustnetconf` 0.14.5, which tolerates a missing type and tag **only**
  for warning severity. A hard error still has to say what it is.

### Changed

- `rustnetconf` 0.14.4 -> 0.14.5.

## [0.22.0] - 2026-08-25

### Fixed

- **`commit_check_config` reaches a verdict on a standalone SRX again**
  (#358). A single-RE physical SRX345 answers commit-check with a closed
  `<commit-results>` element followed by a sibling `<ok/>`, which RFC 6241
  does not allow together. The reply failed to parse with `<ok/> conflicts
  with an existing payload`, so the verdict was lost even though the check
  had succeeded — and because `apply_junos_change_set` runs commit-check
  internally, it refused too.

  The effect was backwards: the **governed** write path was unusable on the
  device while `load_and_commit_config`, the ungoverned one, committed the
  same text happily. An operator reaching for plan/approve/apply got a hard
  stop and was nudged toward the blunter tool.

  Root cause and fix are in `rustnetconf` 0.14.4. The chassis-cluster form of
  this reply already parsed, because there Junos leaves `<routing-engine>`
  unclosed and the parser's tolerance was keyed on the payload still being
  open — so a device that closed the element correctly fared worse than one
  that did not. The tolerance is now scoped to exactly one `<ok/>` after a
  lone, closed `<commit-results>`; every other payload shape keeps the
  conflict, and a hard `<rpc-error>` still wins, so a failed check is never
  reported as passing.

  Distinct from #180, which was the multi-RE reply envelope
  (`rustnetconf`#43) and a different parse error.

### Changed

- `rustnetconf` 0.14.3 -> 0.14.4.
- **`mecmcp` 0.12.0 -> 0.19.0.** That is the jump from the v0.21.2 baseline;
  0.17.0 and 0.18.0 were intermediate untagged steps. Includes the fix for the
  intermittently-empty audit captures.

#### Upgrade note — rolling back needs the state file, not just the binary

`mecmcp-changeset` state carries a schema version. v0.21.2 links 0.12.0, whose
reader accepts **v1-v3 only**. 0.22.0 links 0.19.0, which accepts v1-v4 and
**stamps v4 on any write to a store holding a real approval**.

Once this release has written such a store, reinstalling the 0.21.2 binary
alone will not start — it rejects the file with `unsupported changeset state
version 4`. **Roll back with the Proxmox snapshot**, which restores `/var/lib`
along with the binary. A binary-only downgrade is not a rollback path.
- `rmcp` and the toolchain move to 1.98.0 alongside the builder image.
- Tier-2 packaging hardening: `tokens.json` migration, audit HMAC, systemd
  sandbox, and a legacy token store that is no longer shadowed by an empty
  primary.
- Dependabot added — this repo had none at all.

## [0.21.2] — 2026-08-19

### Fixed

- **`tools/list` carries the cache descriptor a 2026-07-28 client requires.**
  A client on that protocol validates the result and rejects one without
  `ttlMs` and `cacheScope`, which Claude Code reports as **"tools fetch
  failed"** against a server that is healthy and answering in milliseconds —
  the connection succeeds and the tool surface is simply never fetched, so
  every tool from this server is invisible.

  `ListToolsResult::with_all_items` leaves both fields unset and both are
  omitted on the wire. Servers that do not override `list_tools` get them from
  rmcp's generated handler; this one overrides it to filter the surface by
  token scope, so it has to supply them itself.

  Gated on the negotiated version exactly as rmcp does, because the fields are
  not part of the older result shape. `cacheScope` is `private`, where rmcp's
  unfiltered list says `public`: this list is per token, so a cache keyed only
  on the URL must not serve one caller's permitted surface to another.

## [0.21.1] — 2026-08-19

### Fixed

- **A failed apply no longer wedges the device** (#312). 0.21.0 stopped the
  change set claiming it applied, but every later apply on that device was still
  refused with "the device already has an active or unreconciled operation", and
  the only way out was `state resolve` or hand-editing the state file.

  The cleanup now releases the staged session — which on Junos *is* the revert,
  since the close sends `<discard-changes/>` — and settles the records with **no
  device write**. Verified on hardware: a refused apply, a second refused apply,
  and then a valid change set that commits, with no operator intervention in
  between.

  Nothing is recorded that was not established. The lock is taken and returned
  to prove it was free, the candidate fingerprint is read through that held lock
  and must match its pre-stage value, and any failure leaves the operation
  non-terminal for `state resolve`. A commit that may have reached the device is
  recorded `Indeterminate`, never `Discarded`.

  Also fixes a **fifth failure path** that 0.21.0 missed entirely: a device that
  *refuses* a commit reports it as an outcome rather than an error
  (`Ok(CommitOutcome::Reconciled { succeeded: false })`), so the cleanup never
  ran and the change set kept reading `Applied`.

### Changed

- `--cleanup-timeout-secs` now advertises the correct worst case. A failed apply
  can spend four cleanup phases in series — the session close plus the lock,
  fingerprint and unlock probes — so the startup log, `--help`, and
  `worst_case_duration` all report `timeout + 4 × cleanup` (**480s** with the
  defaults, previously under-reported as 420s). Size client idle timeouts from
  the new number.

### Known issues

- **#316**: on a standalone device with a shared candidate, the discard-on-close
  clears the whole candidate, so uncommitted work another session left there can
  be lost. Pre-existing behaviour, not introduced by #312, and unchanged here.

## [0.21.0] — 2026-08-19

### Added

- **`state resolve`** settles an operation stuck in a non-terminal state
  (#313). One such record blocks every later change on its device, and nothing
  in the tool surface could clear it, so the only recovery was editing
  `changeset-state.json` by hand. Wraps `mecmcp_changeset::resolve_persisted_
  operation` and takes the same exact `RESOLVED <id> AS COMMITTED|DISCARDED`
  confirmation rust-panosmcp uses. **Stop the service first** — the running
  server holds its state in memory and will overwrite the file.

- **The Junos commit comment names the approver and the change set** (#307):
  `approved-by=<token> change-set=<16-hex prefix>`. Under two-person control the
  device's own history previously could not say who authorised a change. Both
  segments are omitted rather than emitted empty, so a lab-mode apply names
  nobody. Verified on hardware, including Junos's 512-character comment ceiling
  (513 is refused with `Length 513 is not within range (1..512)`).

### Fixed

- **A change set whose apply fails past staging no longer reads `applied`**
  (#309). It reads `failed`, so a drift check or audit is no longer told a
  change landed that the device rejected.

  **This does not unwedge the device.** The cleanup's discard is still refused
  by the configuration lock the staged session holds, so the operation is left
  non-terminal and blocks every later apply on that device. That is **#312**,
  which remains open. `state resolve` above is the supported way out until it
  lands.

- `h2` moves to 0.4.16 for RUSTSEC-2026-0258 (unbounded empty DATA frames in
  hyper's HTTP/2 layer).

### Changed — breaking

- **`--allow-insecure-bind` and `--allowed-origin` now reach the transport**
  (35fbc28). Both were parsed and shown in `--help`, and neither was ever
  passed to `HttpTransportConfig`. They are active as of this release, which
  changes behaviour for anyone already supplying them:

  - a plaintext off-loopback listener now *needs* `--allow-insecure-bind`; under
    mecmcp 0.9.x the transport refuses one without that acknowledgement. This
    took LXC 950 down during the 0.20.0 upgrade — it crash-looped on a flag its
    unit had supplied since the day it was built.
  - `--allowed-origin` values now actually govern browser Origin admission,
    where previously an empty list was passed regardless of what was
    configured.

  Check any unit that passes either flag before upgrading, and read the values
  as meaningful rather than decorative.

### Changed

- **`mecmcp` moves from 0.9.1 to 0.12.0.**

  **Upgrading is one-way for change-set state that holds a waiver.** v0.9.1
  reads on-disk state versions 1 and 2; v0.12.0 reads 1, 2 and 3, so an existing
  file is accepted as it stands and nothing in flight is orphaned. But
  `read_state` re-signs legacy waiver digests with the v3 scheme, and the next
  write stamps the file version 3 — which v0.9.1 refuses as unsupported. A
  `--lab-mode` server's approvals all carry waivers.

  **Rolling back to 0.20.0 therefore means restoring the state file or the
  guest snapshot, not just swapping the binary.** Do not assume the file is
  untouched because the server answered no requests: `ChangesetCoordinator::
  load` performs restart recovery on startup and persists immediately when it
  finds an operation in `Staging`, `Staged`, `Validating` or `Committing`, or a
  change set in `Applying`. With a waiver anywhere in the file, that startup
  write is already the v3 stamp. **Snapshot before installing**, and treat the
  state file as migrated the moment 0.21.0 starts.

## [0.20.0] — 2026-08-13

### Fixed

- **Commit comments now include `request.id=<uuid>` for provenance join** (#300).
  The audit trail previously could not join audit events to device commits
  because the production apply path was generating commit comments without
  `request.id`. `mecmcp_audit::device_log::parse_device_log` relies on that id
  to correlate server-side audit records with device-native commit log entries,
  so its absence broke provenance chain reconstruction — an audit trail showed
  that *someone* committed, but not what the server claimed to do. Fixed by
  threading the request id from the attribution through to `format_attribution`,
  which now appends `request.id=<uuid>` to every commit comment. Verified on
  hardware: the full untruncated id now stamps into the device's commit log and
  the join succeeds.

### Changed

- **`mecmcp` moves from 0.8.7 to 0.9.1**, which brings breaking transport-layer
  changes. Five API changes: `HttpTransportConfig::new().with_bearer()` becomes
  `authenticated()` for token-store paths, and `unauthenticated()` takes
  `NoAuthAcknowledgement`; `build_http_router` returns `ServePlan` instead of
  `(Router, HttpShutdown)`; `serve_router` no longer takes a separate shutdown
  handle (it travels inside the plan); `CallerCtx` now carries `request_id` as
  a UUID; and mecmcp 0.9.0 enforces `--allowed-origin` for off-loopback binds
  where it was previously decorative, so the Docker Compose example now passes
  `--allowed-origin http://127.0.0.1:30030`.

  The shipped systemd unit binds `127.0.0.1:30030` and remains exempt from the
  new Origin allowlist requirement — loopback binds are always exempt.

- **`rust-junosmcp/tests/http_host_validation.rs` migrated off
  `router.oneshot()`.** These tests drove the Router directly to exercise Host
  header validation, but `ServePlan` deliberately does not expose it (mecmcp
  migration brief: "There is deliberately NO way to extract the Router"). The
  suite was rewritten against the served surface instead: seven `oneshot()`
  call sites became one, and the file grew from seven tests to eight. It was
  not deleted — it is still present and still runs.

## [0.19.0] — 2026-08-11

### Added

- **`--web-enabled-approver` exposes staged actions in status responses** (#297).
  When this CLI flag is set (default false), `get_junos_change_set_status`
  includes the `actions` array — the stored configuration changes — in its
  response. This is for the mechub approval webapp, which needs to show a
  reviewer what they are approving. Off by default because it exposes staged
  config content to any caller with status scope, where previously the status
  endpoint revealed only the change set's lifecycle state and metadata. The
  scope checks (`check_tool_scope` / `check_router_scope`) are unchanged and
  still enforced before the coordinator call. Uses `changeset::
  get_change_set_status_with_actions` from mecmcp 0.8.6. Verified: with the flag
  off, the response has no `actions` key; with it on, the response includes
  `actions` matching what was staged.

- **Configuration authority tracking for Junos devices** (#296). The inventory
  now accepts an optional `config_authority` field on each device, with values
  `local`, `mist`, `security-director-cloud`, `security-director-onprem`, or
  `unknown` (the default). This fixes the audit trail defect where writes to
  plane-owned devices claim durability they cannot support: an apply to a Mist-
  or SDC-owned device writes successfully, the audit says `applied`, and the
  owning plane silently overwrites it at its next push, with nothing marking the
  reversion. The authority is now recorded in the audit event, and the tool
  result includes a `config_authority_warning` when applying changes to a
  plane-owned device, alerting the caller that the change may be overwritten.
  Read tools do not warn — the concern is durability, not visibility. Existing
  `devices.json` files load unchanged; the field is optional and defaults to
  `unknown`, so the LXC 950 production inventory upgrades without changes.

- **Documentation for the `rust-junosmcp-srx-core` public API** (#295). The
  library crate now has crate-level docs explaining what it exports and how to
  use it.

### Changed

- **`mecmcp` pins to released tag v0.8.7.** All ten `mecmcp-*` crates are
  de-pinned from the temporary branch ref used during #297 and now point to the
  published tag.

## [0.18.0] — 2026-08-10

### Changed — breaking

- **`mecmcp` moves to 0.7.3**, which owns the HTTP transport assembly. The
  hand-rolled router construction here is replaced by
  `HttpTransportConfig` / `build_streamable_http_router` / `serve_router`.
  `--allowed-host` and `--allowed-origin` behaviour is unchanged, including the
  deliberate asymmetry that a portless `--allowed-host` entry matches any port
  (which is what LXC 609 relies on) while a portless `--allowed-origin` matches
  only a portless browser Origin.

- **`/metrics` is now behind the Host allowlist.** It was previously reachable
  with any `Host` header. Anything scraping it with a non-allowlisted Host now
  gets **421** and must be given a Host the server accepts, or added via
  `--allowed-host`. This is deliberate: `/metrics` is the only unauthenticated
  route, which makes it the most attractive DNS-rebinding target
  (RUSTSEC-2026-0189) — an attacker-controlled page could otherwise point a
  victim's browser at a loopback-bound server and read the scrape. It needs no
  bearer token, exactly as before.

- **A disallowed `Host` now returns 421, not 403.** Host is validated in
  mecmcp's own middleware rather than by rmcp's built-in allowlist. 421
  Misdirected Request is the accurate code for "this authority is not served
  here"; 403 asserts the caller is unauthorized, which is a different claim.
  The request is refused either way — only the code moved.

- **An oversized request without a valid bearer now returns 401, not 413.**
  Authentication runs before the body limit, so an unauthenticated caller is
  turned away before its body is measured. An authenticated oversized request
  still gets 413.

### Fixed

- **An attributed commit no longer costs a reconnect (#322).** #316 had to close
  a session under its own lock after `commit_with_comment`, because rustez could
  not clear rustnetconf's candidate-dirty flag through the raw `rpc()` path — so
  every apply ended by tearing down its SSH session. rustez 0.14.2 commits
  through the typed `commit_configuration_with_log`, which clears the flag on
  success, so such a session pools normally again.

  No manifest change: the pin already said `0.14`. Every `touched_candidate`
  guard stays — a failed apply, a staged session that never committed, and a
  rollback load all still leave the candidate dirty and must close under the
  lock. The flag simply reports `false` in the case that used to dominate.

- **A commit whose reply never arrives is no longer recorded as a rejection
  (#322).** rustnetconf 0.14.3 raises `RpcError::CommitUnknown` when the
  connection drops after `<commit>` is sent, instead of a generic transport
  error. The classifier had no arm for it and its text backstop did not match
  "connection lost", so it fell through to *known rejection*: the apply was
  recorded as failed and cleanup ran against a device that may already hold the
  change. It is now classified as uncertainty, which is what leaves the
  operation indeterminate for an operator to reconcile.

  Measured on `vsrx-ci` via 611: an apply now records `commit succeeded` rather
  than `session closed to release the candidate lock, release not acknowledged
  by the device`, which is the acknowledged-unlock path, and no
  candidate-dirty-at-Drop warning fires.

- **Client-asserted provenance is no longer permanently empty (#267).**
  `client_name`, `model_id` and `session_id` were structurally present in every
  audit record and never populated, so a consumer could not tell "no client
  asserted one" from "this server never asks". Taking mecmcp 0.13.0 supplies the
  capture: a client that sends `_meta.mecmcp/provenance` now has those fields
  recorded, and `clientInfo.name` populates `client_name` on its own.

  Verified on `vsrx-ci` via 611. A call carrying provenance records
  `model_id=claude-opus-5 session_id=probe-session-267
  client_name=provenance-probe client_version=9.9 client_call_id=toolu_probe267`.
  These remain **client-asserted and unverifiable** — `token_verified_fields`
  is what separates them from the token-bound subset, and it is unchanged.

- **A refused lock no longer destroys an operator's uncommitted work
  (#316).** Junos's candidate datastore is shared, and rustnetconf closed every
  session with an unconditional `<discard-changes/>` — so a session that only
  read, or whose `<lock>` was refused *because* someone had uncommitted work,
  threw away exactly that work. Silently: no error, no log. Fixed upstream in
  rustnetconf 0.14.0 / rustez 0.14.0, which discard only when the session itself
  dirtied the candidate; this release takes those pins. Verified on `vsrx-ci`
  standalone: `commit_check_config`, `rollback_config` preview and
  `apply_junos_change_set` all previously destroyed out-of-band edits and now
  preserve them, while still being correctly refused.

- **Sessions that touched the candidate are no longer pooled (#316).**
  `commit_with_comment` commits through rustez's raw `rpc()` path, which cannot
  clear the new candidate-dirty flag, so such a session carries an armed
  `<discard-changes/>` into its eventual close. Harmless for its own changes —
  but the pool may hold it long past the unlock, and the discard then fires
  against whatever the shared candidate holds by that point. Any session with a
  dirty candidate is now closed rather than returned to the pool, at the cost of
  one reconnect after each attributed commit.

- **`systemctl restart` drains in-flight calls instead of dropping them.** This
  needed three mecmcp releases: 0.7.0's shutdown signal could never fire, and
  0.7.1 terminated rmcp's sessions at the instant shutdown began — and an MCP
  response travels back over its session's SSE stream, so a call in flight lost
  the reply it was about to send. Fixed in 0.7.2. Note the trade: while any SSE
  stream is open, shutdown takes the full drain timeout (10s here, against the
  unit's `TimeoutStopSec`).

## [0.17.0] — 2026-08-07

Hardening release. The server no longer spawns any external process, and the
container image is distroless as a direct result.

### Changed — breaking

- **`mecmcp` moves to 0.6.1**, which brings the bearer-boundary extraction.
  `ScopePreflight::check` now takes `CallerScopes<'_>` instead of `&CallerCtx`;
  `apply_rate_limit` is split into `apply_ip_rate_limit` (outside the boundary,
  so unauthenticated requests are still metered) and `apply_token_rate_limit`;
  `concurrency_middleware` is split into token and target halves. Consumers of
  this crate's HTTP transport wiring see these; the tool surface is unchanged.
- **The container image no longer has a shell, `apt`, or `openssh-client`**
  (#201). Anything that shelled into the image — including custom healthchecks
  or debugging entrypoints — must move to a helper image. `HEALTHCHECK` is
  removed, since `kill -0 1` needed a shell; supervise the process from the
  orchestrator instead.

### Added

- **`host_key_revoked`** — a new stable error code, distinct from
  `host_key_mismatch`. A key marked `@revoked` in `known_hosts` is now refused
  rather than accepted; a mismatch means the device key changed and warrants
  investigation, while a revocation means an operator already judged that key
  compromised. Previously the underlying verifier ignored marker lines entirely.

### Changed

- **`transfer_file` and `fetch_file` no longer spawn `scp`** (#212). They use
  `mecmcp-scp`'s native SCP1 client over the SSH exec channel — the same wire
  protocol `scp -O` was forcing, because Junos disables SFTP-over-SSH.
  `grep -rn "Command::new" rust-junosmcp*/src/` now returns nothing.
  Verified on hardware: a transfer to a real SRX succeeded with
  `PATH=/nonexistent`, so `scp` was unreachable throughout.
  The error taxonomy is unchanged — `unsupported_auth`, `insufficient_disk`,
  `verify_mismatch`, `host_key_mismatch` and `connect_timeout` are still
  produced for the same conditions, and host-key checking stays strict by
  default.
- **Runtime image is `gcr.io/distroless/cc-debian13:nonroot`**, digest-pinned
  (#201). The builder version now derives from `rust-toolchain.toml` rather than
  a separately maintained literal, and the compose example runs `read_only: true`
  with explicit writable mounts.
- `russh` 0.62.4 → 0.62.5, which carries **CVE-2026-68930**, a channel-ID
  validation bypass (#271).

### Fixed

- **`collect_jtac_support_bundle` no longer panics on non-ASCII log content**
  (#273). `redact_log_line` sliced a `&str` at a byte offset that was not
  guaranteed to be a char boundary, so a log line where a near-miss of a
  redaction keyword was followed by a multi-byte character aborted the
  collection — in the redaction pass, on device-controlled data, which is
  exactly the input class it exists to handle.

### Internal

- `clippy::unwrap_used` raised to `deny`; the shipping-code count was already
  zero once measured with clippy rather than grep (#193). The integration test
  harness now honours `CARGO_TARGET_DIR`.

## [0.16.0] — 2026-08-05

### Changed — breaking

- **rmcp 2 → 3.1.1, on mecmcp 0.5.0.** rmcp 3 implements the 2026-07-28 MCP
  revision. This is not a cutover: `legacy_session_mode` defaults to `true`, so
  the `initialize` handshake and `Mcp-Session-Id` remain the default path and
  clients declaring `2026-07-28` are served statelessly per request. Both
  protocols are served at once, so existing clients are unaffected.

  Source changes were small: `rmcp::model::Meta` became `RequestMetaObject`, and
  `ServerHandler::call_tool` now returns `CallToolResponse` — an enum whose other
  variants are the SEP-2322 input-required round-trip and the SEP-2663 task
  handle. Every tool here completes in one call, so the response is always
  `Complete`; the match is explicit rather than an unwrap so that adding a
  non-completing tool later cannot silently skip the audit record on the
  argument-rejection path.

### Fixed

- **rmcp 3's own 4 MiB request-body cap no longer silently overrides
  `--max-request-body-bytes`.** rmcp 3 added `max_request_body_bytes` to
  `StreamableHttpServerConfig`, enforced *inside* rmcp after this server's
  `apply_body_limit` layer has already accepted the request. On the previous
  `StreamableHttpServerConfig::default()` every request between 4 MiB and the
  configured limit (10 MiB by default) would have failed with a 413 attributable
  to no setting the operator could see. `load_and_commit_config` carries whole
  device configurations, which is exactly the payload that gets large. The
  config now comes from `mecmcp_transport::streamable_http_server_config`, which
  derives the cap from `LimitsConfig`.

## [0.15.3] — 2026-08-05

### Removed — breaking

- **`--disable-host-check` is gone, and is now rejected at startup.** The flag
  turned the streamable-http `Host` allowlist off entirely, reintroducing
  RUSTSEC-2026-0189. Its documented framing — "only set this if you understand
  the tradeoff" — had the risk backwards. DNS rebinding *targets* loopback-bound
  services: a browser resolves an attacker-controlled name to `127.0.0.1` and
  reaches the server with a foreign `Host`, and the allowlist is the only thing
  that refuses it. So the flag was most dangerous in the setup that looked most
  harmless, and a deployment that used it for convenience on loopback was the
  exposed one. rustpanosmcp never had an equivalent escape hatch.

  The flag is *rejected* rather than ignored, so a unit file that still carries
  it fails loudly at startup instead of running unprotected. Anyone relying on it
  should name the authority their clients actually send with `--allowed-host`,
  which is repeatable and precise. The deployed LXC 609 override already does
  this (`--allowed-host 192.0.2.10`) and is unaffected.

## [0.15.1] — 2026-07-31

### Fixed

- **A call the server refuses is now recorded.** Every handler opened its audit
  scope as its first statement, but arguments are deserialized *before* the
  handler body runs — so a call rejected for an unrecognised argument returned
  an error to the caller having recorded nothing: no audit event, nothing in the
  journal, nothing in the audit file.

  That gap was created by 0.15.0 mattering more than it used to. Making
  unrecognised arguments an error rather than a silent fallback to broader
  behaviour was the point of that release, but it means an integration can start
  failing against it with no server-side trace — so "zero errors" read as
  "nobody was refused" when it meant "refusals are not recorded".

  Refusals now emit an audit record with `error_kind=dispatch_rejected`, naming
  the tool and carrying the message that identifies the offending field. Calls
  to a tool that does not exist are recorded the same way. Arguments are not
  recorded — they are caller-controlled and may carry configuration payloads —
  and an unrecognised tool name is recorded as `unknown_tool` rather than
  echoed. (#268)

## [0.15.0] — 2026-07-31

### Added

- **Progress notifications for every tool call.** A device operation that runs
  longer than 30s now reports that it is still alive, once every 30s, naming the
  tool, the device, and how long it has been going.

  Without them a client cannot tell "the server is patiently waiting on a
  device" from "the server is dead", so it applies an idle timeout and gives up.
  The operator then sees `tool "load_and_commit_config" sent no response or
  progress for 300s` — the least informative message available — while the
  server holds a precise diagnosis (`primary=operation timed out after 360s;
  rollback=cleanup timed out after 30s; unlock=cleanup timed out after 30s`)
  that only ever reaches the audit log. (#257)

  Emitted only when the client supplies a `progressToken`, as MCP requires.
  Clients that do not ask are unaffected.

- **`--cleanup-timeout-secs`** sets the budget for each post-operation cleanup
  phase on a device — rollback, unlock, session close — previously a hardcoded
  30s. The worst case for one configuration call is `timeout + 2 × this`, which
  the server now states at startup rather than leaving an operator to derive it:
  with the defaults, a stalled 360s call can run 420s, against the 300s idle
  timeout typical of MCP clients. Progress notifications keep a client attached
  across that window; lowering this is the remedy for a client that ignores
  them. (#257)

  The 360s default operation timeout is unchanged. It was long enough to outlive
  any default client only because nothing reported progress; that is now fixed,
  and shortening the budget a real commit may legitimately need would trade one
  failure mode for another.

- **`get_junos_config` honours `max_lines`, `max_bytes`, and `tail`**, the same
  output caps `execute_junos_command` already supported. A caller that needs a
  bounded response can now get one. (#253)

### Changed

- **Dependencies: mecmcp 0.3.8** (from `changeset-v0.3.7`), which brings a
  hardened file reader, a hardened change-set state read, and two overflow
  fixes it exposed.

  **`devices.json` and `tokens.json` must be mode 0600.** The hardened reader
  refuses a group- or world-accessible file, and the server exits at startup
  rather than running with credentials exposed. `packaging/lxc/install.sh`
  already sets both to 0600, so installer-managed deployments need no action;
  a hand-managed one needs `chmod 600` on both before upgrading.

- **`collect_jtac_support_bundle` no longer spawns `tar`.** The archive is built
  in-process with the `tar` and `flate2` crates.

  This is a process holding bearer credentials for a firewall fleet: every
  `Command::new` is an execution boundary, and the image has to carry the
  utilities purely so one tool works — exactly the pivot an attacker wants after
  an RCE. Both security properties of the old invocation are kept and now have
  tests naming them: the archive pathname is never handed to the archiver, and a
  pre-existing file or symlink at the destination is refused rather than
  followed. One property is new — `tar-rs` follows symlinks by default where GNU
  tar does not, so it is explicitly turned off; otherwise a symlink under the
  staging directory would pull its target's contents into the bundle. (#212)

  Tarball bytes are not identical to the previous output: gzip settings and tar
  metadata differ between implementations. The contents and layout are the same.

  `transfer_file` and `fetch_file` still spawn `scp`, so the container image
  still needs `openssh-client` and distroless (#201) stays blocked.

- **Tool schemas describe the argument aliases the server accepts.** `schemars`
  cannot see `#[serde(alias = ...)]`, so closing the schemas would otherwise
  have advertised long-accepted spellings — `router`, `router_name`, `routers`,
  `max_concurrent_routers` — as invalid to any client that validates before
  calling. Each alias now appears as a property, and a required field with
  aliases is published as an `anyOf` over its accepted names rather than a bare
  `required` entry naming only the canonical one.

  `execute_junos_command_batch`'s device targets are also published as
  string-or-array, matching the documented single-device form the deserializer
  has always accepted. Because serde maps every spelling onto one field and
  rejects a second as a duplicate, the schemas also say that only one spelling
  may be supplied.

### Fixed

- **Tool arguments the server does not recognise are now an error rather than
  silently dropped.** Every tool argument type carries
  `#[serde(deny_unknown_fields)]`, and the advertised JSON schemas say so with
  `additionalProperties: false`, so a client can catch the mistake before it
  makes the call.

  This is a security fix, not tidiness. A caller asking `get_junos_config` for
  one stanza under the plausible-but-wrong name `filter` had the field dropped
  and received the device's **entire configuration** — including
  `system root-authentication`'s password hash and SSH keys — in a response
  shaped exactly like a successful narrow query. `filter` is the obvious name
  for that parameter, so it is now an accepted alias for `config_path` as well.
  Wherever a dropped argument means "do the broader thing", ignoring it silently
  hands the caller more than it asked for. (#253)

- **`create_junos_change_set` rejects malformed actions instead of approving
  them.** An action with neither `payload` nor `rollback_source` — or with both
  — is now refused before anything is persisted, digested, or approved. The
  error names the offending index and the field the caller got wrong.

  Previously such an action was stored, digested, and (under `--lab-mode`)
  approved, and failed only at apply. That recorded an approval over an empty
  plan in the audit trail and occupied the principal's one pending change-set
  slot on the device until someone thought to call apply and watch it fail. The
  apply-time check remains as defence in depth; it is no longer reachable
  through the public API. (#254)

- **Output caps are now exact.** `max_lines` and `max_bytes` counted only the
  content and then added the truncation marker on top, so a response could
  exceed the cap the caller asked for — by a line, or by however many bytes the
  marker ran to. The marker is now inside the budget, and the byte cap is
  applied last so that setting both caps cannot push the result back over the
  byte budget.

  A cap too small to hold the marker is refused up front rather than silently
  overshot: `max_lines` must be at least 1 and `max_bytes` at least 64, both now
  advertised as schema minima so a client sees the limit before it calls.
  Affects `execute_junos_command`, `execute_junos_pfe_command`, and
  `execute_junos_command_batch` as well as `get_junos_config`.

  With `tail: true` every cap now agrees on which end to keep: the byte cap
  trims the oldest bytes rather than the newest, and the line-truncation marker
  is printed above the retained tail instead of below it.

## [0.14.0] — 2026-07-29

### Added

- **`--lab-mode` for single-operator environments.** Change sets are approved on
  creation, so one engineer can plan and apply without a second principal.
  Previously a lone operator could create a change set and never move it past
  `Planned` — change sets were unusable in a one-person lab.

  No approver is invented. A waived change set reports `approver: null`
  alongside `approval_waiver: "lab-mode"`, so it stays distinguishable from one
  a second person actually reviewed. The server warns at startup that
  two-person control is relaxed.

  The flow is unchanged from production: plan, then apply. There is no waive
  tool and no extra argument — starting the service with the flag is the
  decision.

### Changed

- **Change-set flags renamed to match every other mecmcp server.** An operator
  who learns one server should not have to relearn the next:

  | before | after |
  |---|---|
  | `--changeset-state-file` | `--state-file` |
  | `--changeset-approval-timeout-secs` | `--approval-timeout-secs` |

  **The old spellings still work** as aliases, so existing units and scripts
  keep running. PAN-OS gains the same three flags in its 0.7.0.

## [0.13.1] — 2026-07-29

### Fixed

- **Confirmed commit is now reachable.** 0.13.0 shipped the implementation but
  no way to ask for it, and its changelog said otherwise. `apply` takes
  `confirm_timeout_mins` and `confirm_junos_change_set` cancels the rollback.

- **`confirm_junos_change_set` is a write tool.** It was registered in the tool
  and scope lists but not the write-tool registry, so a token holding a
  wildcard `*` tool scope could have called it without being granted it by
  name — confirming another principal's provisional commit. Wildcard tokens
  now require it explicitly, like every other change-set mutation.

## [0.13.0] — 2026-07-29

### Added

- **Confirmed commit.** `apply_junos_change_set` takes an optional
  `confirm_timeout_mins`: the device commits and schedules an automatic
  rollback unless the new `confirm_junos_change_set` tool is called before the
  deadline, which the apply response returns as `rollback_deadline_unix`.
  Previously any request for a confirm window was refused outright.

  Confirming is the **owner's** call, not the approver's. Authorization already
  happened at approval and `apply` executed it; confirming only stops the
  safety timer on a change that is already live. Requiring the approver would
  mean changes silently reverting because the reviewer had gone home.

  Junos schedules the rollback in whole minutes, so a window that is not a
  whole number of minutes — or is under one minute — is refused rather than
  rounded. Being told a deadline the device will not honour is worse than
  being told no. Verified on vSRX 24.4R1.9, including that the change survives
  the session that made it and can be confirmed from a different one.

- **`token add` accepts provenance flags** — `--provider`, `--provider-tier`,
  `--on-behalf-of`, `--actor-type`. These were silently discarded, so every
  commit this server made was attributed on the device as
  `(unknown) on-behalf-of=self`. Commit comments now carry the real principal.

- **`get_junos_candidate_fingerprint`** exposes the candidate fingerprint the
  change-set tools compare against.

### Changed

- **The device configuration lock is now held across the fingerprint check and
  staging.** Another session — an operator at the CLI, a second MCP process —
  can no longer move the candidate in the window between the two. Previously
  the lock was taken inside staging, after the check it was meant to protect.

- **A batch call naming a router your token may not access is refused
  outright**, instead of running the routers you are allowed and reporting an
  error row for the rest. Returns 403 `insufficient_scope`; nothing executes.
  Unreachable devices are unchanged and still produce per-router error rows.
  See the entry under Unreleased for the full reasoning (#220).

- Commit comments omit the `model=` field when no model was asserted, rather
  than emitting a dangling `model=`.

### Fixed

- Token files keep their owner across `token add`/`rotate`/`revoke`. Minting a
  token as root previously left `tokens.json` root-owned and the service
  refused to start with a bare permission error.

### Changed

- **A batch call naming a router your token may not access is now refused
  outright, instead of running the routers you *are* allowed and reporting an
  error row for the rest.** The call returns HTTP 403 `insufficient_scope` and
  nothing executes on any device.

  This affects `execute_junos_command_batch` and the other batch tools. If you
  send fifty routers and one is outside your token's scope, you get no results
  at all — previously you got forty-nine results and one error row. Split the
  request, or widen the token.

  Unreachable devices are unchanged: those still come back as per-router error
  rows inside a 200, and the rest of the batch still runs. The distinction is
  deliberate — a device being down is a runtime failure, while asking for a
  device you may not touch is an authorization failure, and partially honouring
  an unauthorized request is the thing worth avoiding.

  The behaviour arrived with the HTTP scope preflight and went undocumented at
  the time (#220).

## [0.12.0] — 2026-07-27

### Changed

- **Policy, inventory, and device locking now come from the shared `mecmcp-*`
  crates** (`phase4-v0.1.7`). No user-visible change: `devices.json` parses
  exactly as before — flat map, `_blocklist_defaults`, and all — every CLI flag
  keeps its spelling, and SIGHUP hot reload is unaffected.

  The local `policy.rs`, `device_lease.rs`, and `cancel.rs` are gone and
  `inventory.rs` is reduced to Junos-specific validation over the shared loader.
  Device locking keeps its cross-process semantics: a kernel file lock held by
  an open descriptor, released on process death, so a long-running
  `upgrade_junos` still cannot be raced by a second process. It is not a
  semaphore.

  Test coverage for the extracted modules moved upstream and grew — 10 test
  functions left this repo, 18 cover the same ground in `mecmcp-device`.


### Added

- **`--devices` is the new spelling for token device scopes.** `token add` and
  `token rotate` now take `--devices`; `--routers` continues to work as a hidden
  alias, so existing runbooks and scripts need no change. The term is universal
  across the fleet — PAN-OS firewalls and the Proxmox and UniFi servers being
  built on the same foundation are none of them routers — and this repo was
  already inconsistent: v0.11.0 renamed the *audit* fields `routers` →
  `devices`, so events used the new term while the CLI still said the old one.
  (mecmcp #29)

### Security

- **`unsafe_code` raised from `deny` to `forbid`.** Unlike `deny`, `forbid`
  cannot be overridden by a local `#[allow]`, so unsafe code cannot re-enter
  this server through a future change. No `unsafe` remains anywhere in the
  workspace.

  Reaching it took two steps across two phases. `rust-junosmcp-auth`'s
  hand-rolled `write_volatile` secret zeroing was replaced with the `zeroize`
  crate, and SIGHUP signalling moved into the shared `mecmcp-runtime` crate,
  which reaches the syscall through `rustix` rather than `libc::kill`. That
  removed the last two `#[allow(unsafe_code)]` sites. (mecmcp #35)


### Changed

- **BREAKING for batch callers — a scope violation now refuses the whole
  batch.** Scope preflight (#219) rejects out-of-scope requests at the
  middleware layer, before dispatch. Previously a batch tool such as
  `execute_junos_command_batch` called with `routers: ["r1","r2"]` by a token
  scoped only to `r1` returned HTTP 200 with a per-router error row for `r2`
  and a real result for `r1`. It now returns **HTTP 403 `insufficient_scope`
  and executes nothing** — at fifty routers with one out of scope, that is
  forty-nine results lost.

  This is deliberate: partially executing a request that names a device the
  caller may not touch is the thing worth avoiding. But it is a response-shape
  change, so a client that parsed per-row errors must handle a 403.

  Note the resulting asymmetry — per-row error rows still work for
  **unreachable** devices. Authorization fails whole; runtime failures do not.
  Tracked in #220, where the alternative of collecting violations and letting
  the handler emit rows is still open.


## [0.11.1] — 2026-07-26

### Changed

- **BREAKING if you terminate TLS — the private key must be mode `0600` and
  owned by the service user.** TLS loading moved to the shared
  `mecmcp-transport` crate, which uses the hardened loader ported from
  `rustpanosmcp`: `O_NOFOLLOW` on open (defeating a symlink swap), a size cap,
  an owner check against the effective uid or root, and a mode check. The
  previous loader performed none of these.

  A deployment whose `--tls-key` file is group- or world-readable **will not
  start**, failing with:

  ```
  private key mode 0644 permits group/other access; use chmod 0600 '<path>'
  ```

  Remedy before upgrading:

  ```bash
  chmod 0600 /path/to/key.pem
  chown <service-user> /path/to/key.pem
  ```

  Servers that do not pass `--tls-cert`/`--tls-key` are unaffected. This
  requirement shipped in 0.11.1 but was omitted from the original release
  notes; the published notes have since been corrected.

### Fixed

- **#197, #208, #209 — First-install service would not start.** The v0.11.0
  installer created a non-bootable `devices.json` referencing a placeholder
  SSH key path that does not exist, causing the service to crash-loop on a
  fresh install with `Error: loading /etc/jmcp/devices.json ... private key
  file not found`. The server now fails at startup with an actionable message
  naming the file when the inventory references a missing key, and the
  installer's closing message branches to stop telling operators to edit a
  file it did not create.

- **#207, #208 — Published `.sha256` checksum embedded build-machine path.**
  The v0.11.0 release asset checksum was hand-generated and embedded the build
  machine's absolute path, so `sha256sum -c` verified only on that machine.
  `scripts/package-lxc.sh` now emits the checksum itself with a bare filename.

- **#210 — `get_junos_config` command-injection and blocklist-bypass.** Added
  optional `config_path` parameter with an allowlist and policy check. Without
  both, a crafted path could inject commands or bypass the `candidate` blocklist.

### Changed

- **#211 — Container runtime base to `debian:13-slim`.** Adds
  `packaging/container/compose.example.yaml` showing how to mount the config
  and run the container.

- **#213 — `unwrap_used` cleared in shipping code.** Raised the lint to `warn`
  so new instances fail CI.

- **#214 — CI installs cargo-deny directly.** Removed dependency on the
  Docker-dependent `cargo-deny-action`.

- **#215 — Wired onto `mecmcp-transport` v0.1.6** (Phase 3a Task 8).

- **#216 — README LXC section corrected to Debian 13.** The binary requires
  `GLIBC_2.39`; Debian 12 ships 2.36 and cannot run it.

## [0.11.0] — 2026-07-25

> **Operators: this release requires action.** The audit-log field names
> changed. Update your SIEM queries, dashboards, and log filters that
> reference `routers=` or `router_count=` to use `devices=` and
> `device_count=` before or immediately after upgrading. The Prometheus
> metric name is **unchanged** — no dashboard updates needed there.

### Changed

- **BREAKING — audit-log field names changed.** Migrated to the shared
  `mecmcp-audit` crate, which brings structured agent attribution and UUID v4
  correlation IDs. Two field names changed:
  - `routers=` → `devices=`
  - `router_count=` → `device_count=`

  SIEM queries and dashboards filtering on the old field names will stop
  matching when this deploys. Update them to `devices=` and `device_count=`.

  The Prometheus metric `junosmcp_tool_duration_seconds` (and its `_bucket`
  series) is **preserved** — the shared crate was fixed to let the consumer
  supply the name. No dashboard changes needed for metrics.

- **Structured agent attribution.** The audit log now records
  `actor_type=Human|Agent`, `on_behalf_of` (the authenticated user when an
  agent acts), and `change_ref` (a session or task ID). The MCP `clientInfo`
  from the `initialize` request is not yet plumbed through, so all calls
  default to `actor_type=Human` in this release. Full agent tracking will
  arrive in a future version.

- **UUID v4 correlation IDs.** Replaced the collision-prone timestamp-based
  scheme with UUIDs. Every tool call gets a unique `correlation_id`, visible
  in the audit log and returned in the MCP response (on errors). This makes
  it safe to correlate logs even when multiple agents call the same tool at
  the same millisecond.

## [0.10.1] — 2026-07-25

> Ships the #199 fix that landed after v0.10.0 was cut. Upgrading from 0.10.0
> needs no operator action; upgrading from 0.9.x still requires the v0.10.0
> steps below.

### Changed

- **#199 — `tools/list` is filtered to the caller's tool scope.** The tool list
  advertised to an authenticated caller now contains only the tools that
  caller's token can invoke, using the same check that gates `tools/call`. A
  wildcard token sees the read-only tools and not the ten write tools; a token
  scoped to nothing sees an empty list. Previously the full surface was
  advertised to everyone, so an agent would plan around a tool, call it, and
  burn a turn on the denial. Authorization behaviour is unchanged — this makes
  the advertisement agree with the enforcement that already existed. Local
  stdio and `--allow-no-auth` loopback carry no caller context and still see
  every tool.

  A client that cached `tools/list` before a `token set-scope` keeps the stale
  view until it reconnects; the server does not emit
  `notifications/tools/list_changed`.

## [0.10.0] — 2026-07-25

> **Operators: this release requires action before upgrading.** A wildcard
> tool scope no longer grants write tools, and the token file must be mode
> `0600`. See [Upgrading to v0.10](README.md#upgrading-to-v010) for the
> two-step procedure.

### Changed

- **BREAKING — a wildcard tool scope (`"tools": ["*"]`) no longer confers
  write tools.** Granting write authority is now always an explicit, named
  decision. The ten tools excluded from the wildcard are `add_device`,
  `discard_candidate`, `load_and_commit_config`,
  `manage_appid_signature_package`, `manage_idp_security_package`,
  `reload_devices`, `render_and_apply_j2_template`, `rollback_config`,
  `transfer_file`, and `upgrade_junos`. A wildcard token still reaches every
  read-only tool, and an explicit allowlist naming a write tool still grants
  it — only the wildcard shorthand changed. Callers denied this way get the
  same `ToolNotInScope` refusal as any other out-of-scope tool.

  Scope checks only apply to authenticated HTTP callers. Local stdio and the
  `--allow-no-auth` loopback escape hatch carry no caller context and are
  unaffected.

- **BREAKING — the token file must be mode `0600`.** The server refuses to
  start on a group- or world-accessible `tokens.json`, and the error names
  the file's owner uid, its mode, the calling process's uid, and the exact
  `chmod` to run. The previous implementation did not check the mode at all.
  The LXC installer already writes `0600`, so packaged installs are
  unaffected; hand-managed and container deployments may not be.

- **A malformed token entry no longer takes authentication offline.** Device
  and tool names are validated when a token is written (`add`, `rotate`,
  `set-scope`), not when the file is loaded. Previously one stale entry —
  a device removed from the inventory, say — was fatal at load and every
  token stopped authenticating. Writes still reject unknown tool names.

### Added

- **`token set-scope` — change a token's scopes without reissuing its
  secret.** `--routers` and `--tools` are each optional; omitting one leaves
  it unchanged, and supplying neither is an error. The digest, `created_at`,
  and envelope version all survive, so existing consumers keep working. This
  is the migration path off wildcard write access: name the write tools a
  token actually needs while still on 0.9.x, then upgrade the binary.
  Accepts `--server-pid` for the usual write-then-SIGHUP reload.

  ```bash
  rust-junosmcp token set-scope --tokens-file /etc/jmcp/tokens.json \
    --name ops \
    --tools gather_device_facts,get_junos_config,load_and_commit_config
  ```

  A scope is either the literal `*` or an explicit list — the two cannot be
  mixed, so a token that needs one write tool must enumerate every tool it
  calls.

### Security

- **The auth stack no longer contains any `unsafe`.** `rust-junosmcp-auth`
  now re-exports [`mecmcp-auth`](https://github.com/mechubsec/mecmcp)
  v0.1.4 rather than carrying its own token, store, file, and caller
  modules. Three `unsafe` sites went with them — hand-rolled `write_volatile`
  secret zeroing (now `zeroize`) and `libc::getuid` (now `rustix`). One
  `unsafe` remains, the `kill(SIGHUP)` in `token_cmd.rs`, which is why
  `unsafe_code` is `deny` and not yet `forbid`.

### Internal

- Token-file field names are canonically `digest` and `devices`; `hash` and
  `routers` are accepted as aliases, so deployed 0.9.x files load unchanged.
  [`tokens-template.json`](tokens-template.json) now shows the canonical
  spelling. CLI flags are unchanged — `--routers` is still `--routers`.

  **This is one-way.** Any 0.10 token write rewrites the file in the canonical
  spelling, and 0.9.x requires `hash` — it will not load such a file. Back up
  `tokens.json` (or snapshot the host) before upgrading if you want a rollback
  path.
- Workspace moved to edition 2024 with `rust-version = 1.88`, adopted a
  shared lint posture (`unsafe_code`, `clippy::all`, `dbg_macro`, `todo`),
  and added `cargo-deny` to CI. `missing_docs` and `clippy::unwrap_used` are
  deferred, tracked in #193. No behaviour change.

## [0.9.1] — 2026-07-22

### Fixed

- **#180 — `commit_check_config` returns a real verdict on chassis clusters.**
  Picks up `rustnetconf 0.13.2`, which repairs the malformed multi-RE
  `validate` / `commit-check` reply Junos clusters send (each `<routing-engine>`
  block opened but never closed) instead of failing to parse it. Cluster
  commit-checks now return `valid` / `invalid` rather than the `check_failed`
  fallback introduced in 0.9.0, which remains as defense-in-depth. No rustEZ
  change (patch pickup).

## [0.9.0] — 2026-07-22

### Added

- **#178 — `rollback_config` tool.** A new MCP tool loads a Junos rollback
  archive (rollback N, `0`–`49`) into the candidate and optionally commits it.
  `commit=false` (default) is a safe, stateless preview — it loads the archive,
  returns the `show | compare` diff, then discards the candidate; `commit=true`
  commits, with confirmed-commit (auto-rollback after `confirm_timeout_mins`).
  Because rollback restores an already-committed archive rather than
  caller-supplied text, the config blocklist is not re-applied — the tool scope
  is the control. This brings the Junos surface to 18 tools (27 with SRX).

### Changed

- **#174 / #179 — `junos_config_diff` accepts `rollback 0`.** The version range
  widened to `0`–`49`; `0` compares the candidate against the running config
  (“what is staged right now?”). The default stays `1` (running vs previous
  commit).

- **#173 — `get_srx_security_services_status` separates check failures from
  absence.** A failed or unsupported RPC, an unparseable reply, or a missing
  RE payload is now reported as a new `error` state instead of
  `not_configured`, so a broken health check is no longer read as “this feature
  is not deployed.” Only a genuine device rpc-error tagged `not-configured`
  stays `not_configured`.

- **#180 — `commit_check_config` distinguishes “invalid” from “could not
  validate.”** The response now carries an `outcome` of `valid`, `invalid`, or
  `check_failed`. Parse/transport failures — including the malformed multi-RE
  reply Junos returns on chassis clusters — are `check_failed` (inconclusive,
  with a `hint`), never `invalid`. Classification uses structured NETCONF
  error-tag matching; no failure path can surface as `valid`.

### Fixed

- **#177 — `| match` / `| except` pipe filters are honored.** The operational
  `<command>` RPC silently drops these filters, so a filtered
  `show configuration | … | match X` returned the *entire* configuration — a
  silent false negative for audits. They are now applied server-side
  (unanchored, case-sensitive regex, with a literal fallback), alongside the
  existing `| count` / `| last` handling.

- **#176 — `discard_candidate` recovers a dirty candidate.** It no longer locks
  the candidate first (Junos rejects locking a modified candidate with
  “configuration database modified”); it issues `rollback 0` directly on the
  shared candidate — the exact dirty state its description documents recovering.

- **#175 — unknown-router vs out-of-scope is distinguishable in server logs.**
  A failed router request now logs, server-side, whether the name is absent
  from the inventory or filtered out by the caller’s token scope. The
  client-visible response is unchanged (still indistinguishable, to avoid
  leaking inventory to unauthorized callers).

### Security

- **#110 — shed prerelease crypto from the SSH transport.** Bumped
  `rustez` / `rustnetconf` to 0.13.1, pulling **russh 0.62.4**, which moves the
  RustCrypto SSH stack (ed25519-dalek, curve25519-dalek, elliptic-curve, ecdsa,
  p256/p384/p521, ssh-cipher/-encoding) from prerelease (`-rc`) to stable
  released crates. Prerelease crypto crates in the lock drop from 13 to 3
  (residual `argon2` / `blake2` / `ssh-key`, gated on upstream `ssh-key 0.7`
  stabilizing). Also clears the transitively-yanked `aes 0.9.0`.

## [0.8.0] — 2026-07-16

### Added

- **#150 - optional per-token request-rate limiting.** The streamable-HTTP
  endpoint can enforce a continuously refilled token bucket for each exact
  authenticated token name using configurable whole-number RPS and burst
  knobs. The limiter is disabled by default; exhaustion returns stable `429`
  JSON with `Retry-After`, runs before existing concurrency/session gates, and
  exports the bounded `token_rate` limit metric without caller labels.

- **#153 - native journald audit sink.** The server can opt into direct,
  structured journald fan-out with `--audit-journald`; only `target="audit"`
  events are routed, fields use a stable `AUDIT_` namespace, and an unavailable
  journal fails startup instead of silently dropping the configured sink.

- **#149 - Prometheus HTTP metrics.** Streamable HTTP can now expose an
  opt-in, unauthenticated `/metrics` route with bounded-label active-session,
  resource-limit, tool-duration, and reaper metrics. The route shares the
  configured listener/TLS but bypasses MCP auth and limits, so deployments must
  protect it with network controls.

- **#148 - per-token MCP session caps.** Streamable HTTP now limits each exact
  bearer-token name to 16 live sessions by default (`0` disables), with atomic
  initialize admission, stable `token_session_cap` 503 responses, token isolation,
  and capacity returned on close or reap.

- **#147 - per-router HTTP concurrency limits.** The streamable-HTTP endpoint
  now caps concurrent work per exact router name at 4 by default (`0` disables),
  with immediate `503` + `Retry-After: 1` load shedding. Multi-router calls hold
  one slot per unique target, and destructive calls count once while waiting for
  or holding the existing cross-process device lease.

### Changed

- **#163 - one Junos and SRX server.** `rust-junosmcp` now registers the
  complete 26-tool Junos/SRX surface on one MCP endpoint. The default feature
  set includes `tls` and `srx`; Junos-only builds remain available with
  `--no-default-features` (or `--no-default-features --features tls`).
- The SRX workflow crate is now `rust-junosmcp-srx-core`, HTTP resource limits
  live in `rust-junosmcp-core`, and every surviving workspace package is
  version `0.8.0`.
- Runtime configuration uses one canonical `JMCP_*` environment namespace.
  Package upgrades remove the retired executable, service unit, and enabled
  service link while preserving existing support bundles below
  `/var/lib/jmcp/srx-staging/bundles`.

### Deprecated

- Existing `JMCP_SRX_*` environment names are accepted as fallbacks for the
  `0.8.0` release only and emit migration warnings. Explicit command-line or
  canonical `JMCP_*` values take precedence. `JMCP_SRX_HTTP_PORT` is ignored
  because there is no second listener.

### Removed

- The standalone `rust-srxmcp` executable, `rust-srxmcp.service`, and legacy
  `127.0.0.1:30032/mcp` endpoint. Clients now register only
  `rust-junosmcp` at the configured listener (packaged default:
  `127.0.0.1:30030/mcp`).

### Fixed

- **#151 - strict global MCP session caps.** Concurrent initialize requests can
  no longer leave live sessions beyond the tracked global cap. A race loser is
  closed without cancellation leaks and receives the existing `session_cap`
  `503` with `Retry-After: 1`; ordinary session-manager failures remain `500`.
  Direct Rust users that explicitly name `LimitedSessionManager`'s associated
  error now receive `LimitedSessionManagerError<E>`.
- **#130 - router-list scope disclosure.** `get_router_list` now returns the
  intersection of the current inventory and the authenticated caller's router
  scope. Wildcard and local stdio callers retain the full sorted list; stale or
  excluded scope entries are never returned, and an empty intersection is a
  successful `[]` response without hidden-router counts or errors.
- **#127 - container SCP support.** The published Junos image now includes an
  OpenSSH client with Junos legacy `scp -O` support, runs as numeric UID/GID
  65532, and uses `/var/lib/jmcp` for writable staging, host-key, and lease
  state. Both Docker stages are digest-pinned. Server startup now fails with
  `[code=scp_dependency_unavailable]` if `scp` is missing or rejects `-O`.
  Container CI performs real upload and fetch transfers against an isolated
  OpenSSH fixture before release images can be published.

### Security

- **#129 stage 2 - cross-process destructive-operation lease.**
  `upgrade_junos` now shares a kernel-backed per-device lease with the SRX IDP
  and AppID package workflows. It re-runs device preflight under the lease and
  holds it through transfer, install, reboot verification, and post-baseline.
  Lease acquisition and every upgrade phase carry one correlation ID.

## [0.7.0] — 2026-07-03

### Added

- `commit_check_config` MCP tool (#95): non-destructive `commit check` —
  loads a candidate, returns `{success, diff, error?}`, then discards it.
  Never activates config. Own token scope (least-privilege). Tool surface 15 → 16.
- `discard_candidate` MCP tool (#107): discard uncommitted candidate changes
  (`rollback 0`) to recover a candidate left dirty ("configuration database
  modified"). Never changes the running config. Own token scope. Tool surface 16 → 17.
- `junos_config_diff` (#108): when the on-box config won't parse for the
  current mode (e.g. after a chassis-cluster change), the raw parse error now
  carries an actionable hint instead of leaving the caller blind.

### Security

- Upgrade `rmcp` 0.8.5 → 2.0.0, closing RUSTSEC-2026-0189 (DNS rebinding in the
  Streamable HTTP transport). The transport now enforces a `Host` allowlist
  (default: loopback only). New flags `--allowed-host <HOST>` (repeatable) and
  `--disable-host-check` configure it; off-loopback deployments MUST pass
  `--allowed-host` for their LAN authority or clients receive HTTP 403.
- Upgrade `quick-xml` 0.36 → 0.41 (+ `rustez` 0.12.1 / `rustnetconf` 0.12.3),
  closing RUSTSEC-2026-0194 / RUSTSEC-2026-0195 (quick-xml DoS). JTAC-bundle
  redaction now suppresses quick-xml 0.41 `GeneralRef` entity events inside
  redacted elements — a bare version bump would have leaked entity fragments of
  secrets (entities are no longer folded into `Text` events).

## [0.6.3] — 2026-06-03

### Fixed

- **#83 — `upgrade_junos` reported a successful upgrade as a failure
  across the reboot boundary.** A real upgrade installed, rebooted, and
  came up on the target version, yet the `confirm=true` call returned a
  spurious `No route to host` / `session expired: keepalive probe
  failed` error — inviting unsafe retries of an already-successful
  upgrade. Two layered fixes:
  - **Global transient-error handling in `DeviceManager`.** A canonical
    `error_is_transient()` classifier plus a `retry_transient()`
    bounded-backoff helper now back a connect-retry in `connect_fresh()`
    and a reconnect-on-stale path in the new `run_cli()`. This also
    fixes `execute_junos_command` failing on a stale pooled session
    (`SessionPool::try_checkout` gates only on a local `session_alive()`
    check, so a peer that rebooted or blipped passes checkout and then
    fails on its first RPC).
  - **Version-as-source-of-truth reboot wait.** The open-only
    `wait_for_netconf` could return `Ok` on the brief pre-reboot sshd
    window, after which the separate post-verify probe hit the genuine
    multi-minute reboot outage and raw-propagated the connect error. It
    is replaced by a single budgeted loop (`wait_for_version`) that
    polls `show version` until the parsed version equals
    `target_version`, swallowing reboot flap and treating a
    parseable-but-wrong version as "keep waiting". On budget exhaustion
    it returns `UpgradePostVerifyMismatch` (came back wrong) or
    `UpgradeRebootTimeout` (never reachable).

### Notes

- No MCP tool surface change; tool count stays at 15.
- Validated by a snapshot-protected live upgrade on vSRX-test11
  (24.4R1.9 → 25.4R1.12) returning a clean synchronous success.

## [0.6.2] — 2026-05-20

### Fixed

- **#59 — `HostKeyMismatch` classifier was inert against real Junos
  devices.** v0.6.1's `classify_scp_failure` required `exit_code == 255`
  before checking for host-key stderr substrings, but Junos requires
  `scp -O` (legacy SCP protocol), and `scp -O` surfaces SSH-layer
  failures via its wrapper-shell as `exit=1`. Real host-key tamper on
  vSRX-test10 produced `[code=scp_failed] (exit=1)` instead of the
  intended `[code=host_key_mismatch]`. The classifier now matches the
  host-key arm on stderr substring alone (`Host key verification
  failed` / `REMOTE HOST IDENTIFICATION HAS CHANGED`); the substrings
  are themselves diagnostic. The `ConnectTimeout` arm still requires
  `exit_code == 255` because its stderr substrings (`Connection timed
  out` / `No route to host`) are less specific.

### Notes

- No MCP tool surface change; tool count stays at 15.
- No public API change. The fix is a single-function refinement to
  `classify_scp_failure` plus one regression test.

## [0.6.1] — 2026-05-20

### Fixed

- **#56 — scp stderr pipe-fill deadlock.** `OpenSshScpRunner::run` and
  `::fetch` previously awaited `child.wait()` before draining the
  stdout/stderr pipes. If `scp` emitted more than the kernel pipe-buffer
  capacity (~64 KiB on Linux) to stderr before exit, the child blocked on
  `write(2)` and `wait()` hung until the MCP `timeout` cancelled the
  request. Extracted a shared `drive_scp_child` helper that drives `wait`
  and both pipe reads concurrently via `tokio::try_join!`, eliminating
  the deadlock on both `transfer_file` and `fetch_file`. Inherited from
  v0.4.0; not a new regression.
- **#57 — host-key verification failures bucketed into generic
  `ScpFailed`.** When `scp` exited 255 with `Host key verification
  failed.` (or `REMOTE HOST IDENTIFICATION HAS CHANGED`), the error
  surfaced as `[code=scp_failed]` with the raw stderr — indistinguishable
  from a permission error. Now surfaces as a new
  `[code=host_key_mismatch]` variant that names both the router and the
  `known_hosts` file the operator needs to review or refresh. The
  network-timeout heuristic (`[code=connect_timeout]`) is unchanged; the
  three-branch classifier lives in a new shared `classify_scp_failure`
  helper so the upload and download paths can't drift.

### Notes

- No MCP tool surface change; tool count stays at 15.
- Existing callers pattern-matching on `JmcpError::ScpFailed`'s stderr
  for the substring `Host key verification failed` should switch to the
  new `JmcpError::HostKeyMismatch` arm. No such callers exist in this
  repository as of v0.6.0.

## [0.6.0] — 2026-05-20

New `fetch_file` MCP tool — mirror image of `transfer_file`. Downloads a
file from a Junos device's `/var/tmp/<basename>` to the host's staging
directory, with sha256 verification, idempotent skip, per-router
serialization, and the same SSH hardening (StrictHostKeyChecking,
BatchMode, IdentitiesOnly, scrubbed scp stderr) as `transfer_file`.

Tool surface grows from 14 → 15 tools.

### Added

- **`fetch_file` MCP tool** at `tools::fetch_file::handle`. Required args:
  `router_name`, `remote_path` (basename under `/var/tmp/`). Optional:
  `local_name` (basename override under staging dir), `force` (overwrite
  divergent local file), `verify` (default `true`), `timeout` (default 600s).
  Downloads land at `<basename>.partial` first, then `std::fs::rename` to
  the canonical name only after the sha256 verify passes — a crashed or
  cancelled fetch never leaves a torn file at the staging name.
- **`ScpRunner::fetch()`** trait method with `OpenSshScpRunner` and
  `MockScpRunner` implementations.
- **`ScpFetchJob`** + **`build_scp_fetch_argv`** in
  `rust_junosmcp_core::tools::transfer_file`. Mirror of the upload variants;
  same flag posture, source/dest swapped.
- **New error variants:**
  - `JmcpError::LocalDestExistsDiffers` — local file present with different sha256;
    set `force=true` to overwrite.
  - `JmcpError::RemoteFileMissing` — device has no file at the requested path.
  - `JmcpError::FetchVerifyMismatch` — post-fetch local sha256 disagrees with
    pre-fetch remote sha256; the corrupted local file is removed.

### Changed

- `SERVER_TOOLS` tripwire test `server_tools_len_is_14` → `server_tools_len_is_15`.

### Verification

- Workspace unit + integration tests all pass; new coverage for the
  fetch_file argv builder, runner mock, scope denial, the three new
  error variants, and four `handle()` validation paths (bad remote
  basename, bad `local_name` override, strict-mode `KnownHostsMissing`,
  password-auth `UnsupportedAuth`).
- `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean.

## [0.5.9] — 2026-05-19

Cooperative cancellation for long-running destructive tools (issue #44
"Half A") + Drop-guard audit diagnostics, plus the upstream rmcp design
work for the remaining "Half B" gap.

### Added

- **`#[tool]` handlers honor `RequestContext::ct`.** Every long-running
  await point in `upgrade_junos` and `transfer_file` now races against
  the per-request `CancellationToken`. When the token fires (either
  from an explicit `notifications/cancelled` from the client, or from
  the server-side per-request timeout), the handler returns
  `JmcpError::Cancelled` rather than running to completion.
- **`rust_junosmcp_core::cancel`** — small `select_cancel{,_raw}`
  helpers using a biased select so cancellation wins ties cleanly.
- **`JmcpError::Cancelled`** with `[code=cancelled]` display, surfaced
  through the MCP error path.
- **`UpgradeOutcome::{Settled, Cancelled, Unsettled}`** drives the
  audit log line so an operator can distinguish a natural success/fail
  from a token-fired cancel from a future that ran to completion after
  the client went away.

### Investigated / documented (no functional change)

- **`docs/spikes/2026-05-19-rmcp-streamable-http-disconnect-half-b.md`**
  — design notes for the rmcp-transport-side gap (raw TCP disconnect ->
  request cancellation). Cannot be fixed downstream; requires an rmcp
  patch.
- **`docs/spikes/2026-05-19-rmcp-upstream-issue-draft.md`** — issue
  body prepared for filing against `modelcontextprotocol/rust-sdk`,
  with minimal repro, observed log evidence (281 polls past
  disconnect), code-walk root cause, and two candidate fix shapes.
- **`docs/spikes/2026-05-19-rmcp-disconnect-repro-server.log`** —
  captured server log from the live minimal repro.

### Verification

- Workspace unit + integration tests all pass; new coverage for the
  cancellation paths in `transfer_file` and `upgrade_junos`.
- `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo audit` clean (last CI run on the PR #54 head).
- Bundles PRs #50 (Drop-guard instrumentation) and #54 (Half A
  cooperative cancellation).

### Tooling

- Workspace version bumped to `0.5.9`.

## [0.5.7] — 2026-05-18

Fixes a latent bug exposed (but not introduced) by v0.5.6: every
NETCONF op command failed with `transport error: connection failed:
SSH connect to <ip>:22 failed: Unknown server key`. Root cause —
`DeviceManager` built the `rustez::Device` without ever calling
`.host_key_verification(...)`, so it inherited the rustnetconf 0.11+
default of `RejectAll` (fail-closed). v0.5.5 had the same bug; it was
just unobserved until a live op command was run after the dep bump.

### Fixed

- **NETCONF SSH host-key policy is now wired through.** `DeviceManager`
  carries a `HostKeyVerification` policy (new field) applied to every
  fresh `Device` connect. Production posture mirrors scp:
  - default → `HostKeyVerification::KnownHosts(args.known_hosts_file)`
    (strict; reuses the pre-existing `/etc/jmcp/known_hosts` file that
    was already populated for scp).
  - `--ssh-accept-new-host-keys` → `HostKeyVerification::AcceptAll`
    (lab/TOFU mode; same flag that already toggles scp behavior).
  - No new CLI surface.

### Added

- `DeviceManager::with_host_key_policy(HostKeyVerification) -> Self` —
  fluent setter for the new policy field. Default for the bare
  `::new()` / `::with_path()` constructors remains `AcceptAll` so the
  ~40 unit-test call sites keep working without plumbing.
- `rust_junosmcp_core::HostKeyVerification` re-export (from rustez 0.12)
  so the binary crate doesn't need its own rustez dep.

### Verification

- 323 unit tests pass (2 new: default-policy + setter coverage).
- `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --check` are clean.
- Live smoke test against vSRX-test10 from LXC 601 after deploy.

### Tooling

- Workspace version bumped to `0.5.7`.

## [0.5.6] — 2026-05-18

Dependency bump. `rustez 0.11.0 → 0.12.0` pulls in `rustnetconf 0.11
→ 0.12`. Additive only — no caller code in this repo changes.

### Added (upstream surface)

- **`HostKeyVerification::KnownHosts(PathBuf)`** is now re-exported by
  rustez (from `rustnetconf 0.12`). Callers may point at an OpenSSH
  `known_hosts` file instead of pinning a single fingerprint at the
  NETCONF layer. RustJunosMCP does not yet opt in to NETCONF host-key
  verification (tracked as a follow-up); scp host-key pinning via
  `known_hosts` remains strict since v0.5.2.

### Fixed (upstream)

- Stale rustez doc comments on `DeviceBuilder::host_key_verification`
  and Python `Device.__init__` corrected — they now reflect the
  `RejectAll` default introduced in `rustnetconf 0.11`.

### Verification

- `cargo audit` against the post-bump `Cargo.lock` reports **zero
  advisories** across 397 crates.
- 321 unit tests pass; `cargo clippy --workspace --all-targets --
  -D warnings` and `cargo fmt --check` are clean.

### Tooling

- Workspace version bumped to `0.5.6`.

## [0.5.5] — TBD

Dependency bump. `rustez 0.10.1 → 0.11.0` pulls in `rustnetconf 0.10
→ 0.11`. Backward-compatible at the API level — no caller code in
this repo changes.

### Security

- **rustez 0.11.0 inherits these upstream fixes** (per the rustEZ
  0.10.1 → 0.11.0 audit cycle):
  - **RZ-SEC-001** — `DeviceBuilder::host_key_verification()` is now
    available for opt-in NETCONF SSH host-key pinning. Default is
    unchanged (`AcceptAll` with warning) for backward compatibility.
    RustJunosMCP does **not** yet opt in to fingerprint pinning at
    the NETCONF layer; tracked as a follow-up. (Note: scp host-key
    pinning via `known_hosts` is already strict since v0.5.2.)
  - **RZ-SEC-002** — RUSTSEC-2023-0071 (rsa timing side-channel) is
    documented as an accepted/tracked risk in the rustEZ CI ignore
    list. No change to RustJunosMCP exposure.
  - **RZ-SEC-003** — rustez now closes the auto-opened config DB on
    load failure, preventing a leaked lock if a config load errors
    after the DB was opened on the caller's behalf. RustJunosMCP's
    `apply_junos_config` / template-render tools inherit the fix
    transparently.
  - **RZ-QUAL-001 / RZ-QUAL-002** — workspace package-drift CI check
    and `rb_id` forwarding through `diff()`. No user-visible change
    here, but reduces the risk of future rustez regressions affecting
    our `diff_against_rollback` tool.

### Verification

- `cargo audit` against the post-bump `Cargo.lock` reports **zero
  advisories** across 397 crates.
- 321 unit tests pass; live `upgrade_junos` integration test passes;
  `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo fmt --check` are clean.

### Tooling

- Workspace version bumped to `0.5.5`.

## [0.5.4] — TBD

Server-side correctness pass for the long-running `upgrade_junos`
tool. No new tools or wire-protocol changes; two bug fixes and one
observability gap closed.

### Fixed

- **`upgrade_junos.args.timeout` now actually constrains the transfer
  phase** (#42). Previously the inner call to `transfer_file::handle`
  used a hard-coded 600 s timeout regardless of the operator-supplied
  `args.timeout` (default 900 s). Raising the outer budget had no
  effect on the longest phase, so large-image transfers on slow links
  hit a phantom 600 s cap. The inner call now uses `args.timeout`; the
  outer `tokio::time::timeout(args.timeout, run(…))` remains the wall
  bound, so `UpgradeOuterTimeout` fires as documented.

### Added

- **`audit tool="upgrade_junos"` log line on every result path** (#42).
  `upgrade_junos` previously had no audit logging in the server-layer
  wrapper, so operators could not distinguish "tool errored" from
  "client disconnected mid-call" from "tool never ran." It now emits
  the same `audit` shape as `transfer_file` / `list_staged_files` on
  Ok, Err, and HTTP-cancellation paths. Cancellation lands via a
  `Drop`-based guard with `outcome="cancelled"`.

### Note

- rmcp 0.8.5's streamable-HTTP transport already emits SSE `:`
  keep-alive comments at 15 s intervals (`sse_keep_alive` default).
  SSE-aware clients should hold the response stream open for the full
  `args.timeout`. The original #42 symptom — `upgrade_junos` appearing
  to hang ~6 min — was a curl `--max-time` wall-clock cap on the
  smoke harness, not a server-side hang. Operators driving
  `upgrade_junos` from curl must set `--max-time` ≥ `args.timeout`.

### Tooling

- Workspace version bumped to `0.5.4`.

## [0.5.3] — TBD

Bugfix release for the `transfer_file` / `upgrade_junos` pre-transfer
checksum probe against Junos 24.x devices.

### Fixed

- **`parse_checksum_output` rejected Junos 24.x missing-file output**
  (#40). The probe (`file checksum sha-256 /var/tmp/<name>`) returns
  `sha256: (sha256: /var/tmp/<name>: No such file or directory) = directory`
  on 24.x when the destination is absent, instead of the older
  `error: stat: /var/tmp/<name>: No such file or directory` form. The
  parser only recognized the older form, so the probe failed with
  `validation error: unable to parse checksum output`, aborting the
  transfer **before any scp was attempted**. Any line containing
  `No such file or directory` is now treated as the missing-file
  signal regardless of prefix; the success format (trailing 64-char
  hex digest) is unambiguous.

### Tooling

- Workspace version bumped to `0.5.3`.

## [0.5.2] — TBD

Security audit response. Six findings from the internal code review
(`SECURITY_CODE_REVIEW_REPORT.md`, RJMCP-SEC-001..006) are now fixed.
No breaking changes to the MCP wire protocol, but two operator-facing
defaults change — see **Changed** below.

### Fixed (security)

- **SEC-001** — `KNOWN_TOOLS` drift. `transfer_file`,
  `list_staged_files`, and `upgrade_junos` were missing from the auth
  allowlist (the `tool:*` bearer-token scope check). A new drift
  test (`known_tools_matches_server_tools`) now asserts
  `KNOWN_TOOLS == SERVER_TOOLS` so future tool additions cannot bypass
  RBAC by omission.
- **SEC-002** — Drop YAML support in `render_and_apply_j2_template`'s
  `vars_content`. The crate depended on `serde_yml`, which carries an
  unmaintained-yaml advisory. `vars_content` is now strict JSON only.
  Callers that were passing YAML must convert to JSON; the `vars_file`
  path was already JSON.
- **SEC-003** — Centralised inventory validation. Username and
  private-key path fields are now validated on `add_device` and on
  inventory load — rejects spaces, leading dashes, control characters,
  and other shell-metacharacter classes that could be smuggled into an
  SSH argv. Helpers live in `rust-junosmcp-core::inventory::validation`
  so `add_device` and `Inventory::validate` share one source of truth.
- **SEC-004** — `transfer_file` / `upgrade_junos` now default to
  `StrictHostKeyChecking=yes`. Previously the server used TOFU
  (`accept-new`) on first contact, which silently pinned any host key
  presented during the first transfer. A new flag,
  `--ssh-accept-new-host-keys`, restores the old behaviour for lab
  bring-up. A helper script, `scripts/scan-known-hosts.sh`, drives
  `ssh-keyscan` against `devices.json` and writes the pinned file
  atomically.
- **SEC-005** — `reload_devices` `file_name` argument is now restricted
  to a relative basename inside the `--device-mapping` directory.
  Absolute paths, `..` traversal, and symlinks whose target escapes
  the inventory directory are all rejected with
  `InventoryInvalid`. Errors carry the original arg verbatim for
  debugging.
- **SEC-006** — Drop the `rustls-pemfile` crate (flagged unmaintained
  upstream). PEM parsing now uses `rustls-pki-types` directly
  (`CertificateDer::pem_slice_iter`, `PrivateKeyDer::from_pem_slice`),
  which ships in-tree with rustls 0.23.

### Changed

- **Default SSH host-key policy is now strict.** Operators who used
  the v0.5.x server against a fresh fleet without first pre-populating
  `known_hosts` will see `transfer_file` / `upgrade_junos` fail with
  the `known_hosts_missing` error code. Two recovery paths: (a) run
  `scripts/scan-known-hosts.sh --inventory /etc/jmcp/devices.json`
  before first use, or (b) start the server with
  `--ssh-accept-new-host-keys` for one-shot lab bring-up.
- **`render_and_apply_j2_template` rejects YAML in `vars_content`.**
  The schema documents `vars_content` as JSON; YAML was previously
  accepted as a best-effort fallback. Callers should switch to JSON
  (or use `vars_file`, which is unchanged).

### Tooling

- Workspace version bumped to `0.5.2`.
- New helper script: `scripts/scan-known-hosts.sh`.

## [0.5.1] — TBD

Bugfix release for the v0.5.0 `upgrade_junos` / `transfer_file` storage
preflight on older Junos layouts.

### Fixed

- **`parse_storage_free_bytes` on vSRX 24.x single-mount layout** (#36).
  v0.5.0's parser required a row whose `Mounted on` column was `/var`
  or `/.mount/var`. vSRX 24.x reports `/var` as a directory inside the
  root `/.mount` filesystem rather than as its own mount, so the
  parser fell through with `device_probe_failed (phase=storage_parse)`
  and blocked every upgrade originating from 24.x. The parser now
  records the `/.mount` row's `Avail` as a fallback and returns it
  when no dedicated `/var` row is found. Order of preference for the
  modern layout is unchanged: `/var` > `/.mount/var` > `/.mount`.

### Tooling

- Workspace version bumped to `0.5.1`.

## [0.5.0] — TBD

Feature release: new `upgrade_junos` MCP tool brings the standalone
vSRX upgrade workflow into the tool surface. Tool count 13 → 14.

### Added

- **`upgrade_junos` tool** — single MCP call automates the proven
  standalone vSRX upgrade workflow: pre-baseline → transfer →
  install + reboot → wait for NETCONF → post-verify → post-baseline
  → response. Two-call confirm protocol: first call returns a
  `ConfirmationRequired` JSON-RPC error carrying the full upgrade
  plan (current version, target version, image, free disk,
  estimated outage); operator re-calls with `confirm=true` to
  perform the destructive workflow. Reuses the v0.4.1
  `TransferLocks` semaphore so transfer_file + upgrade_junos
  serialize per-router. Cluster (ISSU) devices are auto-detected
  and refused — separate v2 tool planned.
- 7 new structured `JmcpError` variants:
  `ConfirmationRequired`, `UpgradeClusterUnsupported`,
  `UpgradeCommitConfirmedActive`, `UpgradeInstallTimeout`,
  `UpgradeRebootTimeout`, `UpgradePostVerifyMismatch`,
  `UpgradeOuterTimeout`. All follow the `[code=<snake>]` Display
  convention.

### Tooling

- Workspace version bumped to `0.5.0`.

## [0.4.1] — 2026-05-15

Security + hardening release. No tool API changes; one server-side
response-header change for unauthenticated requests, plus a new response
field on `list_staged_files`.

### Security

- **RFC 6750 bearer challenges on every 401** — the streamable-HTTP
  endpoint now always returns a `WWW-Authenticate: Bearer ...` header on
  `401 Unauthorized`. Wrong-token rejections include
  `error="invalid_token"` per RFC 6750 §3.1 so clients can distinguish
  bearer rejection from an OAuth-discovery prompt (avoids
  `~/.claude/.credentials.json` corruption from clients that retry as
  OAuth on a bare 401). (#27, PR #28)
- **`transfer_file` source-path allowlist tightened** —
  `validate_source_basename` previously rejected `/`, `\`, `..`, leading
  `.`, and >255 bytes but accepted NUL bytes, ASCII control characters,
  shell metacharacters, and arbitrary Unicode (including RTL overrides
  and homoglyph scripts). Now restricts to `[A-Za-z0-9._-]`. Junos image
  / config artifacts are plain ASCII so this is non-restrictive in
  practice. (#26 L2, PR #30)
- **`scp` stderr scrubbed in `ScpFailed` errors** — absolute filesystem
  paths and IPv4 addresses are redacted to `<path>` / `<host>` before
  the error is surfaced to the MCP caller. Diagnostic text is
  preserved. Closes a path/host leak surface in multi-tenant setups.
  (#26 L1, PR #31)

### Reliability

- **`list_staged_files` capped at 256 entries** — `read_staging_dir`
  previously walked every regular file and computed sha256 on each
  (~3 s/GB), producing slow + large responses when an operator dumped
  thousands of files into staging. Now caps at
  `STAGING_DIR_MAX_ENTRIES = 256` (sorted by name, deterministic
  truncation, sha256 skipped for excess files). Response gains two new
  fields: `staged_files_truncated: bool` and
  `staged_files_total_found: usize`. (#26 L5, PR #32)
- **Per-router serialization for `transfer_file`** — new `TransferLocks`
  process-wide map of `Arc<Semaphore(1)>` keyed by router name. Prevents
  a confused or buggy caller from exhausting a device's `/var/tmp` or
  session pool via fan-out. Different routers proceed in parallel; same
  router serializes. Junos serializes on its side anyway, so this caps
  client-side fan-out. (#26 L4, PR #33)

### Operability

- **Actionable EACCES message on `tokens.json`** — when the running
  process can't read the tokens file due to permissions, the server now
  surfaces the file owner uid + mode and the running process's uid plus
  a `sudo -u <service-user>` / `chown` hint. Previously the operator
  saw a bare `Permission denied (os error 13)` with no pointer at the
  underlying ownership mismatch. README also gained a note in the
  "Mint a token" section about running token subcommands as the service
  user. (#22 / #23, PR #29)

### Tooling

- Workspace version bumped to `0.4.1`.

## [0.4.0]

Initial release of the `transfer_file` + `list_staged_files` MCP tools.
See PR #25 for details.

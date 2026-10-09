# Threat model: rust-junosmcp

One page, for a SOC engineer deciding whether to point an LLM at their Junos
fleet through this server. Shared controls (tokens, transport, audit chain,
change sets, secret files) come from the mecmcp foundation. They are described once in
the mecmcp threat model, in review as [mecmcp#384](https://github.com/mechubsec/mecmcp/pull/384).
This page covers what is Junos-specific. Verified against `main` at `48c0679` on 2026-09-27.

**Status key:** ✅ mitigated in code · 🟡 partial, or opt-in only · ❌ not mitigated.
Every 🟡 or ❌ row names its open issue, or is accepted in [Residual risk](#residual-risk-accepted).

## Assets

- **Device SSH credentials** (inventory) and the `known_hosts` trust store.
- **Running configuration of every inventoried device.** This server can commit, roll back and upgrade.
- **Device output:** configs, which include `$9$`/`$6$` secret material, plus routing, sessions and logs.
- **Audit trail and change-set state** (`/var/lib/jmcp`).

## Trust boundaries

```text
LLM / MCP client ──(1)── rust-junosmcp ──(2) NETCONF/SSH, scp── Junos device
                               │
                               └──(3)── stderr / file / journald / SSDF (opt-in)
```

1. **Client → server.** Model output is untrusted, even with a valid token. That includes
   commands, config text, device names and rollback numbers.
2. **Server ↔ device.** The device must be authenticated by host key. Everything it
   returns is untrusted, and is relayed to the model verbatim.
3. **Audit egress.** The only non-device egress. It is off unless configured.

## Threats and mitigations

| # | Threat | Control | Status |
|---|---|---|---|
| J1 | **Prompt-injected tool call.** The model is steered by the user, a document, or text in device output such as descriptions, banners or log lines. | Per-token tool and device allowlists (`check_tool_scope` / `check_router_scope` in [`server.rs`](../rust-junosmcp/src/server.rs)). Two-person change sets (`create/approve/apply_junos_change_set`). `--inventory-readonly`. `--allow-plane-owned-writes` is off by default. **Nothing detects the injection.** | 🟡 |
| J2 | **Free-form command blocklist fails open.** `execute_junos_command`, `_batch` and `_pfe_command` run any command that no `deny` glob matches. With no `_blocklist_defaults` in inventory there are no rules at all ([`policy.rs`](../rust-junosmcp-core/src/policy.rs)). | An operator-authored denylist, e.g. [`devices-template.json`](../devices-template.json). Denylists miss variants. **No public issue yet.** | ❌ |
| J3 | **Direct commit bypasses two-person control.** `load_and_commit_config`, `rollback_config` and `upgrade_junos` change the device in one call, gated only by token scope. `rollback_config` also skips the config blocklist. | A second-approver rule and `--allow-direct-commit` are in progress (internal MEC-12, no public issue yet). Until then, keep these tools out of every token that a model can use unattended. | ❌ |
| J4 | **Commit without auto-rollback.** A bad commit that cuts management access stays in place. | `confirm_timeout_mins` exists but is **optional, and off by default** ([`load_commit.rs`](../rust-junosmcp-core/src/tools/load_commit.rs), [`rollback_config.rs`](../rust-junosmcp-core/src/tools/rollback_config.rs)). Making commit-confirmed the default: [#414](https://github.com/mechubsec/rustjunosmcp/issues/414). | ❌ |
| J5 | **MITM or impersonated device.** A wrong host key means stolen credentials and false results. | The default is strict: NETCONF uses `KnownHosts(--known-hosts-file)`, scp uses `StrictHostKeyChecking=yes` ([`bootstrap.rs`](../rust-junosmcp-core/src/bootstrap.rs) `build_host_key_policy`). **`--ssh-accept-new-host-keys` is labelled TOFU, but NETCONF gets `AcceptAll`**: it never pins, and it accepts changed keys. Fix: [#415](https://github.com/mechubsec/rustjunosmcp/issues/415), which depends on `AcceptNew` in [rustnetconf#107](https://github.com/mechubsec/rustnetconf/issues/107). Also, library callers of `DeviceManager::new` get `AcceptAll` unless they override it ([`device_manager.rs`](../rust-junosmcp-core/src/device_manager.rs)). | 🟡 |
| J6 | **Tool output leaks secrets to the model provider.** `get_junos_config` returns `$9$` strings, which are reversibly obfuscated rather than hashed, plus SNMP communities and PSKs. | Only the SRX support-bundle workflow redacts ([`support_bundle/redact.rs`](../rust-junosmcp-srx-core/src/workflows/support_bundle/redact.rs)). General tool-output redaction waits on the shared `mecmcp-redact` crate (internal MEC-11 and MEC-14). **Today, config output reaches the model unredacted.** | ❌ |
| J7 | **Metrics or audit data escape.** | `--enable-metrics` is off by default. When on, it is unauthenticated: [mecmcp#377](https://github.com/mechubsec/mecmcp/issues/377). `--audit-redact` (`devices`, `host`, `command`, … → `drop`/`hmac`) defaults to **empty**, and the container image runs unkeyed audit: [mecmcp#376](https://github.com/mechubsec/mecmcp/issues/376). SSDF export only runs if `--ssdf-audit-endpoint` is set. | 🟡 |
| J8 | **Supply chain.** A malicious crate or image. | `Cargo.lock` is committed. Gitleaks, `cargo audit` and `cargo deny check advisories licenses bans sources` run in CI ([`security.yml`](../.github/workflows/security.yml)). `trivy fs` and `trivy image` run against [`trivy.yaml`](../trivy.yaml) on push and PR. Releases are cosign-signed (image via `release-image.yml`, LXC tarball via `release-sign-tarball.yml`), and image-signature verification steps are documented in `README.md`. A Rust dependency CycloneDX SBOM is generated on release, attached to the GitHub release, and pushed as a `cosign attest` attestation on the image; the attestation is signed by mecmcp's reusable `reusable-attest-release-sbom.yml` identity (called from this repo's own `release-sbom.yml`), constrained to this repository via `--certificate-github-workflow-repository`, distinct from the image signature's `release-image.yml` identity, and `README.md` documents `cosign verify-attestation` steps for it separately ([`release-sbom.yml`](../.github/workflows/release-sbom.yml); [#418](https://github.com/mechubsec/rustjunosmcp/issues/418)). | ✅ |

## Residual risk (accepted)

- **Device output is attacker-controllable prompt text.** Anyone who can set an interface
  description, a login banner or a syslog message can talk to the model. Scopes and
  two-person approval bound the damage. Nothing prevents the attempt.
- **Two tokens are not two people.** One operator holding both an owner token and an
  approver token defeats J1's approval step. `--lab-mode` waives approval, and that is
  recorded as `approval_waiver: "lab-mode"`.
- **The host operator and root are trusted.** They can read device credentials from inventory.
- **A committed change is only as safe as the reviewer.** Two-person approval checks
  that someone looked at the plan digest. It does not check that the change is correct.

## Out of scope

- Compromise of the Junos device itself.
- Junos privilege model: the server can do what its SSH user can do, so use a least-privilege login class.
- MCP client security.
- Physical access.

## Deployment minimum

1. Pre-populate `known_hosts`. Never use `--ssh-accept-new-host-keys` outside a lab until J5 is fixed.
2. Issue read-only tokens to any model-driven client. Put commit tools only on tokens that a human drives.
3. Set `_blocklist_defaults`. Treat it as a speed bump, not a boundary.
4. Set `--audit-redact` and `--audit-hmac-key-file` before sending audit to a shared SIEM.

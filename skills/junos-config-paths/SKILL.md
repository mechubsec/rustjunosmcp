---
name: junos-config-paths
description: Write Junos configuration that commits and works, with field-verified platform gotchas. Use when setting DNS, NTP, syslog or any service on a box that has system management-instance (SRX1600, SRX440 EVO, vSRX), when a name-server is set but nothing resolves, when an apply or commit hangs, or when planning a change set with commit confirmed.
version: 1.0.0
author:
  - fastrevmd-lab
  - Claude
license: MIT
---

# Junos configuration paths and gotchas

Everything under "Verified" was observed in the bench lab and is recorded in
`docs/TESTED-PLATFORMS.md` of the rust-junosmcp repo. Model and release are
stated because behaviour differs by box.

## Before you write

1. `lookup_junos_api` with `kind: config` for every path you are unsure of
   (see `junos-api-lookup`). A config write is checked against the catalog for
   the device's release and refused when a path does not exist on it.
2. Check the box first: `show configuration system management-instance` and
   `show version`. The next section depends on the answer.

## Verified: DNS on a box with `management-instance`

On SRX1600 25.4R1.12, SRX440 25.4X300-D40.2-EVO and vSRX 26.2R1.7, management
traffic lives in the `mgmt_junos` routing instance. A plain name-server
silently fails to resolve:

```
set system name-server 192.0.2.53 routing-instance mgmt_junos
```

In the mechubbench baseline (rust-junosmcp 2.8.1), Claude Opus 5.5, Codex
gpt-6-astra and six Ollama models on Hermes all failed this on at least two of
the three management-instance boxes; most wrote the plain name-server.

Test with the instance named:

```
show host example.net routing-instance mgmt_junos
```

Bare `show host` ignores the management instance and reports failure even
when DNS works. Do not conclude DNS is broken from it.

## Verified: boxes where `mgmt_junos` DNS does not work

SRX345 on 24.2R2-S5.3 and 25.4R1-S2.3: DNS via `mgmt_junos` fails (no port-53
packets leave `fxp0`, although ICMP inside `mgmt_junos` works). On 24.2 the
box used `mgmt_junos` and DNS failed. On 25.4 it runs without
`management-instance`, with name-server in the default instance and DNS
working. Do not add `management-instance` to an SRX345 to "fix" DNS.

## Verified: apply hangs when a commit moves management

When a commit moves management into or out of `mgmt_junos` (seen on SRX345,
SRX440 and vSRX), the session you are applying over dies mid-commit and the
stale session keeps the exclusive configuration lock. The apply then hangs.

- Treat `system management-instance` and the management interface's routing
  instance as their own change, apart from everything else.
- Always use commit confirmed for it, so the box rolls itself back if you lose it.
- If a hang happens, do not stack a second apply on top. How the stale lock
  clears has not been verified.

## rust-junosmcp change sets and commit confirmed

- A change set applied with `confirm_timeout_mins` opens a commit-confirmed
  window. Finish with `confirm_junos_change_set`; only the principal that
  opened the window can confirm it.
- `load_and_commit_config`, `rollback_config` and the template tool open a
  window the same way but are closed with `confirm_commit` (not
  `confirm_junos_change_set`).
- `rollback_config` is refused while a commit-confirmed window is open. Run
  `confirm_commit` (or let the window expire) first.
- Writes need: validated target, exact diff, approval, confirmed commit, and a
  verification read afterwards. Run `commit_check_config` and
  `junos_config_diff` before applying.

## Other recorded gaps (see TESTED-PLATFORMS.md)

- SRX345: facts hostname empty; `upgrade_junos`/`transfer_file` storage parse
  fails on `/cf/var`; 24.2 to 25.4 needs `no-validate`; install regenerates
  SSH host keys, so a pinned key fails afterwards.
- No way yet to pass an IKE PSK in a change set without it landing in the
  payload.

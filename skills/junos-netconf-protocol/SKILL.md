---
name: junos-netconf-protocol
description: How Junos NETCONF operations and commit confirmed map onto the rust-junosmcp tools. Use when reasoning about candidate vs running configuration, locks, commit confirmed windows, rollback, or why a config tool call is refused or hangs.
version: 1.0.0
author:
  - fastrevmd-lab
  - Claude
license: MIT
---

# NETCONF on Junos, as this server uses it

The server talks NETCONF over SSH (port 830 or the inventory's port). Tools
wrap the operations; you do not send raw NETCONF.

## Operations and the tools that use them

| NETCONF | Meaning | Tool |
|---|---|---|
| `get` / RPC | operational state | `execute_junos_command`, `execute_junos_rpc`, `gather_device_facts` |
| `get-config` | read configuration | `get_junos_config`, `junos_config_diff` |
| `lock` / `unlock` | exclusive candidate lock | taken inside write tools |
| `load-configuration` | edit the candidate | `commit_check_config`, `load_and_commit_config`, change sets |
| `commit-configuration` | activate | write tools; `check` for `commit_check_config` |
| `discard-changes` | drop candidate | `discard_candidate` |

## Candidate, lock and fingerprint

Junos edits a **candidate** and activates it with a commit. Write tools take
the exclusive lock, load, commit and release. A session that dies while
holding the lock leaves it held until the session ends, so a later write
hangs or reports the configuration locked. Do not retry in a loop.

`get_junos_candidate_fingerprint` reads the candidate's fingerprint. A change
set records it when planned and refuses to apply if the candidate changed
since, so someone else's uncommitted edit is never swept into your commit.

## Commit confirmed

`commit confirmed N` activates the config and schedules an automatic
rollback after N minutes unless a second, confirming commit arrives.

- Opened by passing `confirm_timeout_mins` (change sets, `load_and_commit_config`,
  `rollback_config`, template apply).
- Closed by `confirm_junos_change_set` (change sets; only the principal that
  opened it can confirm) or `confirm_commit` (the other tools).
- `rollback_config` is refused while a window is open. Confirm first.
- If the change cuts your own access, do not confirm; the device rolls back.

## Change-set lifecycle (two-person)

`create_junos_change_set` (plan, with fingerprint) then
`approve_junos_change_set` by a different principal, then
`apply_junos_change_set` with the digest and fingerprint, then confirm.
`cancel_junos_change_set` frees a pending slot;
`get_junos_change_set_status` and `list_junos_change_sets` read state.

## Before any write

`commit_check_config` and `junos_config_diff`, then apply with commit
confirmed, then verify with a read. Platform traps (management instance, DNS)
are in `junos-config-paths`; find RPC and path names with `junos-api-lookup`.

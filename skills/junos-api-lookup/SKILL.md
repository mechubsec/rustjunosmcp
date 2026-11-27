---
name: junos-api-lookup
description: Find the right Junos RPC, CLI command or configuration path before calling a device. Use when about to run execute_junos_command or execute_junos_rpc, when unsure of an RPC name, argument or `show` command, when a command fails with a syntax error, or when a result carries a `warning` about a nearby release train.
version: 1.0.0
author:
  - fastrevmd-lab
  - Claude
license: MIT
---

# Junos API lookup

Do not guess RPC names, arguments or configuration syntax. The server embeds a
catalog of every operational RPC and configuration path per **Family**
(`junos-es` SRX/vSRX, `junos-ex` EX, `junos-evo` Junos OS Evolved) and
**release train** (`major.minor`, 23.1 and later). Ask it first.

## Workflow

1. `lookup_junos_api` with `router` (the device's own model and version pick
   the Family and train) or, with no reachable device, `family` + `release`
   (for example `junos-ex`, `23.4`).
   - `kind: rpc` (default): `query` is an RPC name, a CLI command
     (`show arp`) or keywords.
   - `kind: config`: `query` is a configuration path (`security policies`) or
     keywords. The result gives value type, range and units.
2. Read the hit: RPC name, CLI equivalent, argument names and which are
   `empty` flags, and the trains it exists in.
3. Call it.
   - `execute_junos_rpc` for `get-*` RPCs whose CLI is a `show ...` command.
     `args` maps argument names to a string, or `true` for an `empty` flag.
     The reply is XML, redacted like command output.
   - `execute_junos_command` when the RPC is not `get-*`, its CLI is not a
     `show` command, or you want the CLI text.

## What `execute_junos_rpc` refuses

- Names that do not start with `get-`, or that the catalog does not list.
- Arguments the catalog does not list for that RPC, and values containing
  `< > &`, quotes, `;` or control characters.
- Anything whose CLI equivalent plus arguments the command allow/blocklist
  would refuse in `execute_junos_command`. The RPC route is not a way around
  the policy.
- RPCs whose CLI is not a `show ...` command (these change state).

## Reading a `warning`

A `warning` on a lookup or RPC result means the answer came from a nearby
release train, or the Family was guessed because the model is unknown (SRX on
Junos OS Evolved answers from `junos-es`). The name or argument may not exist
on this device. Verify with a cheap read (`show ... | count`, or retry the CLI
form through `execute_junos_command`) before building on it.

## Pitfalls

- Catalog hits for one RPC name can differ by train: argument sets change.
  Use the entry for the device's train, not the first one shown.
- A catalog gap is not proof an RPC is absent. When the catalog is silent,
  fall back to `execute_junos_command` with the CLI and read the device's own
  error.
- Before writing configuration, look up the path with `kind: config`. Config
  writes through this server are also checked against the catalog for the
  device's release; see `junos-config-paths`.

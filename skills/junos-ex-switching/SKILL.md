---
name: junos-ex-switching
description: Find where a MAC address, VLAN or port is on a Junos EX switch with read-only RPCs. Use when asked which port a MAC is on, which VLANs a port carries, what is plugged into a port, link or PoE state, or LLDP neighbours on an EX.
version: 1.0.0
author:
  - fastrevmd-lab
  - Claude
license: MIT
---

# EX switching lookups

Family `junos-ex`. The names below come from the embedded catalog; argument
sets vary by release train, so confirm each with `lookup_junos_api`
(`router` set) before the first call. They have not all been exercised
on-device: the lab EX is an EX2300-C-12P on 23.4R2-S2.1, where facts, CLI and
config reads were verified.

| Question | RPC (CLI) | Useful arguments |
|---|---|---|
| Which port holds a MAC? | `get-ethernet-switching-table-information` (`show ethernet-switching table`) | `address`, `vlan-name`, `vlan-id` |
| MACs learned on a port | `get-ethernet-switching-table-interface-information` (`show ethernet-switching table interface`) | `interface-name` |
| VLANs and their ports | `get-vlan-information` (`show vlans`) | `vlan-name`, `interface`, `verbosity` |
| Port membership and state per VLAN | `get-ethernet-switching-interface-details` (`show ethernet-switching interface`; catalog lists it from 25.2 only) | `interface-name` |
| What is on the other end | `get-lldp-neighbors-information` (`show lldp neighbors`) | none |
| Link state, speed, errors | `get-interface-information` (`show interfaces`) | `interface-name` |
| PoE draw per port | `get-poe-interface-information` (`show poe interface`) | none |
| LAG state | `get-lacp-interface-information` (`show lacp interfaces`) | `interface-name` |

Call them through `execute_junos_rpc` (`device`, `rpc`, `args`).

## Finding a MAC

1. `get-ethernet-switching-table-information` with `address` set to the MAC,
   lower case, colon separated.
2. The hit gives VLAN and port. If the port is a trunk or LAG (`ae*`), the MAC
   is learned from downstream. Check LLDP on that port and repeat on the next
   switch.
3. No hit: the MAC aged out or was never seen. Try
   `get-ethernet-switching-table-interface-information` on the suspected port,
   and check whether the VLAN exists with `get-vlan-information`.

## Pitfalls

- Some EX models and release trains use the ELS `bridge` tables
  (`show bridge mac-table`, `get-bridge-mac-table`) rather than
  `ethernet-switching`. If the lookup shows the RPC is absent for the device's
  train, search keywords (`mac table`) instead of assuming.
- `show interfaces` for the whole box is large; pass `interface-name`.
- On 23.4 the catalog has no `show ethernet-switching interface` RPC: use
  `get-vlan-information` with `interface`, or `execute_junos_command`.
- Read only. Moving a port between VLANs is a config change: see
  `junos-config-paths` (commit confirmed, one change at a time).

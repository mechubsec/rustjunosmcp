# Filesystem layout

## Directory naming exception (#335)

Junos is the naming outlier in the mecmcp server fleet. Every other server names
its directories after its binary; junos uses `jmcp`.

| Server | service dir | config dir        | state dir           |
|--------|-------------|-------------------|---------------------|
| junos  | `jmcp`      | `/etc/jmcp`       | `/var/lib/jmcp`     |
| panos  | `rust-panosmcp` | `/etc/rust-panosmcp` | `/var/lib/rust-panosmcp` |
| sdc    | `rustsdcmcp`    | `/etc/rustsdcmcp`    | `/var/lib/rustsdcmcp`    |
| mist   | `rustmistmcp`   | `/etc/rustmistmcp`   | `/var/lib/rustmistmcp`   |

This is a **permanent documented exception** to the fleet's full-binary-name
convention. Renaming would touch the unit, installer, site overrides on live
guests (950/610/611), token and inventory paths, audit paths, documentation, and
the MCP registry, with a live client-lockout failure mode, for a cosmetic gain.
The tax is this documentation; the migration risk lands on production guests
tagged `protected`. Decision: keep `jmcp`. (Issue #335)

The same split runs through everything junos-specific: the service user is
`jmcp`, `StateDirectory=jmcp`, and the env vars are `JMCP_*`.

## File locations

### Configuration (read-only to the service)

- `/etc/jmcp/devices.json` — inventory, hand-edited or managed via `add_device`
  when `--inventory-readonly` is not set
- `/etc/jmcp/known_hosts` — SSH host keys for scp transfers

`ProtectSystem=strict` makes `/etc` read-only to the service process, so runtime
state that the server must write lives in `/var/lib/jmcp` instead.

### Runtime state (writable by the service)

- `/var/lib/jmcp/tokens.json` — bearer tokens (moved from `/etc/jmcp` in v0.22.0, #333)
- `/var/lib/jmcp/audit-hmac.key` — HMAC key for tamper-evident audit log (added v0.22.0, #334)
- `/var/lib/jmcp/approver-replay.log` — used approver-assertion `jti` hashes (`--approver-replay-store`, created 0600 on first start)
- `/var/lib/jmcp/changeset-state.json` — two-person approval lifecycle state
- `/var/lib/jmcp/audit.jsonl` — JSON audit log (when configured via site override)
- `/var/lib/jmcp/device-leases/` — cross-process destructive-operation leases
- `/var/lib/jmcp/staging/` — staging directory for scp push (`transfer_file`)
- `/var/lib/jmcp/srx-staging/bundles/` — JTAC support bundle staging

### Migration from legacy token path

Versions prior to v0.22.0 stored `tokens.json` in `/etc/jmcp`. The runtime
prefers `/var/lib/jmcp/tokens.json` and falls back to `/etc/jmcp/tokens.json`
when the new path is absent, logging a migration warning.

The installer creates the new path but **never copies** the old file — a stale
token file left behind in `/etc` is a stale secret on disk. When the warning
appears, the operator must:

1. Verify the new file exists and is owned by the service user: `ls -l /var/lib/jmcp/tokens.json`
2. Mint a token in the new location if needed: `rust-junosmcp token add <name>`
3. Securely delete the stale copy: `shred -u /etc/jmcp/tokens.json`

Do not symlink `/etc/jmcp/tokens.json` to `/var/lib/jmcp/tokens.json` — that
defeats the hardening goal and hands the service write access to `/etc` via the
link target.

## Egress filtering

The packaged unit declares `IPAddressDeny` to block egress to cloud metadata.
However, **systemd cannot enforce these directives in an unprivileged LXC** —
every guest in this fleet is one. systemd implements them with cgroup BPF and
fails open when it cannot load the program, so the unit can declare a full
egress policy while enforcing none of it. `systemd-analyze security` reads the
declaration and cannot tell the difference.

The installer probes actual enforcement and prints one of four verdicts:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install to restore it)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

The probe uses IP accounting, which rides the same BPF attachment, so a
populated counter proves the filter attached. Check it any time:

```console
systemctl show rust-junosmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`JMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything short of
`ENFORCED` — including `UNKNOWN`, since an unmeasurable host is exactly as
unguaranteed as a non-enforcing one.

### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime:

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working (not applicable to this server's
   current unit, which allows `192.168.0.0/16` — adjust for your subnet)

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.

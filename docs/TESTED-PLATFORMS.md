# Tested platforms

Models and Junos releases that rust-junosmcp has been run against on real or virtual devices.
"Verified" lists only what was exercised and observed working. Gaps link to issues or the
backlog. Update this file whenever a model or release is added to the bench lab or a tool is
exercised on a new one.

Bench lab: `~/homelab/docs/superpowers/specs/2026-11-24-junos-bench-lab-design.md`.

| Model | Family | Release | Mgmt | Verified | Gaps found |
|---|---|---|---|---|---|
| EX2300-C-12P | junos-ex | 23.4R2-S2.1 | `vme` static | facts, CLI, config read, change set + commit confirmed + confirm | — |
| SRX345 | junos-es (branch) | 24.2R2-S5.3 | `fxp0` static, `mgmt_junos` | facts, CLI, change set + commit confirmed + confirm | facts hostname empty; DNS via `mgmt_junos` fails on 24.2; `upgrade_junos`/`transfer_file` storage parse fails on `/cf/var` ([#675](https://github.com/mechubsec/rustjunosmcp/issues/675)) |
| SRX345 | junos-es (branch) | 25.4R1-S2.3 | `fxp0` static, default instance | facts, CLI, change set + commit confirmed + confirm, 145-line baseline change set (IPsec, NAT, policies), DNS in default instance | 24.2→25.4 needs `no-validate`; install regenerates SSH host keys, so the pinned key fails (`host key` transport error); first boot sluggish (load ~12); DNS with `name-server … routing-instance mgmt_junos` fails on 24.2 and 25.4 (no port-53 packets leave `fxp0` although ICMP in `mgmt_junos` works), so the box runs without `management-instance`; apply hangs when the commit moves mgmt out of `mgmt_junos` and the stale session keeps the exclusive lock |
| SRX440 | Junos OS Evolved | 25.4X300-D40.2-EVO | `re0:mgmt-0` static, `mgmt_junos` | facts, CLI, change set + commit confirmed + confirm, 150-line baseline change set (IPsec, NAT, policies) | apply hangs when the commit moves mgmt into `mgmt_junos` |
| SRX1600 | junos-es | 24.2R2-S5.5 → 25.4R1.12 | `fxp0` static, `mgmt_junos` | facts, CLI, change set + commit confirmed + confirm, DNS via `mgmt_junos`, 150-line baseline change set (IPsec, NAT, policies) | `upgrade_junos` has no vmhost support and can't stage a 1.6 GB image (upgraded by hand) |
| vSRX 3.0 | junos-es | 26.2R1.7 | `fxp0` static, `mgmt_junos` | facts, CLI, change set + commit confirmed + confirm, DNS via `mgmt_junos`, baseline change set (zones, policy) | apply hangs when the commit moves mgmt into `mgmt_junos`; RE status reports `Testing` |
| cSRX (Docker, routing mode) | junos-es | 26.2R1.7 | container sshd via host tcp/2222 | facts (model `csrx`, personality `csrx`; serial reports the hostname, no route engines), CLI, change set + commit confirmed + confirm (zones, policies, routes) | `show interfaces terse` unsupported; Docker `-p` publish didn't bind with passthru macvlan networks attached |

Cross-platform gaps: a spurious "owned by unknown" config-authority warning
([#674](https://github.com/mechubsec/rustjunosmcp/issues/674)); RT_FLOW traffic-log lines come
back wholesale as `[REDACTED]` from `execute_junos_command_batch` (seen on SRX440 EVO, SRX345,
SRX1600 and cSRX); no way to pass an IKE PSK in a change set without it landing in the payload.

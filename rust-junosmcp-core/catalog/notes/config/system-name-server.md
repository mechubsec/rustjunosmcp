## Example

`set system name-server 192.0.2.53 routing-instance mgmt_junos`

## Reply fields that matter

- Each `name-server` entry is keyed by its address; the optional `routing-instance` child selects the instance used to reach it.

## Version gotchas

- Boxes with `system management-instance` (SRX1600 25.4R1.12, SRX440 25.4X300-D40.2-EVO, vSRX 26.2R1.7) need `routing-instance mgmt_junos` on each name-server; a plain name-server commits without error but `show host <name> routing-instance mgmt_junos` does not resolve (bench lab, SRX1600 25.4R1.12, vSRX 26.2R1.7). In the mechubbench baseline (rust-junosmcp 2.8.1), every tested model failed this on at least two of the three management-instance boxes.
- SRX345 24.2R2-S5.3 and 25.4R1-S2.3: DNS via `mgmt_junos` fails (no port-53 packets leave fxp0), so that box runs without management-instance and uses a plain name-server.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/name-server-edit-system.html

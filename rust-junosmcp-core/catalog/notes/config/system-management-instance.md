## Example

`set system management-instance`

## Reply fields that matter

- A leaf with no value: its presence moves fxp0/management into the `mgmt_junos` routing instance.

## Version gotchas

- An apply hangs when a commit moves management into or out of `mgmt_junos` (SRX345, SRX440, vSRX): the stale session keeps the exclusive lock. Plan for a console or out-of-band recovery, and use commit confirmed.
- After enabling it, name-servers need `routing-instance mgmt_junos` (see `system name-server`).
- SRX440 25.4X300-D40.2-EVO: Juniper publishes no SRX EVO YANG; the server answers from junos-es.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/management-instance-edit-system.html

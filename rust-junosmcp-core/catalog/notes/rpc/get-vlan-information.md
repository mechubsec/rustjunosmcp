## Example

`{"device": "<router>", "rpc": "get-vlan-information", "args": {"vlan-name": "<vlan>"}}`

## Reply fields that matter

- `l2ng-l2ald-vlan-instance-group` carries per-VLAN state; `l2ng-l2ald-ifbd-entry/l2ifbd-vlan-name`, `l2ifbd-vlan-id` and `l2ifbd-ifl-name` give VLAN-to-interface membership.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-vlans.html

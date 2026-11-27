## Example

`{"device": "<router>", "rpc": "get-ethernet-switching-table-information", "args": {"vlan-name": "<vlan>"}}`

## Reply fields that matter

- `l2ng-l2ald-mac-entry-vlan`: `l2ng-l2-mac-address`, `l2ng-l2-mac-vlan-name`, `l2ng-l2-mac-logical-interface`, `l2ng-l2-mac-flags`.
- `l2ng-l2-total-mac-count` in `l2ng-l2ald-ethernet-switching-table-summary` when `show-choice` is `summary`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-ethernet-switching-table.html

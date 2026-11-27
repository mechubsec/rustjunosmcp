## Example

`{"device": "<router>", "rpc": "get-arp-table-information", "args": {"no-resolve": true}}`

## Reply fields that matter

- `arp-table-entry/ip-address`, `mac-address`, `interface-name`, `hostname`.
- `arp-entry-count` (total).

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-arp.html

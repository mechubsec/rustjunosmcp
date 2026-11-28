## Example

`{"device": "<router>", "rpc": "get-arp-table-information", "args": {"no-resolve": true}}`

## Reply fields that matter

- `arp-table-entry/ip-address`, `mac-address`, `interface-name`, `hostname`.
- `arp-entry-count` (total).

## Version gotchas

- cSRX 26.2R1.7 (lab-verified 2026-11-27): the CLI has no `show arp` command (`syntax error, expecting <command>`); the RPC is not available on cSRX.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-arp.html

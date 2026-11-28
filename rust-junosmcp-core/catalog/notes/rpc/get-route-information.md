## Example

`{"device": "<router>", "rpc": "get-route-information", "args": {"destination": "10.0.0.0/24"}}`

The argument shown is illustrative: confirm the exact name in the catalog `input` list; this RPC takes many `te-*` and EVPN-specific arguments.

## Reply fields that matter

- `route-table/table-name`, `destination-count`, `active-route-count`.
- `rt/rt-destination`, `rt-entry/active-tag`, `protocol-name`, `preference`, `nh/to`, `nh/via`.

## Version gotchas

- cSRX 26.2R1.7 (lab-verified 2026-11-27): the CLI has no `show route` command (`syntax error, expecting <command>`); the RPC is not available on cSRX.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-route.html

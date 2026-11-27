## Example

`{"device": "<router>", "rpc": "get-flow-session-information", "args": {"source-prefix": "10.0.0.0/24", "destination-port": 443}}`

## Reply fields that matter

- `flow-session`: `session-identifier`, `policy`, `from-zone`, `to-zone`, `session-state`, `timeout`; `flow-information` gives `direction`, `source-address`, `source-port`, `destination-address`, `destination-port`, `protocol`, `interface-name`.
- `displayed-session-count` and the `displayed-session-*` counters.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session.html

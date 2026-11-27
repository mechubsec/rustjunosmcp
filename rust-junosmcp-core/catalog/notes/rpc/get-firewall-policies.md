## Example

`{"device": "<router>", "rpc": "get-firewall-policies", "args": {"from-zone": "trust", "to-zone": "untrust"}}`

## Reply fields that matter

- `security-context` / `policy-information`: `policy-name`, `policy-action`, `policy-state`, `source-addresses`, `destination-addresses`, `applications`.
- Zone pair context in `context-information` (`source-zone-name`, `destination-zone-name`).

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-policies.html

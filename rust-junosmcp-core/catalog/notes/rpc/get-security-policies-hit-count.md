## Example

`{"device": "<router>", "rpc": "get-security-policies-hit-count", "args": {"from-zone": "trust", "to-zone": "untrust", "order": "ascending"}}`

## Reply fields that matter

- `policy-hit-count-entry`: `policy-hit-count-policy-name`, `policy-hit-count-count`, `policy-hit-count-from-zone`, `policy-hit-count-to-zone`, `policy-hit-count-action`.
- `less-than` selects unused or low-use policies for cleanup.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-policies-hit-count.html

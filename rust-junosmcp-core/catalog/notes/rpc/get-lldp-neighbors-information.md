## Example

`{"device": "<router>", "rpc": "get-lldp-neighbors-information", "args": {}}`

## Reply fields that matter

- `lldp-neighbor-information`: `lldp-local-interface`, `lldp-remote-chassis-id`, `lldp-remote-port-id`, `lldp-remote-system-name`.

## Version gotchas

- None verified. The catalog lists no arguments for this RPC; filter the reply.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-lldp-neighbors.html

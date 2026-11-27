## Example

`{"device": "<router>", "rpc": "get-security-associations-information", "args": {"level": "brief"}}`

## Reply fields that matter

- `security-associations-block`: `sa-name` (VPN), `sa-tunnel-information/sa-remote-gateway`, `sa-local-gateway`, `sa-block-state`.
- `security-associations` entries: `sa-spi`, `sa-hard-lifetime`, `sa-encryption-algorithm`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-ipsec-security-associations.html

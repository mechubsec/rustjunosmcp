## Example

`{"device": "<router>", "rpc": "get-license-key-information", "args": {}}`

## Reply fields that matter

- `license-key`: `name`, `key-data` (the key text).

## Version gotchas

- None verified. `key-data` is the license key itself; do not paste it into tickets or chat.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-license-keys.html

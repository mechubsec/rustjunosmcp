## Example

`{"device": "<router>", "rpc": "get-license-summary-information", "args": {}}`

## Reply fields that matter

- `license-detail-usage-summary/feature-summary`: `name`, `licensed`, `used-licensed`, `end-date`, `validity-type`, `remaining-time`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-license.html

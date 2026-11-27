## Example

`{"device": "<router>", "rpc": "get-system-uptime-information", "args": {}}`

## Reply fields that matter

- `system-uptime-information/system-booted-time/time-length` and `uptime-information/up-time` (boot age).
- `last-configured-time/user` and `time-length` (who committed last, how long ago).
- `uptime-information/load-average-1`, `load-average-5`, `load-average-15`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-system-uptime.html

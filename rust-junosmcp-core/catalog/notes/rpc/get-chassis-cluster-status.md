## Example

`{"device": "<router>", "rpc": "get-chassis-cluster-status", "args": {"redundancy-group": 0}}`

## Reply fields that matter

- `cluster-id`; per `redundancy-group`: `redundancy-group-id`, `redundancy-group-failover-count`.
- `device-stats`: `device-name`, `device-priority`, `redundancy-group-status` (primary/secondary), `preempt`, `monitor-failures`.

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-cluster-status.html

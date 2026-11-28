## Example

`{"device": "<router>", "rpc": "get-host-information", "args": {"host": "<name>", "routing-instance": "mgmt_junos"}}`

## Reply fields that matter

- The catalog models the reply as unstructured text under `output`; parse the resolved addresses from it. An empty result means resolution failed.

## Version gotchas

- Boxes with `system management-instance` (SRX1600 25.4R1.12, SRX440 25.4X300-D40.2-EVO, vSRX 26.2R1.7): bare `show host` ignores the management instance. Pass `routing-instance` `mgmt_junos`.
- SRX345 24.2R2-S5.3 and 25.4R1-S2.3: DNS via `mgmt_junos` fails (no port-53 packets leave fxp0), so that box runs without management-instance and needs no `routing-instance`.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-host.html

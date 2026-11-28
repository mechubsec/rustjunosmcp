## Example

`{"device": "<router>", "rpc": "get-interface-information", "args": {"level-extra": "terse"}}`

`level-extra` selects `terse`, `brief`, `detail` or `descriptions`; `level` selects `extensive`, `statistics` or `media`. Add `interface-name` to narrow to one interface.

## Reply fields that matter

- `physical-interface/name`, `admin-status`, `oper-status`; logical units under `logical-interface` with `address-family/interface-address/ifa-local`.

## Version gotchas

- cSRX (26.2R1.7): `show interfaces terse` is unsupported (docs/TESTED-PLATFORMS.md); expect an error rather than data.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-interfaces-terse.html

## Example

`set security policies from-zone trust to-zone untrust policy allow-web match source-address any destination-address any application junos-https` then `set security policies from-zone trust to-zone untrust policy allow-web then permit`

## Reply fields that matter

- `from-zone`/`to-zone` lists key each policy set; `global` policies are a separate list evaluated after zone policies.
- Order within a zone pair is evaluation order (first match wins): use `insert ... before|after` to reposition, not delete and re-add.

## Version gotchas

- SRX on Junos OS Evolved (SRX440): Juniper publishes no SRX EVO YANG; the server answers from junos-es.

## Example

`{"device": "<router>", "rpc": "get-software-information", "args": {}}`

## Reply fields that matter

- `software-information/junos-version`, `product-model`, `host-name`, `junos-edition` (identify model and release).
- `package-information` and `external-package-information` list installed packages.
- On a multi-RE or clustered box the reply nests everything under `multi-routing-engine-results/multi-routing-engine-item` (with `re-name`).

## Version gotchas

- None verified.

## Reference

https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-version.html

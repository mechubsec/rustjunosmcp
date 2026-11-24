# Embed a generated Junos API catalog instead of asking devices for their schema

LLMs need the exact RPC names, arguments, reply elements and configuration paths for a device's
Family and Release train. We generate a Catalog offline from a pinned commit of Juniper's
Apache-2.0 `Juniper/yang` repository (the `-with-extensions` modules, which carry each RPC's CLI
command), cover the `junos-es` and `junos-ex` families for release trains 23.1 and later, and
embed it in the binary. Answers then work without a reachable device, are identical for every
caller, and can be reviewed and tested in CI.

## Considered Options

- **Live `<get-schema>` / `| display xml rpc` from each device.** Always exact for that device,
  but needs the device up, costs a round trip per lookup, and the YANG must be fetched and parsed
  at runtime. We use it only in lab integration tests, to prove the Catalog matches real devices.
- **Ship the raw YANG.** About 125 MB per release train for two families; too large, and still
  needs a runtime YANG parser.

## Consequences

- The Catalog only knows what Juniper published. A train or Family missing from `Juniper/yang`
  falls back to the nearest train with an "unverified for this device" warning.
- Updating the Catalog is a regenerate-and-review commit, not a code change.
- Juniper's copyright headers and the Apache-2.0 license travel with the generated data.

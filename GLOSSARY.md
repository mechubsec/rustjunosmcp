# RustJunosMCP

The MCP server that lets an LLM read and change Junos devices safely. This glossary covers the
vocabulary for describing which Junos API calls exist on a given device.

## Language

**Family**:
The Juniper schema lineage a device belongs to, which decides its RPC and configuration tree:
`junos-es` (SRX, vSRX), `junos-ex` (EX switches) or `junos-evo` (routers and switches running
Junos OS Evolved, such as PTX and ACX). An SRX running Junos OS Evolved uses the `junos-es`
Family.
_Avoid_: platform, product line, model

**Model**:
The specific hardware or virtual product a device reports (`EX4400-48T`, `vSRX3`). Many models
share one Family.
_Avoid_: platform, SKU

**Release train**:
The `major.minor` Junos release a device runs (`23.4`), ignoring the `R`, `S` and build suffixes.
Only trains 23.1 and later are supported.
_Avoid_: version, build, release

**RPC**:
A named Junos XML operational request (`get-flow-session-information`) with typed arguments and
a reply element. Each RPC has a CLI equivalent (`show security flow session`).
_Avoid_: API call, command

**Configuration path**:
A location in the Junos configuration hierarchy (`security policies from-zone`) with its value
type, range and units.
_Avoid_: config key, stanza

**Catalog**:
The record of every RPC and Configuration path per Family and Release train, generated from
Juniper's published YANG.
_Avoid_: schema, API database

**Catalog entry**:
One RPC or Configuration path in the Catalog, with the Release trains it exists in.

**Overlay note**:
Hand-written guidance attached to a Catalog entry: an example call, the reply fields that matter,
and version gotchas seen in the lab.
_Avoid_: annotation, doc page

**Skill**:
A packaged set of instructions (SKILL.md plus references) the server offers an LLM for a Junos
task. Skills carry workflow and judgement; the Catalog carries facts.
_Avoid_: prompt, playbook

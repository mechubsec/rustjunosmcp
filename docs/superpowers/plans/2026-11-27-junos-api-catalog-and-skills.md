# Junos API Catalog and MCP Skills Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server tells an LLM the exact RPC, arguments, reply elements and configuration paths that exist for a device's Family and Release train, lets it call read-only RPCs directly, and serves Junos skills, so the LLM stops guessing.

**Architecture:** An offline Python generator (pyang plugin) turns a pinned commit of `Juniper/yang` into deduplicated JSON, which `rust-junosmcp-core` embeds and queries. Two new read tools (`lookup_junos_api`, `execute_junos_rpc`) and write-path validation sit on top of it. Skills ship as a `skills/` directory served through rmcp 3.10 `skills-fs` (SEP-2640) plus two fallback tools for clients that do not load MCP skills.

**Tech Stack:** Rust (rmcp 3.10, rustez 0.20, serde_json, flate2 already in the lockfile), Python 3 + pyang 2.6.1 (dev-only, run via `uv run --with pyang==2.6.1`).

**Spec:** `~/.claude/plans/i-want-to-greatly-atomic-wirth.md` (approved, decisions 1–14), `GLOSSARY.md`, `docs/adr/0001-embedded-junos-api-catalog.md`.

## Global Constraints

- Release trains: 23.1 and later only — 23.1, 23.2, 23.4, 24.2, 24.4, 25.2, 25.4, 26.2 (the trains present in `Juniper/yang`; the generator takes whatever ≥ 23.1 exists).
- Families v1: `junos-es` (SRX, vSRX, cSRX), `junos-ex` (EX), `junos-evo` (Junos OS Evolved, e.g. SRX440 `25.4X300-D40.2-EVO`). QFX/MX/NFX later.
- Catalog data is generated, never hand-edited; Juniper's Apache-2.0 LICENSE and copyright notice travel with it.
- `execute_junos_rpc` is read-only in v1: `get-*` RPCs only, through the same `policy.check_command` as `execute_junos_command` (no new bypass).
- Catalog enforcement: warn on reads, reject on writes — but only when Family and train resolve exactly; on a nearest-train fallback, warn only.
- New tools must be in `JUNOS_TOOLS`/`KNOWN_TOOLS` (`rust-junosmcp-auth/src/lib.rs`), read scope (not in `WRITE_TOOLS`), and the golden fixtures `rust-junosmcp/tests/fixtures/junos-tools-v0.7.json`, `execute-tool-v1.json`, `execute-tool-v1-junos-only.json`.
- AGENTS.md: `just fmt lint test guard e2e` offline; `just security` and `just release-check` before handoff; never real-device tests against production; no inventories, tokens or fetched configs committed.
- Generated data larger than 20 MB raw is written gzip-compressed (`.json.gz`) and decoded with `flate2` at first use; under 20 MB it is plain JSON. Measure in Task 1 and record the sizes in the commit message.

## Review Focus

1. A device whose facts are unreachable (down, auth failure) when `lookup_junos_api` is given `router` — expect a clear error telling the caller to pass `family` + `release` instead, never a panic or empty success. → Task 3 test `lookup_router_unreachable_suggests_family_release`.
2. Version strings the parser has not seen (`25.4X300-D40.2-EVO`, `24.2R2-S5.5`, `26.2R1.7`, `15.1X49-D200`, empty) — expect EVO detection, train extraction, and `None` (unsupported) below 23.1 rather than a wrong train. → Task 2 `train_for_*` table test.
3. RPC arguments carrying XML metacharacters or names not in the catalog input list (`interface = "<x/>"`, `foo = 1`) — expect rejection before anything reaches the device. → Task 4 `rpc_rejects_unknown_arg_and_xml_metachars`.
4. Set-format config under `groups <name> ...` or `apply-groups`, `deactivate`/`delete` lines, comments and blank lines — expect no false rejection on writes. → Task 5 `write_check_skips_groups_and_comments`.
5. Skills directory missing at startup (package installed without it) — expect the server to start with the skills extension off, a warning in the log, and the fallback tools returning an explicit "no skills installed" error. → Task 6 `skills_dir_missing_starts_without_extension`.

---

### Task 1: Catalog generator and generated data

**Files:**
- Create: `scripts/catalog/junos_catalog.py` (pyang plugin), `scripts/catalog/generate.py` (driver), `scripts/catalog/test_generate.py`, `scripts/catalog/fixtures/` (tiny YANG tree in both layouts)
- Create: `rust-junosmcp-core/catalog/SOURCE`, `rust-junosmcp-core/catalog/LICENSE-juniper-yang`, `rust-junosmcp-core/catalog/NOTICE`, `rust-junosmcp-core/catalog/data/{rpc,config}.json[.gz]`
- Modify: `justfile` (add `catalog` recipe), `GLOSSARY.md` (Family gains `junos-evo`; keep the glossary free of implementation detail)

**Interfaces:**
- Produces the JSON contract every later task reads:

```json
// rpc.json
{"source": {"repo": "Juniper/yang", "commit": "<sha>"},
 "trains": ["23.1", "23.2", "23.4", "24.2", "24.4", "25.2", "25.4", "26.2"],
 "families": {"junos-es": {"get-arp-table-information": [
   {"trains": ["23.1", "23.2"], "cli": "show arp", "description": "...",
    "input": [{"name": "interface", "type": "string", "description": "..."}],
    "output": {"arp-table-information": {"arp-table-entry": {"mac-address": {}}}},
    "note": "markdown from catalog/notes/rpc/get-arp-table-information.md, or absent"}]}}}
// config.json — paths are space-joined node names, list keys omitted
{"source": {...}, "trains": [...],
 "families": {"junos-es": {"system name-server": [
   {"trains": [...], "kind": "list", "type": null, "description": "...",
    "range": null, "units": null, "note": "...or absent"}]}}}
```

Each entry is a list of variants; consecutive trains with an identical variant (ignoring `trains`) merge into one.

- [ ] **Step 1: Write failing tests** in `scripts/catalog/test_generate.py` against `scripts/catalog/fixtures/`, which holds one ≥23.4 layout (`23.4/23.4R1/native/conf-and-rpcs/junos-es/{rpc,conf}-with-extensions/models/*.yang`), one 23.1 layout (`23.1/23.1R1/junos-es/...-with-extensions/...`), and one EVO layout (`25.4/25.4R1-EVO/native/conf-and-rpcs/{rpc,conf}-with-extensions/models`): `test_rpc_has_cli_and_input` (`get-arp-table-information` → `cli == "show arp"`, an input named `interface`), `test_output_is_element_tree_only` (no types/descriptions inside `output`), `test_identical_variants_merge_trains` (same RPC in 23.1 and 23.4 → one variant, `trains == ["23.1","23.4"]`), `test_changed_variant_splits`, `test_evo_maps_to_junos_evo`, `test_trains_below_23_1_ignored`, `test_latest_R_within_train_wins` (23.4R2 over 23.4R1), `test_config_paths_flattened` (`system name-server` kind `list`), `test_note_attached` (a `notes/rpc/<name>.md` and `notes/config/<path with spaces as dashes>.md` land in `note`).
- [ ] **Step 2: Run** `uv run --with pyang==2.6.1 --with pytest pytest scripts/catalog -q` — expect failures (modules missing).
- [ ] **Step 3: Implement** the pyang plugin (`emit` walks `i_children` after `uses` resolution; reads the `junos:command` extension via `stmt.search_one(("junos-common-ddl-extensions","command"))`) and `generate.py <yang-checkout> <out-dir> [--notes rust-junosmcp-core/catalog/notes]`, which picks the newest `R` release per train (and `R…-EVO` for `junos-evo`), handles all three layouts, dedups, and writes compressed or plain per the 20 MB rule.
- [ ] **Step 4: Run** the tests — PASS.
- [ ] **Step 5: Add `just catalog`**: sparse-clone `Juniper/yang` at the SHA in `rust-junosmcp-core/catalog/SOURCE` into `target/juniper-yang` (only trains ≥ 23.1, only `junos-es`, `junos-ex`, `common` and the EVO `conf-and-rpcs`), then run `generate.py`. Pin the current `master` SHA in `SOURCE`; copy the repo's `LICENSE` to `LICENSE-juniper-yang`; `NOTICE` names the source and commit.
- [ ] **Step 6: Run `just catalog`** and record raw and compressed sizes plus RPC/path counts per family.
- [ ] **Step 7: Commit twice** — code first (`feat(catalog): generator for the Junos API catalog`), then the generated data alone (`data(catalog): generate from Juniper/yang <sha>`) so the large commit is data only.

### Task 2: Catalog module in rust-junosmcp-core

**Files:**
- Create: `rust-junosmcp-core/src/catalog/mod.rs`, `rust-junosmcp-core/src/catalog/version.rs`, `rust-junosmcp-core/src/catalog/lookup.rs`, `rust-junosmcp-core/tests/fixtures/catalog/{rpc,config}.json` (tiny)
- Modify: `rust-junosmcp-core/src/lib.rs` (`pub mod catalog;`)

**Interfaces:**
- Produces:
  - `pub enum Family { JunosEs, JunosEx, JunosEvo }` with `as_str()` → `"junos-es"`… and `FromStr`.
  - `pub struct Train { pub major: u16, pub minor: u16 }`, `Display` → `"23.4"`.
  - `pub fn train_for(version: &str) -> Option<Train>` — `None` below 23.1 or unparseable.
  - `pub fn family_for(model: &str, version: &str) -> Option<Family>` — `-EVO` in version → `JunosEvo`; model `SRX*`/`vSRX*`/`cSRX*`/`csrx` (case-insensitive) → `JunosEs`; `EX*` → `JunosEx`; else `None`.
  - `pub struct Resolution { pub family: Family, pub requested: Train, pub used: Train, pub warning: Option<String> }` — `used` is the highest catalog train ≤ requested, else the lowest; `warning` set when `used != requested` or the family was not detected exactly ("unverified for this device").
  - `pub struct Catalog` with `pub fn embedded() -> &'static Catalog` (`OnceLock`, `include_bytes!` of the Task 1 data), `pub fn from_json(rpc: &[u8], config: &[u8]) -> Result<Catalog, JmcpError>` (for tests), `pub fn resolve(&self, family: Family, requested: Train, exact_family: bool) -> Resolution`, `pub fn lookup_rpc(&self, res: &Resolution, query: &str, limit: usize) -> Vec<RpcHit>`, `pub fn lookup_config(&self, res: &Resolution, query: &str, limit: usize) -> Vec<ConfigHit>`, `pub fn rpc(&self, res: &Resolution, name: &str) -> Option<RpcHit>`, `pub fn config_path_exists(&self, res: &Resolution, path: &[&str]) -> bool`.
  - `RpcHit`/`ConfigHit` are `Serialize` and carry the variant for `res.used` plus `name`/`path`.
- Query order: exact RPC name; then CLI text (whitespace-normalised, anything after the first `|` dropped, longest catalog CLI that is a prefix of the query); then case-insensitive keyword match over name, CLI and description ranked by number of matched words. Config query: space- or slash-separated path, exact then prefix then keyword.

- [ ] **Step 1: Write failing tests** (`#[cfg(test)]` in each file): `train_for` table — `"23.4R2-S2.1"→23.4`, `"25.4R1.12"→25.4`, `"25.4X300-D40.2-EVO"→25.4`, `"26.2R1.7"→26.2`, `"24.2R2-S5.5"→24.2`, `"22.4R3"→None`, `"15.1X49-D200"→None`, `""→None`; `family_for` table including `("SRX440","25.4X300-D40.2-EVO")→JunosEvo`, `("EX2300-C-12P","23.4R2-S2.1")→JunosEx`, `("csrx","26.2R1.7")→JunosEs`, `("MX204","23.4R1")→None`; `resolve_nearest_lower_train_warns`; `resolve_below_lowest_uses_lowest`; `lookup_by_cli_text_with_pipe` (`"show arp no-resolve | match 10."` → `get-arp-table-information`); `lookup_by_keywords_ranks`; `config_path_exists_ignores_list_keys`; `embedded_catalog_loads` (non-empty for all three families).
- [ ] **Step 2: Run** `cargo test -p rust-junosmcp-core catalog` — FAIL.
- [ ] **Step 3: Implement.** `config_path_exists` walks the path left to right and accepts a token that is not a node name when the previous node is a `list` (it is a key value).
- [ ] **Step 4: Run** the tests — PASS; also `just lint`.
- [ ] **Step 5: Commit** `feat(catalog): embedded catalog with family/train resolution and lookup`.

### Task 3: `lookup_junos_api` tool

**Files:**
- Create: `rust-junosmcp-core/src/tools/lookup_api.rs`
- Modify: `rust-junosmcp-core/src/tools/mod.rs`, `rust-junosmcp/src/server.rs` (tool + tool list near line 895), `rust-junosmcp-auth/src/lib.rs` (`JUNOS_TOOLS`, `KNOWN_TOOLS`), the three golden fixtures, the compact `execute` facade

**Interfaces:**
- Consumes Task 2 API.
- Produces: `pub struct LookupApiArgs { pub router: Option<String>, pub family: Option<String>, pub release: Option<String>, pub query: String, pub kind: LookupKind /* rpc|config, default rpc */, pub limit: Option<u8> /* default 10, max 50 */ }` and `pub async fn handle(args: LookupApiArgs, dm: Arc<DeviceManager>, cache: &DeviceTrainCache) -> Result<Value, JmcpError>`; `pub struct DeviceTrainCache` (router → `(Family, Train, exact_family)`, 15-minute TTL, filled from `dev.facts()` model + version). Also used by Tasks 4 and 5.
- Result JSON: `{"family", "train_requested", "train_used", "warning", "hits": [...]}`.
- Exactly one of `router` or (`family` + `release`) — else a validation error naming both forms.

- [ ] **Step 1: Write failing tests**: `lookup_by_family_release` (fixture catalog), `lookup_requires_router_or_family_release`, `lookup_router_unreachable_suggests_family_release` (inventory pointing at 127.0.0.1:1 → error text contains `family` and `release`), `lookup_unsupported_model_errors`, golden fixture tests failing on the new tool name.
- [ ] **Step 2: Run** `cargo test -p rust-junosmcp-core lookup_api` and `cargo test -p rust-junosmcp golden` — FAIL.
- [ ] **Step 3: Implement** the handler; wire the `#[tool]` in `server.rs` with read scope, router-scope check only when `router` is given, audit like `execute_junos_command`; add to auth registries, fixtures and facade. Description tells the LLM to look up before calling an RPC or writing config.
- [ ] **Step 4: Run** `just test` — PASS.
- [ ] **Step 5: Commit** `feat: lookup_junos_api tool`.

### Task 4: `execute_junos_rpc` tool

**Files:**
- Create: `rust-junosmcp-core/src/tools/execute_rpc.rs`
- Modify: `rust-junosmcp-core/src/tools/mod.rs`, `rust-junosmcp/src/server.rs`, `rust-junosmcp-auth/src/lib.rs`, golden fixtures, facade; `rust-junosmcp/tests/common/fake_netconf.rs` scripts as needed

**Interfaces:**
- Consumes Task 2 `Catalog::rpc`, Task 3 `DeviceTrainCache`.
- Produces: `pub struct ExecuteRpcArgs { pub device: String /* alias router_name, router */, pub rpc: String, pub args: BTreeMap<String, RpcArgValue> /* default empty */, pub timeout: u64 /* default_timeout */ }`, `pub enum RpcArgValue { Flag(bool), Text(String) }`, `pub async fn handle(args, dm, policy, cache) -> Result<Value, JmcpError>`.
- Gate order: name must start with `get-` → RPC must be in the catalog for the family (any train; absent for the resolved train → proceed with a warning) → every arg name must be a catalog input leaf for that variant, `Text` values must not contain `<`, `>`, `&`, `"`, `'` or control characters → build the CLI string (catalog `cli` + ` name value` / ` name` for true flags) and run `policy.check_command` on it exactly as `execute_command.rs` does → `exec.call(rpc, &args)` → same redaction path as `execute_junos_command` output.
- Result JSON: `{"device", "rpc", "train_used", "warning", "output": "<redacted xml>"}`.

- [ ] **Step 1: Write failing tests**: `rpc_get_software_information_returns_reply` (fake_netconf script), `rpc_rejects_non_get` (`clear-arp-table`, `request-system-reboot`), `rpc_rejects_unknown_arg_and_xml_metachars`, `rpc_policy_denial_honoured` (allowlist without `show arp` → denied), `rpc_absent_for_train_warns`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** and wire as in Task 3.
- [ ] **Step 4: Run** `just test` — PASS.
- [ ] **Step 5: Commit** `feat: execute_junos_rpc for read-only catalog RPCs`.

### Task 5: Write-path validation against the catalog

**Files:**
- Create: `rust-junosmcp-core/src/catalog/write_check.rs`
- Modify: the config-load paths of `load_and_commit_config`, `create_junos_change_set`, `render_and_apply_j2_template` (after rendering) and `commit_check_config` (find them under `rust-junosmcp-core/src/tools/`)

**Interfaces:**
- Produces: `pub fn check_config_paths(catalog: &Catalog, res: &Resolution, format: ConfigFormat, text: &str) -> Result<Vec<String> /* warnings */, JmcpError>` — on an exact resolution (`res.warning.is_none()`), unknown paths are `Err` naming each bad line and up to 3 nearest catalog paths (shared prefix, then edit distance on the next token); on a fallback resolution they come back as warnings. `ConfigFormat` is the existing format enum the tools already take; `set` lines check the path after the verb (`set|delete|deactivate|activate|protect|unprotect`), text/XML check top-level and second-level element names only.
- Skipped: lines under `groups`, `apply-groups`, comments (`#`, `/* */`), blank lines, `wildcard`/`replace:` markers.

- [ ] **Step 1: Write failing tests**: `write_check_accepts_known_set_paths` (`set system name-server 1.1.1.2 routing-instance mgmt_junos`), `write_check_rejects_typo_with_suggestion` (`set securty policies ...` → error mentions `security`), `write_check_skips_groups_and_comments`, `write_check_fallback_only_warns`, `write_check_text_format_top_level`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement**; call it from each write path after the device's resolution is known (via `DeviceTrainCache`); a device whose facts cannot be read skips the check with a warning rather than blocking the write.
- [ ] **Step 4: Run** `just test` — PASS.
- [ ] **Step 5: Commit** `feat: reject config paths the device's release does not have`.

### Task 6: Skills (SEP-2640 + fallback tools)

**Files:**
- Create: `skills/junos-netconf-protocol/SKILL.md`, `skills/junos-api-lookup/SKILL.md`, `skills/junos-ex-switching/SKILL.md`, `skills/junos-config-paths/SKILL.md` (fwskillsshare SKILL.md format: YAML front matter `name`, `description`; body under 300 lines; references in `references/`)
- Modify: `rust-junosmcp/Cargo.toml` (rmcp feature `skills-fs`), `rust-junosmcp/src/server.rs` (capabilities line ~2418: `.enable_resources().enable_skills_with_directory_read()` when skills loaded; `list_skills`, `get_skill`, `read_resource_directory`, `list_resources`, `read_resource` delegating to `SkillCatalog`; instructions text ~2411), CLI arg `--skills-dir` (env `JMCP_SKILLS_DIR`, default `/usr/share/rust-junosmcp/skills`), `rust-junosmcp-auth/src/lib.rs`, golden fixtures, `scripts/package-lxc.sh` (install `skills/` to the default dir)
- New tools: `list_junos_skills` → `[{name, description, uri}]`; `read_junos_skill { name, path? /* default SKILL.md */ }` → file text.

**Interfaces:**
- Consumes `rmcp::handler::server::skill_catalog::SkillCatalog::{from_dir, list_skills, get_skill, read_resource, read_resource_directory, resources}`.
- Skill content: `junos-api-lookup` teaches lookup-before-call and `execute_junos_rpc`; `junos-config-paths` carries the verified gotchas from `docs/TESTED-PLATFORMS.md` and the bench run — `name-server … routing-instance mgmt_junos` on boxes with `management-instance`, `show host X routing-instance mgmt_junos` (bare `show host` ignores the management instance), SRX345 24.2/25.4 DNS-in-`mgmt_junos` failure, apply hangs when a commit moves management into or out of `mgmt_junos`; `junos-ex-switching` covers MAC/VLAN/port lookup RPCs; `junos-netconf-protocol` covers NETCONF ops and commit confirmed.

- [ ] **Step 1: Write failing tests**: `skills_list_and_get_over_mcp` (handler with a temp skills dir: `skills/list` returns 4, `skills/get skill://junos-api-lookup/SKILL.md` returns its text), `fallback_tools_match_skills`, `skills_dir_missing_starts_without_extension`, `skills_readable_with_read_only_token` (auth layer does not block `resources/read` or `skills/*` for a valid token; unauthenticated still 401), golden fixture updates.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** server wiring, then write the four skills.
- [ ] **Step 4: Run** `just test`; check with MCP Inspector (`npx @modelcontextprotocol/inspector`) against `just dev`: `skills/list`, `skills/get`, `resources/read skill://…`.
- [ ] **Step 5: Commit** server wiring and skills separately: `feat: serve Junos skills (SEP-2640) with fallback tools`, `docs(skills): four Junos skills`.

### Task 7: Overlay notes

**Files:**
- Create: `rust-junosmcp-core/catalog/notes/rpc/<rpc-name>.md`, `rust-junosmcp-core/catalog/notes/config/<path-with-dashes>.md`
- Regenerate: `rust-junosmcp-core/catalog/data/*` via `just catalog`

**Interfaces:**
- Note format: `## Example` (an `execute_junos_rpc` call), `## Reply fields that matter`, `## Version gotchas` (only verified ones, each naming model + release), `## Reference` (Juniper doc URL). No text copied from Juniper HTML docs.
- Must include: every RPC the SRX workflows call (`grep -rhoE 'call\("[a-z-]+"' rust-junosmcp-srx-core/src` plus the RPCs behind their `show` commands); EX: `get-ethernet-switching-table-information`, `get-vlan-information`, `get-interface-information`, `get-lldp-neighbors-information`; system: `get-software-information`, `get-system-uptime-information`, `get-commit-information`, `get-route-information`, `get-arp-table-information`; config notes for `system name-server`, `system management-instance`, `system services netconf`, `security policies`. Add more toward ~100 only where the note says something the YANG description does not.

- [ ] **Step 1: Write a failing test** in `scripts/catalog/test_generate.py`: `test_every_note_names_a_catalog_entry` (a note whose RPC/path is absent from every family fails generation).
- [ ] **Step 2: Write the notes; run `just catalog`** — the test passes and `note` fields appear.
- [ ] **Step 3: Commit** notes, then regenerated data: `docs(catalog): overlay notes`, `data(catalog): regenerate with notes`.

### Task 8: Lab verification and offline fixtures

**Files:**
- Modify: `rust-junosmcp-core/tests/integration_real_device.rs` (ignored tests), `rust-junosmcp/tests/common/fake_netconf.rs` scripts, `rust-junosmcp/tests/fixtures/` (captured replies, redacted)

**Interfaces:**
- Lab targets come from `scripts/bench/` `load_lab_target` (bench devices only — EX2300, SRX1600, SRX440 EVO, vSRX; never prod). For each device: facts → `Resolution` exact; for 10 catalog RPCs per family, `| display xml rpc` of the catalog CLI returns that RPC name, and `execute_junos_rpc` reply root matches the catalog `output` root.

- [ ] **Step 1: Write the ignored tests**; run `CONFIRM_LAB_INTEGRATION=yes just integration` against the bench lab.
- [ ] **Step 2: Capture** one reply per family into fixtures (run through the redactor; no hostnames, serials or addresses beyond RFC 5737/bench ranges) and add offline tests replaying them.
- [ ] **Step 3: Record** any catalog-vs-device mismatch as an overlay note or a TODO in the rustjunosmcp TODO list.
- [ ] **Step 4: Commit** `test: lab verification of the Junos API catalog`.

### Task 9: Docs and release checks

**Files:**
- Modify: `CHANGELOG.md` (Unreleased: the four new tools, skills extension, `--skills-dir`, write-path rejection as a behavior change), `docs/REFERENCE.md` (tools + catalog), `docs/TESTED-PLATFORMS.md` (catalog verified per model)

- [ ] **Step 1: Write the docs.**
- [ ] **Step 2: Run** `just fmt lint test guard e2e`, `just security`, `just release-check`; report embedded catalog size and release binary growth vs `main`.
- [ ] **Step 3: Commit** `docs: catalog, lookup, RPC and skills reference`.

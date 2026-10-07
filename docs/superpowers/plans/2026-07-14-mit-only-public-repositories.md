# MIT-Only Public Repositories Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make all eight active public `fastrevmd-lab` repositories MIT-only, remove non-MIT material from `fwskillsshare`, and update and deploy the matching MIT-only claims on `mechub.org`.

**Architecture:** Treat each repository as an independent, sequentially integrated unit. In every repository, preserve the existing MIT text under a canonical root `LICENSE`, update only current project-owned license surfaces, verify with a red/green repository scan plus native checks, merge a ready pull request, and remove its worktree before opening the next one. Update and deploy the MechHub site only after GitHub reports MIT for all eight public repositories.

**Tech Stack:** Git worktrees, GitHub CLI, Rust/Cargo/Just, Node.js/npm/Vitest/Vite, Python/pytest/ruff/mypy/build, Bash, static HTML, Trivy, GitHub license APIs, and the existing MechHub LXC deployment recipe.

## Global Constraints

- Public repository scope is exactly `firewallintentconverter`, `fwconfigsanitizer`, `fwskillsshare`, `rustez`, `rustjunosmcp`, `rustnetconf`, `rustpanosmcp`, and `srxsync`.
- Process repositories sequentially. Merge and clean up one repository worktree before creating the next repository worktree.
- Use project-local `.worktrees/mit-only-license` directories on branch `agent/mit-only-license`.
- Before creating a project-local worktree, verify `.worktrees/` is ignored. For `fwconfigsanitizer`, `fwskillsshare`, and `srxsync`, commit `.worktrees/` to `.gitignore` before creating the worktree.
- Preserve each repository's existing `LICENSE-MIT` text and copyright line by renaming it to `LICENSE`; do not synthesize new copyright holders.
- Delete the project-owned `LICENSE-APACHE` and change current project-owned metadata, README text, badges, contribution terms, OCI labels, and packaging to `MIT`.
- Preserve historical plans/specifications and third-party dependency license records and allowlists, including Apache-2.0 dependency entries in npm lockfiles and Rust `deny.toml` files.
- Do not hand-edit generated dependency metadata. Regenerate only the npm root-project lockfile entry through npm.
- Never run ignored real-device tests or contact production network devices. Report them as skipped.
- Use ready pull requests and normal merge commits. Do not force-push or use administrative merge overrides.
- The MechHub deployment is limited to the existing `just deploy` recipe and LXC 901. Do not change Cloudflare, nginx, TLS, networking, Proxmox configuration, or any other guest.
- Before every commit and merge, run fresh verification and inspect the full diff. Do not infer success from an earlier command.
- Design source: `docs/superpowers/specs/2026-07-14-mit-only-public-repositories-design.md`.

## File Map

- `rustjunosmcp`: `LICENSE`, `Cargo.toml`, `Dockerfile`, and `README.md` define current source, crate, image, and documentation licensing.
- `rustez`: `LICENSE`, three crate manifests, `rustez-py/pyproject.toml`, and `README.md` define Rust and Python package licensing.
- `rustnetconf`: `LICENSE`, three crate manifests, `README.md`, and `TODOS.md` define package and current release-tracking licensing.
- `rustpanosmcp`: `LICENSE`, workspace/fuzz manifests, `Dockerfile`, `README.md`, and `scripts/build-release.sh` define crate, image, documentation, and release-archive licensing.
- `firewallintentconverter`: `LICENSE`, npm metadata, root lockfile metadata, and `README.md` define web-package and documentation licensing.
- `fwconfigsanitizer`: `LICENSE`, `README.md`, and `CONTRIBUTING.md` define the project's current licensing and contribution terms.
- `srxsync`: `LICENSE`, `pyproject.toml`, and `README.md` define Python source/distribution and contribution licensing.
- `fwskillsshare`: `LICENSE`, `README.md`, installer inventory, package validator, retained cross-skill metadata, and the `skills/` directory define the distributable catalog. Fourteen named subtrees and `NOTICE` are removed.
- `mechubsite`: `index.html` publishes license copy and badges; `test_links.py` prevents the active site from returning to mixed-license wording.

---

### Task 1: Relicense `rustjunosmcp` and integrate its rollout documentation

**Repository:** `/home/mharman/Projects/RustJunosMCP`

**Files:**
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `Cargo.toml:8`
- Modify: `Dockerfile:16`
- Modify: `README.md:640-643`
- Already created: `docs/superpowers/specs/2026-07-14-mit-only-public-repositories-design.md`
- Already created: `docs/superpowers/plans/2026-07-14-mit-only-public-repositories.md`

**Interfaces:**
- Consumes: the approved cross-repository design and existing `LICENSE-MIT` content.
- Produces: the first merged MIT-only public repository and the committed execution record used by all later tasks.

- [ ] **Step 1: Confirm the existing isolated worktree and clean baseline**

Run:

```bash
cd /home/mharman/Projects/RustJunosMCP/.worktrees/mit-only-license
git status -sb
git branch --show-current
~/.local/bin/mise exec just@1.42.4 -- just test
```

Expected: branch `agent/mit-only-license`; only the committed design/plan history is present; the workspace test suite exits 0. Ignored real-device suites remain ignored.

- [ ] **Step 2: Run the MIT-only acceptance check and confirm it fails before editing**

Run:

```bash
cd /home/mharman/Projects/RustJunosMCP/.worktrees/mit-only-license
python3 - <<'PY'
from pathlib import Path

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
assert 'license    = "MIT"' in Path("Cargo.toml").read_text()
assert 'org.opencontainers.image.licenses="MIT"' in Path("Dockerfile").read_text()
readme = Path("README.md").read_text()
assert "Licensed under [MIT](LICENSE)." in readme
PY
```

Expected: FAIL on the missing `LICENSE` assertion.

- [ ] **Step 3: Apply the minimal MIT-only source and metadata changes**

Run:

```bash
cd /home/mharman/Projects/RustJunosMCP/.worktrees/mit-only-license
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Apply these exact replacements:

```diff
--- a/Cargo.toml
+++ b/Cargo.toml
@@
-license    = "MIT OR Apache-2.0"
+license    = "MIT"
--- a/Dockerfile
+++ b/Dockerfile
@@
-LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
+LABEL org.opencontainers.image.licenses="MIT"
--- a/README.md
+++ b/README.md
@@
 ## License

-Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
+Licensed under [MIT](LICENSE).
```

- [ ] **Step 4: Re-run the targeted acceptance check and inspect the diff**

Run the Step 2 Python command again, then:

```bash
git diff --check
git diff -- LICENSE Cargo.toml Dockerfile README.md
git status -sb
```

Expected: the Python command and `git diff --check` exit 0; the diff contains only the MIT-only changes plus the already approved rollout documentation.

- [ ] **Step 5: Run all repository-required checks**

Run:

```bash
~/.local/bin/mise exec just@1.42.4 -- just fmt
~/.local/bin/mise exec just@1.42.4 -- just lint
~/.local/bin/mise exec just@1.42.4 -- just test
~/.local/bin/mise exec just@1.42.4 -- just guard
~/.local/bin/mise exec just@1.42.4 -- just e2e
~/.local/bin/mise exec just@1.42.4 -- just security
~/.local/bin/mise exec just@1.42.4 -- just release-check
```

Expected: every command exits 0. Do not run `just integration`; it requires `CONFIRM_LAB_INTEGRATION=yes` and real devices.

- [ ] **Step 6: Commit the repository license change**

Run:

```bash
git diff --check
git status -sb
git add LICENSE Cargo.toml Dockerfile README.md
git commit -m "chore: adopt MIT-only licensing"
```

Expected: pre-commit hooks pass and the commit contains the license rename/removal plus current metadata/documentation updates. The design and plan remain in their earlier documentation commits.

- [ ] **Step 7: Push, open a ready pull request, merge after checks, and clean up**

Run:

```bash
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/rustjunosmcp --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Adopts the repository's existing MIT terms as the sole current project license. Updates Cargo metadata, the OCI label, and active documentation while preserving historical records and third-party dependency license data. Offline, security, release, and CLI checks are included in the verification."
gh pr checks --repo mechubsec/rustjunosmcp --watch
gh pr merge --repo mechubsec/rustjunosmcp --merge --delete-branch
cd /home/mharman/Projects/RustJunosMCP
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged into `main`, GitHub checks are green, the project-local worktree is removed, and local `main` is clean and current.

---

### Task 2: Relicense `rustez`

**Repository:** `/home/mharman/Projects/rustEZ`

**Files:**
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `rustez/Cargo.toml:7`
- Modify: `rustez-cli/Cargo.toml:7`
- Modify: `rustez-py/Cargo.toml:7`
- Modify: `rustez-py/pyproject.toml:10`
- Modify: `README.md:249-252`

**Interfaces:**
- Consumes: the repository's existing MIT text and its CI command contract.
- Produces: MIT-only Rust core, CLI, and Python package metadata.

- [ ] **Step 1: Create the isolated worktree and establish the baseline**

Run:

```bash
cd /home/mharman/Projects/rustEZ
git status -sb
git pull --ff-only origin main
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
cargo fetch --locked
cargo install cargo-audit --locked
python3 scripts/check_versions.py
cargo check --workspace --locked
cargo test -p rustez --locked
```

Expected: the original checkout is clean, `.worktrees/` is ignored, and all baseline commands exit 0.

- [ ] **Step 2: Prove the MIT-only package contract is initially red**

Run:

```bash
python3 - <<'PY'
from pathlib import Path

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
for name in ["rustez/Cargo.toml", "rustez-cli/Cargo.toml", "rustez-py/Cargo.toml"]:
    assert 'license = "MIT"' in Path(name).read_text(), name
assert 'license = "MIT"' in Path("rustez-py/pyproject.toml").read_text()
assert "Licensed under [MIT](LICENSE)." in Path("README.md").read_text()
PY
```

Expected: FAIL on the missing `LICENSE` assertion.

- [ ] **Step 3: Rename the license and update all package declarations**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

In each of `rustez/Cargo.toml`, `rustez-cli/Cargo.toml`, and `rustez-py/Cargo.toml`, make this exact replacement:

```toml
license = "MIT"
```

In `rustez-py/pyproject.toml`, make the project field:

```toml
license = "MIT"
```

Replace the README license section with:

```markdown
## License

Licensed under [MIT](LICENSE).
```

- [ ] **Step 4: Run targeted and native verification**

Run the Step 2 Python command again, then:

```bash
git diff --check
python3 scripts/check_versions.py
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test -p rustez --locked
cargo clippy -p rustez -- -D warnings
cargo clippy -p rustez-py -- -D warnings
cargo doc -p rustez --no-deps
cargo audit --ignore RUSTSEC-2023-0071
```

Expected: every command exits 0. The ignored vSRX integration tests are not run.

- [ ] **Step 5: Commit, publish, merge, and clean up**

Run:

```bash
git status -sb
git add LICENSE rustez/Cargo.toml rustez-cli/Cargo.toml rustez-py/Cargo.toml rustez-py/pyproject.toml README.md
git commit -m "chore: adopt MIT-only licensing"
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/rustez --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Makes MIT the sole current license across the Rust library, CLI, Python bindings, and active documentation. Historical records and dependency license data remain unchanged; real-device tests were not run."
gh pr checks --repo mechubsec/rustez --watch
gh pr merge --repo mechubsec/rustez --merge --delete-branch
cd /home/mharman/Projects/rustEZ
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged, `main` is current, and the worktree and local feature branch are removed.

---

### Task 3: Relicense `rustnetconf`

**Repository:** `/home/mharman/Projects/rustnetconf`

**Files:**
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `Cargo.toml:11`
- Modify: `rustnetconf-cli/Cargo.toml:7`
- Modify: `rustnetconf-yang/Cargo.toml:7`
- Modify: `README.md:18,597-600`
- Modify: `TODOS.md:127`

**Interfaces:**
- Consumes: the existing MIT license and three-crate workspace metadata.
- Produces: MIT-only crate metadata, README badge/text, and current release tracking.

- [ ] **Step 1: Create the isolated worktree and run the baseline**

Run:

```bash
cd /home/mharman/Projects/rustnetconf
git status -sb
git pull --ff-only origin main
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
cargo fetch --locked
cargo install cargo-audit --locked
cargo build --workspace --all-features --locked
cargo test --workspace --all-features --locked
```

Expected: the baseline build and tests exit 0 without live-device environment variables.

- [ ] **Step 2: Confirm the new license contract fails before editing**

Run:

```bash
python3 - <<'PY'
from pathlib import Path

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
for name in ["Cargo.toml", "rustnetconf-cli/Cargo.toml", "rustnetconf-yang/Cargo.toml"]:
    assert 'license = "MIT"' in Path(name).read_text(), name
readme = Path("README.md").read_text()
assert 'alt="License: MIT"' in readme
assert "\nMIT\n" in readme
assert "Finalize crates.io account setup" in Path("TODOS.md").read_text()
PY
```

Expected: FAIL on the missing `LICENSE` assertion.

- [ ] **Step 3: Apply MIT-only metadata and current-documentation changes**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Set `license = "MIT"` in all three Cargo manifests. Replace the README badge with:

```html
<a href="#license"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-262B38.svg"></a>
```

Replace the README license section with:

```markdown
## License

MIT
```

Replace the active release dependency in `TODOS.md` with:

```markdown
**Depends on:** Finalize crates.io account setup
```

- [ ] **Step 4: Verify the workspace and supply-chain checks**

Run the Step 2 Python command again, then:

```bash
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-features --locked --verbose
cargo test --workspace --all-features --locked --verbose
cargo audit
```

Expected: all commands exit 0; live-device tests remain inactive because no lab environment variables are supplied.

- [ ] **Step 5: Commit, publish, merge, and clean up**

Run:

```bash
git add LICENSE Cargo.toml rustnetconf-cli/Cargo.toml rustnetconf-yang/Cargo.toml README.md TODOS.md
git commit -m "chore: adopt MIT-only licensing"
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/rustnetconf --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Makes MIT the sole current license for the rustnetconf workspace and active documentation. Historical plans and all third-party dependency license data remain unchanged; live-device tests were not run."
gh pr checks --repo mechubsec/rustnetconf --watch
gh pr merge --repo mechubsec/rustnetconf --merge --delete-branch
cd /home/mharman/Projects/rustnetconf
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged and local worktree state is clean.

---

### Task 4: Relicense `rustpanosmcp` and its release artifacts

**Repository:** `/home/mharman/Projects/rust-panosmcp`

**Files:**
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `Cargo.toml:14`
- Modify: `fuzz/Cargo.toml:7`
- Modify: `Dockerfile:30`
- Modify: `README.md:323-326`
- Modify: `scripts/build-release.sh:39`
- Preserve: `deny.toml` and `fuzz/deny.toml` Apache-2.0 dependency allowlist entries

**Interfaces:**
- Consumes: workspace-inherited license metadata and the deterministic release builder.
- Produces: MIT-only crate/fuzz metadata, image label, docs, and release archives containing one `LICENSE`.

- [ ] **Step 1: Create the worktree and run a packaging-aware baseline**

Run:

```bash
cd /home/mharman/Projects/rust-panosmcp
git status -sb
git pull --ff-only origin main
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
cargo fetch --locked
cargo install cargo-audit --locked
cargo install cargo-deny --locked
cargo build --workspace --locked
cargo test --workspace --locked
scripts/verify-packaging.sh
```

Expected: baseline commands exit 0.

- [ ] **Step 2: Run a failing source-and-package license assertion**

Run:

```bash
python3 - <<'PY'
from pathlib import Path

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
assert 'license = "MIT"' in Path("Cargo.toml").read_text()
assert 'license = "MIT"' in Path("fuzz/Cargo.toml").read_text()
assert 'org.opencontainers.image.licenses="MIT"' in Path("Dockerfile").read_text()
assert 'install -m 0644 LICENSE README.md SECURITY.md "$PKG/"' in Path("scripts/build-release.sh").read_text()
assert "Licensed under [MIT](LICENSE)." in Path("README.md").read_text()
PY
```

Expected: FAIL on the missing `LICENSE` assertion.

- [ ] **Step 3: Update source, image, documentation, and release packaging**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Apply these final values:

```toml
# Cargo.toml [workspace.package]
license = "MIT"

# fuzz/Cargo.toml [package]
license = "MIT"
```

```dockerfile
org.opencontainers.image.licenses="MIT"
```

```bash
install -m 0644 LICENSE README.md SECURITY.md "$PKG/"
```

```markdown
## License

Licensed under [MIT](LICENSE).
```

Do not edit either `deny.toml`; Apache-2.0 remains allowed for third-party dependencies.

- [ ] **Step 4: Verify source policy and the contents of a built release archive**

Run the Step 2 Python command again, then:

```bash
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo audit --deny warnings
cargo audit --file fuzz/Cargo.lock --no-fetch --deny warnings
cargo deny check licenses bans sources
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check licenses bans sources
scripts/verify-packaging.sh
PANOSMCP_ALLOW_DIRTY=1 PANOSMCP_OUTPUT_DIR=dist scripts/verify-reproducible-build.sh
archive=$(find dist -maxdepth 1 -name 'rust-panosmcp-*.tar.gz' -type f -print -quit)
tar -tzf "$archive" | grep -E '/LICENSE$'
if tar -tzf "$archive" | grep -Eq '/LICENSE-(MIT|APACHE)$'; then exit 1; fi
```

Expected: all commands exit 0; the archive has one `LICENSE` and neither old license filename.

- [ ] **Step 5: Commit, publish, merge, and clean up**

Run:

```bash
git add LICENSE Cargo.toml fuzz/Cargo.toml Dockerfile README.md scripts/build-release.sh
git commit -m "chore: adopt MIT-only licensing"
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/rustpanosmcp --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Makes MIT the sole current project license across workspace metadata, fuzz metadata, container labels, documentation, and deterministic release archives. Dependency allowlists remain unchanged."
gh pr checks --repo mechubsec/rustpanosmcp --watch
gh pr merge --repo mechubsec/rustpanosmcp --merge --delete-branch
cd /home/mharman/Projects/rust-panosmcp
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the merged default branch produces MIT-only source and release metadata.

---

### Task 5: Relicense `firewallintentconverter`

**Repository:** `/home/mharman/Projects/firewallintentconverter`

**Files:**
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `package.json:5`
- Regenerate: `package-lock.json` root package license entry
- Modify: `README.md:18,542-551`

**Interfaces:**
- Consumes: the existing MIT text and npm lockfile generation.
- Produces: an MIT-only npm package declaration, README badge/terms, and unchanged third-party dependency licenses.

- [ ] **Step 1: Create the worktree and run the web/bridge baseline**

Run:

```bash
cd /home/mharman/Projects/firewallintentconverter
git status -sb
git pull --ff-only origin main
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
npm ci
npx vitest run
for test_file in tests/*.test.js; do if grep -q "from 'vitest'" "$test_file"; then continue; fi; node "$test_file"; done
npm run build
python3 -m venv venv
venv/bin/python -m pip install -r tools/pyez-bridge/requirements.txt
venv/bin/python -m unittest discover tools/pyez-bridge/tests -v
```

Expected: all CI-equivalent baseline commands exit 0.

- [ ] **Step 2: Confirm the new project-license contract is red**

Run:

```bash
node --input-type=module <<'JS'
import fs from 'node:fs';
import assert from 'node:assert/strict';

assert.equal(fs.existsSync('LICENSE'), true);
assert.equal(fs.existsSync('LICENSE-MIT'), false);
assert.equal(fs.existsSync('LICENSE-APACHE'), false);
const pkg = JSON.parse(fs.readFileSync('package.json'));
const lock = JSON.parse(fs.readFileSync('package-lock.json'));
assert.equal(pkg.license, 'MIT');
assert.equal(lock.packages[''].license, 'MIT');
const readme = fs.readFileSync('README.md', 'utf8');
assert.match(readme, /License-MIT-blue\.svg/);
assert.match(readme, /Licensed under \[MIT\]\(LICENSE\)\./);
assert.match(readme, /contribution.*MIT License/is);
JS
```

Expected: FAIL because `LICENSE` does not yet exist.

- [ ] **Step 3: Apply MIT-only project metadata and regenerate the root lock entry**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Set the package field to:

```json
"license": "MIT"
```

Regenerate the lockfile root entry through npm:

```bash
npm install --package-lock-only --ignore-scripts
```

Use this README badge:

```html
<a href="#license"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
```

Use these final license/contribution paragraphs:

```markdown
## License

Licensed under [MIT](LICENSE).

Configuration output produced by this tool is a **migration draft requiring review**, never production-ready. Always validate generated configurations against vendor documentation and your own change-management process before deployment. No warranty is provided, express or implied.

### Contribution

Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).
```

- [ ] **Step 4: Re-run targeted and CI-equivalent verification**

Run the Step 2 Node command again, then:

```bash
git diff --check
npm ci
npx vitest run
for test_file in tests/*.test.js; do if grep -q "from 'vitest'" "$test_file"; then continue; fi; node "$test_file"; done
npm run build
venv/bin/python -m unittest discover tools/pyez-bridge/tests -v
```

Expected: every command exits 0. Confirm in the diff that only `package-lock.json`'s root `packages[""]` license changed; dependency entries remain untouched.

- [ ] **Step 5: Commit, publish, merge, and clean up**

Run:

```bash
git add LICENSE package.json package-lock.json README.md
git commit -m "chore: adopt MIT-only licensing"
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/firewallintentconverter --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Makes MIT the sole current project license in source, npm metadata, lockfile root metadata, README badge, and contribution terms. Third-party dependency license entries remain unchanged."
gh pr checks --repo mechubsec/firewallintentconverter --watch
gh pr merge --repo mechubsec/firewallintentconverter --merge --delete-branch
cd /home/mharman/Projects/firewallintentconverter
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged and local state is clean.

---

### Task 6: Relicense `fwconfigsanitizer`

**Repository:** `/home/mharman/Projects/fwconfigsanitizer`

**Files:**
- Modify prerequisite: `.gitignore`
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `README.md:104-117`
- Modify: `CONTRIBUTING.md:24`

**Interfaces:**
- Consumes: the existing MIT text and single-file static application layout.
- Produces: MIT-only source documentation and contribution terms without changing `index.html` runtime behavior.

- [ ] **Step 1: Commit the worktree-ignore prerequisite, then create isolation**

Run:

```bash
cd /home/mharman/Projects/fwconfigsanitizer
git status -sb
git pull --ff-only origin main
```

Apply this exact prerequisite patch before committing:

```diff
--- a/.gitignore
+++ b/.gitignore
@@
+
+# Codex isolated worktrees
+.worktrees/
```

Then run:

```bash
git add .gitignore
git commit -m "chore: ignore project worktrees"
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
git diff --check HEAD^
```

Expected: the prerequisite commit exists before worktree creation, `.worktrees/` is ignored, and the feature worktree is on `agent/mit-only-license`.

- [ ] **Step 2: Confirm the MIT-only documentation contract is red**

Run:

```bash
python3 - <<'PY'
from pathlib import Path

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
assert "Licensed under [MIT](LICENSE)." in Path("README.md").read_text()
assert "contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE)" in Path("CONTRIBUTING.md").read_text()
PY
```

Expected: FAIL because `LICENSE` is missing.

- [ ] **Step 3: Rename the license and replace active license/contribution text**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Replace the README license subsection with:

```markdown
### License

Licensed under [MIT](LICENSE).
```

Replace the final contribution sentence in `CONTRIBUTING.md` with:

```markdown
Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).
```

- [ ] **Step 4: Verify the static repository and commit**

Run the Step 2 Python command again, then:

```bash
git diff --check
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

HTMLParser().feed(Path("index.html").read_text())
PY
git status -sb
git add .gitignore LICENSE README.md CONTRIBUTING.md
git commit -m "chore: adopt MIT-only licensing"
```

Expected: checks pass; `index.html` remains unmodified; the branch contains the prerequisite and license commits.

- [ ] **Step 5: Publish, merge, and clean up**

Run:

```bash
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/fwconfigsanitizer --base main --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Adds the required project-worktree ignore and makes MIT the sole current source and contribution license. Runtime application code is unchanged."
gh pr view --repo mechubsec/fwconfigsanitizer --json url,mergeStateStatus,statusCheckRollup
gh pr merge --repo mechubsec/fwconfigsanitizer --merge --delete-branch
cd /home/mharman/Projects/fwconfigsanitizer
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the merged repository is MIT-only and its normal checkout is clean.

---

### Task 7: Relicense `srxsync` and verify Python distribution contents

**Repository:** `/home/mharman/Projects/srxsync`

**Files:**
- Create local checkout: `/home/mharman/Projects/srxsync`
- Modify prerequisite: `.gitignore`
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Modify: `pyproject.toml:9-10`
- Modify: `README.md:231-243`

**Interfaces:**
- Consumes: the remote `master` branch, existing MIT text, setuptools metadata, and unit-test suite.
- Produces: MIT-only Python metadata and sdist/wheel license contents.

- [ ] **Step 1: Clone, commit the ignore prerequisite, and create the worktree**

Run:

```bash
cd /home/mharman/Projects
gh repo clone mechubsec/srxsync srxsync
cd /home/mharman/Projects/srxsync
git status -sb
git pull --ff-only origin master
```

Apply this exact prerequisite patch before committing:

```diff
--- a/.gitignore
+++ b/.gitignore
@@
+
+# Codex isolated worktrees
+.worktrees/
```

Then run:

```bash
git add .gitignore
git commit -m "chore: ignore project worktrees"
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license master
cd .worktrees/mit-only-license
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]' build
.venv/bin/python -m pytest -m 'not integration'
```

Expected: the clone is on `master`, the prerequisite commit precedes worktree creation, and unit tests pass without contacting a vSRX.

- [ ] **Step 2: Prove Python metadata is not yet MIT-only**

Run:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import tomllib

assert Path("LICENSE").is_file()
assert not Path("LICENSE-MIT").exists()
assert not Path("LICENSE-APACHE").exists()
project = tomllib.loads(Path("pyproject.toml").read_text())["project"]
assert project["license"] == "MIT"
assert project["license-files"] == ["LICENSE"]
assert "Licensed under [MIT](LICENSE)." in Path("README.md").read_text()
PY
```

Expected: FAIL because `LICENSE` does not exist.

- [ ] **Step 3: Update source, Python metadata, README, and contribution terms**

Run:

```bash
git mv LICENSE-MIT LICENSE
git rm LICENSE-APACHE
```

Use these project fields:

```toml
license = "MIT"
license-files = ["LICENSE"]
```

Replace the README ending with:

```markdown
## License

Licensed under [MIT](LICENSE).

## Contributing

Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).
```

- [ ] **Step 4: Verify code quality and built distributions**

Run the Step 2 Python command again, then:

```bash
git diff --check
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy srxsync
.venv/bin/python -m pytest -m 'not integration'
.venv/bin/python -m build
.venv/bin/python - <<'PY'
from pathlib import Path
import tarfile
import zipfile

sdist = next(Path("dist").glob("*.tar.gz"))
wheel = next(Path("dist").glob("*.whl"))
with tarfile.open(sdist) as archive:
    names = archive.getnames()
    assert any(name.endswith("/LICENSE") for name in names)
    assert not any(name.endswith(("/LICENSE-MIT", "/LICENSE-APACHE")) for name in names)
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    assert any(name.endswith(".dist-info/licenses/LICENSE") for name in names)
    assert not any(name.endswith(("LICENSE-MIT", "LICENSE-APACHE")) for name in names)
PY
```

Expected: all commands pass; integration tests are deselected; both distributions contain `LICENSE` and no old license files.

- [ ] **Step 5: Commit, publish, merge, and clean up**

Run:

```bash
git add .gitignore LICENSE pyproject.toml README.md
git commit -m "chore: adopt MIT-only licensing"
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/srxsync --base master --head agent/mit-only-license --title "chore: adopt MIT-only licensing" --body "Adds the required worktree ignore and makes MIT the sole current source, Python package, distribution, documentation, and contribution license. Real-device integration tests were not run."
gh pr view --repo mechubsec/srxsync --json url,mergeStateStatus,statusCheckRollup
gh pr merge --repo mechubsec/srxsync --merge --delete-branch
cd /home/mharman/Projects/srxsync
git pull --ff-only origin master
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged into `master`; the worktree and feature branch are removed.

---

### Task 8: Remove non-MIT material and relicense `fwskillsshare`

**Repository:** `/home/mharman/Projects/fwskillsshare`

**Files:**
- Modify prerequisite: `.gitignore`
- Rename: `LICENSE-MIT` → `LICENSE`
- Delete: `LICENSE-APACHE`
- Delete: `NOTICE`
- Delete subtrees: `skills/cis-controls-ngfw-compliance/`, `skills/cmmc-nist-800-171-ngfw-compliance/`, `skills/hipaa-ngfw-compliance/`, `skills/iso27001-ngfw-compliance/`, `skills/pci-ngfw-compliance/`, `skills/soc2-ngfw-compliance/`, `skills/srx-advpn/`, `skills/srx-autovpn-full-tunnel/`, `skills/srx-dynamic-ip-feed/`, `skills/srx-ipsec-hub-spoke/`, `skills/srx-mnha/`, `skills/srx-mpls-in-flow/`, `skills/srx-nat/`, and `skills/srx-policy/`
- Modify: `README.md`
- Modify: `TODO.md`
- Modify: `install.sh`
- Modify: `scripts/check-skill-packages.py:64-66,112-113`
- Modify: `skills/firewall-best-practices-audit/SKILL.md:13,22,28,103`
- Modify: `skills/firewall-config-conversion/references/emit-srx.md:8-9,25`
- Modify: `skills/parsing-srx-configs/SKILL.md:24-29,44,48,412`

**Interfaces:**
- Consumes: 21 current skill packages, their license metadata, dynamic package validation, installer inventory, and the user decision to remove all non-MIT material.
- Produces: exactly seven MIT skill packages, an installer that exposes only parser/tooling families, no source-derived notice, and no dangling reference to a removed skill.

- [ ] **Step 1: Commit the ignore prerequisite, create the worktree, and run the 21-skill baseline**

Run:

```bash
cd /home/mharman/Projects/fwskillsshare
git status -sb
git pull --ff-only origin main
```

Apply this exact prerequisite patch before committing:

```diff
--- a/.gitignore
+++ b/.gitignore
@@
+
+# Codex isolated worktrees
+.worktrees/
```

Then run:

```bash
git add .gitignore
git commit -m "chore: ignore project worktrees"
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
~/.local/bin/mise exec -- just setup
~/.local/bin/mise exec -- just lint
~/.local/bin/mise exec -- just test
./install.sh --list
```

Expected: baseline validation reports 21 portable packages and the installer reports 21 skills.

- [ ] **Step 2: Add the new seven-package expectation and verify the test fails**

Change this assertion in `scripts/check-skill-packages.py`:

```python
if len(skill_files) != 7:
    errors.append(f"expected 7 skills, found {len(skill_files)}")
```

Run:

```bash
python3 scripts/check-skill-packages.py
```

Expected: FAIL with `expected 7 skills, found 21`.

- [ ] **Step 3: Delete every non-MIT subtree and obsolete provenance file**

Run:

```bash
git rm -r \
  skills/cis-controls-ngfw-compliance \
  skills/cmmc-nist-800-171-ngfw-compliance \
  skills/hipaa-ngfw-compliance \
  skills/iso27001-ngfw-compliance \
  skills/pci-ngfw-compliance \
  skills/soc2-ngfw-compliance \
  skills/srx-advpn \
  skills/srx-autovpn-full-tunnel \
  skills/srx-dynamic-ip-feed \
  skills/srx-ipsec-hub-spoke \
  skills/srx-mnha \
  skills/srx-mpls-in-flow \
  skills/srx-nat \
  skills/srx-policy
git rm NOTICE LICENSE-APACHE
git mv LICENSE-MIT LICENSE
```

Expected: exactly the 14 approved subtrees and two obsolete top-level files are deleted; the existing MIT text is preserved as `LICENSE`.

- [ ] **Step 4: Reduce the installer to parser and tooling families only**

In `install.sh`, retain exactly these arrays:

```bash
declare -a PARSERS=(
    "parsing-cisco-configs"
    "parsing-fortinet-configs"
    "parsing-palo-configs"
    "parsing-srx-configs"
)

declare -a TOOLING=(
    "firewall-best-practices-audit"
    "firewall-config-conversion"
    "firewall-config-diff"
)
```

Make `get_all_skills` and `get_family_skills` exactly:

```bash
get_all_skills() {
    local -a all_skills=()
    all_skills+=("${PARSERS[@]}")
    all_skills+=("${TOOLING[@]}")
    echo "${all_skills[@]}"
}

get_family_skills() {
    local family="$1"
    case "$family" in
        parsers)
            echo "${PARSERS[@]}"
            ;;
        tooling)
            echo "${TOOLING[@]}"
            ;;
        *)
            echo -e "${C_RED}Error: Unknown family '$family'${C_RESET}" >&2
            echo "Valid families: parsers, tooling" >&2
            exit 1
            ;;
    esac
}
```

Update `print_inventory` and `interactive_skill_selection` to render only `Parsers` and `Tooling`; remove the SRX and Compliance loops. Change every help/list total from 21 to 7, change the `--family` help to `parsers | tooling`, and replace removed-skill examples with:

```text
./install.sh --skill parsing-srx-configs --skill firewall-config-diff
```

- [ ] **Step 5: Remove dangling cross-skill metadata from the seven retained packages**

Set the audit skill's related list to:

```yaml
related_skills: [parsing-cisco-configs, parsing-fortinet-configs, parsing-palo-configs, parsing-srx-configs, firewall-config-conversion, firewall-config-diff]
```

In `skills/firewall-best-practices-audit/SKILL.md`, replace framework-skill routing with direct scope language:

```markdown
This skill is deliberately framework-agnostic. It answers "is this rulebase hardened by general best practice" rather than mapping findings to a compliance framework. It never cites control IDs and never claims an environment is compliant.

Operate on the normalized `parsing-*` schema; do not hand-audit raw vendor text when a parser exists. Treat framework-control mapping as out of scope, route migrations to `firewall-config-conversion`, and route parity or drift comparisons to `firewall-config-diff`.
```

Change the matching common-pitfall line to:

```markdown
- Mapping findings to compliance frameworks — stay framework-agnostic and cite no control IDs.
```

In `skills/firewall-config-conversion/references/emit-srx.md`, make the source sentence and default read:

```markdown
from `references/feature-mapping.md`; SRX syntax discipline follows
`skills/parsing-srx-configs/references/config-format.md`.

Greenfield/migration default: prefer the **global address-book** and
**`security policies global`** with `match from-zone` / `match to-zone` inside each policy,
rather than many `from-zone … to-zone …` contexts.
```

In `skills/parsing-srx-configs/SKILL.md`, retain only these related skills:

```yaml
related_skills:
  - parsing-cisco-configs
  - parsing-fortinet-configs
  - parsing-palo-configs
  - firewall-best-practices-audit
  - firewall-config-conversion
  - firewall-config-diff
```

Delete the operational-skill handoff sentence. Change the downstream sentence to `Downstream consumers are the audit, conversion, and diff skills.` Change pitfall 4 to `Policy matching depends on NAT order and translated addresses; preserve both faithfully for downstream interpretation.`

- [ ] **Step 6: Rewrite the active catalog and contribution text for seven MIT packages**

In `README.md`:

- Change skill/review badges to `skills-7` and `reviewed-7%2F7`.
- Change the license badge to `license-MIT`.
- Describe the catalog as four parsers plus audit, conversion, and diff.
- Delete the SRX operational and compliance problem/fix sections, inventories, deep dives, examples, keywords, and install examples.
- Retain only the `Config parsers` and `Cross-vendor tooling` reference sections.
- Change the quality table to four parsers, three cross-vendor tools, and total `7 / 7`.
- Change installer help/examples to seven skills and families `parsers | tooling`.
- Preserve the trademark disclaimer, parser schema documentation, retained-skill deep dives, and installation-target documentation.
- Replace the license/contribution ending with:

```markdown
## License

Original content in this repository is licensed under the [MIT License](LICENSE).

**Trademark / affiliation disclaimer.** This repository is an independent, community-driven project. It is not affiliated with, endorsed by, sponsored by, or supported by Hewlett Packard Enterprise, Cisco, Palo Alto Networks, Fortinet, or Juniper Networks. "HPE", "Juniper", "Cisco", "Fortinet", "Palo Alto Networks", and "Juniper SRX" are trademarks of their respective owners and are used here only to describe what this software interoperates with. Please direct support and licensing questions about those products to the respective vendors.

## Contributing

Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).
```

In `TODO.md`, delete the `Created` subsection that lists removed compliance packages and remove wording that treats those packages as part of the current catalog. Retain future ideas as proposals, not installed/current packages.

- [ ] **Step 7: Run targeted seven-package and no-dangling-reference checks**

Run:

```bash
python3 scripts/check-skill-packages.py
python3 scripts/check-shared-schema.py
test "$(find skills -mindepth 2 -maxdepth 2 -name SKILL.md | wc -l)" -eq 7
test "$(rg -l '^license: MIT$' skills -g SKILL.md | wc -l)" -eq 7
test "$(./install.sh --list | grep -c '^  - ')" -eq 7
if rg -n --glob '!docs/superpowers/plans/**' --glob '!docs/superpowers/specs/**' '(cis-controls-ngfw-compliance|cmmc-nist-800-171-ngfw-compliance|hipaa-ngfw-compliance|iso27001-ngfw-compliance|pci-ngfw-compliance|soc2-ngfw-compliance|srx-advpn|srx-autovpn-full-tunnel|srx-dynamic-ip-feed|srx-ipsec-hub-spoke|srx-mnha|srx-mpls-in-flow|srx-nat|srx-policy)' .; then exit 1; fi
if rg -n --glob '!docs/superpowers/plans/**' --glob '!docs/superpowers/specs/**' '(LICENSE-APACHE|LICENSE-MIT|MIT/Apache|dual-licensed|source-derived-summary-local-use|CC-BY-NC-SA)'; then exit 1; fi
```

Expected: all commands exit 0; exactly seven packages remain; the active tree contains no removed-skill or mixed-license reference. Historical plan/spec references are excluded deliberately.

- [ ] **Step 8: Run all repository-required checks and commit**

Run:

```bash
~/.local/bin/mise exec -- just fmt
~/.local/bin/mise exec -- just lint
~/.local/bin/mise exec -- just test
~/.local/bin/mise exec -- just guard
~/.local/bin/mise exec -- just integration
~/.local/bin/mise exec -- just e2e
~/.local/bin/mise exec -- just security
~/.local/bin/mise exec -- just release-check
git diff --check
git status -sb
git add -A
git commit -m "chore: publish MIT-only skill catalog"
```

Expected: all offline checks pass. `just integration` prints that real-device validation is opt-in and does not contact a device. The commit contains only the approved removals, seven-package repairs, `.gitignore`, and MIT-only current metadata/docs.

- [ ] **Step 9: Publish, merge, and clean up**

Run:

```bash
git push -u origin agent/mit-only-license
gh pr create --repo mechubsec/fwskillsshare --base main --head agent/mit-only-license --title "chore: publish MIT-only skill catalog" --body "Removes 14 source-derived or otherwise non-MIT skill subtrees, deletes the obsolete provenance notice and Apache project license, and leaves seven MIT packages with repaired installer, catalog, metadata, and validation. No real-device validation was performed."
gh pr view --repo mechubsec/fwskillsshare --json url,mergeStateStatus,statusCheckRollup
gh pr merge --repo mechubsec/fwskillsshare --merge --delete-branch
cd /home/mharman/Projects/fwskillsshare
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the PR is merged, only seven MIT packages remain on `main`, and the worktree is removed.

---

### Task 9: Verify all public repositories, update `mechubsite`, and deploy production

**Repository:** `/home/mharman/Projects/mechub-site`

**Files:**
- Modify: `test_links.py`
- Modify: `index.html:124-126,156,179,203,225,246,267,288,310`
- Preserve: historical `docs/superpowers/plans/` and `docs/superpowers/specs/` license wording

**Interfaces:**
- Consumes: eight merged public repository default branches with GitHub-detected MIT licenses.
- Produces: a merged private site repository and production HTML whose open-source copy and eight repository cards say MIT-only.

- [ ] **Step 1: Verify GitHub sees all eight repositories as MIT before touching the site**

Run:

```bash
gh repo list fastrevmd-lab --visibility public --limit 200 --json name,isFork,isArchived,licenseInfo --jq '
  map(select((.isFork | not) and (.isArchived | not)))
  | {count: length, repositories: map({name, license: .licenseInfo.key}), all_mit: (length == 8 and all(.licenseInfo.key == "mit"))}'
for repo in firewallintentconverter fwconfigsanitizer fwskillsshare rustez rustjunosmcp rustnetconf rustpanosmcp srxsync; do
  gh api "repos/fastrevmd-lab/$repo/contents/LICENSE" --jq '.name' | grep -Fx LICENSE
  if gh api "repos/fastrevmd-lab/$repo/contents/LICENSE-MIT" >/dev/null 2>&1; then exit 1; fi
  if gh api "repos/fastrevmd-lab/$repo/contents/LICENSE-APACHE" >/dev/null 2>&1; then exit 1; fi
done
```

Expected: JSON reports `count: 8` and `all_mit: true`; every repository exposes `LICENSE`; old root license paths return 404. If GitHub detection is still stale, poll the first command before treating the source as wrong.

- [ ] **Step 2: Create the isolated site worktree and run the baseline test**

Run:

```bash
cd /home/mharman/Projects/mechub-site
git status -sb
git pull --ff-only origin main
git check-ignore -q .worktrees/probe
git worktree add .worktrees/mit-only-license -b agent/mit-only-license main
cd .worktrees/mit-only-license
python3 -m unittest -v test_links.py
```

Expected: the existing canonical-link test passes.

- [ ] **Step 3: Add a failing MIT-only site regression test**

Add this method to `CanonicalProjectLinkTests` in `test_links.py`:

```python
    def test_all_public_repositories_show_mit_only_license(self):
        source = Path(__file__).with_name("index.html").read_text()

        self.assertEqual(8, source.count('<span class="badge">MIT</span>'))
        self.assertNotIn("MIT/Apache-2.0", source)
        self.assertNotIn("MIT or Apache-2.0", source)
```

Run:

```bash
python3 -m unittest -v test_links.py
```

Expected: FAIL because the page currently has zero MIT-only badges and contains both forbidden phrases.

- [ ] **Step 4: Update only active site copy and eight card badges**

Replace the open-source paragraph with:

```html
<p>MIT licensed. Read the code before you point it at a firewall —
we would. Every repo is public from the first commit.</p>
```

Replace all eight occurrences of:

```html
<span class="badge">MIT/Apache-2.0</span>
```

with:

```html
<span class="badge">MIT</span>
```

Do not edit historical plan/spec files.

- [ ] **Step 5: Verify, commit, publish, merge, and clean the site worktree**

Run:

```bash
python3 -m unittest -v test_links.py
git diff --check
python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

HTMLParser().feed(Path("index.html").read_text())
PY
git add index.html test_links.py
git commit -m "docs: show MIT-only repository licensing"
git push -u origin agent/mit-only-license
gh pr create --repo fastrevmd-lab/mechubsite --base main --head agent/mit-only-license --title "docs: show MIT-only repository licensing" --body "Updates the active MechHub open-source statement and all eight repository cards to MIT-only, with a regression test preventing mixed-license wording from returning. Historical site plans remain unchanged."
gh pr view --repo fastrevmd-lab/mechubsite --json url,mergeStateStatus,statusCheckRollup
gh pr merge --repo fastrevmd-lab/mechubsite --merge --delete-branch
cd /home/mharman/Projects/mechub-site
git pull --ff-only origin main
git worktree remove .worktrees/mit-only-license
git branch -d agent/mit-only-license
git worktree prune
```

Expected: the site PR is merged, the normal checkout is clean, and its short `HEAD` hash is the deployment version.

- [ ] **Step 6: Deploy the committed default branch to production**

Run only from `/home/mharman/Projects/mechub-site` on clean `main`:

```bash
cd /home/mharman/Projects/mechub-site
git status -sb
git branch --show-current
~/.local/bin/mise exec just@1.42.4 -- just deploy
```

Expected: the recipe reports `deployed` followed by the current short commit hash and `https://mechub.org`. It touches only the prescribed static files in LXC 901.

- [ ] **Step 7: Verify the live deployment hash and MIT-only production content**

Run:

```bash
cd /home/mharman/Projects/mechub-site
expected=$(git rev-parse --short HEAD)
html=$(curl --fail --silent --show-error https://mechub.org/)
grep -F "site.css?v=$expected" <<<"$html"
grep -F "MIT licensed." <<<"$html"
test "$(grep -o '<span class="badge">MIT</span>' <<<"$html" | wc -l)" -eq 8
if grep -Eqi 'MIT/Apache-2\.0|MIT or Apache-2\.0' <<<"$html"; then exit 1; fi
```

Expected: all commands exit 0; production references the merged commit hash, contains the MIT-only statement, has eight MIT badges, and has no active dual-license wording.

- [ ] **Step 8: Capture final compatibility and skipped-check evidence**

Run:

```bash
gh repo list fastrevmd-lab --visibility public --limit 200 --json name,url,licenseInfo --jq 'sort_by(.name) | map({name, url, license: .licenseInfo.key})'
gh pr list --repo mechubsec/rustjunosmcp --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/rustez --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/rustnetconf --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/rustpanosmcp --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/firewallintentconverter --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/fwconfigsanitizer --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/srxsync --state merged --search '"chore: adopt MIT-only licensing" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo mechubsec/fwskillsshare --state merged --search '"chore: publish MIT-only skill catalog" in:title' --limit 1 --json number,url,mergedAt
gh pr list --repo fastrevmd-lab/mechubsite --state merged --search '"docs: show MIT-only repository licensing" in:title' --limit 1 --json number,url,mergedAt
```

Expected: all eight public repositories report `mit`; every rollout PR and the site PR has a merged URL/time. Handoff must explicitly state that historical versions retain their original grants, `fwskillsshare` removed 14 skill families without replacement, all runtime/MCP schemas stayed compatible, and all real-device integration checks were skipped.

## Plan Self-Review Checklist

- [ ] Tasks 1-8 cover all eight public repositories exactly once.
- [ ] Task 8 names every one of the 14 approved `fwskillsshare` removals and all seven retained MIT packages.
- [ ] Task 9 gates the site on GitHub MIT detection, merges source before deploy, limits deployment to the existing recipe, and verifies the live hash/content.
- [ ] Every repository has a red acceptance command, exact implementation values, fresh verification, commit, ready PR, merge, and worktree cleanup.
- [ ] Historical plans/specifications and third-party dependency license data are excluded from rewrites and preserved explicitly.
- [ ] Real-device tests are never invoked and are called out in PR/handoff evidence.

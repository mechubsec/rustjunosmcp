# MIT-Only Public Repositories Design

## Goal

Make every active public repository owned by `fastrevmd-lab` MIT-only on its
default branch, remove material that cannot be distributed under MIT from
`fwskillsshare`, and update and deploy `mechub.org` so its public claims match
the repositories.

## Decisions

- Scope is the eight public, non-fork, non-archived repositories owned by
  `fastrevmd-lab`.
- Each repository will use one canonical root `LICENSE` containing its existing
  MIT text and copyright line.
- Current project-owned metadata and documentation will say `MIT`, not a dual
  license.
- Historical plans and specifications will remain unchanged when they describe
  the license that applied when they were written.
- Third-party dependency license records and dependency allowlists will remain
  unchanged; they describe dependencies rather than the repository's own
  license.
- The non-MIT/source-derived `fwskillsshare` material will be removed rather
  than retained as license exceptions.
- The MechHub site repository and the production site are both in scope.
- Changes will be reviewed and integrated sequentially, one repository at a
  time, with MechHub updated and deployed last.

This changes the license for future repository states and future releases. It
does not rewrite Git history, withdraw artifacts already published under the
old terms, or alter licenses already granted for earlier versions.

## Repository Scope

| Repository | Default branch | Current active license surfaces | MIT-only work |
| --- | --- | --- | --- |
| `firewallintentconverter` | `main` | Two license files, npm metadata and root lockfile metadata, README badge/license/contribution text | Canonical `LICENSE`; update npm metadata and README; remove Apache file and dual-license wording |
| `fwconfigsanitizer` | `main` | Two license files, README, contribution terms | Canonical `LICENSE`; update README/contribution terms; remove Apache file and dual-license wording |
| `fwskillsshare` | `main` | Two license files, `NOTICE`, README, per-skill license metadata | Retain only MIT material; remove the 14 non-MIT skill subtrees and `NOTICE`; repair catalogs/tests/docs; canonicalize the project license |
| `rustez` | `main` | Two license files, Cargo workspace/crate metadata, Python package metadata, README | Canonical `LICENSE`; set project metadata and README to MIT; remove Apache file and dual-license wording |
| `rustjunosmcp` | `main` | Two license files, Cargo workspace metadata, OCI image label, README | Canonical `LICENSE`; set Cargo/OCI/README to MIT; remove Apache file and dual-license wording |
| `rustnetconf` | `main` | Two license files, Cargo workspace/crate metadata, README, active release-tracking document | Canonical `LICENSE`; set current metadata/docs to MIT; remove Apache file and dual-license wording |
| `rustpanosmcp` | `main` | Two license files, Cargo/fuzz metadata, OCI image label, release packaging, README/contribution terms | Canonical `LICENSE`; update current metadata, packaging, and docs; retain Apache in dependency-license allowlists; remove Apache project license |
| `srxsync` | `master` | Two license files, Python metadata/license-files list, README/contribution text | Canonical `LICENSE`; set Python metadata/docs to MIT; remove Apache file and dual-license wording |

The private source repository `fastrevmd-lab/mechubsite` is not being
relicensed as part of the public-repository set. Its content changes are in
scope because it publishes the public repositories' license claims.

## Standard Repository Transformation

For each public repository:

1. Rename the existing `LICENSE-MIT` to `LICENSE`, preserving its MIT text and
   repository-specific copyright line.
2. Delete `LICENSE-APACHE`.
3. Replace current project-owned SPDX expressions such as
   `MIT OR Apache-2.0` with `MIT` in package and crate metadata.
4. Update only the root-project entry in generated npm lockfiles through the
   package manager; do not change third-party package license entries.
5. Update active README badges, license sections, contribution terms, OCI
   labels, release/package scripts, and current operational metadata to point
   to `LICENSE` and describe MIT-only licensing.
6. Run a scoped repository scan that rejects active project-license references
   to `LICENSE-MIT`, `LICENSE-APACHE`, dual licensing, or a project-owned
   `Apache-2.0` declaration. The scan excludes historical plans/specifications
   and third-party dependency metadata.
7. Run the repository's own formatting, linting, unit, guard, security, release,
   and offline end-to-end checks where those commands exist. Real-device and
   production-device integration checks remain skipped.
8. Commit, push a short-lived branch, open a reviewable pull request, merge it
   after required checks succeed, confirm GitHub reports `MIT`, and remove the
   local worktree before starting the next repository.

The canonical MIT text is the OSI-approved MIT License. GitHub recommends a
simple root `LICENSE` file for reliable repository-license detection, so the
design avoids a compound license file or extra terms in `LICENSE`.

## `fwskillsshare` Removal Boundary

The following 14 subtrees are explicitly non-MIT or source-derived and will be
removed in full, including their `SKILL.md`, agent metadata, references,
fixtures, and other bundled files:

- `skills/cis-controls-ngfw-compliance/`
- `skills/cmmc-nist-800-171-ngfw-compliance/`
- `skills/hipaa-ngfw-compliance/`
- `skills/iso27001-ngfw-compliance/`
- `skills/pci-ngfw-compliance/`
- `skills/soc2-ngfw-compliance/`
- `skills/srx-advpn/`
- `skills/srx-autovpn-full-tunnel/`
- `skills/srx-dynamic-ip-feed/`
- `skills/srx-ipsec-hub-spoke/`
- `skills/srx-mnha/`
- `skills/srx-mpls-in-flow/`
- `skills/srx-nat/`
- `skills/srx-policy/`

The seven skill families already marked MIT remain:

- `firewall-best-practices-audit`
- `firewall-config-conversion`
- `firewall-config-diff`
- `parsing-cisco-configs`
- `parsing-fortinet-configs`
- `parsing-palo-configs`
- `parsing-srx-configs`

After deletion, all indexes, README inventories, install/validation scripts,
tests, and generated marketplace metadata must contain only retained skills.
`NOTICE` will be deleted because its purpose is to qualify the removed
source-derived material. A full active-tree scan must find no remaining
non-MIT per-skill declaration or dangling reference to a removed skill.

Removing these directories intentionally narrows the published skill catalog.
Consumers that installed one of the removed skills will not receive an
MIT-licensed replacement from this rollout.

## MechHub Site

After all eight public repositories are merged and GitHub detects MIT:

1. Create an isolated worktree for `fastrevmd-lab/mechubsite`.
2. Change the sovereign/open-source copy from “MIT or Apache-2.0” to MIT.
3. Change each of the eight repository-card license badges to `MIT`.
4. Add or update a regression test so all eight cards must carry an MIT badge
   and the active page cannot reintroduce dual-license wording.
5. Run the site's test and link checks, review the static diff, commit, push,
   merge, and clean up the worktree.
6. From the committed default branch, run the prescribed deployment command:

   ```sh
   ~/.local/bin/mise exec just@1.42.4 -- just deploy
   ```

7. Verify `https://mechub.org` returns the new asset hash, contains the MIT-only
   open-source copy, shows eight MIT badges, and contains no active
   `MIT/Apache-2.0` or `MIT or Apache-2.0` wording.

The deployment is limited to the existing static-site recipe and LXC 901. No
Cloudflare, nginx, TLS, networking, or other guest configuration is changed.

## Rollout and Failure Handling

Repositories are processed sequentially. A repository does not advance to
merge until its diff and applicable checks pass. The next repository does not
start until the prior change is integrated and its worktree is cleaned up.

If a default branch has moved, the worktree is refreshed or recreated before
editing. If a repository-specific check fails, the failure is fixed in that
repository before rollout continues. If GitHub license detection has not
updated immediately after merge, poll the repository license endpoint before
treating it as a content failure.

The site is deployed only after all eight repositories are successfully
integrated. If deployment fails, retain the merged site source, diagnose only
within the existing deployment recipe and allowed LXC 901 scope, and report the
live-site mismatch instead of claiming production success.

## Acceptance Criteria

- All eight public repositories have a root `LICENSE` detected by GitHub as
  `MIT`.
- None of the eight default branches contains `LICENSE-APACHE` or
  `LICENSE-MIT` at its root.
- Current project-owned manifests, README license sections/badges, contribution
  terms, OCI labels, and release packaging declare MIT-only licensing.
- Historical plans/specifications and third-party dependency license metadata
  remain intact.
- `fwskillsshare` retains only the seven MIT skill families, has no non-MIT
  skill declarations, and passes its repository validation suite without
  dangling catalog references.
- Applicable offline, security, release, and end-to-end checks pass in every
  changed repository; real-device checks are explicitly reported as skipped.
- The MechHub repository tests pass, its change is merged, and production
  serves the matching commit hash and MIT-only content.
- Handoff lists every changed repository/file group, PR and merge result,
  command result, skipped live-device check, and remaining compatibility risk.

## References

- [The MIT License — Open Source Initiative](https://opensource.org/license/mit)
- [Licensing a repository — GitHub Docs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)

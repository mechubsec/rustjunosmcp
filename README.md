<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rust-junosmcp</h1>

<p align="center"><strong>One MCP server for Juniper Junos and SRX devices, in Rust</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This repository is an independent, community-driven project. It is not affiliated with, endorsed by, sponsored by, or supported by Hewlett Packard Enterprise or Juniper Networks. "HPE", "Juniper", "SRX", "JUNOS", "Security Director" and "Juniper Mist" are trademarks of their respective owners and are used here only to describe what this software interoperates with. Please direct support and licensing questions about those products to the respective vendors.

A [Model Context Protocol](https://modelcontextprotocol.io/) server for Juniper
Junos and SRX devices, written in Rust. One `rust-junosmcp` process gives an
MCP client the core Junos tools and the SRX security workflows (45 tools by
default), with per-token device and tool scopes, audit logging, and change
control for configuration writes. It reads the same `devices.json` inventory as
[Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server).

The server runs on Linux only, in an LXC container or in Docker. The current
version is 2.6.1. It is stable: see [Stability](docs/REFERENCE.md#stability)
for what that covers.

## 1. Install

Pick one path. Both end with the server on `127.0.0.1:30030/mcp` behind
bearer-token authentication. You need the same things either way:

- A `devices.json` inventory. Start from [`devices-template.json`](devices-template.json).
  Each device needs an `auth` object with a `type` (`ssh_key` or `password`).
- An SSH private key whose public half is installed for a NETCONF user on each
  device. Prefer keys to passwords.
- A `known_hosts` entry for each device. Host-key checking is strict.
  [`scripts/scan-known-hosts.sh`](scripts/scan-known-hosts.sh) builds the file
  from the inventory; check the fingerprints against a trusted source.
- Mode `0600` on `devices.json`, the key and `tokens.json`; the server refuses
  to start otherwise.

### Docker

Prebuilt images are public and need no login:

- `ghcr.io/mechubsec/rustjunosmcp`
- `docker.io/mechub/rustjunosmcp`

The image runs as UID/GID `65532:65532` and has no shell. Its entrypoint already
passes the inventory, state, known-hosts, lease, token-file and audit-key paths,
so add only transport and bind flags. Do not repeat the entrypoint flags.

Verify the image signature first. Your inventory and SSH key get mounted into
this image, so stop if the check fails. Pin the image by digest, so the bytes you
verify are the bytes you run. A later release needs its own version and digest.

```bash
image=ghcr.io/mechubsec/rustjunosmcp:2.6.1@sha256:4edd557a4f3be47d2737f84076486e366a533cf02deefc7d47dacc1c15458a76

cosign verify \
  --certificate-identity-regexp '^https://github\.com/mechubsec/mecmcp/\.github/workflows/reusable-release-image\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository mechubsec/rustjunosmcp \
  --certificate-github-workflow-trigger push \
  --certificate-github-workflow-ref refs/tags/v2.6.1 \
  "$image"
```

Then prepare the host paths:

```bash
mkdir -p junos-docker/keys junos-docker/state/device-leases junos-docker/state/staging
cd junos-docker
# Put devices.json and keys/id_ed25519 here, then pin each device's host key:
/path/to/rustjunosmcp/scripts/scan-known-hosts.sh \
    --inventory ./devices.json --known-hosts ./state/known_hosts
chmod 0600 devices.json keys/id_ed25519
sudo chown -R 65532:65532 devices.json keys state
sudo chmod 0700 keys state state/device-leases
```

Mint a token (below), then start it:

```bash
docker run -d --name junos-twoperson \
  -p 127.0.0.1:30030:30030 \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/state:/var/lib/jmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30030 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30030 --allowed-host localhost:30030 \
  --allowed-origin http://127.0.0.1:30030 --allowed-origin http://localhost:30030
```

Notes:

- `private_key_path` in `devices.json` is the in-container path, for example
  `/etc/jmcp/keys/id_ed25519`.
- Keep `tokens.json` in the mounted `state` directory. **Do not bind-mount it as
  a single file.** Token commands replace the file, so a single-file mount keeps
  the old copy and a revoked token stays valid after a reload.
- `--allowed-host` and `--allowed-origin` carry the port the client dials, which
  is the published port, not the container's 30030.
- Without `--lab-mode` this is two-person mode. To run lab mode, add `--lab-mode`
  as the last argument. See [section 2](#2-choose-a-safety-mode).
- `--audit-journald` does not work in a container (no journald socket). Read the
  audit stream with `docker logs`.

Full walk-through, image digest pinning and troubleshooting:
[docs/HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md).

### LXC (Proxmox)

The container must be **Debian 13 (trixie)**. The published binary needs
`GLIBC_2.39` and Debian 12 ships 2.36, so the service would fail at start with
a "GLIBC_2.39 not found" error after an otherwise clean install. Create it
unprivileged with `--features nesting=1` (systemd 257 needs it). 512 MB and one
core is enough.

Use the release tarball. Do not build the binary on your workstation and copy it
in: a newer glibc than the container's will not load.

The checksum proves the download is intact. The signature proves it came from
this project's release workflow. Stop if either check fails.

```bash
version=2.6.1
base="https://github.com/mechubsec/rustjunosmcp/releases/download/v${version}"
tarball="rust-junosmcp_${version}_amd64.tar.gz"
curl -fLO "$base/$tarball"
curl -fLO "$base/$tarball.sha256"
curl -fLO "$base/$tarball.cosign.bundle"

sha256sum -c "$tarball.sha256"
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/mechubsec/mecmcp/\.github/workflows/reusable-sign-release-tarball\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository mechubsec/rustjunosmcp \
  --certificate-github-workflow-trigger release \
  --certificate-github-workflow-ref "refs/tags/v${version}" \
  --bundle "$tarball.cosign.bundle" "$tarball"

pct push <vmid> "$tarball" /tmp/pkg.tar.gz
pct exec <vmid> -- bash -lc "cd /tmp && tar xzf pkg.tar.gz && cd rust-junosmcp_${version}_amd64 && JMCP_INSTALL_VERIFY_TOOLS=1 ./install.sh"
```

`install.sh` creates the `jmcp` service user, installs the binary and the
systemd unit, and stops. The service will not start until it has an inventory.
Then place the credentials and fix their modes:

```bash
pct push <vmid> devices.json /etc/jmcp/devices.json
pct push <vmid> id_ed25519   /etc/jmcp/id_ed25519
pct push <vmid> known_hosts  /etc/jmcp/known_hosts
pct exec <vmid> -- bash -lc '
    chown -R jmcp:jmcp /etc/jmcp
    chmod 0600 /etc/jmcp/devices.json /etc/jmcp/id_ed25519
    chmod 0644 /etc/jmcp/known_hosts
'
```

Mint a token (below), then start it:

```bash
pct exec <vmid> -- systemctl enable --now rust-junosmcp
```

The shipped unit binds `127.0.0.1:30030` and keeps its token store at
`/var/lib/jmcp/tokens.json`. For remote clients, use an SSH tunnel or a TLS
reverse proxy, or add site settings in a systemd drop-in as the HOW-TO shows.

To upgrade, read the `CHANGELOG.md` upgrade notes, then install the new tarball
the same way. The installer does not restart the service, so do that yourself
and check the version:

```bash
pct exec <vmid> -- systemctl try-restart rust-junosmcp
pct exec <vmid> -- /usr/local/bin/rust-junosmcp --version
```

The installer replaces the binary and the shipped unit, and leaves
`devices.json`, `tokens.json` and `known_hosts` alone. Keep site settings in a
drop-in, because edits to the shipped unit are lost.

Container creation, the site drop-in, verification and troubleshooting:
[docs/HOW-TO-SETUP-LXC.md](docs/HOW-TO-SETUP-LXC.md). Release tarball
verification: [docs/REFERENCE.md](docs/REFERENCE.md#lxc-proxmox).

### Mint a token

Clients authenticate with a bearer token. The secret prints once and is stored
hashed. Define `jmcp` for your install. The token paths are the same in both.

```bash
# LXC: run as the service user inside the guest.
jmcp() { pct exec <vmid> -- runuser -u jmcp -- /usr/local/bin/rust-junosmcp "$@"; }

# Docker: run from junos-docker/. No binary on the host is needed.
jmcp() {
  docker run --rm --entrypoint /usr/local/bin/rust-junosmcp \
    -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
    -v "$PWD/state:/var/lib/jmcp" \
    "$image" "$@"
}

jmcp token add --tokens-file /var/lib/jmcp/tokens.json -f /etc/jmcp/devices.json \
    --name my-client --devices '*' --tools '*'
```

A wildcard `--tools '*'` grants read-only tools only. Name write tools
explicitly or the caller gets `insufficient_scope`. After minting or revoking,
signal the running server:

```bash
pct exec <vmid> -- systemctl kill -s HUP rust-junosmcp.service   # LXC
docker kill -s HUP junos-twoperson                               # Docker
```

Scopes, rotation and rescoping: [Remote transport + auth](docs/REFERENCE.md#remote-transport--auth).

### Check it is up

The service listens on the guest's loopback, so on LXC run this inside the
guest with `pct exec <vmid> -- curl ...`. For Docker, run it on the host.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30030/mcp \
     -H 'content-type: application/json' -d '{}'
```

`401` is success: the transport is up and rejecting unauthenticated callers.
`000` means nothing is listening. `421` means the allowed-host list is wrong.

## 2. Choose a safety mode

By default, every configuration write goes through a change set: one principal
proposes it, a different principal approves it, and then it is applied. A
principal is a bearer token. Choose how that rule applies to your deployment.

| | Two-person (default) | Lab mode (`--lab-mode`) |
|---|---|---|
| Flag | none | `--lab-mode` |
| Who approves | a second principal | nobody; approved on creation |
| Self-approval | refused | not needed |
| Record | approver identity | `approver: null`, `approval_waiver: "lab-mode"` |
| Use it for | anything real | a single-operator lab |

### Two-person change control (default)

The flow is `create_junos_change_set`, then `approve_junos_change_set`, then
`apply_junos_change_set`. **A change set needs a second principal unless lab mode
is on.** The token that creates a change set cannot approve it. Plan, plan digest,
drift detection and apply-time revalidation all run.

Set it up with two tokens. The token from [Mint a token](#mint-a-token) is
read-only, so it can do neither job.

- A proposer token that names the change-set tools.
- An approver token held by a different person, with `--actor-type human` and
  the `approve_junos_change_set` tool. The server refuses approval from a
  non-human actor.

Mint both with the `jmcp` function from [Mint a token](#mint-a-token):

```bash
jmcp token add --tokens-file /var/lib/jmcp/tokens.json -f /etc/jmcp/devices.json \
  --name proposer --actor-type agent --devices '*' \
  --tools get_junos_candidate_fingerprint,create_junos_change_set,get_junos_change_set_status,apply_junos_change_set,confirm_junos_change_set

jmcp token add --tokens-file /var/lib/jmcp/tokens.json -f /etc/jmcp/devices.json \
  --name alice --actor-type human --devices '*' \
  --tools approve_junos_change_set
```

Then signal the running server, as shown above.

Two tokens held by one person are not a second reviewer. To bind the approver to
a real identity, use a verified approver (`--oidc-issuer`,
`--require-verified-approver`). See
[`--lab-mode`](docs/REFERENCE.md#--lab-mode) and
[Verified approver](docs/REFERENCE.md#verified-approver-setup-and-failure-behaviour).

Commits are issued as `commit confirmed` by default, so a bad change rolls back
on its own unless confirmed. See
[Confirmed commits](docs/REFERENCE.md#confirmed-commits-v03-default-on-since-v012).

### Lab mode

`--lab-mode` waives the second-principal requirement. Do not enable it on a
server that manages production devices. It does not remove the change record,
the digest or drift detection, and the server warns at startup. No approver is
invented: a waived change set records `approver: null`, so it can always be told
apart from a real two-person approval.

Docker: add `--lab-mode` to the arguments after the image name.

LXC: add it in a systemd drop-in so an upgrade does not drop it. The drop-in
restates `ExecStart` in full, so copy the arguments from
[`packaging/systemd/rust-junosmcp.service`](packaging/systemd/rust-junosmcp.service)
and append the flag:

```ini
# systemctl edit rust-junosmcp
[Service]
ExecStart=
ExecStart=/usr/local/bin/rust-junosmcp \
    --device-mapping /etc/jmcp/devices.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30030 \
    --tokens-file /var/lib/jmcp/tokens.json \
    --device-lease-dir /var/lib/jmcp/device-leases \
    --audit-hmac-key-file /var/lib/jmcp/audit-hmac.key \
    --inventory-readonly \
    --lab-mode
```

A drop-in does not touch the running process, so restart it, then confirm the
running server has the flag:

```bash
# LXC
pct exec <vmid> -- systemctl restart rust-junosmcp
pct exec <vmid> -- bash -c 'tr "\0" " " < /proc/$(systemctl show -p MainPID --value rust-junosmcp)/cmdline | grep -o -- --lab-mode'

# Docker
docker inspect -f '{{.Args}}' <container> | grep -o -- --lab-mode
```

Output of `--lab-mode` means it is on. Silence means it is off. Two-person mode
is the same configuration without the flag.

### Related switches

- **`--allow-direct-commit`** (off by default). `load_and_commit_config` and
  three other tools commit in one call with no change set, so no second person
  can review them. They are refused unless this flag is set.
  [Details](docs/REFERENCE.md#--allow-direct-commit).
- **Plane guard** (on by default). Local edits to a device managed by Security
  Director or Mist can be overwritten at the next push. When `config_authority`
  is unset, the server detects the managing plane from
  `system services outbound-ssh`, so this needs no setup. Mist devices are
  read-only here. Security Director devices refuse changes to `security`,
  `applications`, `schedulers` and `system services outbound-ssh`.
  `--allow-plane-owned-writes` turns the refusals into warnings.
  `upgrade_junos` honours only a declared `config_authority`.
  [Details](docs/REFERENCE.md#security-director-and-mist-managed-srx).

## 3. Connect a client

The server speaks MCP over streamable HTTP at `/mcp`, with the header
`Authorization: Bearer <secret>`. For a local stdio server, a Claude Desktop
registration, and VS Code, see [`examples/`](examples/) and
[Claude Desktop config](docs/REFERENCE.md#claude-desktop-config).

## Documentation

- [docs/HOW-TO-SETUP-LXC.md](docs/HOW-TO-SETUP-LXC.md): build an LXC from scratch.
- [docs/HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md): run the container.
- [docs/REFERENCE.md](docs/REFERENCE.md): everything else that used to be in
  this file: blocklist and allowlist, config format, confirmed commits, file
  transfers, token scopes, OAuth, audit logging, resource limits, CLI, and
  upgrade notes.
- [featurescope.md](featurescope.md): what each release added.
- [CHANGELOG.md](CHANGELOG.md): full release history and upgrade notes.
- [SECURITY.md](SECURITY.md): reporting a vulnerability.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md), [docs/AUDIT.md](docs/AUDIT.md),
  [docs/METRICS.md](docs/METRICS.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
- [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under [MIT](LICENSE).

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>

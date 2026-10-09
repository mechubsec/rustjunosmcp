# How to set up a rust-junosmcp LXC from scratch

Builds one Proxmox LXC running `rust-junosmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run, and the two failures that occurred are in
[Troubleshooting](#troubleshooting) with their exact error text.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production devices. It says so itself at
startup, in a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** A NETCONF SSH private key whose public
  half is installed on the target devices, a `devices.json` inventory, and a
  `known_hosts` entry per device. Building the container is the easy part;
  these are the part you cannot regenerate. If you are rebuilding an existing
  rig, back them up first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc:

```bash
docker create --name jx ghcr.io/mechubsec/rustjunosmcp:0.27.2
docker cp jx:/usr/local/bin/rust-junosmcp ./rust-junosmcp
docker rm jx
```

No docker? `skopeo copy docker://ghcr.io/mechubsec/rustjunosmcp:0.27.2 dir:/tmp/img`
then find the layer containing `usr/local/bin/rust-junosmcp` and untar it.

## 2. Assemble the install package

`scripts/package-lxc.sh` builds the package. Point it at the binary you just
extracted rather than letting it compile one:

```bash
cd /path/to/RustJunosMCP
mkdir -p target/release
install -m 0755 ./rust-junosmcp target/release/rust-junosmcp
JMCP_PACKAGE_SKIP_BUILD=1 ./scripts/package-lxc.sh
# >> Wrote dist/rust-junosmcp_0.27.2_amd64.tar.gz
```

The package is deliberately small — the binary, an example inventory, the
systemd unit, `install.sh`, and a `BUILD-INFO` provenance file. Skip-build
records `rustc=unknown (...)` rather than naming the workstation toolchain,
and `binary_sha256` is always taken from the bytes in the archive.

```
usr/local/bin/rust-junosmcp
etc/jmcp/devices.json.example
etc/systemd/system/rust-junosmcp.service
install.sh
BUILD-INFO
```

> **Note.** Release tags do not currently carry this tarball as an asset, and CI
> builds it without uploading it. Until that changes, assembling it as above is
> the supported path.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 611 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-labmode-junos \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.11/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;labmode"

pct start 611
```

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

## 4. Install

```bash
pct push 611 dist/rust-junosmcp_0.27.2_amd64.tar.gz /tmp/pkg.tar.gz
pct exec 611 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && cd rust-junosmcp_*/ && ./install.sh'
```

`install.sh` creates the `jmcp` service user, installs the binary and the unit,
and stops there. **The service will not start yet** — it has no inventory, and it
says so.

## 5. Configuration and credentials

Place the inventory, the NETCONF key, and the host keys:

```bash
pct push 611 devices.json   /etc/jmcp/devices.json
pct push 611 id_ed25519     /etc/jmcp/id_ed25519
pct push 611 known_hosts    /etc/jmcp/known_hosts
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start when any of these files is group- or world-readable, and
it names every offender in one error:

```bash
pct exec 611 -- bash -lc '
    chown -R jmcp:jmcp /etc/jmcp
    for f in devices.json tokens.json id_ed25519 ssdf-audit.pw ssdf-audit-verify.pw; do
        [ -f "/etc/jmcp/$f" ] && chmod 0600 "/etc/jmcp/$f"
    done
    chmod 0644 /etc/jmcp/known_hosts
    install -d -o jmcp -g jmcp -m 0750 /var/lib/jmcp/device-leases
'
```

Adding a device later takes **three** steps, not one, and the errors tell you
which you missed:

1. the entry in `/etc/jmcp/devices.json`;
2. an entry in `/etc/jmcp/known_hosts` — host-key checking is strict, and
   without it every call fails with `host <ip>:22 not found in known_hosts`,
   which reads like a device fault rather than a local omission;
3. on the device, a `netconf` user holding the public half of `id_ed25519`.

Reload the inventory without a restart: `systemctl kill -s HUP rust-junosmcp.service`.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable:

```bash
mkdir -p /etc/systemd/system/rust-junosmcp.service.d
```

`/etc/systemd/system/rust-junosmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rust-junosmcp \
    --device-mapping /etc/jmcp/devices.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30030 \
    --tokens-file /etc/jmcp/tokens.json \
    --device-lease-dir /var/lib/jmcp/device-leases \
    --inventory-readonly \
    --allow-insecure-bind \
    --allowed-host 192.0.2.11 \
    --allowed-host test-labmode-junos:30030 \
    --allowed-origin http://console.example.org \
    --lab-mode \
    --audit-format json \
    --audit-log-file /var/lib/jmcp/audit.jsonl \
    --audit-journald
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one.

**Two-person mode is the same file with `--lab-mode` removed.** That single flag
is the whole difference.

`--allowed-host` lists the server authorities clients dial (the address and port
of this server). `--allowed-origin` lists the trusted browser application origins
that call this server — typically a web console hosted elsewhere. These are
configured independently and are usually different values. An off-loopback
listener requires at least one `--allowed-origin` or the server refuses to start,
but the value shown (`http://console.example.org`) is an example: replace it
with the actual origin of your browser client. The scheme must match the server's
TLS configuration — this plaintext drop-in uses `http://`; an HTTPS console origin
requires `--tls-cert` and `--tls-key`. Clients that send no Origin header — curl
and non-browser MCP clients — are unaffected by the origin allowlist.

Then:

```bash
systemctl daemon-reload
systemctl enable --now rust-junosmcp.service
```

## 7. Mint a token

```bash
pct exec 611 -- runuser -u jmcp -- /usr/local/bin/rust-junosmcp token add \
    --tokens-file /etc/jmcp/tokens.json \
    --name my-client --devices '*' --tools '*' \
    -f /etc/jmcp/devices.json
```

The secret is printed **once** and stored hashed. Two things worth knowing:

- A running server holds its token store in memory. A newly minted or revoked
  token does nothing until the server is signalled:
  `systemctl kill -s HUP rust-junosmcp.service`. The CLI warns you about this.
- `--tools '*'` is a wildcard that resolves to *read-only tools only*. Write
  tools must be named explicitly, so a wildcard token calling
  `create_junos_change_set` gets `insufficient_scope`. That is deliberate.

## 8. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 611 -- /usr/local/bin/rust-junosmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 611 -- systemctl show rust-junosmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 611 -- grep -l SystemCallErrorNumber /etc/systemd/system/rust-junosmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 611 -- systemctl show -p MainPID --value rust-junosmcp.service)
pct exec 611 -- grep -E '^Seccomp' /proc/$pid/status                                    # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.11:30030/mcp \
     -H 'content-type: application/json' -d '{}'                                        # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. Without it a denied syscall raises
SIGSYS and kills the process mid-request instead of returning `EPERM`; that is
mecmcp#351, and reading it back from the unit is how you know the fix is present.

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 611
cp -a /var/lib/lxc/611/rootfs/etc/jmcp        /root/backup-611/
cp -a /var/lib/lxc/611/rootfs/var/lib/jmcp    /root/backup-611/
cp -a /var/lib/lxc/611/rootfs/etc/systemd/system/rust-junosmcp.service.d /root/backup-611/
pct config 611 > /root/backup-611/pct-config.txt
pct unmount 611
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

## Troubleshooting

Both of these were hit during the rebuild this document is written from.

**`2 credential file(s) failed validation`**, naming `devices.json` and `ssdf-audit.pw`
A credential file is too permissive. Startup names every loose file, its mode,
and the `chmod` to run, in one error. Fix every file it lists before
restarting. `known_hosts` stays mode `0644` and is not part of this check.

**`failed to create file: /etc/systemd/system/rust-junosmcp.service.d/override.conf: No such file or directory`**
The drop-in directory does not exist yet. `install.sh` does not create it,
because a drop-in is a site decision. `mkdir -p` it first.

**`host <ip>:22 not found in known_hosts file /etc/jmcp/known_hosts`**
Step 5, item 2. This is a local omission, not a device fault.

**`authentication failed for user 'netconf'`**
Step 5, item 3: the device does not hold the public half of `id_ed25519`.

**Service active but every call returns 421 `"Host '<host>' is not allowed"`** —
`--allowed-host` does not match the server authority clients dial. Add the exact
host and port they use.

**Browser calls return 403 `"Origin '<origin>' is not allowed"`** —
The browser application's origin is not in the `--allowed-origin` allowlist. Add
the origin of the calling browser page (e.g., `https://console.example.org`).
Non-browser clients (curl, CLI MCP clients) send no Origin header and are
unaffected.

**`non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**
The service fails to start immediately. An off-loopback listener must supply at
least one `--allowed-origin` — set it to the origin of the browser client that
will call this server. If there is no browser client today, any single well-formed
origin will satisfy the startup requirement (it has no effect on non-browser
clients, which send no Origin header), but it must be replaced with the real
client origin before any browser client is pointed at the server.

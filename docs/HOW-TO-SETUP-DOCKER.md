# How to run rust-junosmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the two failures that occurred are in [Troubleshooting](#troubleshooting)
with their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

If you see that line and did not intend it, stop and fix the flag.

## What the image already supplies

The image runs as numeric UID/GID `65532:65532` and its `ENTRYPOINT` already
passes four arguments:

```
-f /etc/jmcp/devices.json
--staging-dir /var/lib/jmcp/staging
--known-hosts-file /var/lib/jmcp/known_hosts
--device-lease-dir /var/lib/jmcp/device-leases
```

So you append only what is left: transport, bind, tokens, allow-lists, and
`--lab-mode` when you want it. Do not repeat the four above.

## 1. Prepare host paths

```bash
mkdir -p junos-docker/keys junos-docker/state/device-leases junos-docker/state/staging
cd junos-docker
touch state/known_hosts
```

`devices.json` — note the **`auth.type`** field. It is required, and omitting it
is the first thing that will stop you (see Troubleshooting):

```json
{
    "vsrx-demo": {
        "ip": "192.0.2.20",
        "port": 22,
        "username": "netconf",
        "auth": {
            "type": "ssh_key",
            "private_key_path": "/etc/jmcp/keys/id_ed25519"
        }
    }
}
```

Junos enables NETCONF over SSH with `set system services netconf ssh`, using
the normal SSH port 22 by default. If NETCONF is configured on a dedicated
port 830 instead, set `port` to 830 explicitly in the inventory.

**`private_key_path` must be the in-container path**, not the host path. The
file lives at `keys/id_ed25519` on the host and is mounted to `/etc/jmcp/keys`.

Place the NETCONF private key whose public half is installed on the devices:

```bash
cp /path/to/id_ed25519 keys/id_ed25519
```

Mint a bearer token. The binary can do this on the host — no container needed:

```bash
rust-junosmcp token add --tokens-file ./tokens.json \
    --name my-client --devices '*' --tools '*' -f ./devices.json
```

The secret prints **once** and is stored hashed. `--tools '*'` resolves to
read-only tools only; write tools must be named explicitly, so a wildcard token
calling `create_junos_change_set` gets `insufficient_scope`. That is deliberate.

Then lock the modes down:

```bash
chmod 0600 devices.json keys/id_ed25519 tokens.json
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown -R 65532:65532 devices.json keys tokens.json state
sudo chmod 0700 keys state state/device-leases
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both are shown below. The second is what the examples here were verified with.

## 3. Pin the image version

Obtain the immutable digest for the version you want to run. If the image has not
been pulled yet, choose one of the published registries and pull it first:

```bash
image=ghcr.io/mechubsec/rustjunosmcp:0.27.5
# Docker Hub equivalent: image=docker.io/mechub/rustjunosmcp:0.27.5
docker pull "$image"
image=$(docker inspect "$image" \
    --format '{{index .RepoDigests 0}}')
# $image is now ghcr.io/...@sha256:... — pinned, and printable if you want it recorded
```

The digest should be recorded wherever the deployment is tracked, since it identifies
the exact bytes.

## 4. Run it — two-person mode

```bash
docker run -d --name junos-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30030:30030 \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/tokens.json:/etc/jmcp/tokens.json:ro" \
  -v "$PWD/state:/var/lib/jmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30030 \
  --tokens-file /etc/jmcp/tokens.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30030 --allowed-host localhost:30030 \
  --allowed-origin http://127.0.0.1:30030 --allowed-origin http://localhost:30030
```

The `--allowed-origin` values shown work for same-origin browser clients (a page
served from the same scheme, host, and port as the server). A browser client on a
different origin needs to reach the server through a CORS-capable proxy — the
transport emits no CORS headers, so cross-origin requests are blocked by the
browser before authentication runs. The origin allowlist is a restriction on top
of same-origin or proxied access, not a way to enable cross-origin calls directly.

Configuration and keys are mounted read-only; only the state directory is
writable. It holds staged transfers, the destructive-operation leases and
`known_hosts` — do not delete lease files while a server is running.

## 5. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side:

```bash
docker run -d --name junos-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30040:30030 \
  -v "$PWD/devices.json:/etc/jmcp/devices.json:ro" \
  -v "$PWD/keys:/etc/jmcp/keys:ro" \
  -v "$PWD/tokens.json:/etc/jmcp/tokens.json:ro" \
  -v "$PWD/state:/var/lib/jmcp" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30030 \
  --tokens-file /etc/jmcp/tokens.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30040 --allowed-host localhost:30040 \
  --allowed-origin http://127.0.0.1:30040 --allowed-origin http://localhost:30040 \
  --lab-mode
```

The port publish (`-p 127.0.0.1:...`) binds to loopback only, so the server is
reachable from this host but not from another. Reaching the server from another
host requires TLS rather than a wider publish.

**Note the port asymmetry, because it catches people.** The server always
listens on `30030` *inside* the container; `-p 30040:30030` publishes it as
30040 on the host. But `--allowed-host` and `--allowed-origin` are matched
against the `Host` and `Origin` headers the **client** sends, and the client is
talking to 30040. So those flags carry the *published* port, not the internal
one. Get this wrong and the server starts cleanly and then refuses every request
with `421`.

Give each mode its own state directory if you run them against the same devices;
the destructive-operation leases are shared state, and two servers pointed at one
lease directory are two servers that can disagree about who holds a device.

## 6. Verify

```bash
docker ps --filter name=junos- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30030/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30040/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs junos-labmode 2>&1 | grep -i 'lab mode'
```

## 7. Stop

```bash
docker stop junos-twoperson junos-labmode
docker rm junos-twoperson junos-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the device blocked.

## Troubleshooting

Both of these were hit while writing this document.

**`Error: non-loopback bind '0.0.0.0' requires at least one --allowed-origin (the accepted browser Origin, e.g. https://server.example.org:8443)`**
Binding anything other than loopback demands an explicit origin allow-list. This
is a guard, not an inconvenience: a container published to a host port is
reachable by any browser page that can resolve it, and the origin list is what
stops one driving your firewalls. `--allowed-origin` lists the origins of browser
applications that call this server. Clients sending no Origin header (curl,
non-browser MCP clients) are never matched against it.

**`Error: loading /etc/jmcp/devices.json` / `invalid devices.json: inventory parse failed: canonical envelope: missing field 'type'`**
The `auth` object needs a `type`, either `ssh_key` or `password`. Copy the shape
from `devices-template.json` in the repository rather than writing it from
memory.

**Container exits immediately with no log output** — check `docker logs` on the
stopped container: `docker ps -a --filter name=junos-`. Startup validation
failures print and exit before the transport is up, so the container is gone by
the time you look for it with plain `docker ps`.

**`[code=scp_dependency_unavailable]` at startup** — the runtime cannot execute
an OpenSSH-compatible `scp -O`. The published image includes it; a custom image
that strips it fails this check before the server accepts requests, so a broken
image is never advertised as transfer-ready.

**Permission denied reading the inventory or writing state** — the container
process is UID 65532 and does not own your files. Either `chown -R 65532:65532`
them, or run with `--user "$(id -u):$(id -g)"` as shown above.

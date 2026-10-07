#!/usr/bin/env bash
set -euo pipefail

# NOTE: This test validates the distroless hardening properties and MCP server
# operation. End-to-end transfer_file/fetch_file are not exercised here because
# those tools require a NETCONF subsystem for preflight (free-space check) and
# verification (checksum commands), which the minimal sshd fixture does not provide.
#
# SCP1 protocol coverage exists elsewhere:
# - mecmcp-scp carries 62 end-to-end tests driven against a real loopback russh
#   SSH server: successful upload/download, coalesced vs one-byte framing,
#   cancellation, exec rejection, exit signals, error acks, filename fidelity,
#   and advertised mode.
# - Hardware validation: transfer_file from LXC 600 to vsrx-ci with PATH=/nonexistent
#   returned status:transferred with verified:true, confirmed on device.
#
# The old test never exercised transfer_file either — it ran /usr/bin/scp
# straight out of the app image, a raw-binary check for a binary that no longer
# exists. No tool-level coverage was lost.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_IMAGE="${JMCP_CONTAINER_IMAGE:-rust-junosmcp:container-smoke}"
WORK="$(mktemp -d)"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

if [[ -z "${JMCP_CONTAINER_IMAGE:-}" ]]; then
    echo ">> Building rust-junosmcp runtime image"
    docker build --tag "$APP_IMAGE" "$ROOT"
else
    docker image inspect "$APP_IMAGE" >/dev/null
fi

echo ">> Verifying distroless hardening properties"
image_config="$(docker image inspect --format '{{json .Config}}' "$APP_IMAGE")"
for expected in \
    '"User":"65532:65532"' \
    '"/var/lib/jmcp":{}' \
    '"--staging-dir"' \
    '"/var/lib/jmcp/staging"' \
    '"--known-hosts-file"' \
    '"/var/lib/jmcp/known_hosts"' \
    '"--device-lease-dir"' \
    '"/var/lib/jmcp/device-leases"' \
    '"--audit-hmac-key-file"' \
    '"/var/lib/jmcp/audit-hmac.key"'; do
    [[ "$image_config" == *"$expected"* ]] || {
        echo "application image config missing: $expected" >&2
        exit 1
    }
done

# Distroless has no HEALTHCHECK (no shell to run CMD-SHELL)
if grep -q '"Healthcheck"' <<<"$image_config"; then
    echo "distroless image should not contain a HEALTHCHECK" >&2
    exit 1
fi

# Verify no shell exists (distroless hardening)
if docker run --rm --entrypoint /bin/sh "$APP_IMAGE" -c true 2>/dev/null; then
    echo "distroless image should not contain /bin/sh" >&2
    exit 1
fi

# Verify no scp binary (transfer is in-process now)
if docker run --rm --entrypoint /usr/bin/scp "$APP_IMAGE" --version 2>/dev/null; then
    echo "distroless image should not contain /usr/bin/scp" >&2
    exit 1
fi

echo ">> Verifying config-path argv survival under operator overrides"
# Regression guard for mecmcp#357: config paths must survive operator overrides.
# Docker replaces CMD entirely when the caller supplies args, but appends to
# ENTRYPOINT, so config paths must live in ENTRYPOINT or they vanish the
# moment anyone passes --host.
container_id=$(docker create "$APP_IMAGE" --host 0.0.0.0)
argv=$(docker inspect "$container_id" --format '{{join .Args "\n"}}')
docker rm "$container_id" > /dev/null

# Assert the five config path VALUES (not the -f flag, which is too weak to grep).
for p in /etc/jmcp/devices.json /var/lib/jmcp/staging /var/lib/jmcp/known_hosts /var/lib/jmcp/device-leases /var/lib/jmcp/tokens.json /var/lib/jmcp/audit-hmac.key; do
  echo "$argv" | grep -q -- "$p" || { echo "FAIL: $p missing from argv with --host override"; exit 1; }
done
echo "PASS: config paths survive --host override"

echo ">> Testing MCP server operation"
cat > "$WORK/devices.json" <<'DEVICES'
{
  "version": 1,
  "devices": {}
}
DEVICES

VOLUME="jmcpsmoke$$"
AUDIT_VOLUME="jmcpauditsmoke$$"
docker volume create "$VOLUME" >/dev/null
docker volume create "$AUDIT_VOLUME" >/dev/null
trap 'docker volume rm "$VOLUME" "$AUDIT_VOLUME" 2>/dev/null || true; rm -rf "$WORK"' EXIT

docker run --rm -v "$VOLUME:/vol" -v "$WORK:/host:ro" \
  rust:1.97-slim-bookworm \
  bash -c 'cp /host/devices.json /vol/devices.json && chown 65532:65532 /vol/devices.json && chmod 0600 /vol/devices.json' >/dev/null

# Send initialize and tools/list, verify we get JSON-RPC responses
response=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke-test","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | \
  timeout 10 docker run --rm -i \
    --entrypoint /usr/local/bin/rust-junosmcp \
    -v "$VOLUME:/vol:ro" \
    "$APP_IMAGE" \
    -f /vol/devices.json -t stdio 2>&1)

# Check for successful initialize response
if ! grep -q '"id":1.*"result".*"protocolVersion"' <<<"$response"; then
    echo "initialize did not return expected response" >&2
    echo "$response" >&2
    exit 1
fi

# Check for tools/list response
if ! grep -q '"id":2.*"result".*"tools"' <<<"$response"; then
    echo "tools/list did not return expected response" >&2
    echo "$response" >&2
    exit 1
fi

# Verify the tool surface includes transfer_file and fetch_file
if ! grep -q '"name":"transfer_file"' <<<"$response"; then
    echo "tools/list did not include transfer_file" >&2
    exit 1
fi

if ! grep -q '"name":"fetch_file"' <<<"$response"; then
    echo "tools/list did not include fetch_file" >&2
    exit 1
fi

echo ">> Verifying audit HMAC key is generated in the state volume on first run"
# Run the image's real ENTRYPOINT against an otherwise-empty state volume. No
# devices.json is mounted at /etc/jmcp, so the process exits nonzero shortly
# after -- that's expected and ignored (the exit code is never asserted here).
# ensure_audit_hmac_key (src/main.rs) runs before device-mapping is even
# read, so the key file lands in the volume regardless of that later failure.
docker run --rm -v "$AUDIT_VOLUME:/var/lib/jmcp" "$APP_IMAGE" >/dev/null 2>&1 || true

key_present=$(docker run --rm -v "$AUDIT_VOLUME:/vol:ro" rust:1.97-slim-bookworm \
    bash -c '[ -s /vol/audit-hmac.key ] && echo yes || echo no')
if [[ "$key_present" != "yes" ]]; then
    echo "FAIL: audit-hmac.key was not generated in /var/lib/jmcp on first run" >&2
    exit 1
fi
echo "PASS: audit HMAC key auto-generated on first run"

echo ">> Distroless container smoke test passed (hardening + MCP server operation verified)"

#!/usr/bin/env bash
set -euo pipefail

ARCHIVE="${1:?usage: package-smoke.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/extract"
tar -xzf "$ARCHIVE" -C "$WORK/extract"
mapfile -t package_roots < <(find "$WORK/extract" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#package_roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
PACKAGE_ROOT="${package_roots[0]}"

for relative in \
    install.sh \
    usr/local/bin/rust-junosmcp \
    etc/jmcp/devices.json.example \
    etc/systemd/system/rust-junosmcp.service \
    BUILD-INFO; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || { echo "missing package file: $relative" >&2; exit 1; }
done
recorded_sha=$(sed -n 's/^binary_sha256=//p' "$PACKAGE_ROOT/BUILD-INFO")
expected_sha=$(sha256sum "$PACKAGE_ROOT/usr/local/bin/rust-junosmcp" | cut -d' ' -f1)
[[ "$recorded_sha" == "$expected_sha" ]] || {
    echo "archive BUILD-INFO binary_sha256 does not match the shipped binary" >&2
    exit 1
}
recorded_rustc=$(sed -n 's/^rustc=//p' "$PACKAGE_ROOT/BUILD-INFO")
case "$recorded_rustc" in
    rustc\ *) ;;
    *)
        echo "compile-path BUILD-INFO rustc should name the compiling toolchain; got: $recorded_rustc" >&2
        exit 1
        ;;
esac
[[ ! -e "$PACKAGE_ROOT/usr/local/bin/rust-srxmcp" ]]
[[ ! -e "$PACKAGE_ROOT/etc/systemd/system/rust-srxmcp.service" ]]

# A corrupt package must fail before creating any target state.
cp -a "$PACKAGE_ROOT" "$WORK/bad-package"
rm "$WORK/bad-package/usr/local/bin/rust-junosmcp"
if JMCP_INSTALL_ROOT="$WORK/bad-root" \
    JMCP_INSTALL_SKIP_USER=1 \
    JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    "$WORK/bad-package/install.sh" >/dev/null 2>&1; then
    echo "installer accepted a package with a missing binary" >&2
    exit 1
fi
[[ ! -e "$WORK/bad-root" ]] || { echo "failed preflight changed target state" >&2; exit 1; }

ROOTFS="$WORK/rootfs"
mkdir -p "$ROOTFS/usr/local/bin" "$ROOTFS/etc/systemd/system"
printf '%s\n' legacy-binary >"$ROOTFS/usr/local/bin/rust-srxmcp"
printf '%s\n' legacy-unit >"$ROOTFS/etc/systemd/system/rust-srxmcp.service"
mkdir -p "$ROOTFS/var/lib/jmcp/srx-staging/bundles"
printf '%s\n' preserve-me >"$ROOTFS/var/lib/jmcp/srx-staging/bundles/existing.tgz"

run_installer() {
    JMCP_INSTALL_ROOT="$ROOTFS" \
        JMCP_INSTALL_SKIP_USER=1 \
        JMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        "$PACKAGE_ROOT/install.sh" >/dev/null
}

run_installer
[[ ! -e "$ROOTFS/usr/local/bin/rust-srxmcp" ]]
[[ ! -e "$ROOTFS/etc/systemd/system/rust-srxmcp.service" ]]
grep -Fqx preserve-me "$ROOTFS/var/lib/jmcp/srx-staging/bundles/existing.tgz"
printf '%s\n' '{"preserved":"devices"}' >"$ROOTFS/etc/jmcp/devices.json"
printf '%s\n' 'preserved-known-host' >"$ROOTFS/etc/jmcp/known_hosts"
# Place a legacy tokens.json in /etc to verify the installer does NOT copy it
printf '%s\n' '{ "version": 1, "tokens": [{"name":"legacy"}] }' >"$ROOTFS/etc/jmcp/tokens.json"
devices_before="$(sha256sum "$ROOTFS/etc/jmcp/devices.json")"
legacy_tokens_before="$(sha256sum "$ROOTFS/etc/jmcp/tokens.json")"
known_hosts_before="$(sha256sum "$ROOTFS/etc/jmcp/known_hosts")"
run_installer
[[ ! -e "$ROOTFS/usr/local/bin/rust-srxmcp" ]]
[[ ! -e "$ROOTFS/etc/systemd/system/rust-srxmcp.service" ]]
grep -Fqx preserve-me "$ROOTFS/var/lib/jmcp/srx-staging/bundles/existing.tgz"
[[ "$devices_before" == "$(sha256sum "$ROOTFS/etc/jmcp/devices.json")" ]]
# The legacy /etc/jmcp/tokens.json must NOT be copied or touched
[[ "$legacy_tokens_before" == "$(sha256sum "$ROOTFS/etc/jmcp/tokens.json")" ]]
[[ "$known_hosts_before" == "$(sha256sum "$ROOTFS/etc/jmcp/known_hosts")" ]]

# First install created tokens.json and audit-hmac.key in /var/lib/jmcp
[[ -f "$ROOTFS/var/lib/jmcp/tokens.json" ]]
[[ -f "$ROOTFS/var/lib/jmcp/audit-hmac.key" ]]
tokens_new_before="$(sha256sum "$ROOTFS/var/lib/jmcp/tokens.json")"
hmac_key_before="$(sha256sum "$ROOTFS/var/lib/jmcp/audit-hmac.key")"

# Second install must preserve both files (no regeneration)
run_installer
[[ "$tokens_new_before" == "$(sha256sum "$ROOTFS/var/lib/jmcp/tokens.json")" ]]
[[ "$hmac_key_before" == "$(sha256sum "$ROOTFS/var/lib/jmcp/audit-hmac.key")" ]]

[[ "$(stat -c '%a' "$ROOTFS/usr/local/bin/rust-junosmcp")" == "755" ]]
[[ "$(stat -c '%a' "$ROOTFS/etc/jmcp/devices.json")" == "600" ]]
[[ "$(stat -c '%a' "$ROOTFS/var/lib/jmcp/tokens.json")" == "600" ]]
[[ "$(stat -c '%a' "$ROOTFS/var/lib/jmcp/audit-hmac.key")" == "600" ]]
[[ -d "$ROOTFS/var/lib/jmcp/staging" ]]
[[ -d "$ROOTFS/var/lib/jmcp/srx-staging/bundles" ]]
[[ -d "$ROOTFS/var/lib/jmcp/device-leases" ]]
[[ "$(stat -c '%a' "$ROOTFS/var/lib/jmcp/device-leases")" == "700" ]]

JUNOS_UNIT="$ROOTFS/etc/systemd/system/rust-junosmcp.service"
grep -Fq -- '--transport streamable-http' "$JUNOS_UNIT"
grep -Fq -- '--tokens-file /var/lib/jmcp/tokens.json' "$JUNOS_UNIT"
grep -Fq -- '--audit-hmac-key-file /var/lib/jmcp/audit-hmac.key' "$JUNOS_UNIT"
grep -Fq -- '--host 127.0.0.1' "$JUNOS_UNIT"
grep -Fq -- '--device-lease-dir /var/lib/jmcp/device-leases' "$JUNOS_UNIT"
grep -Fq 'JMCP_SUPPORT_BUNDLE_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles' "$JUNOS_UNIT"
grep -Fq 'JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES=524288000' "$JUNOS_UNIT"
printf '%s\n' 'jmcp:x:998:998:RustJunosMCP:/var/lib/jmcp:/usr/sbin/nologin' >"$ROOTFS/etc/passwd"
printf '%s\n' 'jmcp:x:998:' >"$ROOTFS/etc/group"
systemd-analyze verify --recursive-errors=no --root="$ROOTFS" \
    rust-junosmcp.service

# Start the installed binary and perform an authenticated MCP initialize.
cat >"$ROOTFS/etc/jmcp/devices.json" <<'JSON'
{
  "smoke": {
    "ip": "192.0.2.1",
    "username": "smoke",
    "auth": {"type": "password", "password": "unused"}
  }
}
JSON
SECRET="$("$ROOTFS/usr/local/bin/rust-junosmcp" token add \
    --tokens-file "$ROOTFS/var/lib/jmcp/tokens.json" \
    --name packaging-smoke \
    --routers '*' \
    --tools '*')"
PORT="${JMCP_PACKAGE_SMOKE_PORT:-39030}"
"$ROOTFS/usr/local/bin/rust-junosmcp" \
    --device-mapping "$ROOTFS/etc/jmcp/devices.json" \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port "$PORT" \
    --tokens-file "$ROOTFS/var/lib/jmcp/tokens.json" \
    --device-lease-dir "$ROOTFS/var/lib/jmcp/device-leases" \
    --state-file "$ROOTFS/var/lib/jmcp/changeset-state.json" \
    --inventory-readonly \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -sS -o /dev/null "http://127.0.0.1:$PORT/mcp" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$ready" != "1" ]]; then
    cat "$WORK/server.log" >&2
    echo "MCP endpoint did not become ready" >&2
    exit 1
fi

HTTP_STATUS="$(curl -sS \
    -D "$WORK/headers" \
    -o "$WORK/body" \
    -w '%{http_code}' \
    -H "Authorization: Bearer $SECRET" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"package-smoke","version":"1"}}}' \
    "http://127.0.0.1:$PORT/mcp")"
if [[ "$HTTP_STATUS" != "200" ]] || ! grep -Fq '"result"' "$WORK/body"; then
    cat "$WORK/server.log" >&2
    cat "$WORK/body" >&2
    echo "MCP initialize failed with HTTP $HTTP_STATUS" >&2
    exit 1
fi

SESSION_ID="$(awk -F ': *' 'tolower($1) == "mcp-session-id" {print $2}' "$WORK/headers" | tr -d '\r' | tail -n 1)"
[[ -n "$SESSION_ID" ]] || { echo "initialize did not return Mcp-Session-Id" >&2; exit 1; }

INITIALIZED_STATUS="$(curl -sS \
    -o "$WORK/initialized-body" \
    -w '%{http_code}' \
    -H "Authorization: Bearer $SECRET" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "http://127.0.0.1:$PORT/mcp")"
[[ "$INITIALIZED_STATUS" == "200" || "$INITIALIZED_STATUS" == "202" ]]

TOOLS_STATUS="$(curl -sS \
    -o "$WORK/tools-body" \
    -w '%{http_code}' \
    -H "Authorization: Bearer $SECRET" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    "http://127.0.0.1:$PORT/mcp")"
[[ "$TOOLS_STATUS" == "200" ]]
grep -Fq '"name":"get_router_list"' "$WORK/tools-body"
grep -Fq '"name":"srxmcp_status"' "$WORK/tools-body"

echo ">> Package layout, idempotence, units, and MCP endpoint passed"

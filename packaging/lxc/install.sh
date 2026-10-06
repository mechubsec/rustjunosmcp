#!/usr/bin/env bash
# Installer for the extracted RustJunosMCP LXC package.
set -euo pipefail

PACKAGE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_ROOT="${JMCP_INSTALL_ROOT:-/}"
SERVICE_USER="${JMCP_SERVICE_USER:-jmcp}"
SERVICE_GROUP="${JMCP_SERVICE_GROUP:-jmcp}"
SKIP_USER_SETUP="${JMCP_INSTALL_SKIP_USER:-0}"
SKIP_SYSTEMD_RELOAD="${JMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}"
SKIP_RUNTIME_DEPS="${JMCP_INSTALL_SKIP_RUNTIME_DEPS:-0}"

fail() {
    echo ">> Installation refused: $*" >&2
    exit 1
}

target_path() {
    local relative="${1#/}"
    if [[ "$INSTALL_ROOT" == "/" ]]; then
        printf '/%s\n' "$relative"
    else
        printf '%s/%s\n' "${INSTALL_ROOT%/}" "$relative"
    fi
}

# Refuse to operate on a path that is not a plain file or directory, so a
# caller never chmod/chown/writes through whatever unexpected entry happens
# to sit at a destination this installer does not fully control.
require_regular_file() {
    local path="$1"
    if [[ -L "$path" ]] || { [[ -e "$path" ]] && [[ ! -f "$path" ]]; }; then
        fail "$path is not a regular file; refusing"
    fi
}

require_plain_dir() {
    local path="$1"
    if [[ -L "$path" ]] || { [[ -e "$path" ]] && [[ ! -d "$path" ]]; }; then
        fail "$path is not a directory; refusing"
    fi
}

# Install generated content ($tmp) at $target with a fixed owner and mode.
# install(1) replaces an existing non-regular destination rather than writing
# through it, so pair this with a require_regular_file check immediately
# beforehand rather than relying on install(1) alone.
install_owned() {
    local mode="$1" tmp="$2" target="$3"
    if [[ "$SKIP_USER_SETUP" != "1" ]]; then
        install -m "$mode" -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$tmp" "$target"
    else
        install -m "$mode" "$tmp" "$target"
    fi
}

# Resolve the journald drop-in directory and prove it is safe to touch.
#
# Echoes the canonical directory, or nothing when it does not exist. Fails
# closed on anything unexpected rather than skipping silently.
#
# This is called TWICE, deliberately: once in preflight so a refusal costs no
# mutation, and again immediately before unlinking. Caching the preflight
# result and reusing it is not sufficient — the cached value is a path *string*,
# so if the directory is replaced by a symlink in between, that same string
# traverses the new link at `rm` time and reaches outside the install root.
# Testing `-L` on the file does not catch a symlinked *parent*.
resolve_journald_dropins() {
    local dir resolved root_resolved
    dir="$(target_path /etc/systemd/journald.conf.d)"

    [[ -d "$dir" ]] || return 0

    [[ -L "$dir" ]] && fail "refusing to touch journald drop-ins: $dir is a symlink"

    resolved="$(readlink -f "$dir")" \
        || fail "refusing to touch journald drop-ins: cannot resolve $dir"

    if [[ "$INSTALL_ROOT" != "/" ]]; then
        root_resolved="$(readlink -f "$INSTALL_ROOT")" \
            || fail "refusing to touch journald drop-ins: cannot resolve $INSTALL_ROOT"
        case "$resolved/" in
            "$root_resolved"/*) ;;
            *) fail "refusing to touch journald drop-ins: $resolved escapes $root_resolved" ;;
        esac
    fi

    # Candidate files too, not just the directory. A real journald.conf.d
    # containing a symlinked retention.conf must be refused in preflight as
    # well, or the refusal lands after the install has already written.
    local candidate
    for candidate in "$resolved/retention.conf" "$resolved/jmcp.conf"; do
        [[ -L "$candidate" ]] \
            && fail "refusing to touch journald drop-ins: $candidate is a symlink"
    done

    printf '%s\n' "$resolved"
}

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# JMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    local require=$1 reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    [[ "$require" == 1 ]] \
        && fail 'JMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    return 0
}

report_egress_enforcement() {
    local require=${JMCP_REQUIRE_EGRESS_FILTER:-0}
    local probe_unit="rust-junosmcp-egress-probe-$$"
    local unit_path="$UNIT_DIR/rust-junosmcp.service"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    local counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [[ -z "$counters" || "$counters" == '[no data]' ]]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rust-junosmcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  packaging/FILESYSTEM.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        [[ "$require" == 1 ]] \
            && fail 'JMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install or add the directives by hand.' >&2
        [[ "$require" == 1 ]] \
            && fail 'JMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

required_files=(
    usr/local/bin/rust-junosmcp
    etc/jmcp/devices.json.example
    etc/systemd/system/rust-junosmcp.service
)

# Validate the complete payload before creating users, directories, or files.
for relative in "${required_files[@]}"; do
    [[ -s "$PACKAGE_ROOT/$relative" ]] || fail "package payload is missing $relative"
done
[[ -x "$PACKAGE_ROOT/usr/local/bin/rust-junosmcp" ]] \
    || fail "package binary is not executable: usr/local/bin/rust-junosmcp"

[[ "$INSTALL_ROOT" == /* ]] || fail "JMCP_INSTALL_ROOT must be an absolute path"
if [[ "$INSTALL_ROOT" != "/" && "$SKIP_USER_SETUP" != "1" ]]; then
    fail "a staged install requires JMCP_INSTALL_SKIP_USER=1"
fi
if [[ "$SKIP_USER_SETUP" != "1" && "$EUID" -ne 0 ]]; then
    fail "run as root, or use JMCP_INSTALL_SKIP_USER=1 for a staged smoke test"
fi

# Preflight, before ANY mutation — including groupadd/useradd, which create a
# system account and /var/lib/jmcp. A refused install must leave the host alone.
resolve_journald_dropins >/dev/null

if [[ "$SKIP_USER_SETUP" != "1" ]] && ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
fi
if [[ "$SKIP_USER_SETUP" != "1" ]] && ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --create-home --home-dir /var/lib/jmcp \
        --shell /usr/sbin/nologin "$SERVICE_USER"
fi

BIN_DIR="$(target_path /usr/local/bin)"
CONFIG_DIR="$(target_path /etc/jmcp)"
UNIT_DIR="$(target_path /etc/systemd/system)"
STATE_DIR="$(target_path /var/lib/jmcp)"
JUNOS_STAGING_DIR="$STATE_DIR/staging"
SRX_STAGING_DIR="$STATE_DIR/srx-staging/bundles"
DEVICE_LEASE_DIR="$STATE_DIR/device-leases"

remove_legacy_runtime() {
    local legacy_binary legacy_unit
    legacy_binary="$(target_path /usr/local/bin/rust-srxmcp)"
    legacy_unit="$(target_path /etc/systemd/system/rust-srxmcp.service)"

    if [[ "$INSTALL_ROOT" == "/" && -e "$legacy_unit" ]]; then
        command -v systemctl >/dev/null 2>&1 \
            || fail "systemctl is required to retire rust-srxmcp.service"
        if systemctl is-active --quiet rust-srxmcp.service; then
            systemctl stop rust-srxmcp.service
        fi
        systemctl disable rust-srxmcp.service >/dev/null
    fi

    rm -f "$legacy_binary" "$legacy_unit"
}

for dir in "$BIN_DIR" "$UNIT_DIR" "$CONFIG_DIR" "$STATE_DIR" "$JUNOS_STAGING_DIR" "$SRX_STAGING_DIR" "$DEVICE_LEASE_DIR"; do
    require_plain_dir "$dir"
done
install -d -m 0755 "$BIN_DIR" "$UNIT_DIR"
install -d -m 0750 "$CONFIG_DIR" "$STATE_DIR" "$JUNOS_STAGING_DIR" "$SRX_STAGING_DIR"
install -d -m 0700 "$DEVICE_LEASE_DIR"

remove_legacy_runtime

install -m 0755 "$PACKAGE_ROOT/usr/local/bin/rust-junosmcp" "$BIN_DIR/rust-junosmcp"
install -m 0644 "$PACKAGE_ROOT/etc/jmcp/devices.json.example" "$CONFIG_DIR/devices.json.example"
install -m 0644 "$PACKAGE_ROOT/etc/systemd/system/rust-junosmcp.service" "$UNIT_DIR/rust-junosmcp.service"

# DO NOT create devices.json on first install — the server will fail with a
# clear actionable error telling the operator to copy the example and edit it.
# Only preserve an existing devices.json on upgrade (it already exists).

# tokens.json moved from /etc/jmcp to /var/lib/jmcp in v0.22.0 (#333). Create
# it in the new location if it does not exist. Do NOT copy from the old location
# — the runtime handles fallback and warns loudly so the operator can migrate
# explicitly and remove the stale secret.
# tokens.json moved from /etc/jmcp to /var/lib/jmcp (#333).
#
# Create an empty store ONLY when no legacy store exists. The runtime prefers an
# existing primary, so writing an empty file here while the live tokens are still
# at "$CONFIG_DIR/tokens.json" would shadow them: the service starts and rejects every
# existing bearer token. A silent auth wipe on upgrade is worse than a refusal.
#
# The file is never copied automatically — that would leave a duplicate secret
# behind, which is exactly what the stale-secret scan exists to flag.
state_tokens_file="$STATE_DIR/tokens.json"
legacy_tokens_file="$CONFIG_DIR/tokens.json"
known_hosts_file="$CONFIG_DIR/known_hosts"
changeset_state_file="$STATE_DIR/changeset-state.json"
audit_key_file="$STATE_DIR/audit-hmac.key"

require_regular_file "$state_tokens_file"
if [[ ! -e "$state_tokens_file" ]]; then
    if [[ -e "$legacy_tokens_file" ]]; then
        printf '%s\n' ">> Not creating $state_tokens_file: a token store already exists at"
        printf '%s\n' ">> $legacy_tokens_file. The server reads it via the legacy fallback and warns."
        printf '%s\n' ">>"
        printf '%s\n' ">> Migrate it deliberately. The service must be RESTARTED, not reloaded:"
        printf '%s\n' ">> the token store is bound to the path resolved at startup, so SIGHUP"
        printf '%s\n' ">> keeps reloading the old file. Rotations and revocations would silently"
        printf '%s\n' ">> stop applying — revoked credentials would stay active."
        printf '%s\n' ">> try-restart, not restart: a service deliberately left stopped must stay"
        printf '%s\n' ">> stopped rather than have its endpoint exposed by the migration."
        printf '>>   install -m 0600 -o %s -g %s %s %s\n' \
            "$SERVICE_USER" "$SERVICE_GROUP" \
            "$legacy_tokens_file" "$state_tokens_file"
        printf '%s\n' ">>   systemctl try-restart rust-junosmcp   # restarts ONLY if already running"
        printf '%s\n' ">>   systemctl status rust-junosmcp        # confirm state is what you expect"
        printf '%s\n' ">>   shred -u $legacy_tokens_file  # secure erase, per packaging/FILESYSTEM.md"
    else
        tokens_tmp=$(mktemp)
        printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_tmp"
        install_owned 0600 "$tokens_tmp" "$state_tokens_file"
        rm -f "$tokens_tmp"
    fi
fi

require_regular_file "$known_hosts_file"
if [[ ! -e "$known_hosts_file" ]]; then
    known_hosts_tmp=$(mktemp)
    install_owned 0644 "$known_hosts_tmp" "$known_hosts_file"
    rm -f "$known_hosts_tmp"
fi

require_regular_file "$changeset_state_file"
if [[ ! -e "$changeset_state_file" ]]; then
    changeset_state_tmp=$(mktemp)
    printf '%s\n' '{"version":1,"state":{"operations":{},"change_sets":{}}}' >"$changeset_state_tmp"
    install_owned 0600 "$changeset_state_tmp" "$changeset_state_file"
    rm -f "$changeset_state_tmp"
fi

# Generate audit HMAC key if it does not exist. Do NOT regenerate on upgrade —
# a new key breaks verification of every prior record (#334).
require_regular_file "$audit_key_file"
if [[ ! -e "$audit_key_file" ]]; then
    audit_key_tmp=$(mktemp)
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 >"$audit_key_tmp"
    elif command -v head >/dev/null 2>&1 && [[ -e /dev/urandom ]]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$audit_key_tmp"
    else
        echo ">> WARNING: cannot generate audit-hmac.key (no openssl or /dev/urandom)" >&2
        echo ">> WARNING: audit log will not be tamper-evident until the key is created" >&2
    fi
    if [[ -s "$audit_key_tmp" ]]; then
        install_owned 0600 "$audit_key_tmp" "$audit_key_file"
    fi
    rm -f "$audit_key_tmp"
fi

# Set modes on files that exist. devices.json may not exist on first install.
# Each path is re-checked with require_regular_file immediately before the
# chmod/chown that follows it, rather than trusting an earlier check or the
# fact that install(1) just created it.
if [[ -e "$CONFIG_DIR/devices.json" ]]; then
    require_regular_file "$CONFIG_DIR/devices.json"
    chmod 0600 "$CONFIG_DIR/devices.json"
fi
# The legacy /etc store is hardened too, when present. It is not vestigial: under
# the migration fallback it is the store the service actually reads, so leaving it
# at whatever mode it happened to have is a live credential exposure. Dropping
# this when the primary moved to /var/lib was a regression the distribution smoke
# test caught by asserting mode 600 on /etc/jmcp/tokens.json.
if [[ -e "$legacy_tokens_file" ]]; then
    require_regular_file "$legacy_tokens_file"
    chmod 0600 "$legacy_tokens_file"
fi
if [[ -e "$state_tokens_file" ]]; then
    require_regular_file "$state_tokens_file"
    chmod 0600 "$state_tokens_file"
fi
require_regular_file "$known_hosts_file"
chmod 0644 "$known_hosts_file"
require_regular_file "$changeset_state_file"
chmod 0600 "$changeset_state_file"
if [[ -e "$audit_key_file" ]]; then
    require_regular_file "$audit_key_file"
    chmod 0600 "$audit_key_file"
fi

if [[ "$SKIP_USER_SETUP" != "1" ]]; then
    require_plain_dir "$CONFIG_DIR"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    # chown only files that exist. devices.json may not exist on first install.
    if [[ -e "$CONFIG_DIR/devices.json" ]]; then
        require_regular_file "$CONFIG_DIR/devices.json"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/devices.json"
    fi
    require_regular_file "$known_hosts_file"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$known_hosts_file"
    # chown -R covers device-leases/, staging/, and srx-staging/ subdirs,
    # plus changeset-state.json, tokens.json, and audit-hmac.key. GNU chown -R
    # does not follow symlinks while recursing by default, so an entry under
    # this directory is re-owned by its own name, not by whatever it resolves to.
    require_plain_dir "$STATE_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for a live install"
    systemctl daemon-reload
fi

# Runtime dependencies.
#
# `openssh-client` is REQUIRED. Do not remove it without reading this.
#
# The old rationale here claimed transfer_file and fetch_file spawn ssh/scp.
# That part is genuinely obsolete: #212 removed the last `Command::new` in this
# repo, and transfers run through mecmcp-scp (russh + aws-lc-rs). Grepping this
# repo for `Command::new` returns nothing, which is what led #329 to conclude
# the dependency was dead.
#
# It is not dead. The subprocess moved one crate down, it did not go away:
#
#   rust-junosmcp-core/src/inventory.rs:319   `ssh_config: Option<PathBuf>`
#   rust-junosmcp-core/src/device_manager.rs  forwards it on connect
#   rustnetconf/src/client.rs                 maps ProxyCommand into the builder
#   rustnetconf/src/transport/ssh.rs          spawn_proxy_command runs
#                                             `Command::new("sh")` with it
#
# A supported inventory entry carrying `ProxyCommand ssh -W %h:%p bastion`
# therefore needs the ssh binary at runtime. Without it, every NETCONF
# connection for a device behind a jump host fails with `ssh: not found` —
# silently, and only for those devices.
#
# This can be dropped only when ProxyJump/ProxyCommand inventory support is
# dropped, or when that path stops shelling out. Not before.
#
# `tar` was here for collect_jtac_support_bundle, which no longer spawns it —
# the bundle is built in-process with the `tar` and `flate2` crates (#212). It
# is also redundant on its own terms: the operator has already used tar to
# unpack the release archive that contains this script.
#
# `curl` is needed by the verification step in the README, and the Debian 13
# standard template does not ship it (mecmcp#33). Installing an HTTP client on
# every deploy is deliberate for the LXC path and deliberate *not* for the
# container image: an LXC already has a shell and a package manager, so curl
# changes nothing about its attack surface, whereas adding it to a distroless
# image hands an attacker a pivot tool after an RCE. That said, README
# verification is an operator convenience, not a server runtime requirement,
# so the curl install is now behind an opt-in flag.
if [[ "$INSTALL_ROOT" == "/" && "$SKIP_RUNTIME_DEPS" != "1" ]]; then
    missing=()
    # Required: see the ProxyCommand rationale above.
    command -v ssh >/dev/null 2>&1 || missing+=(openssh-client)
    if [[ "${JMCP_INSTALL_VERIFY_TOOLS:-0}" == "1" ]]; then
        command -v curl >/dev/null 2>&1 || missing+=(curl)
    fi

    if (( ${#missing[@]} > 0 )); then
        if command -v apt-get >/dev/null 2>&1; then
            echo ">> Installing runtime dependencies: ${missing[*]}"
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                ca-certificates "${missing[@]}"
            # Clean up apt cache to avoid leaving 98 MB in /var/cache.
            apt-get clean
        else
            echo ">> WARNING: missing ${missing[*]} and no apt-get to install them." >&2
            echo ">> WARNING: install these if you need the README verification steps." >&2
        fi
    fi
fi

# Clean up stale journald drop-ins.
#
# An unnumbered /etc/systemd/journald.conf.d/retention.conf sorts after the
# numbered fleet policy drop-ins (10-audit-sealing.conf,
# 20-audit-retention.conf) and silently overrides them. Previous versions of
# this installer did not write any journald drop-ins, but if one exists from a
# manual edit or another tool, remove it so the numbered fleet policy wins.
# This repo's policy is: journald retention is set by the numbered drop-ins
# shipped by the fleet management layer, not by this installer.
#
# Two details that are easy to get wrong:
#
#  1. This runs through `target_path` rather than hard-coding /etc, so a staged
#     install (JMCP_INSTALL_ROOT=...) actually exercises this branch. Guarding
#     on INSTALL_ROOT == "/" meant the packaging test could never reach it, so
#     the test asserted nothing.
#  2. Unlinking a drop-in journald has ALREADY loaded does not change the
#     running daemon. `systemctl daemon-reload` above reloads systemd *unit*
#     configuration, not journald.conf — journald must be signalled to reread
#     it. Without this, the stale 30-day retention stays active until a manual
#     reload or a reboot, which is exactly the defect #331 exists to fix.
#  3. The directory is re-resolved and re-contained HERE, not trusted from
#     preflight. Preflight exists so a refusal costs no mutation; this call
#     exists so the path is validated at the moment it is used.
JOURNALD_CLEANED=0
JOURNALD_DROPINS_RESOLVED="$(resolve_journald_dropins)"
if [[ -n "$JOURNALD_DROPINS_RESOLVED" ]]; then
    for stale in "$JOURNALD_DROPINS_RESOLVED/retention.conf" "$JOURNALD_DROPINS_RESOLVED/jmcp.conf"; do
        [[ -L "$stale" ]] \
            && fail "refusing to remove symlinked journald drop-in: $stale"
        if [[ -f "$stale" ]]; then
            echo ">> Removing stale journald drop-in: $stale"
            rm -f "$stale"
            JOURNALD_CLEANED=1
        fi
    done
fi

if [[ "$INSTALL_ROOT" == "/" && "$JOURNALD_CLEANED" == "1" && "$SKIP_SYSTEMD_RELOAD" != "1" ]]; then
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is required to reload journald"
    echo ">> Reloading systemd-journald so the fleet retention policy takes effect"
    systemctl reload-or-restart systemd-journald.service
fi

if [[ "$INSTALL_ROOT" == "/" && "$SKIP_SYSTEMD_RELOAD" != "1" ]]; then
    report_egress_enforcement
fi

echo ">> RustJunosMCP package installed."
if [[ -e "$CONFIG_DIR/devices.json" ]]; then
    echo ">> Edit $CONFIG_DIR/devices.json and mint a bearer token before enabling the service."
else
    echo ">> No inventory yet. Before enabling the service:"
    echo ">>   cp $CONFIG_DIR/devices.json.example $CONFIG_DIR/devices.json"
    echo ">>   \$EDITOR $CONFIG_DIR/devices.json    # replace the placeholder paths"
    echo ">>   chmod 0600 $CONFIG_DIR/devices.json"
    echo ">> Then mint a bearer token. The service will not start until the"
    echo ">> inventory exists — it exits with a message naming this file."
fi
echo ">> Junos/SRX endpoint: http://127.0.0.1:30030/mcp"

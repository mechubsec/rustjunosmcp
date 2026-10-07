#!/usr/bin/env bash
# Build a release tarball for LXC / Debian and Ubuntu deployment.
# Output: dist/rust-junosmcp_<version>_<arch>.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${JMCP_PACKAGE_VERSION:-$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-junosmcp/Cargo.toml)}"
case "$(uname -m)" in
    x86_64) DEFAULT_ARCH=amd64 ;;
    aarch64) DEFAULT_ARCH=arm64 ;;
    *) DEFAULT_ARCH="$(uname -m)" ;;
esac
ARCH="${JMCP_PACKAGE_ARCH:-$DEFAULT_ARCH}"
OUTPUT_DIR="${JMCP_PACKAGE_OUTPUT_DIR:-dist}"

if [[ "${JMCP_PACKAGE_SKIP_BUILD:-0}" != "1" ]]; then
    echo ">> Building release binary..."
    cargo build --release -p rust-junosmcp
fi

if [[ ! -x target/release/rust-junosmcp ]]; then
    echo ">> Missing executable target/release/rust-junosmcp" >&2
    exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rust-junosmcp_${VERSION}_${ARCH}"
PKGROOT="$STAGING/$PKG"

mkdir -p "$PKGROOT/usr/local/bin"
mkdir -p "$PKGROOT/etc/jmcp"
mkdir -p "$PKGROOT/etc/systemd/system"

install -m 0755 target/release/rust-junosmcp "$PKGROOT/usr/local/bin/rust-junosmcp"
install -m 0644 devices-template.json "$PKGROOT/etc/jmcp/devices.json.example"
install -m 0644 packaging/systemd/rust-junosmcp.service "$PKGROOT/etc/systemd/system/rust-junosmcp.service"
install -m 0755 packaging/lxc/install.sh "$PKGROOT/install.sh"

# Provenance for the bytes actually in the archive. Skip-build must not name a
# local rustc that did not compile the binary (mecmcp packaging R3).
binary_sha256=$(sha256sum "$PKGROOT/usr/local/bin/rust-junosmcp" | cut -d' ' -f1)
git_commit=$(git rev-parse HEAD)
if [[ "${JMCP_PACKAGE_SKIP_BUILD:-0}" == "1" ]]; then
    toolchain_channel=$(awk -F= '/^[[:space:]]*channel[[:space:]]*=/ {
        gsub(/^[[:space:]]*|[[:space:]]*$|"/, "", $2)
        print $2
        exit
    }' rust-toolchain.toml)
    [[ -n "$toolchain_channel" ]] || {
        echo ">> could not read toolchain channel from rust-toolchain.toml" >&2
        exit 1
    }
    rustc_metadata="unknown (binary supplied prebuilt via JMCP_PACKAGE_SKIP_BUILD; pinned toolchain $toolchain_channel per rust-toolchain.toml at ${git_commit:0:12}; not compiled by this script)"
else
    rustc_metadata=$(rustc -vV | tr '\n' ' ' | sed 's/[[:space:]]*$//')
fi
cat >"$PKGROOT/BUILD-INFO" <<EOF
version=$VERSION
git_commit=$git_commit
rustc=$rustc_metadata
binary_sha256=$binary_sha256
EOF

mkdir -p "$OUTPUT_DIR"
DIST_DIR="$(cd "$OUTPUT_DIR" && pwd)"
TARBALL="$DIST_DIR/$PKG.tar.gz"

tar -czf "$TARBALL" -C "$STAGING" "$PKG"
( cd "$DIST_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo ">> Wrote $TARBALL"
echo ">> Wrote $TARBALL.sha256"

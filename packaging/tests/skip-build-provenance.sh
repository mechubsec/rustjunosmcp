#!/usr/bin/env bash
# Regression guard for skip-build provenance: packaging a prebuilt binary
# must record an honest rustc field (unknown (...)) and a binary_sha256 that
# matches the bytes in the archive. A compile-path BUILD-INFO that names the
# workstation toolchain is the same false claim this test exists to catch.
#
# Must run after target/release/rust-junosmcp already exists. Writes into a
# private output directory so it does not overwrite dist/.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

[[ -x target/release/rust-junosmcp ]] || {
    printf '%s\n' 'target/release/rust-junosmcp must already be built before this test runs' >&2
    exit 1
}

expected_sha=$(sha256sum target/release/rust-junosmcp | cut -d' ' -f1)

cleanup_dir=""
output_dir=""
cleanup() {
    [[ -z "$cleanup_dir" ]] || rm -rf -- "$cleanup_dir"
    [[ -z "$output_dir" ]] || rm -rf -- "$output_dir"
}
trap cleanup EXIT

output_dir=$(mktemp -d)
JMCP_PACKAGE_SKIP_BUILD=1 \
JMCP_PACKAGE_OUTPUT_DIR="$output_dir" \
    scripts/package-lxc.sh

mapfile -t archives < <(find "$output_dir" -maxdepth 1 -type f -name 'rust-junosmcp_*_*.tar.gz')
[[ ${#archives[@]} -eq 1 ]] || {
    printf '%s\n' "expected exactly one skip-build archive, found ${#archives[@]}" >&2
    exit 1
}
archive=${archives[0]}

cleanup_dir=$(mktemp -d)
tar -xzf "$archive" -C "$cleanup_dir"
build_info=$(find "$cleanup_dir" -maxdepth 2 -name BUILD-INFO)
[[ -n "$build_info" && -f "$build_info" ]] || {
    printf '%s\n' 'skip-build archive is missing BUILD-INFO' >&2
    exit 1
}

recorded_rustc=$(sed -n 's/^rustc=//p' "$build_info")
case "$recorded_rustc" in
    unknown\ \(*) ;;
    *)
        printf '%s\n' "skip-build BUILD-INFO must record an honest rustc field starting with 'unknown ('; got: $recorded_rustc" >&2
        exit 1
        ;;
esac
if printf '%s\n' "$recorded_rustc" | grep -Eq 'rustc [0-9]+\.[0-9]+\.[0-9]+'; then
    printf '%s\n' "skip-build BUILD-INFO names a compiler version as if it compiled the binary: $recorded_rustc" >&2
    exit 1
fi

recorded_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
[[ "$recorded_sha" == "$expected_sha" ]] || {
    printf '%s\n' "skip-build BUILD-INFO binary_sha256 ($recorded_sha) does not match the packaged binary ($expected_sha)" >&2
    exit 1
}

printf '%s\n' 'skip-build provenance is honest'

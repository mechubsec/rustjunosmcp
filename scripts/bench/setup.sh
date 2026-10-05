#!/usr/bin/env bash
# Build every benchmarked server at a pinned commit into a work directory,
# and write the servers.json that bench.py reads.
#
#   scripts/bench/setup.sh /path/to/workdir
#
# Needs: git, uv, cargo (with the toolchain from rust-toolchain.toml; set
# CARGO and RUSTC to pick a specific toolchain).
# Competitor code is cloned and run as published, never modified. A tag that
# no longer points at the pinned commit is an error, not a warning.
set -euo pipefail

WORK=${1:?usage: setup.sh WORKDIR}
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
PY=${BENCH_PYTHON:-3.13}
CARGO=${CARGO:-cargo}

RUST_TAG=v0.27.2
RUST_SHA=864ca6cb4ea0f91e2435c10914532ca5a067b889
JUNIPER_URL=https://github.com/Juniper/junos-mcp-server.git
JUNIPER_TAG=v1.1.1
JUNIPER_SHA=0fe6354dfc209a11e491f23e5cc1ecfa050ed069
SHIGE_URL=https://github.com/shigechika/junos-mcp.git
SHIGE_PINS=("v0.18.0 ecec068bf5cfeb53625cc35e9b36a946d9a19166" "v0.22.0 af4f84aed6687d1c2819263c4c5b32dbd0184daf")

mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
export UV_CACHE_DIR=${UV_CACHE_DIR:-$WORK/uv-cache}
# Keep uv-managed interpreters in the workdir too, so the venvs do not point
# into a HOME that may not outlive this shell.
export UV_PYTHON_INSTALL_DIR=${UV_PYTHON_INSTALL_DIR:-$WORK/uv-python}

checkout_pinned() { # dir url tag sha
  local dir=$1 url=$2 tag=$3 sha=$4
  [ -d "$dir/.git" ] || git clone -q "$url" "$dir"
  git -C "$dir" fetch -q --tags origin
  local got
  got=$(git -C "$dir" rev-parse "$tag^{commit}")
  if [ "$got" != "$sha" ]; then
    echo "setup: $url tag $tag now points at $got, expected $sha; refusing" >&2
    exit 1
  fi
  git -C "$dir" checkout -q --detach "$sha"
}

# rust-junosmcp, from this repository's history.
if [ "$(git -C "$REPO" rev-parse "$RUST_TAG^{commit}")" != "$RUST_SHA" ]; then
  echo "setup: $RUST_TAG does not point at $RUST_SHA; refusing" >&2
  exit 1
fi
[ -d "$WORK/rust-junosmcp" ] || git -C "$REPO" worktree add -q --detach "$WORK/rust-junosmcp" "$RUST_SHA"
(cd "$WORK/rust-junosmcp" && CARGO_TARGET_DIR="$WORK/target" "$CARGO" build --release --locked -p rust-junosmcp)

# Juniper/junos-mcp-server, from its own uv.lock.
checkout_pinned "$WORK/juniper" "$JUNIPER_URL" "$JUNIPER_TAG" "$JUNIPER_SHA"
(cd "$WORK/juniper" && uv sync --frozen --python "$PY" -q)

# shigechika/junos-mcp, one venv per pinned version, deps from our lock.
for pin in "${SHIGE_PINS[@]}"; do
  read -r tag sha <<<"$pin"
  checkout_pinned "$WORK/shigechika-$tag" "$SHIGE_URL" "$tag" "$sha"
  uv venv -q --clear --python "$PY" "$WORK/venv-shigechika-$tag"
  VIRTUAL_ENV="$WORK/venv-shigechika-$tag" uv pip install -q -r "$HERE/requirements/shigechika-${tag#v}.txt"
  VIRTUAL_ENV="$WORK/venv-shigechika-$tag" uv pip install -q --no-deps "$WORK/shigechika-$tag"
done

# Harness venv (asyncssh for the mock server and the host-key pre-flight).
uv venv -q --clear --python "$PY" "$WORK/venv-bench"
VIRTUAL_ENV="$WORK/venv-bench" uv pip install -q -r "$HERE/requirements/harness.txt"

cat >"$WORK/servers.json" <<EOF
{
  "rustjunosmcp-${RUST_TAG#v}": {"flavour": "rustjunosmcp", "version": "${RUST_TAG#v}", "commit": "$RUST_SHA",
    "bin": "$WORK/target/release/rust-junosmcp"},
  "juniper-${JUNIPER_TAG#v}": {"flavour": "juniper", "version": "${JUNIPER_TAG#v}", "commit": "$JUNIPER_SHA",
    "python": "$WORK/juniper/.venv/bin/python", "src": "$WORK/juniper"},
  "shigechika-0.18.0": {"flavour": "shigechika", "version": "0.18.0", "commit": "${SHIGE_PINS[0]#* }",
    "python": "$WORK/venv-shigechika-v0.18.0/bin/python"},
  "shigechika-0.22.0": {"flavour": "shigechika", "version": "0.22.0", "commit": "${SHIGE_PINS[1]#* }",
    "python": "$WORK/venv-shigechika-v0.22.0/bin/python"}
}
EOF
echo "setup: done. Next:"
echo "  $WORK/venv-bench/bin/python $HERE/bench.py run --target mock --servers $WORK/servers.json --out OUT --run-index 1"

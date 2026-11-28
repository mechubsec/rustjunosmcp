set dotenv-load := false
set export := false

setup:
    rustup toolchain install
    cargo fetch --locked
    pre-commit install

dev:
    cargo run -p rust-junosmcp -- --help

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace --locked

guard: lint test

integration:
    @if [ "${CONFIRM_LAB_INTEGRATION:-}" != "yes" ]; then echo "Set CONFIRM_LAB_INTEGRATION=yes after reviewing inventory and targets."; exit 2; fi
    cargo test -p rust-junosmcp-core --test integration_real_device -- --ignored --nocapture

e2e:
    cargo run -p rust-junosmcp -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features -- --help >/dev/null
    cargo run -p rust-junosmcp --no-default-features --features tls -- --help >/dev/null

security:
    trivy fs --scanners vuln,misconfig,secret --exit-code 1 .

release-check: fmt lint test security

# Regenerate rust-junosmcp-core/catalog/data from the Juniper/yang commit pinned in SOURCE.
catalog:
    #!/usr/bin/env bash
    set -euo pipefail
    sha=$(sed -n 's/^commit: *//p' rust-junosmcp-core/catalog/SOURCE)
    dir=target/juniper-yang
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$sha" ]; then
        rm -rf "$dir"
        git init -q "$dir"
        git -C "$dir" remote add origin https://github.com/Juniper/yang.git
        # Trains 23.x-29.x only; junos-es, junos-ex, common and EVO conf-and-rpcs.
        git -C "$dir" sparse-checkout set --no-cone '/LICENSE' \
            '/2[3-9].*/*/common/' \
            '/2[3-9].*/*/junos-e[sx]/rpc-with-extensions/' '/2[3-9].*/*/junos-e[sx]/conf-with-extensions/' \
            '/2[3-9].*/*/native/conf-and-rpcs/common/' \
            '/2[3-9].*/*/native/conf-and-rpcs/junos-e[sx]/rpc-with-extensions/' \
            '/2[3-9].*/*/native/conf-and-rpcs/junos-e[sx]/conf-with-extensions/' \
            '/2[3-9].*/*-EVO/native/conf-and-rpcs/rpc-with-extensions/' \
            '/2[3-9].*/*-EVO/native/conf-and-rpcs/conf-with-extensions/'
        git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$sha"
        git -C "$dir" checkout -q FETCH_HEAD
    fi
    cp "$dir/LICENSE" rust-junosmcp-core/catalog/LICENSE-juniper-yang
    uv run --with pyang==2.6.1 --with 'setuptools<81' python -W ignore::UserWarning \
        scripts/catalog/generate.py "$dir" rust-junosmcp-core/catalog/data \
        --notes rust-junosmcp-core/catalog/notes

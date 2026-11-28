# syntax=docker/dockerfile:1.6
# Multi-arch image index digests pinned on 2026-08-07; the release builds
# linux/amd64 and linux/arm64 from them. Update both deliberately when
# refreshing either base.
#
# Builder version is taken from rust-toolchain.toml (currently 1.100.0). The two
# must stay in sync.
# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Not the
# runtime itself, so keep it ahead of the builder and out of the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:532c7a94f9e96ba9db75eb9388f4227751131c7cb0a411d1a8521af4096135de AS libgcc

FROM rust:1.100-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS builder
WORKDIR /src

# rustez / rustnetconf are crates.io dependencies now (no sibling checkout),
# so the build context is just the repo root and this Dockerfile is
# self-contained:
#   docker build -t rust-junosmcp:2.9.1 .
COPY . .
RUN cargo build --release --bin rust-junosmcp

# Create the directory tree and known_hosts file in the builder stage with the
# right modes and ownership, since distroless has no shell and cannot run
# groupadd/useradd/install. The distroless :nonroot variant already ships uid
# 65532, so we create the tree with explicit modes and then COPY it.
#
# COPY preserves source modes, so we set them here to match the current Debian
# image's layout: 0750 for most dirs, 0700 for device-leases, 0600 for known_hosts.
RUN install -d -m 0750 -o 65532 -g 65532 \
        /stage-etc/jmcp /stage-etc/jmcp/keys \
    && install -d -m 0750 -o 65532 -g 65532 \
        /stage-var/lib/jmcp /stage-var/lib/jmcp/staging \
        /stage-var/lib/jmcp/srx-staging /stage-var/lib/jmcp/srx-staging/bundles \
    && install -d -m 0700 -o 65532 -g 65532 /stage-var/lib/jmcp/device-leases \
    && install -m 0600 -o 65532 -g 65532 /dev/null /stage-var/lib/jmcp/known_hosts

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory is taken from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Runtime base: distroless base-nossl (no libssl3t64/libcrypto: the binary is
# rustls-only, and libssl3t64 carries unfixed CVE-2026-124709). Now possible because #212 removed the last
# Command::new spawn (the scp subprocess). The server no longer shells out, so
# it no longer needs a shell or utilities.
#
# glibc rule: builder generation must be <= runtime generation. The builder is
# bookworm (glibc 2.36) and this is debian13 (glibc 2.41), so the direction is
# safe. Moving the builder forward would require moving this first.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:4006ac92504be607b70de01d1f64f38288c69fcd8faa820f6d3aed266ea32ac5
LABEL org.opencontainers.image.source="https://github.com/mechubsec/rustjunosmcp"
LABEL org.opencontainers.image.licenses="MIT"
# Official MCP Registry ownership check: must equal server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/rustjunosmcp"

# CA certificates are shipped in gcr.io/distroless/base-nossl-* at /etc/ssl/certs. The
# binary makes outbound TLS calls (HTTPS requests for device APIs), and rustls
# uses the system CA bundle via rustls-native-certs.
COPY --from=builder /stage-libgcc/ /
COPY --from=builder --chown=65532:65532 \
    /src/target/release/rust-junosmcp /usr/local/bin/rust-junosmcp
COPY --from=builder --chown=65532:65532 /stage-etc/jmcp /etc/jmcp
COPY --from=builder --chown=65532:65532 /stage-var/lib/jmcp /var/lib/jmcp
# Default --skills-dir (read-only content, root-owned).
COPY --from=builder /src/skills /usr/share/rust-junosmcp/skills

ENV RUST_LOG=info \
    JMCP_SUPPORT_BUNDLE_STAGING_DIR=/var/lib/jmcp/srx-staging/bundles \
    JMCP_SUPPORT_BUNDLE_STAGING_MAX_BYTES=524288000
VOLUME ["/var/lib/jmcp"]
USER 65532:65532

# HEALTHCHECK removed: distroless has no shell and no `kill` utility. Container
# orchestrators (Compose healthcheck, Kubernetes liveness probes) supervise the
# process directly via the container runtime rather than shelling out.

# ENTRYPOINT carries what must always hold: config paths and anything security-
# relevant. CMD carries only what an operator is expected to replace: bind
# address, port, and mode flags. Docker replaces CMD when the caller supplies
# arguments, so security-relevant defaults must stay in ENTRYPOINT.
#
# --audit-hmac-key-file: without a shell (see above), the binary itself
# generates /var/lib/jmcp/audit-hmac.key on first run if it is absent (see
# ensure_audit_hmac_key in src/main.rs) -- the container-image equivalent of
# packaging/lxc/install.sh's own key-generation step, closing the "5 of 6
# server images run unkeyed audit" gap (mecmcp#376 / MEC-978). The path is
# under the writable /var/lib/jmcp volume, not /etc/jmcp, because
# compose.example.yaml mounts /etc/jmcp read-only, so a key path there could
# never be generated on a fresh container. --audit-redact still defaults to
# empty (redaction itself stays opt-in, see docs/AUDIT.md), so this alone
# does not change what is logged -- it only means the key is already there
# the moment an operator turns redaction on.
ENTRYPOINT ["/usr/local/bin/rust-junosmcp", \
    "-f", "/etc/jmcp/devices.json", \
    "--staging-dir", "/var/lib/jmcp/staging", \
    "--known-hosts-file", "/var/lib/jmcp/known_hosts", \
    "--device-lease-dir", "/var/lib/jmcp/device-leases", \
    "--tokens-file", "/var/lib/jmcp/tokens.json", \
    "--audit-hmac-key-file", "/var/lib/jmcp/audit-hmac.key"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30030"]

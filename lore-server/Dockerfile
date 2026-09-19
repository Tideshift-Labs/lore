# Revision of the Lore source this image is built from, supplied by the build
# host. `.dockerignore` excludes `.git/`, so the build container has no git
# metadata to read — the revision cannot be derived inside the build and must be
# threaded in. A build that omits the arg degrades to the literal "unknown"
# rather than claiming a revision it does not have.
ARG LORE_REVISION=unknown
# Where LORE_REVISION can be resolved. Defaults to this fork, because that is
# what an image built from this checkout actually contains.
ARG LORE_SOURCE_URL=https://github.com/Tideshift-Labs/lore

FROM rust:slim-trixie AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# build-helper.rs reads LORE_BUILD_VERSION_NAME at build-script time and bakes
# "{CARGO_PKG_VERSION}+{name}" into VERGEN_LORE_LIBRARY_VERSION_NAME, which is
# what ServerInfoResponse.version, the OTel resource and the user-agent report.
ARG LORE_REVISION
ENV LORE_BUILD_VERSION_NAME=${LORE_REVISION}

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin loreserver --bin cell-schema-install --bin cell-budget-configure && \
    cp /build/target/release/loreserver /build/loreserver-bin && \
    cp /build/target/release/cell-schema-install /build/cell-schema-install-bin && \
    cp /build/target/release/cell-budget-configure /build/cell-budget-configure-bin

FROM debian:trixie-slim

ARG LORE_REVISION
ARG LORE_SOURCE_URL
LABEL org.opencontainers.image.title="loreserver" \
      org.opencontainers.image.description="Lore server (loreserver), the centralized Lore version-control server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="${LORE_SOURCE_URL}" \
      org.opencontainers.image.revision="${LORE_REVISION}"

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/loreserver-bin /usr/local/bin/loreserver
COPY --from=builder /build/cell-schema-install-bin /usr/local/bin/cell-schema-install
COPY --from=builder /build/cell-budget-configure-bin /usr/local/bin/cell-budget-configure
COPY --from=builder /build/lore-server/config/default.toml /etc/lore/config/default.toml

# Docker environment config: local stores at /data. No QUIC certificate is
# configured, so the server generates an ephemeral self-signed cert for the
# public endpoint at startup (zero-config). For a durable deployment, mount a
# real cert into the container and add a [server.quic.certificate] override.
RUN cat <<'EOF' > /etc/lore/config/docker.toml
[immutable_store.local]
path = "/data"

[mutable_store.local]
path = "/data"
EOF

ENV LORE_CONFIG_PATH=/etc/lore/config
ENV LORE_ENV=docker
ENV RUST_LOG=info

RUN mkdir -p /data
VOLUME /data

# QUIC + gRPC: 41337, HTTP: 41339
EXPOSE 41337 41339

ENTRYPOINT ["loreserver"]

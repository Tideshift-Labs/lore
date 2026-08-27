FROM rust:slim-trixie@sha256:fb4b2f1dc68c06f46618948b09d0ade147e6d2b11a6581e599b0c808d5b8a167 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin lore-object-dispatch && \
    cp /build/target/release/lore-object-dispatch /build/lore-object-dispatch-bin

FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 object-dispatch \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin object-dispatch

COPY --from=builder /build/lore-object-dispatch-bin /usr/local/bin/lore-object-dispatch

ENV LORE_OBJECT_DISPATCH_SERVICE_CONFIG_REVISION=object-store-dispatch-service-mtls-shell-v1
ENV LORE_OBJECT_DISPATCH_LISTEN_ADDR=127.0.0.1:50051

USER 10001:10001

ENTRYPOINT ["lore-object-dispatch"]

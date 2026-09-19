# Running loreserver in Docker

A basic Docker image for running loreserver with local filesystem storage. No authorization,
telemetry integration, or replication is configured.

## Prerequisites

- Docker with BuildKit support
- On Apple Silicon (M-series Macs), builds must target `linux/amd64` due to Graviton-specific
  compiler flags in `.cargo/config.toml` for `aarch64-unknown-linux-gnu`

## Building

From the repository root:

```sh
docker build --platform linux/amd64 -f lore-server/Dockerfile -t loreserver \
  --build-arg LORE_REVISION="$(git rev-parse --short HEAD)" .
```

The build compiles the `loreserver` binary and generates self-signed TLS certificates for QUIC
using `scripts/server/make-certs.sh`.

### Recording the revision

`.dockerignore` excludes `.git/`, so the build container cannot read git metadata. Pass
`--build-arg LORE_REVISION=<sha>` to record which source the image was built from. The value
lands in two places:

- `org.opencontainers.image.revision` on the image
  (`docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' loreserver`)
- the binary's own version string — `ServerInfoResponse.version`, the OTel resource and the
  outbound user-agent all report `{crate version}+{LORE_REVISION}`.

Omit the arg and both degrade to the literal `unknown` rather than claiming a revision. Every
deploy path must pass it.

## Running

```sh
docker run -p 41337:41337/tcp -p 41337:41337/udp -p 41339:41339 loreserver
```

Both TCP and UDP mappings are required on port 41337 because gRPC uses TCP and QUIC uses UDP.

### Persisting data

By default, store data is written to `/data` inside the container and is lost when the container
stops. Mount a host directory to persist it across restarts:

```sh
docker run \
  -p 41337:41337/tcp \
  -p 41337:41337/udp \
  -p 41339:41339 \
  -v /path/to/local/data:/data \
  loreserver
```

## Ports

| Port  | Protocol | Service        |
|-------|----------|----------------|
| 41337 | TCP      | gRPC           |
| 41337 | UDP      | QUIC           |
| 41339 | TCP      | HTTP           |

## Configuration

The image stores config files in `/etc/lore/config/` (`LORE_CONFIG_PATH`):

- `default.toml` — copied from `lore-server/config/default.toml` at image build time. Loaded as the on-disk default layer on top of the compiled-in defaults, so you can mount a custom `default.toml` to override compiled-in values without rebuilding the image.
- `docker.toml` — overrides store paths to `/data` and configures QUIC TLS certificates. Loaded as the `docker` environment layer (`LORE_ENV=docker`).

Settings can be overridden via environment variables with the `LORE__` prefix and `__` as the
separator. For example:

```sh
docker run -e LORE__SERVER__HTTP__PORT=8080 -p 8080:8080 -p 41337:41337/tcp -p 41337:41337/udp loreserver
```

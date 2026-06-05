# Lore Server

The Lore Server provides the backend service for Lore

## Features

- **Content-Addressable Storage**: Storage of immutable data with deduplication and isolation
- **Mutable Store**: Branch and reference management
- **Distributed Locking**: Concurrent access control for collaborative workflows
- **Plugin System**: Modular architecture for storage backends and topology discovery
- **Hook System**: Extensible event processing for compliance and notifications

## Quick Start

### Running the Server

```bash
# Using default configuration
cargo run --bin loreserver

# With custom configuration path
LORE_CONFIG_PATH=/etc/lore cargo run --bin loreserver

# With environment-specific config
LORE_ENV=production cargo run --bin loreserver
```

### Configuration

Configuration is TOML-based and applied in the following order (later sources win):

1. **Compiled-in defaults** — `config/default.toml` is baked into the binary at compile time. The server starts with sensible defaults even with no config files on disk.
2. **On-disk `default.toml`** — if `{config_path}/default.toml` exists it is layered on top, letting operators override compiled-in defaults without a rebuild.
3. **Environment config** — `{config_path}/{LORE_ENV}.toml` (optional)
4. **Regional override** — `{config_path}/{LORE_ENV}_{LORE_PLATFORM_REGION}.toml` (optional)
5. **Local overrides** — `{config_path}/local.toml` (optional)
6. **Environment variables** — prefixed with `LORE__`, using `__` as separator

`config_path` defaults to `lore-server/config` and can be overridden with `--config` or `LORE_CONFIG_PATH`. All on-disk files are optional.

See the `examples/` directory for complete configuration examples:
- `config-local.toml` - Local storage with fixed topology
- `config-aws.toml` - AWS (S3 + DynamoDB) storage
- `config-consul.toml` - Consul service discovery
- `config-hooks.toml` - Hook configuration examples

## Plugin System

The Lore Server uses a plugin system for swappable storage backends and topology discovery.

### Architecture

```
PluginRegistry
├── Immutable Store Plugins
├── Mutable Store Plugins
├── Lock Store Plugins
└── Topology Plugins
```

### Plugin Types

| Type | Description | Available Plugins |
|------|-------------|-------------------|
| **Immutable Store** | Storage for content-addressable fragments | `aws` |
| **Mutable Store** | Storage for branches and references | `aws` |
| **Lock Store** | Distributed locking mechanism | `dynamodb` |
| **Topology** | Peer discovery for replication | `consul` |

### Configuration Format

Plugins are configured via the `[plugins.X]` sections in your TOML configuration:

```toml
# Select the topology provider
[topology]
provider = "consul"

# Plugin-specific configuration
[plugins.consul]
address = "http://consul.service.consul:8500"
service_name = "lore-server"
poll_interval_secs = 30
```

### Creating a New Plugin

#### Step 1: Create the Plugin File

Create a new file in `src/plugins/` (e.g., `my_plugin.rs`):

```rust
use std::sync::Arc;
use serde::Deserialize;
use crate::plugins::{PluginRegistry, PluginError, TopologyPluginFactory, plugin_config_error};
use urccore::cluster::topology::Topology;

// Configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct MyPluginConfig {
    pub setting1: String,
    pub setting2: u64,
}

// Plugin factory
pub struct MyTopologyPluginFactory;

impl TopologyPluginFactory for MyTopologyPluginFactory {
    fn name(&self) -> &'static str {
        "my_plugin"
    }

    fn create(
        &self,
        config: &toml::Value,
    ) -> Result<Arc<dyn Topology + Send + Sync>, PluginError> {
        let config: MyPluginConfig = config.clone().try_into()
            .map_err(|e| plugin_config_error(self.name(), format!("Config error: {e}")))?;

        // Create and return your topology implementation
        Ok(Arc::new(MyTopology::new(config)))
    }
}

// Registration function
pub fn register(registry: &mut PluginRegistry) {
    registry.register_topology_plugin(Box::new(MyTopologyPluginFactory));
}
```

#### Step 2: Build and Use

The `build.rs` script automatically discovers and registers plugins. After adding your file, rebuild and configure:

```toml
[topology]
provider = "my_plugin"

[plugins.my_plugin]
setting1 = "value"
setting2 = 42
```

## Hook System

Hooks allow custom logic to be executed at specific points in the server's lifecycle.

### Hook Points

| Hook Point | Triggered When |
|------------|----------------|
| `BranchPush` | Before a branch push is committed |
| `BranchCreate` | Before a new branch is created |
| `BranchDelete` | Before a branch is deleted |
| `RepositoryCreate` | Before a new repository is created |
| `Obliterate` | Before content is obliterated |

### Hook Configuration

```toml
[hooks.compliance]
enabled = true
deny_patterns = ["^release/.*$"]
webhook_url = "https://api.example.com/notify"
```

### Creating a New Hook

#### Step 1: Create the Hook File

Create a new file in `src/hooks/` (e.g., `my_hook.rs`):

```rust
use async_trait::async_trait;
use crate::hooks::{Hook, HookContext, HookError, HookFactory, HookPoint, HookRegistry};

// Hook implementation
pub struct MyHook {
    config: MyHookConfig,
}

#[async_trait]
impl Hook for MyHook {
    fn hook_points(&self) -> Vec<HookPoint> {
        vec![HookPoint::BranchPush, HookPoint::BranchCreate]
    }

    async fn execute(&self, context: &HookContext) -> Result<(), HookError> {
        // Your hook logic
        // Return Err to veto the operation
        Ok(())
    }
}

// Factory for creating hook instances
pub struct MyHookFactory;

impl HookFactory for MyHookFactory {
    fn name(&self) -> &'static str {
        "my_hook"
    }

    fn create(
        &self,
        config: &toml::Value,
    ) -> Result<Box<dyn Hook + Send + Sync>, HookError> {
        let config: MyHookConfig = config.clone().try_into()?;
        Ok(Box::new(MyHook { config }))
    }
}

// Registration
pub fn register(registry: &mut HookRegistry) {
    registry.register(Box::new(MyHookFactory));
}
```

## Development

### Building

```bash
cargo build -p lore-server
```

### Running Tests

```bash
# All tests
cargo test -p lore-server

# Specific test modules
cargo test -p lore-server plugins
cargo test -p lore-server topology
cargo test -p lore-server hooks
```

### Code Generation

The `build.rs` script generates:
- `src/plugins/mod.rs` - Plugin registration and module declarations
- `src/hooks/mod.rs` - Hook registration and module declarations

These files are regenerated on each build to discover new plugins/hooks automatically.

## Architecture

```
lore-server/
├── src/
│   ├── bin/loreserver/      # Server binary
│   │   ├── main.rs        # Entry point
│   │   └── settings.rs    # Configuration handling
│   ├── plugins/           # Plugin system
│   │   ├── mod.rs         # Auto-generated plugin registration
│   │   ├── traits.rs      # Plugin traits and errors
│   │   ├── registry.rs    # Plugin registry
│   │   ├── aws.rs         # AWS store plugins
│   │   ├── local.rs       # Local store plugins
│   │   ├── hashicorp.rs   # Consul topology plugin
│   │   └── fixed.rs       # Fixed topology plugin
│   ├── hooks/             # Hook system
│   │   ├── mod.rs         # Auto-generated hook registration
│   │   ├── traits.rs      # Hook traits
│   │   ├── registry.rs    # Hook registry
│   │   ├── context.rs     # Hook context
│   │   └── dispatch.rs    # Hook dispatcher
│   ├── grpc/              # gRPC services
│   ├── http/              # HTTP endpoints
│   ├── quic/              # QUIC protocol
│   ├── store/             # Store utilities
│   ├── lock/              # Lock store
│   └── topology.rs        # Topology configuration
├── examples/              # Configuration examples
├── config/                # Default configuration files
└── build.rs               # Code generation
```

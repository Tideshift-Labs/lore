---
status: proposed
date: 2026-06-20
deciders: Khurram Virani
---

# ADR-00017: DynamoDB-backed bucket resolution for the AWS store

## Context and Problem Statement

[ADR-00011](00011-per-tenant-storage-isolation.md) introduced a pluggable `BucketResolver` so the
AWS immutable store can route each repository's fragments to a different S3 bucket, giving
repositories physically isolated storage. ADR-00011 shipped only the default `StaticBucketResolver`
(every repository → one configured bucket); the actual per-repository routing was left to be
injected as code by whoever embeds `lore-aws`.

A multi-tenant host built on Lore needs a concrete, configurable resolver that maps each repository
to its bucket **without baking the host's naming scheme into Lore**, and without a tenant/org model
leaking into Lore's vocabulary. The natural source of truth is a lookup table the host already
maintains: repository → bucket. This ADR adds a `DynamoBucketResolver` that reads that mapping from
DynamoDB, plus the trait change required to make a resolver that does real I/O viable.

## Decision Drivers

- A resolver that reads an external table must be able to do **I/O and to fail** — the CR-001 trait
  was synchronous and infallible.
- Routing a repository's bytes to the **wrong** bucket is a storage-isolation (security) failure, so
  an unknown repository must **fail closed**, never fall back to a shared/default bucket.
- Keep the default (`static`) path **byte-for-byte unchanged** and fully backward compatible.
- Stay in Lore's **partition/repository** vocabulary; the table is keyed by a repository identifier,
  not a tenant.
- Confine the change to `lore-aws` plus the server plugin config; keep `Arc<dyn BucketResolver>`
  dynamic dispatch.

## Considered Options

- **Async, fallible `BucketResolver` + `DynamoBucketResolver` (chosen).**
- Keep the resolver synchronous and pre-load the whole table into memory at boot. Rejected: doesn't
  scale to large or growing repository counts, and a repository provisioned after boot would be
  invisible until restart.
- Resolve buckets by a naming convention computed from the `Context` (for example, hash → bucket name).
  Rejected: bakes one host's bucket-naming scheme into Lore and removes the host's freedom to place
  repositories arbitrarily.

## Decision Outcome

### 1. Evolve `BucketResolver` to async + fallible

```rust
#[async_trait]
pub trait BucketResolver: Send + Sync {
    async fn bucket_for(&self, repository: &Context) -> Result<String, StoreError>;
}
```

`bucket_for` becomes `async` and returns `Result<String, StoreError>`. The trait stays object-safe
(`Arc<dyn BucketResolver>` still works) via `async-trait`, which boxes the returned future — one
small heap allocation per call, negligible next to the S3 round-trip that every call precedes.
`StaticBucketResolver` becomes a trivial async implementation that clones its single bucket and never errors.
The store's internal `bucket_for` helper and its call sites (`write`/`read`/`delete`/`copy`/
`ensure_bucket_exists`, all already `async` and returning `Result`) simply `.await?` the resolver.

### 2. `DynamoBucketResolver`

Holds a DynamoDB client (the same client type the AWS stores already use), the routing **table
name**, and an in-memory `Context → bucket` cache (a `DashMap`). On `bucket_for`:

- **cache hit** → return from memory, no network call;
- **cache miss** → `GetItem` with **`ConsistentRead = true`** (so a freshly provisioned route is
  observed immediately); on a found row, cache the `bucket` attribute and return it;
- **no row** (or a row without a usable `bucket`) → **fail-closed `StoreError`**. The resolver holds
  no default and never substitutes a shared bucket.

Cache entries are never invalidated: a repository→bucket mapping is immutable (moving a repository's
existing bytes between buckets is out of scope), so there is no TTL and no invalidation path.

### 3. Table contract (what the host must provision)

| Element | Encoding |
| --- | --- |
| Partition key `repository` | DynamoDB **string** (`S`): Lore's canonical `Context` representation — `Context`'s `Display`/`to_string`, that is, the lowercase hex (no separators) of its 16 raw bytes (32 hex chars). |
| Attribute `bucket` | DynamoDB **string** (`S`): the destination bucket name. All other attributes are ignored. |

**Key encoding — concrete example.** The `Context` with raw bytes
`01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef` is keyed under
`repository = "0123456789abcdef0123456789abcdef"`. This is Lore's own `Context` string, *not* a
hand-rolled UUID/hex format — a downstream writer that provisions the table must use
`Context::to_string()` (equivalently `Display`) to compute the key. This encoding is pinned by a
unit test so it's a stable contract for that writer.

The resolver requires only `dynamodb:GetItem` on the routing table (read-only). Creating the table
and writing its rows is the host's responsibility, out of scope here.

### 4. Configuration (server plugin)

The AWS immutable store plugin gains a resolver selector, default `"static"`:

```toml
# "static" (default) → every repository uses `s3_bucket` (today's behaviour).
# "dynamo" → resolve each repository's bucket from a DynamoDB routing table.
bucket_resolver = "dynamo"

[dynamo_bucket_resolver]
routing_table = "repository-bucket-routing"
# Optional; default to the store's dynamodb endpoint/region when unset.
# endpoint_url = "http://localhost:4566"
# region = "us-west-2"
```

When `dynamo` is selected the plugin builds a (read-only) DynamoDB client for the routing table and
injects a `DynamoBucketResolver` via `AwsImmutableStore::with_bucket_resolver`. Because dynamo
routing has no single canonical bucket, the boot-time `s3_bucket` existence check is skipped on this
path (it remains in force for `static`). Selecting `dynamo` without a `[dynamo_bucket_resolver]`
section is a config error.

### Consequences

- Good, because the `static` path is unchanged: defaults reproduce today's behaviour byte-for-byte,
  and existing tests pass untouched.
- Good, because a multi-tenant host can place repositories in arbitrary buckets via a table it owns,
  with no tenant/org concept entering Lore.
- Good, because repositories with no route fail closed — a missing route never routes bytes to the wrong bucket.
- Good, because `Arc<dyn BucketResolver>` dynamic dispatch is preserved.
- Bad, because the async trait boxes a future on every resolve, including the static path (one small
  allocation per S3 op; negligible in practice).
- Bad, because the first reference to each repository pays one DynamoDB `GetItem` (consistent read)
  before its bucket is cached.

## More Information

Builds directly on [ADR-00011](00011-per-tenant-storage-isolation.md) (pluggable `BucketResolver`,
`dedup_scope`, lazy bucket provisioning, cross-bucket copy). The resolver lives in
[`lore-aws/src/store/bucket_resolver.rs`](../../../lore-aws/src/store/bucket_resolver.rs); wiring is
in the server's AWS plugin
([`lore-server/src/plugins/aws.rs`](../../../lore-server/src/plugins/aws.rs)).

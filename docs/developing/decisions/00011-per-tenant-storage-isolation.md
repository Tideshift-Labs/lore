---
status: proposed
date: 2026-06-20
deciders: Khurram Virani
---

# ADR-00011: Per-repository storage isolation in the AWS store

## Context and Problem Statement

The AWS immutable store ([`lore-aws`](../../../lore-aws)) writes every fragment payload to a
**single, statically configured S3 bucket** and deduplicates fragments **globally**: existence is
decided by the fragment hash alone, across all repositories. Today that is exactly what a
single-deployment Lore server wants.

Deployments that host many repositories on one `loreserver` — for example a multi-tenant hosting
platform built on Lore — need two things the current store cannot express:

1. **Physical storage isolation.** Different repositories' fragments must be able to live in
   different buckets, so a repository's bytes can be isolated, billed, lifecycle-managed, or deleted
   independently of every other repository's.
2. **Per-repository deduplication.** With global dedup, a client pushing to repository B is told a
   fragment "already exists" merely because repository A uploaded it. The client then skips the
   upload — but if B's payloads live in a *different* bucket, B's bucket ends up with a dangling
   reference to bytes it never received. Global dedup also leaks existence across repositories (B
   learns A holds a given hash) and forces a cross-repository refcount that blocks clean per-
   repository deletion.

The constraint is that this must stay in **Lore's own vocabulary**. Lore models a *partition*
(`RepositoryId`) and a *repository/context*; it has no notion of tenants, orgs, or accounts, and
must not gain one. Any mapping from "tenant" to "bucket" belongs to the hosting platform, not to
Lore.

## Decision Drivers

- Keep the single-tenant deployment **byte-for-byte unchanged** by default.
- Stay within Lore's partition/repository vocabulary; no tenant/org/account model in Lore.
- Confine the change to `lore-aws` and the server plugin configuration.
- Keep the public `ImmutableStore` trait signatures unchanged (partition is already a parameter).
- Be upstreamable: general, configurable, tested, documented.

## Decision Outcome

Add four capabilities to the AWS immutable store, all opt-in and all defaulting to today's
behaviour:

### 1. Pluggable bucket resolution

A new trait decides the bucket for a repository:

```rust
pub trait BucketResolver: Send + Sync {
    fn bucket_for(&self, repository: &Context) -> Cow<'_, str>;
}
```

The store holds an `Arc<dyn BucketResolver>` instead of a fixed bucket string, and resolves the
bucket on every S3 read, write and delete. The default `StaticBucketResolver` returns the single
configured bucket and preserves current behaviour exactly. The standard `AwsImmutableStore::new`
constructor installs it automatically; a hosting platform injects its own resolver via
`AwsImmutableStore::with_bucket_resolver`. The resolver's repository→bucket logic (and any
tenant concept behind it) lives entirely in the caller.

### 2. Configurable deduplication scope

A `dedup_scope` setting (`"global"` | `"partition"`, default `"global"`) controls the client-facing
existence path (`exist`/`exist_batch`). Under `partition`, a global (`MatchHash`) existence check is
narrowed to `MatchPartition`, so a fragment present in repository A is never reported as present for
repository B. This removes both the dangling-reference failure mode and the cross-repository
existence leak. The put/query specificity walk is unchanged.

### 3. Partition dimension on the `metadata` table

The `metadata` table is hash-only today, which makes it a global existence index and forces a
cross-repository refcount. Under `dedup_scope = partition`, metadata is keyed by
**(hash, repository)** — an optional `repository` sort-key attribute — so each repository owns
independent metadata and lifecycle for a given hash. The per-repository refcount used by
obliterate/GC is likewise scoped to the repository, so a repository's payload is deleted as soon as
that repository stops referencing it, regardless of other repositories. Under `global` scope the
schema and refcount are unchanged.

### 4. Lazy, multi-bucket provisioning

Boot-time validation of a single bucket no longer fits when buckets are provisioned per repository
after the server starts. Bucket validation becomes on-demand and cached: a hosting platform calls
`AwsImmutableStore::ensure_bucket_exists(partition)` when it provisions a repository, and each
distinct bucket is checked at most once. The server plugin exposes
`validate_bucket_on_startup` (default `true`) so the static deployment keeps its startup check while
routed deployments opt out.

### Copy under routing

`Copy` was a DynamoDB-only association and never touched S3. Under per-bucket routing a copy whose
source and destination resolve to **different** buckets would leave the destination referencing bytes
that only exist in the source's bucket. The store now performs a real **server-side S3 object copy**
for cross-bucket copies and, under partition scope, writes the destination repository's metadata
entry. Same-bucket copies remain metadata-only.

### Configuration

The AWS immutable store plugin gains:

```toml
# Deduplication/isolation scope: "global" (default) or "partition".
dedup_scope = "partition"

# Validate `s3_bucket` exists at startup. Default true; set false for
# per-repository routing where buckets are provisioned after boot.
validate_bucket_on_startup = false
```

Per-repository bucket routing itself is **not** server configuration: it is injected as a
`BucketResolver` by code that embeds `lore-aws` as a library, because the routing logic is
deployment-specific and outside Lore's vocabulary.

### Consequences

- Good, because single-tenant deployments are unaffected: defaults reproduce today's behaviour
  byte-for-byte, and existing data, schemas and tests are unchanged.
- Good, because repositories can be physically isolated across buckets and deduplicated/deleted
  independently.
- Good, because the blast radius is confined to `lore-aws` plus the server plugin config; the
  `ImmutableStore` trait is untouched.
- Bad, because `partition` scope requires a `metadata` table provisioned with a `repository` sort
  key (see migration), so it is not a flip-the-switch change on an existing global table.
- Bad, because cross-bucket copies now incur an S3 object copy rather than a pure metadata write.

### Migration implications

- Switching an existing deployment from `global` to `partition` is **not** an in-place toggle. The
  `metadata` table changes from a hash-only key to a (hash, repository) key; DynamoDB primary keys
  are immutable, so this requires a **new metadata table** (partition key `hash`, sort key
  `repository`) and a backfill that re-stamps each existing hash-only metadata row with its owning
  repository (derivable from the `fragments` association table). The `fragments` table is unchanged
  (it already carries the `repository_context` sort key).
- New deployments simply create the metadata table with the sort key and set
  `dedup_scope = "partition"` from the start.
- `global` deployments need no migration.

## Considered Options

- **Pluggable resolver + `dedup_scope` (chosen).** General, opt-in, stays in Lore's vocabulary.
- **Hard-code a tenant→bucket scheme in Lore.** Rejected: introduces a tenant model Lore must not
  own, and bakes one platform's naming into the VCS.
- **Bucket prefixes within one bucket instead of separate buckets.** Rejected: does not provide
  physical isolation (independent lifecycle/billing/deletion) and still shares a global keyspace.
- **Reject cross-bucket copies instead of copying.** Considered and viable, but rejected in favour of
  a real object copy so the copy feature keeps working under routing; the trade-off is one extra S3
  operation on the (rare) cross-bucket copy path.

## Out of Scope

- Mutable and lock store physical isolation (already logically per-partition).
- Org-/tenant-level deduplication: intentionally only repository-level (`MatchPartition`).
- Any user/org/account/tenant model in Lore — it stays repository/partition + JWT only.

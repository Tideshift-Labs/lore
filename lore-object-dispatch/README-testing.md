# Verification & Testing

## Standard Tests

```sh
cargo +nightly fmt --all -- --check
cargo clippy -p lore-object-dispatch --all-targets -- -D warnings --no-deps
cargo test -p lore-object-dispatch
```

## Live Integration Tiers

These suites test against a disposable PostgreSQL 16 instance.

```sh
# Local-authority live tier: installs the CD-1 set, runs all 12 by exact name
tests/run-local-authority-live.ps1

# Cell-schema installer/attester live tier
tests/run-cell-schema-install-live.ps1

# Shared-limiter and charge-before-send live tier
tests/run-provider-charge-live.ps1

# Bounded cell retention through the supported installer
tests/run-cell-retention-live.ps1
```

## Manual Fallback / Single Fixture

To run one fixture directly against an explicit, disposable, preprovisioned PostgreSQL target without the runner, set the appropriate environment variable (e.g., `LORE_TEST_LOCAL_CODEC_PG_URL=postgresql://...`) and run `cargo test --ignored --exact ...`.

*Example:*
```sh
LORE_TEST_LOCAL_CODEC_PG_URL=postgresql://... cargo test -p lore-object-dispatch --test local_authority_canonical_codec -- --ignored --exact live_postgres_reserved_and_spool_ready_bytes_match_independent_rust_vectors
```

## Notes

- `run-cell-schema-install-live.ps1` runs against its own disposable container and connects **as** `object_dispatch_retention_migrator`.
- Policy rollover is offline: finish drain and cleanup, stop all replicas, and run `cell-drain-policy-configure rotate policy.json --replicas-excluded`.

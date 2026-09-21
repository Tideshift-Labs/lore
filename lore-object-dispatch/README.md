# lore-object-dispatch

Server-only object-store dispatch authority primitives. WP-118 Phase 5 composes them behind the opt-in `fragment_provider` block. The block defaults dark and authorizes no traffic when absent or disabled.

## Architecture

### In-process Cell Authority
There is no separate dispatcher process, no in-cell mTLS service, and no surviving RPC (CR-033 D1, 2026-08-28). The cell dispatch authority operates via retained PostgreSQL procedures installed in the cell database. The enabled `loreserver` direct path calls these procedures via the typed Rust client in `dispatch_client.rs`.

- **Pool Isolation:** The client uses a separately credentialed pool (`dispatch_pool.rs`). It asserts `session_user = 'object_dispatch_retention_runtime'`.
- **Bounded Execution:** Every mutation enforces `statement_timeout` and `lock_timeout`. Read-only transactions are never retried; mutations retry explicitly on safe aborts (`40001`, `40P01`).
- **Schema & Data Integrity:** Uses canonical record schemas, with closed result decoding and strictly resolved authoritative outcomes.

### Out-of-Band Cell Schema Install (WP-114 CD-1)
Migrations are never auto-installed by runtime. They are installed out of band through the concrete `cell-schema-install` binary.
For a detailed catalogue of embedded migrations (including BLAKE3 hashes and detailed bytes sizes), see [README-migrations.md](./README-migrations.md).

### Shared Spool Verifier
`LinuxSpoolVerifier` is a source-dark, read-only observer for derived shared-spool paths on Linux. It opens artifacts descriptor-relative (using `openat2`), requires beneath-root, no-symlink, and no-cross-mount resolution, and hashes complete candidates via BLAKE3-256 to verify file identity.

### Request Contract
`request.rs` validates and canonicalizes the complete request (seven-operation descriptor, context, scope). It derives a stable 5-part durable request key and `object-dispatch-fingerprint-v1` (a BLAKE3 fingerprint). Effect-free APIs classify request lifecycle events (e.g., identity absent, replay, reuse) locally without database or network access.

### Governed Provider Client (WP-114 CD-5)
`provider_client.rs` manages provider attempts and the charge-before-send kernel.
- **Provider Ledger:** A ledger is bound exclusively to one boundary and one request (`ProviderAttemptLedger::new`).
- **Authorization:** Replaces global execution flows with bounded ledger auditing. Charging outside a ledger is unreachable.

### Typed Cell-Authority Client (WP-114 CD-3)
`dispatch_client.rs` manages the typed pathway to the retained PostgreSQL procedures for admission, progress, spool readiness, and schema readiness.
- **Connection Budget:** Enforces a strict overall pool cap against the hard limit (20 connections maximum).
- **Provable Outcomes:** Distinguishes between provable aborts (PostgreSQL SQLSTATE) and ambiguous outcomes (e.g. wall-clock timeouts, resolved by re-issue).
- **Redaction:** No credentials, diagnostic strings, or connection identifiers reach standard logging or error variants.

## Verification & Testing
For live integration testing against disposable PostgreSQL containers and test suite commands, see [README-testing.md](./README-testing.md).

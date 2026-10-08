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
- **TLS:** The installer's transport follows the same rule as the dispatch pool (`dispatch_pool::cell_tls_connector`). When `LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM` (PEM text) is set, the URL must say `sslmode=require`. The server is verified against exactly that bundle (chain and host name, libpq `verify-full` semantics). When it is unset, the URL must say `sslmode=disable`. `prefer` or a missing `sslmode` exits 2.
- **Install set:** migrations `0002`, `0003`, then `0007` through `0031` (`0004`-`0006` stay deferred); the embedded identity is cell schema R31 (R30 plus forward step `0031`). Existing R30 cells reach R31 through `cell-schema-install upgrade`.
- **No database BLAKE3:** the cell Postgres provides no `public.blake3` and needs no plpython3u. Rust callers compute and check BLAKE3 digests and hash columns; the database does not verify them. The participant key check uses the built-in `sha256()`.

For a detailed catalogue of embedded migrations (including BLAKE3 hashes and detailed bytes sizes), see [README-migrations.md](./README-migrations.md).

### Shared Spool Verifier
`LinuxSpoolVerifier` is a source-dark, read-only observer for derived shared-spool paths on Linux. It opens artifacts descriptor-relative (using `openat2`), requires beneath-root, no-symlink, and no-cross-mount resolution, and hashes complete candidates via BLAKE3-256 to verify file identity.

### Request Contract
`request.rs` validates and canonicalizes the complete request (seven-operation descriptor, context, scope). It derives a stable 5-part durable request key and `object-dispatch-fingerprint-v1` (a BLAKE3 fingerprint). Effect-free APIs classify request lifecycle events (e.g., identity absent, replay, reuse) locally without database or network access.

### Governed Provider Client (WP-114 CD-5)
`provider_client.rs` manages provider attempts and the charge-before-send kernel.
- **Provider Ledger:** A ledger is bound exclusively to one boundary and one request (`ProviderAttemptLedger::new`).
- **Authorization:** Replaces global execution flows with bounded ledger auditing. Charging outside a ledger is unreachable.
- **Budget Provenance:** `budget_provenance.rs` and the `cell-budget-configure --cell-config` binary accept two provenance types. The local type is for a local http endpoint and has a window of at most 24 h. `owner-decision-documented-provider-limit-v1` is for `https://sfo3.digitaloceanspaces.com` only, with a window of at most 7 days and at most 800 charged ops/s. The `lore-server` boot check enforces the pairing. Limits and operator steps are in `lorehub/docs/contracts/object-store-budget-v1.md` (amendment).
- **No-Dispatch Proof Binding:** The `object-store-no-dispatch-proof-v1` canonical preimage carries the logical request's identity. `record_no_dispatch` refuses a correctly digested proof minted for a different request (`LedgerRequestMismatch`), so a no-dispatch proof cannot finalize the wrong ledger.

### Typed Cell-Authority Client (WP-114 CD-3)
`dispatch_client.rs` manages the typed pathway to the retained PostgreSQL procedures for admission, progress, spool readiness, and schema readiness.
- **Connection Budget:** Enforces a strict overall pool cap against the hard limit (20 connections maximum).
- **Provable Outcomes:** Distinguishes between provable aborts (PostgreSQL SQLSTATE) and ambiguous outcomes (e.g. wall-clock timeouts, resolved by re-issue).
- **Redaction:** No credentials, diagnostic strings, or connection identifiers reach standard logging or error variants.

## Verification & Testing
For live integration testing against disposable PostgreSQL containers and test suite commands, see [README-testing.md](./README-testing.md).

# Fork-delta inventory: `lore-object-dispatch` CD-wave test methodology

Split out of [`testing-fork-delta-inventory.md`](testing-fork-delta-inventory.md) on 2026-09-21 to
keep that file under its size budget; nothing below was edited, only relocated. Covers WP-114's
CD-1 through CD-6 test methodology for the CR-033 cell dispatch authority
(`lore-object-dispatch` **[SERVER]**): the installer/attester, the `local_authority_*` live tests,
the provider-client ledger, the shared charge limiter, and CR-034's runtime budget-pin re-read.

The eleven `local_authority_*` live tests (the retained cell-authority half) have a
checked-in provisioning harness, `lore-object-dispatch/tests/run-local-authority-live.ps1`
(`-KeepOnFailure` leaves the labelled container up for debugging). Ten self-provision from a
fresh database; `local_authority_canonical_codec.rs` is the exception -- it states its own
requirement in its `#[ignore = "..."]` message, so the harness pre-installs precisely that pair,
not the full chain -- match what a test's calls actually touch. The harness also installs the
full chain once as proof it installs cleanly, asserting 0002's tables present and 0004-0006's
uninstalled procedures absent. Run:
`pwsh -File lore-object-dispatch/tests/run-local-authority-live.ps1`. All eleven tests stay
`#[ignore]`; the harness opts them in with `--ignored --exact <name>` rather than un-ignoring
them, so the crate's baseline `cargo test -p lore-object-dispatch` ignored count is unchanged by
this run. Do not hardcode that count here, it drifts; list it fresh with `-- --list --ignored`.

CD-1's out-of-band installer/attester itself (`lore-object-dispatch/src/cell_schema_install.rs`
plus `src/bin/cell-schema-install.rs`, a one-shot operator CLI, not a service) has its own
offline-only suite, `tests/cell_schema_install.rs` — no Postgres, no `#[ignore]`. It re-reads
`migrations/*.sql` from disk independently of the module's own `include_str!` copies (so a
frozen-bytes claim is checked against ground truth, not against itself), and pins: the exact
install set against the on-disk directory, so a future migration must be classified
installed-or-deferred or the test fails (read its current size from `CELL_INSTALL_SET`, never
from a number written here — it grows every CD wave); the interleaved install plan; each schema
layer's install/read_state function names, revisions, and digest against the migration that
creates them; the `CREATE OR REPLACE FUNCTION` replacement inventory (scanned by text, not
hand-enumerated, so an unpinned replace and one dropped from the pinned list both fail); and a `local_authority_put_reservation_provisioning.rs`-style "runtime source never
calls the install entrypoints" guard extended to the new bin target. Gate:
`cargo test -p lore-object-dispatch --test cell_schema_install`. One test
(`cell_schema_error_is_a_standard_redacted_error_type`) is a type-level stub pending the real
`CellSchemaError` variant list, which the module's pinned contract deliberately left open —
fill in the per-variant `format!("{e}")`/`{e:?}` redaction assertions once the enum lands.

WP-114 CD-5's provider client (`provider_client.rs`): `AuthorizedProviderAttempt` is
crate-private-constructed, and a transport reporting `provider_requests_issued != 1` poisons the
ledger. That bounds what a transport may issue *and admit to*; it does not prove SDK auto-retry is
off, because an SDK retry happens below the one call and reports one honestly. Disabling it is
CD-6's construction obligation, and `ProviderRetryPolicy` is only the declaration.
`record_no_dispatch` refuses after any issued attempt regardless of outcome: generate such state
matrices by driving the real API, and give a sequencing rule an axis on both sides of the sequence
(two successive hand-listed versions both missed the ambiguous case). Keep
`ProviderAttemptLedger::audit`'s call into `compaction`'s `provider_attempt_audit_is_valid` rather
than restating the algebra. The matrix's pinned state set is a change-detector, not an oracle — it
is invariant under swapping the decisive/ambiguous arms, so the two tests pinning that mapping
directly are load-bearing.
`validate_endpoint_host` accepts a single-label host (`minio`, `localhost`).
Double pattern: one closure-scripted double per trait, `new` returning `(Self, Rc<Cell<u32>>)`
(the counter handle must outlive the double once moved into the client); close over an
`Rc<RefCell<Option<T>>>` in the same closure to capture what it *receives*, not just call counts.
When the received type is deliberately non-`Clone` (`ProviderChargeRequest`, so nothing can retain
a chargeable value past the call), copy the asserted fields into your own plain struct instead.
`ProviderAttemptLedger::new` takes `(provider_boundary_id, logical_request_id) -> Result<Self, _>`
(no `Default`); `execute` refuses a request naming a different boundary/logical-request with
`LedgerRequestMismatch`, and `audit_for(logical_request_id)` replaced `audit()` for the same
reason — one ledger cannot accumulate two requests' attempts. `authorize` is crate-private; its
public replacement is `validate_attempt`, so a test asserting the `ProviderChargeRequest` an
authority receives needs the capture-closure pattern above during a real `execute()`, not a direct
call. Adding an identity field to a `#[derive(Debug)]` type risks a redaction regression -- check
for a hand-written impl whenever a type gains an identity string.
Gate: `cargo test -p lore-object-dispatch --test provider_client -j 4` (no `#[ignore]`).

WP-114 CD-4's shared limiter (`provider_charge.rs`, migrations 0021/0022) splits its evidence
across two tiers. `tests/run-provider-charge-live.ps1` (six `#[ignore]`d tests, disposable
PostgreSQL 16) owns the effect claims: fusing the debit into the check loop, so a class-cap
refusal leaves the shared bucket debited, fails
`..._last_unit_charges_are_atomic_and_fail_closed` at "shared debit must roll back"
(revert-checked). It does NOT own the locking claims — deleting both the per-boundary
`pg_advisory_xact_lock` and the check loop's `FOR UPDATE OF state` leaves all six green, since
SERIALIZABLE plus the harness's own `40001` retry still delivers the outcome. Only
`provider_charge_schema.rs`'s `charge_locks_and_checks_every_cap_before_inserting_or_debiting`
(source order lock < grant insert < debit) catches that, so it is load-bearing, not a redundant
change-detector. `concurrent_charges` is `tokio::join!` over two connections with no barrier, so
every assertion also holds sequentially: it proves the rollback, not the race. Open gap: nothing
exercises the function's refusal of a non-serializable caller.
Comparing a crate's counts across two commits needs `--no-fail-fast`; the default stops at the
first failing target and tallies only what it reached (19 of 47 here), a plausible-looking count.

**CR-034 runtime budget pin re-read [SERVER]**, layered on the CD-4/CD-5 pair above: on
`BudgetPinRejected`, `execute` calls the new `refresh_budget_pin` trait method (default:
`Err(ConfigurationUnresolved)`, every pre-existing implementor unaffected) at most once, retries
the same attempt at most once, and accepts the refresh only when its fence is the exact successor
AND its revision token differs — a real publish always mints a fresh revision, so a fixture that
only bumps the fence and keeps the old revision string is refused for the wrong reason; pin that
case explicitly (`refresh_to_the_exact_successor_fence_but_an_unchanged_revision_is_still_refused`),
don't rely on catching it by accident. `PostgresProviderChargeAuthority::refresh_budget_pin`
(`provider_charge.rs`) reads migration 0025's `SECURITY DEFINER` head-read function through the
same dispatch pool the charge uses, `ReadCommitted` not `Serializable`, no boundary advisory lock.
Unit coverage (mocked authority, no database — 9 cases): `cargo test -p lore-object-dispatch
--test provider_client -- refresh_ non_budget_pin_rejected`, `tests/provider_client.rs` section
"7a" (`RefreshScriptedChargeAuthority` scripts `charge`/`refresh_budget_pin` independently and
records every pin observed; `PanicOnRefreshChargeAuthority` turns an unwanted refresh call into a
hard failure). Live coverage, `tests/run-budget-pin-refresh-live.ps1` (own throwaway Postgres 16
container per test, pattern of `provider_charge_live.rs`): 0025 least-privilege (runtime role
only, `42501` for maintenance/migrator, head table itself still unreachable), a real
renewal-and-retry (double-spend proof: old fence's bucket untouched, only the new fence's is
debited), N+2 drift refusing with zero debit anywhere, and expiry staying
`CONFIGURATION_UNRESOLVED` with zero refresh calls (`CountingRefreshAuthority` wraps the real
authority to count real `refresh_budget_pin` invocations, not a fake's). One fixture gotcha
this file's `set_available` hit that `provider_charge_live.rs`'s twin never needed: its
bare-literal `{units} * {INTERVAL_MS}` SQL multiplies as `int4` and overflows past ~2.1e9
(`int4mul`, SQLSTATE `22003`) the moment `units` exceeds ~2 — cast both operands to
`numeric(20,0)` (the `uint64` domain's own base type) before multiplying. Owned by the
implementation lane, not this test lane: the live catalog re-measure
(`run-cell-schema-install-live.ps1 -Measure`) pins 0025's two moved sections (`functions`,
`function_acls`) into `CELL_CATALOG_SECTION_BLAKE3_R27`/`CELL_CATALOG_MANIFEST_BLAKE3_R27` (named
`*_V1` before CR-038; the current state's pins are the `*_R28` pair) --
invisible to the default (non-live) suite and caught only by the live installer tier, so run it
whenever 0025 changes.

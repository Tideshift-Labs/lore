# Fork-delta inventory: `lore-object-dispatch` CD-wave test methodology

Split out of [`testing-fork-delta-inventory.md`](testing-fork-delta-inventory.md) to keep it under
budget. Covers WP-114's CD-1 through CD-6 test methodology for the CR-033 cell dispatch authority
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
`pwsh -File lore-object-dispatch/tests/run-local-authority-live.ps1`. All eleven stay `#[ignore]`; the harness
opts them in with `--ignored --exact <name>`. Never hardcode the ignored count; list it with `-- --list --ignored`.

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
`cargo test -p lore-object-dispatch --test cell_schema_install`.

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
(the handle must outlive the double); capture what it *receives* via an `Rc<RefCell<Option<T>>>`.
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
every assertion also holds sequentially: it proves the rollback, not the race. Open gap: no test
drives a non-serializable caller.
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
Unit coverage (mocked authority, no database): `cargo test -p lore-object-dispatch
--test provider_client -- refresh_ non_budget_pin_rejected`, `tests/provider_client.rs` section
"7a" (`RefreshScriptedChargeAuthority` scripts `charge`/`refresh_budget_pin` independently and
records every pin observed; `PanicOnRefreshChargeAuthority` turns an unwanted refresh call into a
hard failure). Live coverage, `tests/run-budget-pin-refresh-live.ps1` (own throwaway Postgres 16
container per test, pattern of `provider_charge_live.rs`): 0025 least-privilege (runtime role
only, `42501` for maintenance/migrator, head table itself still unreachable), a real
renewal-and-retry (double-spend proof: old fence's bucket untouched, only the new fence's is
debited), N+2 drift refusing with zero debit anywhere, and expiry staying
`CONFIGURATION_UNRESOLVED` with zero refresh calls (`CountingRefreshAuthority` wraps the real
authority to count real `refresh_budget_pin` invocations, not a fake's). Fixture gotcha:
`set_available`'s bare-literal `{units} * {INTERVAL_MS}` multiplies as `int4` and overflows past
~2.1e9 (SQLSTATE `22003`); cast both operands to `numeric(20,0)`. A change to 0025 moves two
catalog sections pinned in the `*_R27`/`*_R28` constants, visible only to the live installer tier
(`run-cell-schema-install-live.ps1 -Measure`), so run it whenever 0025 changes.

**Budget provenance types [SERVER]** (`budget_provenance.rs`, `cell_budget_configure.rs`): a
local and a documented-provider (sfo3, 800 ops/s, <=7 d) record, told apart by provenance and by
the `owner-decision-f<fence>-x<expiry>` revision token the consumer sees as its pin. No-DB gates:
`cargo test -p lore-object-dispatch --lib --test budget_provenance --test provider_client`
(a refusal before any connection is proven by a bound listener that sees no accept, plus a
matching-binding control that does connect). `lore-server`: `--test phase5_fragment_provider_config`; the pin/endpoint rule made every
`objects.example.com` + plain-pin fixture a config error, so such fixtures use `http://minio:9000`
+ `minio`. Live: `run-budget-configure-live.ps1`; a new `#[ignore]` live test must ALSO be added
to the known-tests list in `run-local-authority-live.ps1` or that runner's catalog cross-check
throws. Mutation-check each refusal; a survivor means a sibling rule masked the case (an unknown
provenance on a documented-schema record is refused by the schema, not the provenance).

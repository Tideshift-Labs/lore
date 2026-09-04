// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-109 Phase 2: the local, no-provider, two-coordinator shared-backend
//! proof.
//!
//! Two independently constructed coordinator/store sets — separate pools,
//! separate S3 clients, separate coordinator handles — against **one** real
//! PostgreSQL database and **one** real MinIO bucket. Every case drives a race
//! between them, releases a barrier that PostgreSQL itself attests, and then
//! asserts authoritative SQL and object-store state alongside the public
//! result each caller received.
//!
//! Run it with `tests/run-active-active-shared-backend-live.ps1`, never with a
//! bare `cargo test`. The runner creates a database per case, mints the
//! object-store environment, sets the per-case failpoint configuration that
//! `domain/fragments/failpoints.rs` reads once per process, and reports PASS,
//! FAIL, and NOT RUN separately against an EXPECTED count. A case's own exit
//! code cannot make that distinction, which is why the runner exists.
//!
//! # What this file proves, stated exactly
//!
//! It proves that the **coordinators** hold their invariants when two
//! independently constructed sets share one backend. It does not prove
//! anything about two operating-system processes: process-global state — the
//! failpoint configuration above all — is shared here, and one process cannot
//! be killed without taking the other with it. Two real loreserver processes
//! are WP-109 Phase 3's, and nothing below should be read as standing in for
//! them.
//!
//! # Barriers, and why a bare `tokio::join!` is not one
//!
//! Two futures joined on a current-thread runtime may run strictly in
//! sequence, and "exactly one winner" is trivially true of a sequence. Every
//! race here is therefore held at a gate — `LOCK TABLE ... IN EXCLUSIVE MODE`
//! on the contended relation, `pg_advisory_xact_lock` on the contended hash, or
//! a WP-118 Phase 9 failpoint — and the gate is released only after
//! `pg_stat_activity`/`pg_locks` report the contenders queued behind it. A
//! barrier that never engages **panics**, so a case that degenerates into a
//! sequence fails rather than passing on a race it did not run. See
//! `active_active_support::barrier`.
//!
//! # Namespacing and cleanup
//!
//! Each case takes its own `CaseNamespace` schema (shared by both sets, which
//! is the point) and its own MinIO bucket, records both creations, and records
//! the release or a `retained for debug` disposition. The runner supplies the
//! database arm on top of that.
//!
//! # Deliberate scope notes
//!
//! - **Cutover marker and mixed-version refusal** (`cutover.*` anchors plus
//!   WP-119 Step B's `lore-server` startup gate) are **out of scope for this
//!   crate-level harness**: the gate lives in `lore-server`, which cannot be a
//!   dependency here. They belong to Phase 3.
//! - **Promotion** (`Staged` -> `Remote`) is not exercised as a race. The
//!   coordinator route is default dark and the CR-007 store path has no
//!   promotion, so a "query during promotion" case at this layer would be a
//!   race against a code path no configuration in this harness can reach.
//!   `d2` covers the readable-boundary crossing the store path does have: the
//!   window where the object bytes are already durable in the shared bucket and
//!   the rows that make them readable have not committed.
//! - **Object-prefix namespacing** is met by a bucket per case rather than a
//!   key prefix; `PostgresImmutableStore` derives its key from the content hash
//!   alone and WP-109 forbids changing that. See `active_active_support::bucket`.

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "active_active_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use lore_postgres::domain::coordinator::CAS_MISMATCH_V1;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GENERATION_MISMATCH_V1;
use lore_postgres::domain::coordinator::NAME_TAKEN_V1;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
// The fragment-lifecycle surface is reached only by the failpoint tier at the
// end of this file, so its imports and helpers carry the same gate the cases do
// rather than being dead in a default build.
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::BeginOutcome;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::CommitVerdict;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::EpochAuthority;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::FragmentManifest;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::FragmentVerdict;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::FragmentWriteSettlement;
#[cfg(feature = "failure_generator")]
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::locks::LockRejection;
use lore_postgres::domain::locks::ReleaseInput;
use lore_postgres::domain::locks::acquire_or_renew_binding;
use lore_postgres::domain::locks::force_release_binding;
use lore_postgres::domain::locks::release_binding;
use lore_postgres::domain::outbox::AckInputs;
use lore_postgres::domain::outbox::ResetAcceptance;
use lore_postgres::domain::outbox::accept_reset;
use lore_postgres::domain::outbox::builders;
use lore_postgres::domain::outbox::evaluate_consumer_safe;
use lore_postgres::domain::outbox::evaluator::MAX_EVALUATION_BATCH;
use lore_postgres::domain::outbox::membership;
use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::relay::BrokerAcceptanceRecord;
use lore_postgres::domain::receipts::REASON_VERSION;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::FragmentFlags;
use lore_storage::Hash;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use support::barrier;
use support::barrier::AdvisoryGate;
#[cfg(feature = "failure_generator")]
use support::barrier::FailpointHold;
use support::barrier::TableGate;
use support::bucket::CaseBucket;
use support::domain_fixture as fixture;
use support::env;
use support::outbox_fixture as outbox;
use support::sets::SharedBackend;
use support::tally::Identities;
use support::tally::RaceOutcome;
use support::tally::RaceTally;

/// How many rounds a repeated race runs. Small on purpose: every round here is
/// gated and attested, so a round is a *proof*, not a lottery ticket, and the
/// contention it needs is manufactured rather than hoped for.
const HIGH_CONTENTION_ROUNDS: usize = 4;

fn not_applied(reason: &str) -> DomainOutcome {
    DomainOutcome::NotApplied {
        reason_version: REASON_VERSION,
        reason: reason.to_owned(),
    }
}

fn partition_from(bytes: [u8; 16]) -> Partition {
    let mut partition = Partition::default();
    *partition.data_mut() = bytes;
    partition
}

fn context_from(bytes: [u8; 16]) -> Context {
    let mut context = Context::default();
    *context.data_mut() = bytes;
    context
}

/// Open one set's own `PostgresImmutableStore` against the shared bucket.
async fn object_store(
    url: &str,
    bucket: &str,
    endpoint: &str,
    region: &str,
) -> Arc<PostgresImmutableStore> {
    let settings = ObjectStoreSettings {
        bucket: bucket.to_owned(),
        endpoint_url: Some(endpoint.to_owned()),
        region: Some(region.to_owned()),
        force_path_style: true,
        slow_operation_threshold_millis: u64::MAX,
        timeout_millis: 30_000,
        // The harness created this bucket itself and asserts against it
        // directly, so a startup HEAD would only add a failure mode.
        validate_bucket_on_startup: false,
    };
    Arc::new(
        PostgresImmutableStore::connect(url, 5, &TlsConfig::default(), settings)
            .await
            .expect("connect this set's immutable store"),
    )
}

async fn query_one(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    address: Address,
) -> StoreMatchResult {
    let mut results = vec![StoreMatchResult::default(); 1];
    store
        .query(partition, &[address], &mut results)
        .await
        .expect("query the shared backend");
    results.remove(0)
}

#[cfg(feature = "failure_generator")]
fn write_claim(ids: &mut Identities) -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        ids.id16(),
        ids.id16(),
        ids.id32(),
        128,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .expect("a valid write claim")
}

#[cfg(feature = "failure_generator")]
fn manifest(object_key: &str, seed: u8) -> FragmentManifest {
    FragmentManifest {
        authority: EpochAuthority::Remote,
        object_key: object_key.to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 128,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 0,
    }
}

fn hex_key(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ===========================================================================
// (a) Repository identity
// ===========================================================================

/// Two sets create different repositories claiming the same name, held at the
/// name table until both are queued. Exactly one may own the live name; the
/// loser must be decisively refused and must leave no repository row behind —
/// the create writes its repository row *before* it learns the name is taken,
/// so a partial loser is a real possible failure, not a hypothetical one.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn a1_two_sets_racing_one_repository_name_leave_exactly_one_live_owner() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "a1-name-race").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;
    let readback = backend.b.raw().await;
    let mut tally = RaceTally::new("repository_create/create on one name", seed);

    for round in 0..HIGH_CONTENTION_ROUNDS {
        let name = ids.name("name-race");
        let repository_a = ids.id16();
        let repository_b = ids.id16();
        let input_a = fixture::create_input(repository_a, ids.id16(), name.clone(), &mut ids);
        let input_b = fixture::create_input(repository_b, ids.id16(), name.clone(), &mut ids);
        let operation_a = fixture::admitted(&backend.a.domain, "repository_create", &mut ids).await;
        let operation_b = fixture::admitted(&backend.b.domain, "repository_create", &mut ids).await;

        // Neither racer has touched the name table yet, so this gate changes no
        // row: it only stops both of them at the statement that claims the
        // name, with their repository rows already written.
        let gate = TableGate::take(&mut gate_client, "lore_domain_repository_names").await;
        let race = async {
            tokio::join!(
                backend.a.domain.repository_create(&operation_a, &input_a),
                backend.b.domain.repository_create(&operation_b, &input_b),
            )
        };
        let opening = async {
            barrier::wait_for_lock_waiters(
                &observer,
                2,
                &format!("round {round} of the repository-name race"),
            )
            .await;
            gate.release().await;
        };
        let ((result_a, result_b), ()) = tokio::join!(race, opening);
        let result_a = result_a.expect("set A's create must not error");
        let result_b = result_b.expect("set B's create must not error");

        let outcome_of = |result: &lore_postgres::domain::coordinator::MutationResult| {
            if result.outcome == DomainOutcome::Applied {
                RaceOutcome::Won
            } else {
                assert_eq!(
                    result.outcome,
                    not_applied(NAME_TAKEN_V1),
                    "the losing create must be refused as NAME_TAKEN_V1, not {:?}",
                    result.outcome
                );
                RaceOutcome::Lost
            }
        };
        tally.round(outcome_of(&result_a), outcome_of(&result_b));

        // Authoritative SQL, read through the set that did not win, whichever
        // that was.
        let owner: Vec<u8> = readback
            .query_one(
                "SELECT repository_id FROM lore_domain_repository_names WHERE name = $1",
                &[&name],
            )
            .await
            .expect("exactly one live name row")
            .get(0);
        assert!(
            owner == repository_a.to_vec() || owner == repository_b.to_vec(),
            "the live name must belong to one contender, not to a third identity"
        );
        let loser = if owner == repository_a.to_vec() {
            repository_b
        } else {
            repository_a
        };
        let loser_rows: i64 = readback
            .query_one(
                "SELECT count(*)::bigint FROM lore_domain_repositories WHERE repository_id = $1",
                &[&loser.as_slice()],
            )
            .await
            .expect("count the losing repository's rows")
            .get(0);
        assert_eq!(
            loser_rows, 0,
            "a create that lost the name must leave no repository row; found a half-created \
             repository for {loser:02x?}"
        );
    }

    tally.report();
    assert_eq!(tally.winners(), HIGH_CONTENTION_ROUNDS);
    assert_eq!(tally.losers(), HIGH_CONTENTION_ROUNDS);
    backend.release().await;
}

/// A name released by one set's delete is claimable by the other set, and the
/// tombstoned identity is not: identities are never reused, names are.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn a2_a_name_released_by_one_set_is_reusable_by_the_other_but_the_identity_is_not() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "a2-name-reuse").await;
    backend.assert_namespaced().await;

    let name = ids.name("reuse");
    let repository_id = ids.id16();
    let create = fixture::admitted(&backend.a.domain, "repository_create", &mut ids).await;
    let create_input = fixture::create_input(repository_id, ids.id16(), name.clone(), &mut ids);
    assert_eq!(
        backend
            .a
            .domain
            .repository_create(&create, &create_input)
            .await
            .expect("set A's create must not error")
            .outcome,
        DomainOutcome::Applied
    );

    // Set B must see set A's repository without any handoff.
    let seen_by_b = backend
        .b
        .domain
        .repository_snapshot(&repository_id)
        .await
        .expect("set B reads the shared backend")
        .expect("set A's repository must be visible to set B");
    assert_eq!(seen_by_b.name, name);
    assert!(seen_by_b.live);

    let delete = fixture::admitted(&backend.a.domain, "repository_delete", &mut ids).await;
    let delete_input = fixture::delete_input(repository_id, &mut ids);
    assert_eq!(
        backend
            .a
            .domain
            .repository_delete(&delete, &delete_input)
            .await
            .expect("set A's delete must not error")
            .outcome,
        DomainOutcome::Applied
    );

    // The freed name is claimable by the other set, under a new identity.
    let reused_id = ids.id16();
    let reuse = fixture::admitted(&backend.b.domain, "repository_create", &mut ids).await;
    let reuse_input = fixture::create_input(reused_id, ids.id16(), name.clone(), &mut ids);
    assert_eq!(
        backend
            .b
            .domain
            .repository_create(&reuse, &reuse_input)
            .await
            .expect("set B's reuse must not error")
            .outcome,
        DomainOutcome::Applied,
        "a name released by a tombstone must be reclaimable from the other set"
    );

    // The tombstoned identity is not reusable, from either set.
    let revive = fixture::admitted(&backend.b.domain, "repository_create", &mut ids).await;
    let revive_input =
        fixture::create_input(repository_id, ids.id16(), ids.name("revive"), &mut ids);
    let revived = backend
        .b
        .domain
        .repository_create(&revive, &revive_input)
        .await
        .expect("set B's revive attempt must not error");
    assert_eq!(
        revived.outcome,
        not_applied(lore_postgres::domain::coordinator::TOMBSTONED_V1),
        "a tombstoned repository identity must stay permanently unusable"
    );

    let readback = backend.a.raw().await;
    let owner: Vec<u8> = readback
        .query_one(
            "SELECT repository_id FROM lore_domain_repository_names WHERE name = $1",
            &[&name],
        )
        .await
        .expect("exactly one live name row")
        .get(0);
    assert_eq!(owner, reused_id.to_vec());
    backend.release().await;
}

// ===========================================================================
// (b) Branch publication
// ===========================================================================

/// Both sets push the same branch from the same observed generation. Exactly
/// one advances the tip; the loser is refused with a compare-and-swap outcome
/// and the branch generation moves by exactly one.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn b1_two_sets_pushing_one_head_advance_it_exactly_once() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "b1-push-race").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;
    let mut tally = RaceTally::new("branch_push_commit/push on one head", seed);

    let (repository_id, branch_id, mut tip) =
        fixture::create_repository(&backend.a.domain, &mut ids, "push-race").await;

    for round in 0..HIGH_CONTENTION_ROUNDS {
        // Both sets run their own preflight against the shared backend.
        let snapshot_a = backend
            .a
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("set A preflight")
            .expect("branch exists");
        let snapshot_b = backend
            .b
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("set B preflight")
            .expect("branch exists");
        assert_eq!(
            snapshot_a, snapshot_b,
            "two independently constructed sets must read one branch identically"
        );
        let witness = backend
            .a
            .locks()
            .capture_push_witness(&repository_id, &branch_id)
            .await
            .expect("capture the push witness");

        let tip_a = ids.id32().to_vec();
        let tip_b = ids.id32().to_vec();
        let input_a = fixture::push_input(
            repository_id,
            branch_id,
            snapshot_a.repository_generation,
            snapshot_a.generation,
            witness,
            tip.clone(),
            tip_a.clone(),
        );
        let input_b = fixture::push_input(
            repository_id,
            branch_id,
            snapshot_b.repository_generation,
            snapshot_b.generation,
            witness,
            tip.clone(),
            tip_b.clone(),
        );
        let operation_a =
            fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
        let operation_b =
            fixture::admitted(&backend.b.domain, "branch_push_commit", &mut ids).await;

        let gate = TableGate::take(&mut gate_client, "lore_domain_branches").await;
        let race = async {
            tokio::join!(
                backend.a.domain.branch_push_commit(&operation_a, &input_a),
                backend.b.domain.branch_push_commit(&operation_b, &input_b),
            )
        };
        let opening = async {
            barrier::wait_for_lock_waiters(
                &observer,
                2,
                &format!("round {round} of the push race"),
            )
            .await;
            gate.release().await;
        };
        let ((result_a, result_b), ()) = tokio::join!(race, opening);
        let result_a = result_a.expect("set A's push must not error");
        let result_b = result_b.expect("set B's push must not error");

        let classify = |result: &lore_postgres::domain::coordinator::MutationResult| {
            if result.outcome == DomainOutcome::Applied {
                RaceOutcome::Won
            } else {
                assert_eq!(
                    result.outcome,
                    not_applied(CAS_MISMATCH_V1),
                    "the losing push must carry the CAS outcome, not {:?}",
                    result.outcome
                );
                RaceOutcome::Lost
            }
        };
        let (outcome_a, outcome_b) = (classify(&result_a), classify(&result_b));
        tally.round(outcome_a, outcome_b);

        let expected_tip = if outcome_a == RaceOutcome::Won {
            tip_a
        } else {
            tip_b
        };
        // How a losing pusher learns what actually happened, recorded because
        // it is not what a reader would assume. `metadata_compare_and_swap`
        // returns `observed_pointer` on a CAS loss (`MutationResult::cas_lost`);
        // `branch_push_commit` does not — its mismatch arm is a plain
        // `MutationResult::rejected(CAS_MISMATCH_V1)`, so the pointer is `None`
        // on this path. The loser's reconciliation is therefore a fresh
        // authoritative read, which is what the next round's preflight does and
        // what this assertion stands in for. Asserted rather than assumed, so
        // the asymmetry is visible if either side changes.
        let loser = if outcome_a == RaceOutcome::Won {
            &result_b
        } else {
            &result_a
        };
        assert!(
            loser.observed_pointer.is_none(),
            "branch_push_commit's CAS arm carries no observed pointer today; a change here is a \
             contract change for every losing pusher's reconciliation, got {:?}",
            loser.observed_pointer
        );
        let after = backend
            .b
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("read back through the other set")
            .expect("branch exists");
        assert_eq!(
            after.latest_hash, expected_tip,
            "one winner's tip must stand"
        );
        assert_eq!(
            after.generation,
            snapshot_a.generation + 1,
            "exactly one push may advance the branch generation"
        );
        tip = expected_tip;
    }

    tally.report();
    assert_eq!(tally.winners(), HIGH_CONTENTION_ROUNDS);
    assert_eq!(tally.losers(), HIGH_CONTENTION_ROUNDS);
    backend.release().await;
}

/// A push from one set against a repository the other set is deleting. Either
/// the push lands before the tombstone or it is refused; a tombstoned
/// repository must never end up with an advanced branch tip.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn b2_a_push_racing_a_repository_delete_never_advances_a_tombstoned_branch() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "b2-push-delete").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let (repository_id, branch_id, tip) =
        fixture::create_repository(&backend.a.domain, &mut ids, "push-delete").await;
    let snapshot = backend
        .a
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("preflight")
        .expect("branch exists");
    let witness = backend
        .a
        .locks()
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("capture the push witness");
    let new_tip = ids.id32().to_vec();
    let push_input = fixture::push_input(
        repository_id,
        branch_id,
        snapshot.repository_generation,
        snapshot.generation,
        witness,
        tip.clone(),
        new_tip.clone(),
    );
    let push_op = fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
    let delete_op = fixture::admitted(&backend.b.domain, "repository_delete", &mut ids).await;
    let delete_input = fixture::delete_input(repository_id, &mut ids);

    // Both transitions write `lore_domain_branches`: the push advances the tip,
    // the delete tombstones every live branch.
    let gate = TableGate::take(&mut gate_client, "lore_domain_branches").await;
    let race = async {
        tokio::join!(
            backend.a.domain.branch_push_commit(&push_op, &push_input),
            backend
                .b
                .domain
                .repository_delete(&delete_op, &delete_input),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the push/delete race").await;
        gate.release().await;
    };
    let ((push, delete), ()) = tokio::join!(race, opening);
    let push = push.expect("the push must not error");
    let delete = delete.expect("the delete must not error");

    assert_eq!(
        delete.outcome,
        DomainOutcome::Applied,
        "a delete of a live repository must apply whichever order it lands in"
    );
    let repository = backend
        .b
        .domain
        .repository_snapshot(&repository_id)
        .await
        .expect("read the repository through set B")
        .expect("a tombstoned repository keeps its row");
    assert!(!repository.live, "the repository must be tombstoned");

    let branch = backend
        .a
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("read the branch through set A")
        .expect("a tombstoned branch keeps its row");
    assert!(
        !branch.live,
        "the branch must be tombstoned with its repository"
    );
    if push.outcome == DomainOutcome::Applied {
        assert_eq!(
            branch.latest_hash, new_tip,
            "a push that applied before the tombstone keeps its published tip"
        );
    } else {
        assert_eq!(
            branch.latest_hash, tip,
            "a push that lost must not have published its tip"
        );
        assert!(
            matches!(&push.outcome, DomainOutcome::NotApplied { reason, .. }
                if reason == GENERATION_MISMATCH_V1
                    || reason == lore_postgres::domain::coordinator::TOMBSTONED_V1
                    || reason == lore_postgres::domain::coordinator::NOT_FOUND_V1),
            "the losing push must carry a decisive reason, got {:?}",
            push.outcome
        );
    }

    // The name must be released exactly once, whichever order won.
    let readback = backend.a.raw().await;
    let names: i64 = readback
        .query_one(
            "SELECT count(*)::bigint FROM lore_domain_repository_names WHERE repository_id = $1",
            &[&repository_id.as_slice()],
        )
        .await
        .expect("count the tombstoned repository's name rows")
        .get(0);
    assert_eq!(names, 0, "a tombstone must release the live name");
    backend.release().await;
}

/// The obliteration fence across two sets: one set begins obliteration while
/// the other pushes from the pre-obliteration generation. The push must be
/// refused, and the same push carrying the post-obliteration generation must
/// then succeed — proving both sets agree on the same fence value.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn b3_a_push_racing_begin_obliterate_is_fenced_by_the_repository_generation() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "b3-push-oblit").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let (repository_id, branch_id, tip) =
        fixture::create_repository(&backend.a.domain, &mut ids, "push-oblit").await;
    let snapshot = backend
        .a
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("preflight")
        .expect("branch exists");
    let witness = backend
        .a
        .locks()
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("capture the push witness");
    let stale_tip = ids.id32().to_vec();
    let push_input = fixture::push_input(
        repository_id,
        branch_id,
        snapshot.repository_generation,
        snapshot.generation,
        witness,
        tip.clone(),
        stale_tip.clone(),
    );
    let push_op = fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
    let obliterate_op = fixture::admitted(&backend.b.domain, "begin_obliterate", &mut ids).await;

    // Both write `lore_domain_repositories`: the obliterate bumps the
    // generation, the push revalidates it under the row lock.
    let gate = TableGate::take(&mut gate_client, "lore_domain_repositories").await;
    let race = async {
        tokio::join!(
            backend.a.domain.branch_push_commit(&push_op, &push_input),
            backend
                .b
                .domain
                .begin_obliterate(&obliterate_op, &repository_id, None),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the push/obliterate race").await;
        gate.release().await;
    };
    let ((push, obliterate), ()) = tokio::join!(race, opening);
    let push = push.expect("the push must not error");
    let obliterate = obliterate.expect("begin_obliterate must not error");
    assert_eq!(obliterate.outcome, DomainOutcome::Applied);
    let fence = obliterate
        .repository_generation
        .expect("begin_obliterate publishes the fence generation");

    let branch_after = backend
        .b
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("read the branch through set B")
        .expect("branch exists");
    if push.outcome == DomainOutcome::Applied {
        assert_eq!(
            branch_after.latest_hash, stale_tip,
            "a push that committed before the fence keeps its tip"
        );
    } else {
        assert_eq!(
            push.outcome,
            not_applied(GENERATION_MISMATCH_V1),
            "a push across the obliteration fence must be refused on the generation"
        );
        assert_eq!(
            branch_after.latest_hash, tip,
            "a fenced push must not publish its tip"
        );
    }

    // Set A now re-runs its preflight against the post-obliteration state and
    // must be admitted. This is the half that proves the fence is a fence and
    // not a wall: the two sets agree on one generation value.
    let refreshed_branch = backend
        .a
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("set A re-preflight")
        .expect("branch exists");
    let refreshed_witness = backend
        .a
        .locks()
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("re-capture the push witness");
    let good_tip = ids.id32().to_vec();
    let retry_input = fixture::push_input(
        repository_id,
        branch_id,
        fence,
        refreshed_branch.generation,
        refreshed_witness,
        refreshed_branch.latest_hash.clone(),
        good_tip.clone(),
    );
    let retry_op = fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
    let retry = backend
        .a
        .domain
        .branch_push_commit(&retry_op, &retry_input)
        .await
        .expect("the retried push must not error");
    assert_eq!(
        retry.outcome,
        DomainOutcome::Applied,
        "a push carrying the post-obliteration generation must be admitted"
    );
    assert_eq!(
        backend
            .b
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("final read through set B")
            .expect("branch exists")
            .latest_hash,
        good_tip
    );
    backend.release().await;
}

// ===========================================================================
// (c) Locks
// ===========================================================================

/// Two sets acquire one resource under different verified owners. Exactly one
/// owner pair may hold it, and the loser must be told `ForeignOwner` rather
/// than silently sharing the row.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn c1_two_sets_racing_one_lock_resource_choose_exactly_one_owner() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "c1-lock-race").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;
    let mut tally = RaceTally::new("acquire/acquire on one resource", seed);

    let (repository_id, branch_id, _) =
        fixture::create_repository(&backend.a.domain, &mut ids, "lock-race").await;
    let owner_a = fixture::owner("https://issuer-a.example/wp109", "shared-subject");
    let owner_b = fixture::owner("https://issuer-b.example/wp109", "shared-subject");
    let mut highest_fence = 0i64;

    for round in 0..HIGH_CONTENTION_ROUNDS {
        let hash = ids.id32();
        let input_a = fixture::acquire_input(
            repository_id,
            branch_id,
            owner_a.clone(),
            vec![fixture::resource(hash, None)],
            None,
        );
        let input_b = fixture::acquire_input(
            repository_id,
            branch_id,
            owner_b.clone(),
            vec![fixture::resource(hash, None)],
            None,
        );
        let operation_a = fixture::admitted_lock(
            &backend.a.domain,
            &owner_a,
            &repository_id,
            &branch_id,
            acquire_or_renew_binding(&input_a).expect("binding A"),
        )
        .await;
        let operation_b = fixture::admitted_lock(
            &backend.b.domain,
            &owner_b,
            &repository_id,
            &branch_id,
            acquire_or_renew_binding(&input_b).expect("binding B"),
        )
        .await;

        let gate = TableGate::take(&mut gate_client, "lore_locks").await;
        let coordinator_a = backend.a.locks();
        let coordinator_b = backend.b.locks();
        let race = async {
            tokio::join!(
                coordinator_a.acquire_or_renew(&operation_a, &input_a),
                coordinator_b.acquire_or_renew(&operation_b, &input_b),
            )
        };
        let opening = async {
            barrier::wait_for_lock_waiters(
                &observer,
                2,
                &format!("round {round} of the lock race"),
            )
            .await;
            gate.release().await;
        };
        let ((result_a, result_b), ()) = tokio::join!(race, opening);
        let result_a = result_a.expect("set A's acquire must not error");
        let result_b = result_b.expect("set B's acquire must not error");

        let classify = |result: &lore_postgres::domain::locks::LockMutationResult| {
            if result.outcome == DomainOutcome::Applied {
                assert_eq!(result.locks.len(), 1);
                RaceOutcome::Won
            } else {
                assert_eq!(
                    result.rejection,
                    Some(LockRejection::ForeignOwner),
                    "the losing acquire must be told the row belongs to another verified pair"
                );
                RaceOutcome::Lost
            }
        };
        tally.round(classify(&result_a), classify(&result_b));

        // Read the committed row through the set that did not write it,
        // whichever that was.
        let rows = backend
            .b
            .locks()
            .query(&repository_id, Some(&branch_id), None)
            .await
            .expect("query the shared lock table");
        let held = rows
            .iter()
            .find(|row| row.resource_hash == hash.to_vec())
            .expect("exactly one row for the contested resource");
        assert!(
            held.owner == owner_a || held.owner == owner_b,
            "the held lock must belong to one contender"
        );
        // A fence above zero is true of every row the schema admits, so it
        // discriminates nothing. What the two sets have to agree on is that the
        // fence is drawn from one monotonic sequence: each round's winner, on
        // whichever set won it, must carry a strictly greater fence than the
        // previous round's.
        assert!(
            held.fence > highest_fence,
            "fences must increase strictly across rounds and across sets: round {round} \
             committed {} after {highest_fence}",
            held.fence
        );
        highest_fence = held.fence;
    }

    tally.report();
    assert_eq!(tally.winners(), HIGH_CONTENTION_ROUNDS);
    assert_eq!(tally.losers(), HIGH_CONTENTION_ROUNDS);
    backend.release().await;
}

/// One set takes over an expired lease; the original holder's renew and
/// release must then both lose, and the successor's fence must be strictly
/// greater than the predecessor's.
///
/// The lease is expired by moving `expires_at` into the past with one
/// statement rather than by waiting, because a barrier must be a state change
/// the harness controls, not elapsed time it hopes for.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn c2_an_expired_lease_takeover_by_one_set_fences_the_other_sets_renew_and_release() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "c2-lease").await;
    backend.assert_namespaced().await;
    let direct = backend.a.raw().await;

    let (repository_id, branch_id, _) =
        fixture::create_repository(&backend.a.domain, &mut ids, "lease").await;
    backend
        .a
        .locks()
        .backfill(&std::collections::BTreeMap::new())
        .await
        .expect("empty backfill before cutover");
    backend
        .a
        .locks()
        .enable_fencing_for_component_fixture(true)
        .await
        .expect("enable finite leases for this fixture");

    let owner_a = fixture::owner("https://issuer.example/wp109", "holder-a");
    let owner_b = fixture::owner("https://issuer.example/wp109", "holder-b");
    let hash = ids.id32();
    let input_a = fixture::acquire_input(
        repository_id,
        branch_id,
        owner_a.clone(),
        vec![fixture::resource(hash, None)],
        Some(Duration::from_secs(300)),
    );
    let operation_a = fixture::admitted_lock(
        &backend.a.domain,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_a).expect("binding A"),
    )
    .await;
    let acquired = backend
        .a
        .locks()
        .acquire_or_renew(&operation_a, &input_a)
        .await
        .expect("set A acquires");
    assert_eq!(acquired.outcome, DomainOutcome::Applied);
    let held = acquired.locks.first().expect("one acquired row").clone();
    assert!(held.expires_at.is_some(), "a finite lease must be stamped");

    // Expire the lease on the authoritative row.
    //
    // The whole timeline moves back, not just the expiry: `lore_locks_fenced_shape`
    // requires `renewed_at >= acquired_at` and `expires_at > renewed_at`, so an
    // expiry alone is rejected as a malformed row rather than accepted as an
    // expired lease. That constraint is also why this is one statement instead
    // of a sleep — the row can be aged deterministically, and waiting for a real
    // lease to run out would make the case slow and timing-dependent for no
    // additional coverage.
    let expired = direct
        .execute(
            "UPDATE lore_locks SET \
                 acquired_at = clock_timestamp() - interval '10 seconds', \
                 renewed_at = clock_timestamp() - interval '10 seconds', \
                 expires_at = clock_timestamp() - interval '5 seconds' \
             WHERE repository = $1 AND branch = $2 AND hash = $3",
            &[
                &repository_id.as_slice(),
                &branch_id.as_slice(),
                &hash.as_slice(),
            ],
        )
        .await
        .expect("expire the lease");
    assert_eq!(expired, 1, "exactly one lock row must be expired");

    // Set B takes over the logically absent row.
    let input_b = fixture::acquire_input(
        repository_id,
        branch_id,
        owner_b.clone(),
        vec![fixture::resource(hash, None)],
        Some(Duration::from_secs(300)),
    );
    let operation_b = fixture::admitted_lock(
        &backend.b.domain,
        &owner_b,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&input_b).expect("binding B"),
    )
    .await;
    let taken = backend
        .b
        .locks()
        .acquire_or_renew(&operation_b, &input_b)
        .await
        .expect("set B takes over");
    assert_eq!(
        taken.outcome,
        DomainOutcome::Applied,
        "an expired lease must be takeable by the other set"
    );
    let successor = taken.locks.first().expect("one successor row").clone();
    assert!(
        successor.fence > held.fence,
        "the successor's fence must strictly exceed the predecessor's: {} then {}",
        held.fence,
        successor.fence
    );
    assert_ne!(
        successor.ownership_token, held.ownership_token,
        "a takeover must mint a new ownership token"
    );

    // Set A's renew, carrying its old token, must lose.
    let renew_input = fixture::acquire_input(
        repository_id,
        branch_id,
        owner_a.clone(),
        vec![fixture::resource(hash, Some(held.ownership_token))],
        Some(Duration::from_secs(300)),
    );
    let renew_op = fixture::admitted_lock(
        &backend.a.domain,
        &owner_a,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&renew_input).expect("renew binding"),
    )
    .await;
    let renewed = backend
        .a
        .locks()
        .acquire_or_renew(&renew_op, &renew_input)
        .await
        .expect("the stale renew must not error");
    assert_eq!(
        renewed.rejection,
        Some(LockRejection::ForeignOwner),
        "a renew after a takeover must lose to the successor, got {renewed:?}"
    );

    // So must set A's release — but with a different classification, and the
    // difference is information rather than noise. A renew is an acquire on a
    // row a *different verified pair* now holds, so it is `ForeignOwner`; a
    // release presents a token, and the successor's token check fires first, so
    // it is `AuthorityMismatch`. Both are decisive; only the second tells the
    // caller its token is the stale thing.
    let release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: owner_a.clone(),
        resources: vec![fixture::resource(hash, Some(held.ownership_token))],
        event: None,
    };
    let release_op = fixture::admitted_lock(
        &backend.a.domain,
        &owner_a,
        &repository_id,
        &branch_id,
        release_binding(&release_input).expect("release binding"),
    )
    .await;
    let released = backend
        .a
        .locks()
        .release(&release_op, &release_input)
        .await
        .expect("the stale release must not error");
    assert_eq!(
        released.rejection,
        Some(LockRejection::AuthorityMismatch),
        "a stale release must not touch the successor, got {released:?}"
    );

    let rows = backend
        .a
        .locks()
        .query(&repository_id, Some(&branch_id), None)
        .await
        .expect("query after the takeover");
    let still_held = rows
        .iter()
        .find(|row| row.resource_hash == hash.to_vec())
        .expect("the successor's row must still be there");
    assert_eq!(still_held.owner, owner_b);
    assert_eq!(still_held.fence, successor.fence);
    backend.release().await;
}

/// A token-checked release from one set racing an administrative force release
/// from the other. Exactly one may apply; the row must be gone afterwards and
/// the loser must be a decisive rejection, never a second deletion.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn c3_a_release_racing_a_force_release_removes_the_row_exactly_once() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "c3-force").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let (repository_id, branch_id, _) =
        fixture::create_repository(&backend.a.domain, &mut ids, "force").await;
    let holder = fixture::owner("https://issuer.example/wp109", "holder");
    let admin = fixture::owner("https://issuer.example/wp109", "admin");
    let hash = ids.id32();
    let acquire_input = fixture::acquire_input(
        repository_id,
        branch_id,
        holder.clone(),
        vec![fixture::resource(hash, None)],
        None,
    );
    let acquire_op = fixture::admitted_lock(
        &backend.a.domain,
        &holder,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&acquire_input).expect("acquire binding"),
    )
    .await;
    let held = backend
        .a
        .locks()
        .acquire_or_renew(&acquire_op, &acquire_input)
        .await
        .expect("acquire the fixture lock")
        .locks
        .into_iter()
        .next()
        .expect("one acquired row");

    let release_input = ReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner: holder.clone(),
        resources: vec![fixture::resource(hash, Some(held.ownership_token))],
        event: None,
    };
    let release_op = fixture::admitted_lock(
        &backend.a.domain,
        &holder,
        &repository_id,
        &branch_id,
        release_binding(&release_input).expect("release binding"),
    )
    .await;
    let force_input = lore_postgres::domain::locks::ForceReleaseInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        target_owner: holder.clone(),
        acting_owner: admin.clone(),
        resources: vec![fixture::resource(hash, Some(held.ownership_token))],
        event: None,
    };
    let force_op = fixture::admitted_lock(
        &backend.b.domain,
        &admin,
        &repository_id,
        &branch_id,
        force_release_binding(&force_input).expect("force binding"),
    )
    .await;

    let gate = TableGate::take(&mut gate_client, "lore_locks").await;
    let coordinator_a = backend.a.locks();
    let coordinator_b = backend.b.locks();
    let race = async {
        tokio::join!(
            coordinator_a.release(&release_op, &release_input),
            coordinator_b.force_release(&force_op, &force_input),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the release/force-release race").await;
        gate.release().await;
    };
    let ((released, forced), ()) = tokio::join!(race, opening);
    let released = released.expect("the release must not error");
    let forced = forced.expect("the force release must not error");

    let applied = usize::from(released.outcome == DomainOutcome::Applied)
        + usize::from(forced.outcome == DomainOutcome::Applied);
    assert_eq!(
        applied, 1,
        "exactly one of release and force-release may apply: release={released:?} \
         force={forced:?}"
    );
    for result in [&released, &forced] {
        if result.outcome != DomainOutcome::Applied {
            assert!(
                matches!(
                    result.rejection,
                    Some(LockRejection::NotFound | LockRejection::AuthorityMismatch)
                ),
                "the loser must be a decisive rejection, got {result:?}"
            );
        }
    }

    let rows = backend
        .b
        .locks()
        .query(&repository_id, Some(&branch_id), None)
        .await
        .expect("query after the release race");
    assert!(
        rows.iter().all(|row| row.resource_hash != hash.to_vec()),
        "the released row must be gone from the shared backend"
    );
    backend.release().await;
}

/// A lock taken by one set moves the namespace fence the other set captured for
/// its push. The stale push must be refused as contention, and a re-captured
/// witness must then let it through.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn c4_a_lock_from_one_set_invalidates_the_other_sets_captured_push_witness() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "c4-witness").await;
    backend.assert_namespaced().await;

    let (repository_id, branch_id, tip) =
        fixture::create_repository(&backend.a.domain, &mut ids, "witness").await;
    let captured = backend
        .a
        .locks()
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("set A captures the witness");

    // Set B takes a lock, which advances the namespace fence set A captured.
    let lock_owner = fixture::owner("https://issuer.example/wp109", "witness-mover");
    let lock_input = fixture::acquire_input(
        repository_id,
        branch_id,
        lock_owner.clone(),
        vec![fixture::resource(ids.id32(), None)],
        None,
    );
    let lock_op = fixture::admitted_lock(
        &backend.b.domain,
        &lock_owner,
        &repository_id,
        &branch_id,
        acquire_or_renew_binding(&lock_input).expect("lock binding"),
    )
    .await;
    assert_eq!(
        backend
            .b
            .locks()
            .acquire_or_renew(&lock_op, &lock_input)
            .await
            .expect("set B acquires")
            .outcome,
        DomainOutcome::Applied
    );

    let moved = backend
        .a
        .locks()
        .capture_push_witness(&repository_id, &branch_id)
        .await
        .expect("re-capture the witness");
    assert_ne!(
        captured, moved,
        "a lock mutation from the other set must move the witness set A captured"
    );

    let snapshot = backend
        .a
        .domain
        .branch_snapshot(&repository_id, &branch_id)
        .await
        .expect("preflight")
        .expect("branch exists");
    let new_tip = ids.id32().to_vec();
    let stale_input = fixture::push_input(
        repository_id,
        branch_id,
        snapshot.repository_generation,
        snapshot.generation,
        captured,
        tip.clone(),
        new_tip.clone(),
    );
    let stale_op = fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
    let stale = backend
        .a
        .domain
        .branch_push_commit(&stale_op, &stale_input)
        .await;
    assert!(
        matches!(stale, Err(DomainError::Contention(_))),
        "a push carrying a witness the other set moved must be refused as contention, got \
         {stale:?}"
    );
    assert_eq!(
        backend
            .b
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("read through set B")
            .expect("branch exists")
            .latest_hash,
        tip,
        "a refused push must not publish its tip"
    );

    let fresh_input = fixture::push_input(
        repository_id,
        branch_id,
        snapshot.repository_generation,
        snapshot.generation,
        moved,
        tip.clone(),
        new_tip.clone(),
    );
    let fresh_op = fixture::admitted(&backend.a.domain, "branch_push_commit", &mut ids).await;
    assert_eq!(
        backend
            .a
            .domain
            .branch_push_commit(&fresh_op, &fresh_input)
            .await
            .expect("the re-captured push must not error")
            .outcome,
        DomainOutcome::Applied,
        "re-running preflight against the shared backend must clear the witness"
    );
    assert_eq!(
        backend
            .b
            .domain
            .branch_snapshot(&repository_id, &branch_id)
            .await
            .expect("read through set B")
            .expect("branch exists")
            .latest_hash,
        new_tip
    );
    backend.release().await;
}

// ===========================================================================
// (d) Immutable fragments over one MinIO bucket
// ===========================================================================

/// Two sets put two valid representations of one content hash at the same
/// moment. One object must exist in the shared bucket, both associations must
/// be live, and either set must read the winner's exact bytes.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn d1_two_sets_putting_one_hash_converge_on_one_object_and_keep_both_associations() {
    let base_url = env::pg_url();
    let object_env = env::object_store();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "d1-put-race").await;
    backend.assert_namespaced().await;
    let bucket = CaseBucket::create(&object_env, "d1-put-race", seed).await;
    let store_a = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let store_b = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let hash_bytes = ids.id32();
    let hash = Hash::from(hash_bytes);
    let partition_a = partition_from(ids.id16());
    let partition_b = partition_from(ids.id16());
    let address_a = Address {
        hash,
        context: context_from(ids.id16()),
    };
    let address_b = Address {
        hash,
        context: context_from(ids.id16()),
    };
    let fragment_a = Fragment {
        flags: FragmentFlags::PayloadCompressedZstd.bits(),
        size_payload: 1024,
        size_content: 8192,
    };
    let fragment_b = Fragment {
        flags: FragmentFlags::PayloadCompressedLZ4.bits(),
        size_payload: 1536,
        size_content: 8192,
    };
    let payload_a = Bytes::from(ids.content(fragment_a.size_payload as usize));
    let payload_b = Bytes::from(ids.content(fragment_b.size_payload as usize));
    let payload_a_expected = payload_a.clone();

    // `PostgresImmutableStore::put` opens with
    // `pg_advisory_xact_lock(hash[..8])`, so holding that key stops both puts
    // before either reads lifecycle state or writes an object. If this gate
    // computed the wrong key the case would fail rather than pass quietly: with
    // the gate missing, one put takes the real advisory lock and the other
    // blocks on *it*, so only one backend is ever blocked and the attestation
    // below — which demands two — panics.
    let gate = AdvisoryGate::take(&mut gate_client, &hash_bytes).await;
    let race = async {
        tokio::join!(
            store_a
                .clone()
                .put(partition_a, address_a, fragment_a, Some(payload_a), false),
            store_b.clone().put(
                partition_b,
                address_b,
                fragment_b,
                Some(payload_b.clone()),
                false
            ),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the same-hash put race").await;
        gate.release().await;
    };
    let ((put_a, put_b), ()) = tokio::join!(race, opening);
    put_a.expect("set A's put must succeed");
    put_b.expect("set B's put must succeed");

    // One object, not two. This is the object-store half of the proof and it
    // reads the bucket directly rather than trusting either store's report.
    let keys = bucket.keys().await;
    assert_eq!(
        keys,
        vec![hex_key(&hash_bytes)],
        "two sets putting one hash must converge on exactly one object"
    );

    // Each set reads the other set's association, and the bytes it gets back
    // must be the ones actually stored — not the ones it submitted.
    let read_by_b = store_b
        .clone()
        .get(partition_a, address_a)
        .await
        .expect("set B serves set A's association")
        .into_payload()
        .expect("a readable association must carry bytes");
    let read_by_a = store_a
        .clone()
        .get(partition_b, address_b)
        .await
        .expect("set A serves set B's association")
        .into_payload()
        .expect("a readable association must carry bytes");
    assert_eq!(
        read_by_a.1, read_by_b.1,
        "both associations must resolve to the one stored payload"
    );
    // `size_content` is 8192 in both submissions, so it cannot tell the winner
    // from the loser or from a merge. `size_payload` can: 1024 for the Zstd
    // representation, 1536 for the LZ4 one. Both sets must read the same one,
    // and it must be a whole submitted representation rather than a mixture of
    // the two.
    assert_eq!(
        read_by_a.0, read_by_b.0,
        "both sets must read the same stored representation"
    );
    assert!(
        read_by_a.0.size_payload == fragment_a.size_payload
            || read_by_a.0.size_payload == fragment_b.size_payload,
        "the stored representation must be exactly one of the two submitted, got {:?}",
        read_by_a.0
    );
    assert_eq!(
        read_by_a.1.len(),
        read_by_a.0.size_payload as usize,
        "the served bytes must match the representation the store advertises"
    );
    assert_eq!(
        read_by_a.1,
        if read_by_a.0.size_payload == fragment_a.size_payload {
            payload_a_expected
        } else {
            payload_b
        },
        "the surviving object must be one contender's bytes, not a splice"
    );

    let match_a = query_one(store_b.clone(), partition_a, address_a).await;
    let match_b = query_one(store_a.clone(), partition_b, address_b).await;
    assert_eq!(match_a.match_made, StoreMatch::MatchFull);
    assert_eq!(match_b.match_made, StoreMatch::MatchFull);

    bucket.release().await;
    backend.release().await;
}

/// The other set's read, taken in the window where the object bytes are
/// already in the bucket and the rows that make them readable are not yet
/// committed. It must report no match and refuse to serve, and must then serve
/// the exact bytes once the put commits.
///
/// # The window this case holds, and why it is not the obvious one
///
/// `PostgresImmutableStore::put` opens with `pg_advisory_xact_lock`, so gating
/// on the hash would stop it before it read anything or wrote anything — and
/// then "no match, no bytes, empty bucket" is true because nothing has
/// happened, which is not a claim about concurrency at all. A first draft of
/// this case did exactly that and could not have failed.
///
/// The window that can actually go wrong is the one between the S3 `put_object`
/// and the transaction's commit: the payload is durable in the shared bucket
/// while `lore_fragment_state` and the association row are still invisible to
/// everyone else. A gate on `lore_fragment_state` lands the put precisely
/// there, because `EXCLUSIVE` admits the plain `SELECT`s of the earlier state
/// and association reads and blocks the `INSERT` that follows the upload. The
/// case asserts the object IS in the bucket while the reader still sees
/// nothing.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn d2_a_read_during_a_concurrent_put_never_advertises_bytes_it_cannot_serve() {
    let base_url = env::pg_url();
    let object_env = env::object_store();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "d2-read-put").await;
    backend.assert_namespaced().await;
    let bucket = CaseBucket::create(&object_env, "d2-read-put", seed).await;
    let store_a = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let store_b = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let hash_bytes = ids.id32();
    let hash = Hash::from(hash_bytes);
    let partition = partition_from(ids.id16());
    let address = Address {
        hash,
        context: context_from(ids.id16()),
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: 2048,
        size_content: 2048,
    };
    let payload = Bytes::from(ids.content(2048));

    let gate = TableGate::take(&mut gate_client, "lore_fragment_state").await;
    let writer = store_a
        .clone()
        .put(partition, address, fragment, Some(payload.clone()), false);
    let reader = async {
        barrier::wait_for_lock_waiters(&observer, 1, "the read-during-put case").await;
        // Set A is provably stopped at the lifecycle-state INSERT, which comes
        // after its upload. The assertion below is what makes that placement
        // load-bearing: the bytes exist and are still not readable.
        assert_eq!(
            bucket.keys().await,
            vec![hex_key(&hash_bytes)],
            "the gate must hold the put AFTER its upload; an empty bucket here means the case \
             is asserting invisibility of a write that had not started"
        );
        let during = query_one(store_b.clone(), partition, address).await;
        assert_eq!(
            during.match_made,
            StoreMatch::MatchNone,
            "an uncommitted put must not be advertised to the other set even though its bytes \
             are already durable in the shared bucket"
        );
        let served = store_b.clone().get(partition, address).await;
        assert!(
            served.is_err(),
            "the other set must not serve bytes whose association has not committed, got \
             {served:?}"
        );
        gate.release().await;
    };
    let (put, ()) = tokio::join!(writer, reader);
    put.expect("set A's put must succeed once released");

    // After the commit, the other set must serve the exact bytes.
    let after = query_one(store_b.clone(), partition, address).await;
    assert_eq!(
        after.match_made,
        StoreMatch::MatchFull,
        "a committed put must be a full match for the other set"
    );
    let (stored, bytes) = store_b
        .clone()
        .get(partition, address)
        .await
        .expect("the other set must serve the committed fragment")
        .into_payload()
        .expect("a full match must carry bytes");
    assert_eq!(bytes, payload, "the served bytes must be byte-identical");
    assert_eq!(stored.size_content, fragment.size_content);
    assert_eq!(bucket.keys().await, vec![hex_key(&hash_bytes)]);

    bucket.release().await;
    backend.release().await;
}

/// One set copies a fragment's last association while the other obliterates
/// it. Whichever wins, the destination association must never point at deleted
/// bytes: a successful copy keeps a readable payload, a failed one leaves no
/// association at all.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn d3_a_copy_racing_the_last_association_obliterate_never_dangles_across_two_sets() {
    let base_url = env::pg_url();
    let object_env = env::object_store();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "d3-copy-oblit").await;
    backend.assert_namespaced().await;
    let bucket = CaseBucket::create(&object_env, "d3-copy-oblit", seed).await;
    let store_a = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let store_b = object_store(
        &backend.url,
        bucket.name(),
        &object_env.endpoint,
        &object_env.region,
    )
    .await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;

    let hash_bytes = ids.id32();
    let hash = Hash::from(hash_bytes);
    let source_partition = partition_from(ids.id16());
    let destination_partition = partition_from(ids.id16());
    let source_address = Address {
        hash,
        context: context_from(ids.id16()),
    };
    let destination_context = context_from(ids.id16());
    let destination_address = Address {
        hash,
        context: destination_context,
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: 1024,
        size_content: 1024,
    };
    let seeded_payload = Bytes::from(ids.content(1024));
    store_a
        .clone()
        .put(
            source_partition,
            source_address,
            fragment,
            Some(seeded_payload.clone()),
            false,
        )
        .await
        .expect("seed the only association");

    let gate = AdvisoryGate::take(&mut gate_client, &hash_bytes).await;
    let race = async {
        tokio::join!(
            store_a.clone().copy(
                source_partition,
                source_address,
                destination_partition,
                destination_context,
                false,
            ),
            store_b.clone().obliterate(
                source_partition,
                source_address,
                Arc::new(StoreObliterateStats::default()),
            ),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the copy/obliterate race").await;
        gate.release().await;
    };
    let ((copied, obliterated), ()) = tokio::join!(race, opening);
    obliterated.expect("the source obliteration must succeed");

    let destination_match =
        query_one(store_b.clone(), destination_partition, destination_address).await;
    if copied.is_ok() {
        assert_eq!(
            destination_match.match_made,
            StoreMatch::MatchFull,
            "a successful copy must leave a readable destination association"
        );
        let (_, bytes) = store_b
            .clone()
            .get(destination_partition, destination_address)
            .await
            .expect("a successful copy must keep its bytes readable from the other set")
            .into_payload()
            .expect("a full match must carry bytes");
        // Byte-exact, not merely the right length: a copy that survived an
        // obliteration must hold the original payload, and a length check would
        // pass on any 1024 bytes the obliteration left behind.
        assert_eq!(
            bytes, seeded_payload,
            "a surviving copy must serve the original bytes"
        );
        assert_eq!(
            bucket.keys().await,
            vec![hex_key(&hash_bytes)],
            "the surviving association must keep exactly its own object"
        );
    } else {
        assert_eq!(
            destination_match.match_made,
            StoreMatch::MatchNone,
            "a copy that lost must leave no destination association: {copied:?}"
        );
        assert!(
            bucket.keys().await.is_empty(),
            "an obliteration that won must leave no object behind"
        );
    }

    bucket.release().await;
    backend.release().await;
}

// ===========================================================================
// (e) CR-032 transactional outbox and relay
// ===========================================================================

/// A committed mutation leaves exactly the rows CR-032 classifies for it; a
/// decisively rejected one carrying the same events leaves none. Both are read
/// back through the set that did not write them.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn e1_a_committed_mutation_leaves_its_classified_rows_and_a_rejected_one_leaves_none() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "e1-append").await;
    backend.assert_namespaced().await;
    let readback_b = backend.b.raw().await;
    let readback_a = backend.a.raw().await;
    let cell_id = ids.cell_id();

    // The two events CR-032 says a repository create owes, built by the
    // production builders rather than by hand: a hand-written event would prove
    // the coordinator appends what it is given, which is `domain_outbox_producers`'s
    // job, not that two sets agree on what a create commits.
    let name = ids.name("append");
    let committed_id = ids.id16();
    let committed_branch = ids.id16();
    let mut committed_input =
        fixture::create_input(committed_id, committed_branch, name.clone(), &mut ids);
    committed_input.events = vec![
        builders::repository_published(
            &cell_id,
            &committed_id,
            &name,
            &committed_branch,
            &committed_input.default_branch_name.clone(),
        )
        .expect("build the repository.published event"),
        builders::branch_created(
            &cell_id,
            &committed_id,
            &committed_branch,
            &committed_input.default_branch_name.clone(),
            &committed_input.default_branch_latest_hash.clone(),
        )
        .expect("build the branch.created event"),
    ];
    let committed_op = fixture::admitted(&backend.a.domain, "repository_create", &mut ids).await;
    assert_eq!(
        backend
            .a
            .domain
            .repository_create(&committed_op, &committed_input)
            .await
            .expect("the committed create must not error")
            .outcome,
        DomainOutcome::Applied
    );

    let rows: i64 = readback_b
        .query_one(
            "SELECT count(*)::bigint FROM lore_outbox_events WHERE repository_id = $1",
            &[&committed_id.as_slice()],
        )
        .await
        .expect("count the committed mutation's outbox rows")
        .get(0);
    assert_eq!(
        rows, 2,
        "a committed create must leave exactly the two rows it owes, visible to the other set"
    );
    let committed_rows = readback_b
        .query(
            "SELECT event_kind, aggregate_kind, repository_generation \
             FROM lore_outbox_events WHERE repository_id = $1 ORDER BY event_kind",
            &[&committed_id.as_slice()],
        )
        .await
        .expect("read the committed rows");
    let kinds: Vec<String> = committed_rows
        .iter()
        .map(|row| row.get::<_, String>("event_kind"))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "branch.created".to_owned(),
            "repository.published".to_owned()
        ],
        "both classified rows must be present, not one standing in for the other"
    );
    for row in &committed_rows {
        assert_eq!(
            row.get::<_, i64>("repository_generation"),
            1,
            "both rows carry the generation the transaction committed"
        );
    }

    // Set B now loses the same name, with both events supplied. The coordinator
    // rolls its repository insert back and must append neither.
    let rejected_id = ids.id16();
    let rejected_branch = ids.id16();
    let mut rejected_input =
        fixture::create_input(rejected_id, rejected_branch, name.clone(), &mut ids);
    rejected_input.events = vec![
        builders::repository_published(
            &cell_id,
            &rejected_id,
            &name,
            &rejected_branch,
            &rejected_input.default_branch_name.clone(),
        )
        .expect("build the losing repository.published event"),
        builders::branch_created(
            &cell_id,
            &rejected_id,
            &rejected_branch,
            &rejected_input.default_branch_name.clone(),
            &rejected_input.default_branch_latest_hash.clone(),
        )
        .expect("build the losing branch.created event"),
    ];
    let rejected_op = fixture::admitted(&backend.b.domain, "repository_create", &mut ids).await;
    assert_eq!(
        backend
            .b
            .domain
            .repository_create(&rejected_op, &rejected_input)
            .await
            .expect("the rejected create must not error")
            .outcome,
        not_applied(NAME_TAKEN_V1)
    );
    let rejected_rows: i64 = readback_a
        .query_one(
            "SELECT count(*)::bigint FROM lore_outbox_events WHERE repository_id = $1",
            &[&rejected_id.as_slice()],
        )
        .await
        .expect("count the rejected mutation's outbox rows")
        .get(0);
    assert_eq!(
        rejected_rows, 0,
        "a rolled-back mutation must leave no outbox row even with events supplied"
    );
    backend.release().await;
}

/// Two relay workers, one from each set, claim over one backlog. Their batches
/// must be disjoint and must together cover the backlog: `SKIP LOCKED` is what
/// lets two replicas relay without an elected leader, and a shared row would be
/// a double publication.
///
/// **What the gate here buys, stated narrowly.** It does line both claimers up
/// at the table — `EXCLUSIVE` conflicts with the `ROW SHARE` a
/// `SELECT ... FOR UPDATE` needs, and both are granted together on release — so
/// the overlap is real. But disjointness and full coverage follow from the
/// eligibility predicate whether or not the claimers overlapped, so this case
/// is *not* the proof that a claimer skips another's **uncommitted** rows.
/// `f2` is that proof, because only a failpoint can hold one claimer inside its
/// transaction while the other selects.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn e2_two_relay_claimers_over_one_backlog_never_claim_the_same_row() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "e2-claim").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut gate_client = backend.a.raw().await;
    let mut appender = backend.a.raw().await;
    let cell_id = ids.cell_id();
    let repository_id = ids.id16();

    let mut appended = Vec::new();
    for ordinal in 1..=6u64 {
        appended.push(
            outbox::append_pending(
                &mut appender,
                &cell_id,
                &repository_id,
                &ids.id16(),
                ordinal,
            )
            .await,
        );
    }

    let mut claim_client_a = backend.a.checkout().await;
    let mut claim_client_b = backend.b.checkout().await;
    let gate = TableGate::take(&mut gate_client, "lore_outbox_events").await;
    let race = async {
        tokio::join!(
            relay::claim_batch(
                &mut claim_client_a,
                "wp109-relay-a",
                3,
                Duration::from_secs(30)
            ),
            relay::claim_batch(
                &mut claim_client_b,
                "wp109-relay-b",
                3,
                Duration::from_secs(30)
            ),
        )
    };
    let opening = async {
        barrier::wait_for_lock_waiters(&observer, 2, "the two-claimer race").await;
        gate.release().await;
    };
    let ((claimed_a, claimed_b), ()) = tokio::join!(race, opening);
    let claimed_a = claimed_a.expect("set A's claim must not error");
    let claimed_b = claimed_b.expect("set B's claim must not error");

    let ids_a: std::collections::BTreeSet<_> =
        claimed_a.iter().map(|event| event.event.event_id).collect();
    let ids_b: std::collections::BTreeSet<_> =
        claimed_b.iter().map(|event| event.event.event_id).collect();
    assert!(
        ids_a.is_disjoint(&ids_b),
        "two claimers must never hold the same row: A={ids_a:?} B={ids_b:?}"
    );
    let union: std::collections::BTreeSet<_> = ids_a.union(&ids_b).copied().collect();
    assert_eq!(
        union.len(),
        6,
        "two claimers limited to three rows each must cover the six-row backlog"
    );
    assert_eq!(
        union,
        appended
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        "the claimed set must be exactly the appended set"
    );

    // Authoritative SQL: every row carries one owner and one generation.
    let readback = backend.b.raw().await;
    let rows = readback
        .query(
            "SELECT event_id, claim_owner, claim_generation FROM lore_outbox_events \
             WHERE cell_id = $1 ORDER BY event_id",
            &[&cell_id],
        )
        .await
        .expect("read the claimed rows");
    assert_eq!(rows.len(), 6);
    for row in &rows {
        let owner: Option<String> = row.get("claim_owner");
        let generation: i64 = row.get("claim_generation");
        let owner = owner.expect("every claimed row carries an owner");
        assert!(
            owner == "wp109-relay-a" || owner == "wp109-relay-b",
            "a row's owner must be one of the two claimers, got {owner}"
        );
        assert_eq!(generation, 1, "a first claim stamps generation 1");
    }
    backend.release().await;
}

/// One set's broker acknowledgement lands; the other set's stale claim on the
/// same row must be fenced out, and its retry must read as an already-accepted
/// duplicate rather than a second acceptance.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn e3_broker_acceptance_from_one_set_fences_a_stale_claim_from_the_other() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "e3-fence").await;
    backend.assert_namespaced().await;
    let mut appender = backend.a.raw().await;
    let raw_a = backend.a.raw().await;
    let raw_b = backend.b.raw().await;
    let cell_id = ids.cell_id();
    let repository_id = ids.id16();
    let mut tally = RaceTally::new("broker acceptance versus a stale claim", seed);

    let event_id =
        outbox::append_pending(&mut appender, &cell_id, &repository_id, &ids.id16(), 1).await;

    let mut client_a = backend.a.checkout().await;
    let claim_a = relay::claim_batch(&mut client_a, "wp109-relay-a", 1, Duration::from_secs(300))
        .await
        .expect("set A claims")
        .pop()
        .expect("one claimable row");
    assert_eq!(claim_a.claim_generation, 1);

    // Expire set A's lease on the authoritative row rather than waiting for it.
    let expired = raw_a
        .execute(
            "UPDATE lore_outbox_events SET claim_expires_at = clock_timestamp() \
             - interval '1 second' WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("expire set A's lease");
    assert_eq!(expired, 1);

    let mut client_b = backend.b.checkout().await;
    let claim_b = relay::claim_batch(&mut client_b, "wp109-relay-b", 1, Duration::from_secs(300))
        .await
        .expect("set B reclaims")
        .pop()
        .expect("an expired claim must be reclaimable");
    assert_eq!(
        claim_b.claim_generation, 2,
        "a reclaim must increment the generation and fence the dead worker"
    );

    let acceptance = BrokerAcceptanceRecord {
        stream_identity: "DURABLE-wp109-cell".to_owned(),
        stream_epoch: 1,
        broker_sequence: 41,
        gateway_response_id: "gw-wp109-41".to_owned(),
        publisher_contract_version: 1,
    };
    // Set A still believes it holds the row.
    let stale =
        relay::record_broker_accepted(&raw_a, event_id, claim_a.claim_generation, &acceptance)
            .await
            .expect("the stale acknowledgement must not error");
    assert_eq!(
        stale,
        relay::CasOutcome::StaleClaim {
            current_claim_generation: 2
        },
        "a fenced worker must be told which generation owns the row"
    );

    let accepted =
        relay::record_broker_accepted(&raw_b, event_id, claim_b.claim_generation, &acceptance)
            .await
            .expect("the current acknowledgement must not error");
    assert_eq!(accepted, relay::CasOutcome::Applied);
    tally.round(RaceOutcome::Won, RaceOutcome::Lost);

    // A second delivery of the same acknowledgement is a duplicate, not a
    // second acceptance.
    let duplicate =
        relay::record_broker_accepted(&raw_b, event_id, claim_b.claim_generation, &acceptance)
            .await
            .expect("the duplicate acknowledgement must not error");
    assert_eq!(duplicate, relay::CasOutcome::AlreadyAccepted);
    tally.round(RaceOutcome::Won, RaceOutcome::Duplicate);

    assert_eq!(
        outbox::event_state(&raw_a, event_id).await,
        "broker_accepted"
    );
    let owner: Option<String> = raw_a
        .query_one(
            "SELECT claim_owner FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("read the accepted row")
        .get(0);
    assert!(
        owner.is_none(),
        "a published row must not look claimed to a backlog probe"
    );
    tally.report();
    backend.release().await;
}

/// A broker epoch reset accepted by one set requeues the other set's accepted
/// rows, and every requeued row keeps the exact keys it was written with.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn e4_a_broker_epoch_reset_requeues_accepted_rows_with_their_original_keys() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "e4-reset").await;
    backend.assert_namespaced().await;
    let mut appender = backend.a.raw().await;
    let raw_a = backend.a.raw().await;
    let cell_id = ids.cell_id();
    let repository_id = ids.id16();
    let stream_identity = "DURABLE-wp109-reset";
    let old_epoch = 7;
    let new_epoch = 8;

    outbox::place_cell(&raw_a, &cell_id, stream_identity, old_epoch).await;

    let mut client_a = backend.a.checkout().await;
    let mut accepted = Vec::new();
    for sequence in 1..=2i64 {
        let event_id = outbox::append_pending(
            &mut appender,
            &cell_id,
            &repository_id,
            &ids.id16(),
            sequence as u64,
        )
        .await;
        let claim = relay::claim_batch(&mut client_a, "wp109-relay-a", 1, Duration::from_secs(300))
            .await
            .expect("set A claims")
            .pop()
            .expect("one claimable row");
        let outcome = relay::record_broker_accepted(
            &raw_a,
            claim.event.event_id,
            claim.claim_generation,
            &BrokerAcceptanceRecord {
                stream_identity: stream_identity.to_owned(),
                stream_epoch: old_epoch,
                broker_sequence: sequence,
                gateway_response_id: format!("gw-wp109-{sequence}"),
                publisher_contract_version: 1,
            },
        )
        .await
        .expect("record the acknowledgement");
        assert_eq!(outcome, relay::CasOutcome::Applied);
        accepted.push(outbox::stable_keys(&raw_a, event_id).await);
    }

    // Set B accepts the reset and drives the requeue.
    let mut client_b = backend.b.checkout().await;
    let report =
        outbox::epoch_advance_report(&cell_id, stream_identity, old_epoch, new_epoch, ids.id32());
    let acceptance = accept_reset(
        &mut client_b,
        &report,
        "spiffe://commit0/ns/notification/sa/wp109",
        |inputs: &AckInputs| format!("wp109-ack-{}", inputs.reset_generation).into_bytes(),
    )
    .await
    .expect("accept_reset must not error");
    let ResetAcceptance::Accepted {
        old_stream_identity,
        old_stream_epoch,
        ..
    } = acceptance
    else {
        panic!("a first, well-formed reset must be accepted, got {acceptance:?}");
    };
    assert_eq!(old_stream_identity, stream_identity);
    assert_eq!(old_stream_epoch, old_epoch);

    let requeued = relay::requeue_unsafe_for_epoch_reset(
        &mut client_b,
        &old_stream_identity,
        old_stream_epoch,
    )
    .await
    .expect("requeue must not error");
    assert_eq!(
        requeued, 2,
        "every accepted-but-unsafe row for the void epoch must be requeued"
    );

    for before in &accepted {
        let after = outbox::stable_keys(&raw_a, before.event_id).await;
        assert_eq!(
            after, *before,
            "a requeued row must keep its original event id, idempotency key, aggregate \
             version, and cell"
        );
        assert_eq!(
            outbox::event_state(&raw_a, before.event_id).await,
            "pending",
            "a requeued row must be publishable again"
        );
        let lookup = relay::lookup_by_idempotency_key(
            &raw_a,
            &before.cell_id,
            &before
                .idempotency_key
                .clone()
                .try_into()
                .expect("a 32-byte idempotency key"),
        )
        .await
        .expect("look the row up by its stable key")
        .expect("the row must still be findable by the key a producer would rebuild");
        assert_eq!(lookup.event.event_id, before.event_id);
        assert!(
            lookup.acceptance.is_none(),
            "a requeued row must carry no acceptance from the void epoch"
        );
    }
    backend.release().await;
}

/// `consumer_safe` advances only as far as the minimum contiguous frontier of
/// the required receiver set, and a lagging member added by the other set stops
/// it from going further.
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn e5_consumer_safe_advances_only_under_the_required_checkpoint_vector() {
    let base_url = env::pg_url();
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "e5-safe").await;
    backend.assert_namespaced().await;
    let mut appender = backend.a.raw().await;
    let raw_a = backend.a.raw().await;
    let raw_b = backend.b.raw().await;
    let cell_id = ids.cell_id();
    let repository_id = ids.id16();
    let stream_identity = "DURABLE-wp109-safe";
    let stream_epoch = 8;

    outbox::place_cell(&raw_a, &cell_id, stream_identity, stream_epoch).await;

    // Each receiver is joined through a different set, so the membership
    // vector is genuinely written by two independently constructed writers.
    let mut client_a = backend.a.checkout().await;
    let mut client_b = backend.b.checkout().await;
    outbox::join_ready_receiver(
        &raw_a,
        &mut client_a,
        &cell_id,
        "loreserver-wp109-a",
        stream_identity,
        stream_epoch,
        930,
    )
    .await;
    outbox::join_ready_receiver(
        &raw_b,
        &mut client_b,
        &cell_id,
        "loreserver-wp109-b",
        stream_identity,
        stream_epoch,
        925,
    )
    .await;

    let mut accepted_at = Vec::new();
    for sequence in [918i64, 930i64] {
        let event_id = outbox::append_pending(
            &mut appender,
            &cell_id,
            &repository_id,
            &ids.id16(),
            sequence as u64,
        )
        .await;
        let claim = relay::claim_batch(&mut client_a, "wp109-relay-a", 1, Duration::from_secs(300))
            .await
            .expect("claim the appended row")
            .pop()
            .expect("one claimable row");
        assert_eq!(claim.event.event_id, event_id);
        assert_eq!(
            relay::record_broker_accepted(
                &raw_a,
                event_id,
                claim.claim_generation,
                &BrokerAcceptanceRecord {
                    stream_identity: stream_identity.to_owned(),
                    stream_epoch,
                    broker_sequence: sequence,
                    gateway_response_id: format!("gw-wp109-{sequence}"),
                    publisher_contract_version: 1,
                },
            )
            .await
            .expect("record the acknowledgement"),
            relay::CasOutcome::Applied
        );
        accepted_at.push((sequence, event_id));
    }

    // The evaluator runs on the set that joined neither the appender nor the
    // first receiver's raw writes.
    let outcome = evaluate_consumer_safe(&mut client_b, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("evaluate consumer safety");
    assert_eq!(outcome.block, None, "unexpected block: {:?}", outcome.block);
    let proven = outcome.proven.expect("a proven safe vector");
    assert_eq!(
        proven.safe_sequence, 925,
        "the safe sequence is the minimum of the required frontiers"
    );
    assert_eq!(proven.required_members, 2);
    assert_eq!(
        outcome.advanced, 1,
        "only the row at or below 925 may advance"
    );
    assert_eq!(
        outbox::event_state(&raw_a, accepted_at[0].1).await,
        "consumer_safe"
    );
    assert_eq!(
        outbox::event_state(&raw_a, accepted_at[1].1).await,
        "broker_accepted"
    );

    // A third, lagging receiver joined by the other set must hold the vector
    // back rather than being ignored.
    outbox::join_ready_receiver(
        &raw_b,
        &mut client_b,
        &cell_id,
        "loreserver-wp109-c",
        stream_identity,
        stream_epoch,
        900,
    )
    .await;
    let after = evaluate_consumer_safe(&mut client_a, &cell_id, MAX_EVALUATION_BATCH)
        .await
        .expect("re-evaluate consumer safety");
    assert_eq!(after.block, None, "unexpected block: {:?}", after.block);
    let proven_after = after.proven.expect("a proven safe vector");
    assert_eq!(
        proven_after.safe_sequence, 900,
        "a lagging required member must lower the proven safe sequence"
    );
    assert_eq!(proven_after.required_members, 3);
    assert_eq!(
        after.advanced, 0,
        "no further row may advance under a lower frontier"
    );
    assert_eq!(
        outbox::event_state(&raw_a, accepted_at[1].1).await,
        "broker_accepted",
        "the row above the frontier must stay accepted"
    );

    // Membership is one shared fact, whichever set reads it.
    let snapshot_a = membership::read_membership_snapshot(&raw_a, &cell_id)
        .await
        .expect("set A reads the snapshot");
    let snapshot_b = membership::read_membership_snapshot(&raw_b, &cell_id)
        .await
        .expect("set B reads the snapshot");
    assert_eq!(
        snapshot_a, snapshot_b,
        "two independently constructed sets must read one membership snapshot identically"
    );
    backend.release().await;
}

// ===========================================================================
// Failpoint tier. These cases need `--features failure_generator` and a
// per-case `LORE_FRAGMENT_FAILPOINTS` the runner sets before the process
// starts, because `domain/fragments/failpoints.rs` reads it once per process.
// ===========================================================================

/// A publication whose commit acknowledgement is lost. The commit really
/// happened; the caller is told `OutcomeUnknown` and must not retry. A freshly
/// constructed set — standing in for the restarted process — reconciles by
/// reading authoritative state, and the other set's later write is fenced
/// rather than publishing a second epoch.
///
/// **This case is deliberately a sequence, not a race**, and the distinction
/// matters because every other case here is the opposite. What it proves is
/// that a commit whose acknowledgement never reached its caller is nonetheless
/// durable and authoritative for *every* later reader: the second set's write,
/// issued after the loss, must see a published head rather than an admission,
/// and a set constructed after the loss must resolve the committed
/// representation. Racing the two would test the publication race that `d1`
/// already covers, and would say nothing extra about the lost acknowledgement.
///
/// The process-global failpoint is safe here for a reason worth checking rather
/// than assuming: `publication.commit.settled` has one call site, after
/// `classify_commit`, on the `Ok(CommitVerdict::Published)` path only
/// (`domain/fragments/coordinator.rs`), so the fenced participant never reaches
/// it even though both sets share the configuration.
#[cfg(feature = "failure_generator")]
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn f1_a_lost_publication_commit_acknowledgement_is_reconciled_by_a_restarted_set() {
    let base_url = env::pg_url();
    let _dir = env::failpoints("publication.commit.settled=unknown");
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "f1-lost-ack").await;
    backend.assert_namespaced().await;

    let (repository_id, _, _) =
        fixture::create_repository(&backend.a.domain, &mut ids, "lost-ack").await;
    let context = ids.id16().to_vec();
    let hash = ids.id32().to_vec();
    let key = hex_key(&hash);

    let coordinator_a = backend.a.fragments();
    let coordinator_b = backend.b.fragments();

    let BeginOutcome::Admitted(intent_a) = coordinator_a
        .begin_direct_write(&hash, &key, write_claim(&mut ids))
        .await
        .expect("set A begins its direct write")
    else {
        panic!("a fresh hash must admit set A's direct write");
    };
    let claim_a = intent_a
        .write_claim()
        .expect("a direct write carries a write claim");
    coordinator_a
        .authorize_write_claim(claim_a)
        .await
        .expect("authorize set A's claim");
    let committed = coordinator_a
        .commit_remote(
            &intent_a,
            IoObservation::Valid(manifest(&key, 0xA1)),
            FragmentWriteSettlement::Decisive,
        )
        .await;
    assert!(
        matches!(committed, Err(DomainError::OutcomeUnknown(_))),
        "the armed failpoint must withhold the acknowledgement of a commit that happened, got \
         {committed:?}"
    );

    // Set B's competing write must be fenced, not admitted into a second epoch.
    let second = coordinator_b
        .begin_direct_write(&hash, &key, write_claim(&mut ids))
        .await
        .expect("set B's begin must not error");
    assert!(
        matches!(second, BeginOutcome::AlreadyReadable(_)),
        "the other set must see the committed publication rather than admitting a rival write, \
         got {second:?}"
    );

    // The reconciliation read: a set constructed after the loss, standing in
    // for a restarted process, must find the publication durable.
    let restarted = support::sets::CoordinatorSet::connect(&backend.url, "a", 4).await;
    let restarted_coordinator = restarted.fragments();
    assert_eq!(
        restarted_coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate the reconciled publication"),
        CommitVerdict::Published
    );
    let resolved = restarted_coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve through the restarted set");
    let FragmentVerdict::Readable { manifest, .. } = &resolved[0].verdict else {
        panic!(
            "a lost acknowledgement must not lose the commit; got {:?}",
            resolved[0].verdict
        );
    };
    assert_eq!(
        manifest.object_key, key,
        "the reconciled representation must be the one set A committed"
    );

    // Authoritative SQL: exactly one lifecycle head and one current epoch.
    let direct = backend.b.raw().await;
    let heads: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count lifecycle heads")
        .get(0);
    assert_eq!(heads, 1, "a lost acknowledgement must not fork the head");
    println!(
        "race tally publication with a lost commit acknowledgement: seed={seed} rounds=1 \
         winners=0 losers=1 unknown=1 duplicates=0 (a deliberate sequence, not a race)"
    );
    backend.release().await;
}

/// A relay claim held inside its own transaction, at the window between its
/// `FOR UPDATE SKIP LOCKED` select and its commit, must not block the other
/// set's claim. The second claimer skips the held rows and takes the rest.
///
/// The barrier here is the whole point: `SKIP LOCKED` never blocks, so nothing
/// in a joined pair of claims would prove they overlapped. Holding set A at
/// `outbox.claim.after_select` and refusing to release until PostgreSQL reports
/// both backends holding row locks on `lore_outbox_events` is what makes the
/// overlap a fact rather than a hope.
///
/// **The second claimer pauses too, and the case depends on it.** There is one
/// hold file per anchor and the failpoint configuration is process-global, so
/// set B stops at the same anchor set A is stopped at — *after* its own
/// `FOR UPDATE SKIP LOCKED` select. That is what puts both backends in the
/// attested state at once, and it is why the release happens after the
/// attestation rather than after set A alone arrives. If a future change let
/// set B through without pausing, the attestation would time out and the case
/// would fail; it would not quietly become a sequence.
#[cfg(feature = "failure_generator")]
#[tokio::test]
#[ignore = "run with tests/run-active-active-shared-backend-live.ps1"]
async fn f2_a_claim_held_inside_its_transaction_does_not_block_the_other_sets_claim() {
    let base_url = env::pg_url();
    let dir = env::failpoints("outbox.claim.after_select=pause");
    let seed = env::seed();
    let mut ids = Identities::from_seed(seed);
    let backend = SharedBackend::open(&base_url, "f2-claim-hold").await;
    backend.assert_namespaced().await;
    let observer = barrier::observer(&backend.url).await;
    let mut appender = backend.a.raw().await;
    let cell_id = ids.cell_id();
    let repository_id = ids.id16();

    for ordinal in 1..=4u64 {
        outbox::append_pending(
            &mut appender,
            &cell_id,
            &repository_id,
            &ids.id16(),
            ordinal,
        )
        .await;
    }

    let hold = FailpointHold::arm(&dir, "outbox.claim.after_select");
    let mut client_a = backend.a.checkout().await;
    let mut client_b = backend.b.checkout().await;

    let held_claim =
        relay::claim_batch(&mut client_a, "wp109-relay-a", 2, Duration::from_secs(300));
    let driver = async {
        // Set A is inside its transaction with two rows locked and no lease
        // stamped yet.
        hold.wait_reached().await;
        let second =
            relay::claim_batch(&mut client_b, "wp109-relay-b", 2, Duration::from_secs(300));
        let releaser = async {
            barrier::wait_for_row_share_holders(
                &observer,
                "lore_outbox_events",
                2,
                "both claimers are inside their transactions past their locking select",
            )
            .await;
            hold.release();
        };
        let (second, ()) = tokio::join!(second, releaser);
        second
    };
    let (first, second) = tokio::join!(held_claim, driver);
    let first = first.expect("the held claim must complete once released");
    let second = second.expect("the second claim must not error");

    assert_eq!(first.len(), 2, "the held claimer keeps the rows it locked");
    assert_eq!(second.len(), 2, "the second claimer takes the rest");
    let ids_a: std::collections::BTreeSet<_> =
        first.iter().map(|event| event.event.event_id).collect();
    let ids_b: std::collections::BTreeSet<_> =
        second.iter().map(|event| event.event.event_id).collect();
    assert!(
        ids_a.is_disjoint(&ids_b),
        "a claimer held mid-transaction must not have its rows taken: A={ids_a:?} B={ids_b:?}"
    );

    let readback = backend.b.raw().await;
    let claimed: i64 = readback
        .query_one(
            "SELECT count(*)::bigint FROM lore_outbox_events \
             WHERE cell_id = $1 AND claim_owner IS NOT NULL",
            &[&cell_id],
        )
        .await
        .expect("count claimed rows")
        .get(0);
    assert_eq!(claimed, 4, "all four rows must end up claimed exactly once");
    backend.release().await;
}

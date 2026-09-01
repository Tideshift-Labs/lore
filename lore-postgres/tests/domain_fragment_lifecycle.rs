// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real-Postgres proof for WP-118 Phases 2 and 3's fragment lifecycle
//! coordinator (`lore-postgres/src/domain/fragments/`).
//!
//! Every case is `#[ignore]` and is executed by `run-fragment-lifecycle-live.ps1`,
//! which gives each exact case a fresh PostgreSQL 16 database. The pure-logic
//! parts (witness matching, key distinctness, readiness fail-closed, state and
//! diagnostic round trips, the mask partition) are already pinned offline in
//! `states.rs`, `masks.rs`, and `coordinator.rs`'s own `mod tests` — this file
//! is exclusively the real-database tier: resolver agreement, the no-held-
//! connection proof, cross-instance racing, stale-witness fencing, generation
//! fanout atomicity, and readiness against real schema damage.

use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::EpochWitness;
use lore_postgres::domain::fragments::FragmentLifecycleReadiness;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentResolution;
use lore_postgres::domain::fragments::FragmentVerdict;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::MAX_PUSH_FRAGMENT_REVALIDATIONS;
use lore_postgres::domain::fragments::MissingDiagnostic;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::PushWitnessVerdict;
use lore_postgres::domain::fragments::REQUIRED_FRAGMENT_CHANGED;
use lore_postgres::domain::fragments::REQUIRED_FRAGMENT_REVALIDATION_LIMIT;
use lore_postgres::domain::fragments::RequiredFragment;
use lore_postgres::domain::fragments::STAGED_LEASE_ALREADY_RELEASED;
use lore_postgres::domain::fragments::STAGED_LEASE_MEMBER_NOT_STAGED;
use lore_postgres::domain::fragments::STAGED_LEASE_MEMBER_SET_MISMATCH;
use lore_postgres::domain::fragments::StagedReaderLease;
use lore_postgres::domain::fragments::schema;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::domain::lock_order::LockClass;
use lore_postgres::domain::lock_order::LockSequence;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio::time::timeout;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

/// Connect and install SCHEMA-118 through the isolated component fixture.
/// Production never calls `bootstrap()` (it is migration-owned), so this is a
/// test-only shortcut, exactly like `PostgresLockCoordinator::bootstrap()`.
async fn store(url: &str) -> PostgresDomainStore {
    store_with_pool(url, 8).await
}

async fn store_with_pool(url: &str, pool_max: u32) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, pool_max, &TlsConfig::default())
        .await
        .expect("connect domain store");
    store
        .fragment_coordinator()
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-118 fixture");
    store
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn uuid_v7_at(time: SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
}

/// PostgreSQL `timestamptz` is microsecond-precision; a `SystemTime` with a
/// sub-microsecond remainder (Windows' `SystemTime::now()` is 100 ns
/// resolution) would silently lose precision on a round trip through the
/// database, breaking an exact deadline-equality assertion for a reason that
/// has nothing to do with the coordinator's own logic. Truncate before using
/// a deadline in an assertion that reads it back from a stored row.
fn microsecond_deadline(offset: Duration) -> SystemTime {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("test timestamp follows epoch");
    let micros =
        u64::try_from(since_epoch.as_micros()).expect("test timestamp fits in u64 microseconds");
    SystemTime::UNIX_EPOCH + Duration::from_micros(micros) + offset
}

fn binding(method: &str) -> OperationBinding {
    OperationBinding {
        method: method.to_owned(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

/// Prepare one admissible receipt for a CR-029 domain-level operation (e.g.
/// `PostgresDomainStore::begin_obliterate`, the repository-generation fence).
/// The fragment coordinator's own begin/commit pairs take no `GovernedOperation`
/// at all -- they are not receipted CR-029 mutations -- so this helper exists
/// only for the CR-029 domain-store calls this file makes to move a
/// repository's generation.
async fn prepare_operation(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read receipt database clock");
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp118/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:wp118-fragment-test".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: uuid_v7_at(clock),
    };
    let op_binding = binding(method);
    let prepared = store
        .domain_operation_prepare(&key, &op_binding, None)
        .await
        .expect("prepare domain operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("an admissible domain operation must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding: op_binding,
        prepare_token: token,
    }
}

async fn create_repository(store: &PostgresDomainStore) -> [u8; 16] {
    let repository_id: [u8; 16] = rand::random();
    let branch_id: [u8; 16] = rand::random();
    let operation = prepare_operation(store, "lore.domain.v1.test/FragmentRepositoryCreate").await;
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("wp118-fragment-{:016x}", rand::random::<u64>()),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        event: None,
    };
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("create repository fixture");
    assert_eq!(result.outcome, DomainOutcome::Applied);
    repository_id
}

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn random_context() -> Vec<u8> {
    rand::random::<[u8; 16]>().to_vec()
}

fn manifest(object_key: &str, seed: u8, authority: EpochAuthority) -> FragmentManifest {
    FragmentManifest {
        authority,
        object_key: object_key.to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 128,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 0,
    }
}

fn expect_readable(resolution: &FragmentResolution) -> (&EpochWitness, &FragmentManifest, i64) {
    match &resolution.verdict {
        FragmentVerdict::Readable {
            witness,
            manifest,
            association_epoch,
        } => (witness, manifest, *association_epoch),
        FragmentVerdict::Absent => panic!(
            "expected Readable for hash {:02x?}, got Absent",
            resolution.hash
        ),
    }
}

fn expect_absent(resolution: &FragmentResolution) {
    assert!(
        matches!(resolution.verdict, FragmentVerdict::Absent),
        "expected Absent for hash {:02x?}, got {:?}",
        resolution.hash,
        resolution.verdict
    );
}

/// Item 1: the batched resolver must return the identical verdict for a given
/// (hash, repository, context) whichever caller shape asks. A batched request
/// repeating the same hash mimics two simultaneous callers; a single-hash
/// request mimics `get`/`get_metadata`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn resolver_returns_the_identical_verdict_whether_asked_singly_or_batched() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    let readable_hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&readable_hash, "resolver-agreement/readable")
        .await
        .expect("begin readable")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let published_manifest = manifest("resolver-agreement/readable", 0x60, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Valid(published_manifest.clone()))
            .await
            .expect("commit readable"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&readable_hash, &repository_id, &context)
            .await
            .expect("associate readable"),
        CommitVerdict::Published
    );

    let absent_hash = random_hash(); // never written at all

    let batched = coordinator
        .resolve(
            &repository_id,
            &context,
            &[
                readable_hash.clone(),
                absent_hash.clone(),
                readable_hash.clone(),
            ],
        )
        .await
        .expect("batched resolve");
    let single_readable = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&readable_hash),
        )
        .await
        .expect("single readable resolve");
    let single_absent = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&absent_hash))
        .await
        .expect("single absent resolve");

    assert_eq!(batched.len(), 3);
    assert_eq!(
        batched[0], batched[2],
        "two batched requests for the same hash must agree"
    );
    assert_eq!(
        batched[0], single_readable[0],
        "a batched and a single-hash request for the same hash must agree"
    );
    assert_eq!(
        batched[1], single_absent[0],
        "a batched and a single-hash request for the same absent hash must agree"
    );

    let (witness, resolved_manifest, association_epoch) = expect_readable(&batched[0]);
    assert_eq!(resolved_manifest, &published_manifest);
    assert_eq!(witness.hash, readable_hash);
    assert!(association_epoch >= 1);
    expect_absent(&batched[1]);
}

/// Item 2, corrected against the reviewed contract: `resolve`'s
/// repository-generation clause is `<=`, not `=` (an ordinary metadata CAS
/// bumping `lore_domain_repositories.generation` must not fence an existing
/// association — equality would make every fragment in a repository
/// permanently `Absent` the moment anyone touched its metadata). The real
/// permanent fence is a repository tombstone, checked via `r.state`, and a
/// tombstoned association is the other independent fence.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn stale_association_rejection_comes_from_repository_tombstone_not_generation_drift() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    // An ordinary repository generation bump (CR-029's own
    // repository-obliteration fence is a convenient generation-only bump that
    // leaves the repository live) must NOT fence an existing association.
    let repository_id = create_repository(&store).await;
    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "generation-drift/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let published = manifest("generation-drift/key", 0x70, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Valid(published.clone()))
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let bump_op = prepare_operation(&store, "lore.domain.v1.test/FragmentGenerationDrift").await;
    let bumped = store
        .begin_obliterate(&bump_op, &repository_id)
        .await
        .expect("begin_obliterate must not error");
    assert_eq!(bumped.outcome, DomainOutcome::Applied);

    let after_bump = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after generation drift");
    let (_, resolved_manifest, _) = expect_readable(&after_bump[0]);
    assert_eq!(
        resolved_manifest, &published,
        "an ordinary repository generation bump must not fence an existing association"
    );

    // The real permanent fence is a repository tombstone.
    let delete_op =
        prepare_operation(&store, "lore.domain.v1.test/FragmentRepositoryTombstone").await;
    let deleted = store
        .repository_delete(
            &delete_op,
            &RepositoryDeleteInput {
                repository_id: repository_id.to_vec(),
                expected_generation: None,
                delete_proof: rand::random::<[u8; 32]>().to_vec(),
                projection: Vec::new(),
                event: None,
            },
        )
        .await
        .expect("repository_delete must not error");
    assert_eq!(deleted.outcome, DomainOutcome::Applied);

    let after_tombstone = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after repository tombstone");
    expect_absent(&after_tombstone[0]);

    // Half 2: a tombstoned association, independent of repository state.
    let repository_id_2 = create_repository(&store).await;
    let hash_2 = random_hash();
    let BeginOutcome::Admitted(intent_2) = coordinator
        .begin_direct_write(&hash_2, "tombstoned-association/key")
        .await
        .expect("begin 2")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_2,
                IoObservation::Valid(manifest(
                    "tombstoned-association/key",
                    0x71,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit 2"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash_2, &repository_id_2, &context)
            .await
            .expect("associate 2"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .tombstone_association(&hash_2, &repository_id_2, &context)
            .await
            .expect("tombstone"),
        CommitVerdict::Published
    );

    let after_tombstone = coordinator
        .resolve(&repository_id_2, &context, std::slice::from_ref(&hash_2))
        .await
        .expect("resolve after tombstone");
    expect_absent(&after_tombstone[0]);
}

/// Item 3: a positive read needs a live association AND a readable current
/// epoch/manifest. Each missing half independently yields absent; both
/// present yields readable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_positive_read_requires_both_a_live_association_and_a_readable_current_epoch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // Case A: a live association, but the head is not readable (Missing).
    let missing_hash = random_hash();
    let BeginOutcome::Admitted(intent_a) = coordinator
        .begin_direct_write(&missing_hash, "half-missing/key")
        .await
        .expect("begin missing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_a,
                IoObservation::Unusable(MissingDiagnostic::Truncated)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&missing_hash, &repository_id, &context)
            .await
            .expect("associate missing"),
        CommitVerdict::Published
    );

    // Case B: a readable head, but no association at all.
    let unassociated_hash = random_hash();
    let BeginOutcome::Admitted(intent_b) = coordinator
        .begin_direct_write(&unassociated_hash, "half-unassociated/key")
        .await
        .expect("begin unassociated")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_b,
                IoObservation::Valid(manifest(
                    "half-unassociated/key",
                    0x80,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit unassociated"),
        CommitVerdict::Published
    );

    // Positive control: both halves present.
    let positive_hash = random_hash();
    let BeginOutcome::Admitted(intent_c) = coordinator
        .begin_direct_write(&positive_hash, "half-both/key")
        .await
        .expect("begin positive")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent_c,
                IoObservation::Valid(manifest("half-both/key", 0x81, EpochAuthority::Remote))
            )
            .await
            .expect("commit positive"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&positive_hash, &repository_id, &context)
            .await
            .expect("associate positive"),
        CommitVerdict::Published
    );

    let resolved = coordinator
        .resolve(
            &repository_id,
            &context,
            &[
                missing_hash.clone(),
                unassociated_hash.clone(),
                positive_hash.clone(),
            ],
        )
        .await
        .expect("batch resolve");
    expect_absent(&resolved[0]);
    expect_absent(&resolved[1]);
    expect_readable(&resolved[2]);
}

/// Item 4, the discriminating case: a coordinator built on a **one-connection
/// pool** must not hold that connection across its caller's I/O phase.
/// `begin_direct_write` returns an owned [`FragmentIntent`] that borrows no
/// transaction, connection, or lock; this proves that structurally rather than
/// by source reading, by racing a second real pool operation during a real
/// await that stands in for blocked provider I/O, bounded by a timeout so a
/// held connection fails the test instead of hanging it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_blocked_io_phase_does_not_hold_the_one_connection_pool() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store_with_pool(&url, 1).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "one-connection/direct")
        .await
        .expect("begin on a one-connection pool")
    else {
        panic!("a fresh hash must admit a direct write");
    };

    // The "I/O phase": sleep while holding the returned intent, standing in
    // for a blocked provider PUT. Concurrently, a second real coordinator
    // operation on the SAME one-connection pool must still complete: if
    // `begin_direct_write` had left a transaction or checked-out connection
    // open, the pool would have zero connections free and this would hang
    // until the bounded timeout below fires.
    let io_phase = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "one-connection/direct",
                    0x01,
                    EpochAuthority::Remote,
                )),
            )
            .await
    };
    let second_operation = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        timeout(
            Duration::from_secs(5),
            coordinator.resolve(&repository_id, &context, std::slice::from_ref(&hash)),
        )
        .await
    };

    let (commit_result, second_result) = tokio::join!(io_phase, second_operation);
    assert_eq!(
        commit_result.expect("commit must not error"),
        CommitVerdict::Published
    );
    let second_result = second_result.expect(
        "a second coordinator operation must complete within 5s on a one-connection pool; \
         a timeout means begin_direct_write's caller is still holding the sole connection \
         during its I/O phase",
    );
    second_result.expect("resolve must not error");
}

/// Item 5: two independently constructed coordinators (separate pools, same
/// database) racing the same fresh head. Exactly one must publish; the loser
/// is fenced.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn two_independently_constructed_coordinators_race_one_fresh_head_and_exactly_one_wins() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store_a = store(&url).await;
    let store_b = store_with_pool(&url, 8).await; // separate connect/pool; bootstrap is idempotent
    let coordinator_a = store_a.fragment_coordinator();
    let coordinator_b = store_b.fragment_coordinator();
    let repository_id = create_repository(&store_a).await;
    let context = random_context();
    let hash = random_hash();

    async fn race_attempt(
        coordinator: PostgresFragmentCoordinator,
        hash: Vec<u8>,
        key: String,
        manifest: FragmentManifest,
    ) -> bool {
        match coordinator
            .begin_direct_write(&hash, &key)
            .await
            .expect("begin must not error")
        {
            BeginOutcome::AlreadyReadable(_) | BeginOutcome::Fenced(_) => false,
            BeginOutcome::Admitted(intent) => matches!(
                coordinator
                    .commit_remote(&intent, IoObservation::Valid(manifest))
                    .await
                    .expect("commit must not error"),
                CommitVerdict::Published
            ),
        }
    }

    let (a_won, b_won) = tokio::join!(
        race_attempt(
            coordinator_a.clone(),
            hash.clone(),
            "race/a".to_owned(),
            manifest("race/a", 0xA1, EpochAuthority::Remote),
        ),
        race_attempt(
            coordinator_b.clone(),
            hash.clone(),
            "race/b".to_owned(),
            manifest("race/b", 0xB2, EpochAuthority::Remote),
        ),
    );
    assert_eq!(
        usize::from(a_won) + usize::from(b_won),
        1,
        "exactly one of two independently constructed coordinators must publish \
         against one shared head: a_won={a_won} b_won={b_won}"
    );

    assert_eq!(
        coordinator_a
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate the winner"),
        CommitVerdict::Published
    );
    let resolved = coordinator_a
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve winner");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert!(
        resolved_manifest.object_key == "race/a" || resolved_manifest.object_key == "race/b",
        "published manifest must be exactly one contender's, not a merge: {resolved_manifest:?}"
    );
    assert_eq!(a_won, resolved_manifest.object_key == "race/a");
    assert_eq!(b_won, resolved_manifest.object_key == "race/b");
}

/// Item 6a: a competing direct write independently turns a late commit into
/// `Fenced` with zero mutation.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_stale_witness_from_a_competing_direct_write_fences_a_late_commit_with_zero_mutation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(stale_intent) = coordinator
        .begin_direct_write(&hash, "competing-write/stale")
        .await
        .expect("begin stale")
    else {
        panic!("a fresh hash must admit a direct write");
    };

    // While the stale intent's I/O is imagined in flight, a second direct
    // write on the same hash fully begins and commits first.
    let BeginOutcome::Admitted(winning_intent) = coordinator
        .begin_direct_write(&hash, "competing-write/winner")
        .await
        .expect("begin winner")
    else {
        panic!("a non-readable, non-deleting head must still admit a new begin");
    };
    let winner_manifest = manifest("competing-write/winner", 0x10, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(&winning_intent, IoObservation::Valid(winner_manifest))
            .await
            .expect("winner commit"),
        CommitVerdict::Published
    );

    let stale_manifest = manifest("competing-write/stale", 0x20, EpochAuthority::Remote);
    let late = coordinator
        .commit_remote(&stale_intent, IoObservation::Valid(stale_manifest))
        .await
        .expect("late commit must not error");
    assert_eq!(
        late,
        CommitVerdict::Fenced,
        "a competing direct write must fence the delayed commit"
    );

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &stale_intent.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(
        epoch_rows, 0,
        "a fenced commit must publish zero rows for its own epoch"
    );
}

/// Item 6b: a competing obliterate independently turns a late commit into
/// `Fenced` with zero mutation.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_stale_witness_from_a_competing_obliterate_fences_a_late_commit_with_zero_mutation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(stale_intent) = coordinator
        .begin_direct_write(&hash, "competing-obliterate/stale")
        .await
        .expect("begin stale")
    else {
        panic!("a fresh hash must admit a direct write");
    };

    let BeginOutcome::Admitted(_obliterate_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("competing obliterate begin")
    else {
        panic!("a non-tombstoned head must admit begin_obliterate");
    };

    let stale_manifest = manifest("competing-obliterate/stale", 0x30, EpochAuthority::Remote);
    let late = coordinator
        .commit_remote(&stale_intent, IoObservation::Valid(stale_manifest))
        .await
        .expect("late commit must not error");
    assert_eq!(
        late,
        CommitVerdict::Fenced,
        "a competing obliterate must fence the delayed commit"
    );

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &stale_intent.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(epoch_rows, 0);

    let state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head state")
        .get(0);
    assert_eq!(
        state,
        FragmentLifecycleState::DeletingPayload.bits(),
        "the head must remain in the obliteration sequence, not be overwritten by the fenced loser"
    );
}

/// Item 6c: a competing repair independently turns a late commit into
/// `Fenced` with zero mutation.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_stale_witness_from_a_competing_repair_fences_a_late_commit_with_zero_mutation() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    // Get the head to Missing first.
    let BeginOutcome::Admitted(setup_intent) = coordinator
        .begin_direct_write(&hash, "competing-repair/legacy")
        .await
        .expect("begin setup")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &setup_intent,
                IoObservation::Unusable(MissingDiagnostic::Absent)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(stale_repair) = coordinator
        .claim_repair(&hash)
        .await
        .expect("begin stale repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };

    // A second, later repair claim on the still-Missing head races ahead and
    // wins: `claim_repair`'s begin only moves the fence, never the state, so
    // the head is still Missing and admits again.
    let BeginOutcome::Admitted(winning_repair) = coordinator
        .claim_repair(&hash)
        .await
        .expect("begin winning repair")
    else {
        panic!("a second claim on the still-Missing head must also admit");
    };
    let winner_manifest = manifest("competing-repair/winner", 0x40, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_repair(&winning_repair, IoObservation::Valid(winner_manifest))
            .await
            .expect("winner repair commit"),
        CommitVerdict::Published
    );

    let stale_manifest = manifest("competing-repair/stale", 0x50, EpochAuthority::Remote);
    let late = coordinator
        .commit_repair(&stale_repair, IoObservation::Valid(stale_manifest))
        .await
        .expect("late repair commit must not error");
    assert_eq!(
        late,
        CommitVerdict::Fenced,
        "a competing repair must fence the delayed commit"
    );

    let epoch_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &stale_repair.epoch],
        )
        .await
        .expect("count stale epoch rows")
        .get(0);
    assert_eq!(epoch_rows, 0);
}

/// Item 8: a readable/unreadable transition must bump `fragment_lifecycle_generation`
/// for every live-associated repository atomically. This also proves item 7's
/// lock-order claim for a real coordinator transaction: `bump_lifecycle_generation`
/// is reached only after `lock_fragment_head` has already entered
/// `LockClass::Fragments`, so this is the real multi-row transaction F-032-3's
/// order applies to.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_readable_to_unreadable_transition_bumps_every_live_associated_repository_atomically() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    let repository_ids = [
        create_repository(&store).await,
        create_repository(&store).await,
        create_repository(&store).await,
    ];

    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "fanout/key")
        .await
        .expect("begin fanout fragment")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("fanout/key", 0x90, EpochAuthority::Remote))
            )
            .await
            .expect("commit fanout fragment"),
        CommitVerdict::Published
    );
    for repository_id in &repository_ids {
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, &context)
                .await
                .expect("associate fanout repo"),
            CommitVerdict::Published
        );
    }

    for repository_id in &repository_ids {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness before")
            .expect("repository must exist");
        assert_eq!(witness.fragment_lifecycle_generation, 1);
    }

    let resolved = coordinator
        .resolve(&repository_ids[0], &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve to capture epoch witness");
    let (epoch_witness, ..) = expect_readable(&resolved[0]);
    let epoch_witness = epoch_witness.clone();

    let verdict = coordinator
        .mark_missing(&epoch_witness, MissingDiagnostic::Absent)
        .await
        .expect(
            "mark_missing must not error: a readable/unreadable transition with a live \
             multi-repository fanout must bump every associated repository atomically",
        );
    assert_eq!(verdict, CommitVerdict::Published);

    for repository_id in &repository_ids {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness after")
            .expect("repository must exist");
        assert_eq!(
            witness.fragment_lifecycle_generation, 2,
            "every repository with a live association must move together, not partially"
        );
    }
}

/// Item 8 (concurrency half): two readable-to-unreadable transitions over an
/// OVERLAPPING repository fanout must not deadlock, bounded by a watchdog so a
/// real deadlock fails the test instead of hanging the suite.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn two_concurrent_transitions_over_an_overlapping_fanout_do_not_deadlock() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let context = random_context();

    let repo_1 = create_repository(&store).await;
    let repo_2 = create_repository(&store).await;
    let repo_3 = create_repository(&store).await;

    async fn publish(coordinator: &PostgresFragmentCoordinator, key: &str, seed: u8) -> Vec<u8> {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, key)
            .await
            .expect("begin overlap fragment")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(manifest(key, seed, EpochAuthority::Remote))
                )
                .await
                .expect("commit overlap fragment"),
            CommitVerdict::Published
        );
        hash
    }

    let hash_x = publish(&coordinator, "overlap/x", 0xA0).await;
    let hash_y = publish(&coordinator, "overlap/y", 0xA1).await;

    for repository_id in [&repo_1, &repo_2] {
        assert_eq!(
            coordinator
                .create_association(&hash_x, repository_id, &context)
                .await
                .expect("associate x"),
            CommitVerdict::Published
        );
    }
    // repo_2 is shared between x's and y's fanout on purpose: this is the
    // overlap the sorted-order rule exists to make deadlock-free.
    for repository_id in [&repo_2, &repo_3] {
        assert_eq!(
            coordinator
                .create_association(&hash_y, repository_id, &context)
                .await
                .expect("associate y"),
            CommitVerdict::Published
        );
    }

    let resolved_x = coordinator
        .resolve(&repo_1, &context, std::slice::from_ref(&hash_x))
        .await
        .expect("resolve x");
    let (witness_x, ..) = expect_readable(&resolved_x[0]);
    let witness_x = witness_x.clone();
    let resolved_y = coordinator
        .resolve(&repo_2, &context, std::slice::from_ref(&hash_y))
        .await
        .expect("resolve y");
    let (witness_y, ..) = expect_readable(&resolved_y[0]);
    let witness_y = witness_y.clone();

    let coordinator_x = coordinator.clone();
    let coordinator_y = coordinator.clone();
    let (result_x, result_y) = tokio::join!(
        timeout(
            Duration::from_secs(10),
            coordinator_x.mark_missing(&witness_x, MissingDiagnostic::Absent)
        ),
        timeout(
            Duration::from_secs(10),
            coordinator_y.mark_missing(&witness_y, MissingDiagnostic::Absent)
        ),
    );
    let result_x = result_x
        .expect("mark_missing(x) must not deadlock past a 10s watchdog")
        .expect("mark_missing(x) must not error");
    let result_y = result_y
        .expect("mark_missing(y) must not deadlock past a 10s watchdog")
        .expect("mark_missing(y) must not error");
    assert_eq!(result_x, CommitVerdict::Published);
    assert_eq!(result_y, CommitVerdict::Published);

    // repo_1 and repo_3 are each associated with exactly one of the two
    // transitioning fragments, so each moves once (1 -> 2). repo_2 is
    // associated with BOTH x and y, so it legitimately receives one bump per
    // independent transition (1 -> 3) -- not a partial or doubled fanout, but
    // two genuinely separate lifecycle transitions that happen to share a
    // repository.
    for (repository_id, expected_generation) in [(&repo_1, 2i64), (&repo_2, 3i64), (&repo_3, 2i64)]
    {
        let witness = coordinator
            .capture_push_witness(repository_id)
            .await
            .expect("capture witness")
            .expect("repository must exist");
        assert_eq!(
            witness.fragment_lifecycle_generation, expected_generation,
            "repository {repository_id:02x?} must reflect exactly the transitions of the \
             fragments it is associated with, no more and no less"
        );
    }
}

/// Reviewer gap: repair on a `Missing` fragment that HAS a live association
/// must bump that repository's fanout, exercising `commit_repair`'s
/// Missing-to-Remote transition through the real fanout-locking path (a repair
/// with zero associations never reaches it).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_repair_on_a_missing_fragment_with_a_live_association_bumps_its_repository_fanout() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(setup) = coordinator
        .begin_direct_write(&hash, "repair-with-association/legacy")
        .await
        .expect("begin setup")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&setup, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate missing fragment"),
        CommitVerdict::Published
    );

    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture before")
        .expect("repository must exist");

    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    let repaired_manifest = manifest(
        "repair-with-association/repaired",
        0x60,
        EpochAuthority::Remote,
    );
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(repaired_manifest.clone())
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after")
        .expect("repository must exist");
    assert_eq!(
        after.fragment_lifecycle_generation,
        before.fragment_lifecycle_generation + 1,
        "Missing-to-Remote via repair is a readable transition and must bump the \
         associated repository exactly once"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve repaired fragment");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert_eq!(resolved_manifest, &repaired_manifest);
}

/// Reviewer gap: obliterate on a readable fragment that HAS a live association
/// must bump that repository's fanout and remove the association, exercising
/// `begin_obliterate`'s fanout-locking path (zero associations never reach
/// it).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_obliterate_on_a_readable_fragment_with_a_live_association_bumps_its_repository_fanout()
{
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "obliterate-with-association/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "obliterate-with-association/key",
                    0x61,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture before")
        .expect("repository must exist");
    assert_eq!(before.fragment_lifecycle_generation, 1);

    let BeginOutcome::Admitted(_obliterate_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate on a readable, associated fragment")
    else {
        panic!("a non-tombstoned head must admit begin_obliterate");
    };

    let after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture after")
        .expect("repository must exist");
    assert_eq!(
        after.fragment_lifecycle_generation, 2,
        "moving a readable head into the deletion sequence is a readable-to-unreadable \
         transition and must bump the associated repository"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve during obliteration");
    expect_absent(&resolved[0]);
}

/// Reviewer gap: `readiness().unresolved_rows` must stay zero for a live
/// `Preparing` head (no epoch row yet by construction) and for a `Missing`
/// head committed by a failed first write. Neither is damage; both are
/// ordinary in-flight or terminal states the resolver's join already handles.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn readiness_reports_zero_unresolved_rows_for_a_preparing_head_and_a_missing_head() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();

    let preparing_hash = random_hash();
    let BeginOutcome::Admitted(_preparing_intent) = coordinator
        .begin_direct_write(&preparing_hash, "readiness-preparing/key")
        .await
        .expect("begin preparing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    let readiness_with_preparing = coordinator
        .readiness()
        .await
        .expect("readiness with a Preparing head");
    assert_eq!(
        readiness_with_preparing.unresolved_rows, 0,
        "a Preparing head with no epoch row yet must not count as damage"
    );

    let missing_hash = random_hash();
    let BeginOutcome::Admitted(missing_intent) = coordinator
        .begin_direct_write(&missing_hash, "readiness-missing/key")
        .await
        .expect("begin missing")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &missing_intent,
                IoObservation::Unusable(MissingDiagnostic::Absent)
            )
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    let readiness_with_missing = coordinator
        .readiness()
        .await
        .expect("readiness with a Missing head");
    assert_eq!(
        readiness_with_missing.unresolved_rows, 0,
        "a Missing head from a failed first write must not count as damage"
    );
}

/// Reviewer gap: a promotion round trip must allocate a NEW epoch (not
/// republish the staged one) and must publish under `Remote` authority.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_promotion_round_trip_allocates_a_new_epoch_and_publishes_under_remote_authority() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_epoch = stage_intent.epoch;
    let staged_manifest = manifest("promotion/staged", 0x80, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, staged_epoch,
        "promotion must allocate a NEW epoch, not republish the staged one"
    );
    let remote_manifest = manifest("promotion/remote", 0x81, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(remote_manifest.clone())
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );
    assert_eq!(remote_manifest.authority, EpochAuthority::Remote);

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    assert_eq!(current_epoch, promotion_intent.epoch);
    assert_eq!(state, FragmentLifecycleState::Remote.bits());

    let epoch_row = direct
        .query_one(
            "SELECT authority, object_key FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &promotion_intent.epoch],
        )
        .await
        .expect("read published epoch row");
    let authority: i16 = epoch_row.get(0);
    assert_eq!(
        authority,
        EpochAuthority::Remote.bits(),
        "the published epoch row must record Remote authority, not Staged"
    );
}

/// Item 9: an absent SCHEMA-118 is a routing answer (the cell boots on the
/// legacy route); a partially installed one is refused, never routed around.
/// Mirrors `domain_lock_fencing.rs`'s
/// `an_absent_schema_routes_legacy_but_a_partial_one_is_refused` for SCHEMA-117.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_absent_fragment_schema_routes_legacy_but_a_partial_one_is_refused() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    // Deliberately not the bootstrapping `store()` helper: this case needs the
    // state a booting cell actually finds before any migration has run.
    let bare = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .expect("connect domain store without SCHEMA-118");
    let readiness = bare
        .fragment_coordinator()
        .readiness()
        .await
        .expect("an unmigrated database must answer, not error");
    assert_eq!(readiness, FragmentLifecycleReadiness::not_provisioned());

    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("install SCHEMA-118");
    let direct = client(&url).await;

    // One relation missing: partially installed.
    direct
        .execute("DROP TABLE lore_fragment_staged_lease_members", &[])
        .await
        .expect("drop one fenced relation");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a half-installed SCHEMA-118 must be refused, never reported as unprovisioned"
    );

    // All relations present, singleton state row gone: also incomplete.
    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-118");
    direct
        .execute("DELETE FROM lore_fragment_schema_state WHERE id = 1", &[])
        .await
        .expect("remove the singleton schema-state row");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a missing singleton schema-state row must be refused, not reported as unprovisioned"
    );

    // A provisioned schema missing its repository generation columns: these
    // are part of SCHEMA-118's own DDL (an ALTER TABLE on the CR-029 table),
    // so their absence is damage specific to how this schema installs, not
    // covered by the relation-presence probe at all.
    bare.fragment_coordinator()
        .bootstrap()
        .await
        .expect("reinstall SCHEMA-118 and its schema-state row");
    bare.fragment_coordinator()
        .readiness()
        .await
        .expect("a fully installed schema must answer");
    direct
        .execute(
            "ALTER TABLE lore_domain_repositories DROP COLUMN content_association_generation",
            &[],
        )
        .await
        .expect("drop one repository generation column");
    assert!(
        matches!(
            bare.fragment_coordinator().readiness().await,
            Err(DomainError::NotReady(_))
        ),
        "a provisioned schema missing its repository generation columns must be refused, \
         never reported as ready"
    );
}

// ---------------------------------------------------------------------------
// INV-EF P1-2 / P1-3: six previously-untested public entry points, all
// closable inside Phases 2-3.
// ---------------------------------------------------------------------------

/// Open a caller-owned transaction on a fresh connection pool. This coordinator
/// deliberately does not expose its own pool, and `revalidate_push_witness` is
/// the one method that borrows the caller's `Transaction` rather than owning
/// one -- a real push transaction supplies it, so a test does too.
async fn own_transaction_client(url: &str) -> deadpool_postgres::Client {
    let pool = build_pool(url, 4, &TlsConfig::default()).expect("build push-witness pool");
    pool.get().await.expect("checkout push-witness connection")
}

/// P1-2 item 1a: `revalidate_push_witness`'s `Unchanged` verdict, reached when
/// neither per-repository scalar moved between preflight capture and the final
/// push transaction. The fast path reads no fragment row at all, so an empty
/// `required` slice is enough to prove it.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_reports_unchanged_when_neither_scalar_moved() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &[])
        .await
        .expect("revalidate must not error");
    assert_eq!(verdict, PushWitnessVerdict::Unchanged);
}

/// P1-2 item 1b: `FallbackSatisfied`. The lifecycle scalar moves via a
/// bystander fragment's readable-to-unreadable transition; the two required
/// fragments are untouched and still readable at their captured epoch, so the
/// bounded fallback revalidates and satisfies the push.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_is_satisfied_by_the_fallback_when_the_lifecycle_scalar_moved_and_required_fragments_are_still_readable()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // Two required fragments, published and associated BEFORE capture, so
    // their association does not itself move the content-association scalar
    // after the witness is taken.
    let mut required = Vec::new();
    for seed in 0u8..2 {
        let hash = random_hash();
        let key = format!("push-fallback/required-{seed}");
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_direct_write(&hash, &key)
            .await
            .expect("begin required fragment")
        else {
            panic!("a fresh hash must admit a direct write");
        };
        assert_eq!(
            coordinator
                .commit_remote(
                    &intent,
                    IoObservation::Valid(manifest(&key, 0xD0 + seed, EpochAuthority::Remote))
                )
                .await
                .expect("commit required fragment"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_id, &context)
                .await
                .expect("associate required fragment"),
            CommitVerdict::Published
        );
        required.push(RequiredFragment {
            hash,
            epoch: intent.epoch,
        });
    }

    // A bystander fragment, also associated before capture, whose later
    // transition is the only thing that moves the lifecycle scalar.
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, "push-fallback/bystander")
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "push-fallback/bystander",
                    0xD9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 2 }
    );
}

/// P1-2 item 1c (first `Aborted` shape): a required fragment that has become
/// unreadable (here, `Missing`) since preflight.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_a_required_fragment_is_no_longer_readable() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "push-abort/removed")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("push-abort/removed", 0xD1, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let required_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before removal");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    let required = vec![RequiredFragment {
        hash,
        epoch: required_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// P1-2 item 1c (second `Aborted` shape): a required fragment whose epoch
/// advanced (a repair successor) since preflight, even though it is still
/// readable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_a_required_fragments_epoch_advanced() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "push-abort/repaired")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "push-abort/repaired",
                    0xD2,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let original_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before repair");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );
    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(manifest(
                    "push-abort/repaired-successor",
                    0xD3,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    // `required` still names the ORIGINAL (now stale) epoch.
    let required = vec![RequiredFragment {
        hash,
        epoch: original_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// P1-2 item 1d: the 4,097-synthetic-fragment refusal. `MAX_PUSH_FRAGMENT_REVALIDATIONS`
/// is a count check on the caller's slice, reachable with fabricated hashes
/// that were never inserted -- this is the case INV-EF's own record wrongly
/// attributed to needing real upload traffic. Proven behaviorally (`Aborted`)
/// and structurally: the refusal happens before `LockClass::Fragments` is
/// ever entered.
///
/// **No push-witness before/after comparison here on purpose.**
/// `revalidate_push_witness` has no code path, in this or any other verdict,
/// that writes to `lore_domain_repositories` -- it only ever reads that table
/// and, past the count check, takes `FOR UPDATE` locks on
/// `lore_fragment_lifecycle`. A witness-unchanged assertion would therefore
/// hold no matter what this function did, which is the same
/// cannot-fail-regardless-of-behavior shape INV-EF's own P2-11 flagged
/// elsewhere -- caught here by a reviewer pass rather than shipped. The
/// `LockClass::Repository` re-entry below is the one proof that actually
/// discriminates: it could not succeed if `Fragments` had already been
/// entered.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_refuses_over_the_revalidation_limit_before_locking_any_fragment_row()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "push-abort/limit")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest("push-abort/limit", 0xD4, EpochAuthority::Remote))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Move the lifecycle scalar so the call reaches the count check rather
    // than short-circuiting on `Unchanged`.
    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before mark missing");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    // 4,097 synthetic RequiredFragment values: fabricated hashes, never
    // inserted anywhere, one over the frozen limit.
    let required: Vec<RequiredFragment> = (0..=MAX_PUSH_FRAGMENT_REVALIDATIONS)
        .map(|_| RequiredFragment {
            hash: random_hash(),
            epoch: 1,
        })
        .collect();
    assert_eq!(required.len(), MAX_PUSH_FRAGMENT_REVALIDATIONS + 1);

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_REVALIDATION_LIMIT
        }
    );

    // Structural proof: the count check runs BEFORE any fragment row is
    // locked. `LockClass::Fragments` (position 4) is later than
    // `LockClass::Repository` (position 1); if the refusal had already
    // entered Fragments, re-entering Repository here would be rejected as a
    // lock-order inversion.
    sequence.enter(LockClass::Repository).expect(
        "the revalidation-limit refusal must return before locking any fragment row; if \
         LockClass::Fragments had been entered, this would be a lock-order violation",
    );
    drop(tx); // never committed; the function made no writes to roll back
}

/// CR-031:266 (INV-EF P2-2): a required fragment promoted from `Staged` to a
/// `Remote` epoch that is semantically equivalent -- same `decoded_hash`,
/// `size_content`, `size_payload`, and `payload_flags` -- must satisfy the
/// push fallback even though its epoch genuinely advanced and its
/// `object_key`/`manifest_id` changed (deliberately not compared).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_accepts_a_required_fragment_promoted_to_a_semantically_equivalent_epoch()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    // The required fragment: staged, then associated BEFORE capture, so its
    // association does not itself move the content-association scalar after
    // the witness is taken.
    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("equivalent-epoch/staged", 0xC0, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let original_epoch = stage_intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    // A bystander, also associated before capture, whose later transition is
    // the only thing that moves the lifecycle scalar (a Staged->Remote
    // promotion crosses no readability boundary and moves nothing on its own).
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, "equivalent-epoch/bystander")
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "equivalent-epoch/bystander",
                    0xC9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Promote the required fragment: a NEW epoch, a different `object_key`
    // and `manifest_id`, but identical decoded_hash/size_content/size_payload/
    // payload_flags.
    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_ne!(
        promotion_intent.epoch, original_epoch,
        "promotion must allocate a new epoch, not republish the staged one"
    );
    let mut promoted_manifest = staged_manifest.clone();
    promoted_manifest.authority = EpochAuthority::Remote;
    promoted_manifest.object_key = "equivalent-epoch/promoted".to_owned();
    promoted_manifest.manifest_id = vec![0xCA; 32];
    assert_ne!(
        promoted_manifest.manifest_id, staged_manifest.manifest_id,
        "the successor manifest id must genuinely differ from the staged one"
    );
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_intent, IoObservation::Valid(promoted_manifest))
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so the call reaches the fallback rather than
    // short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // The epoch really did advance -- this is what stops the case from
    // silently degenerating into the exact-match path.
    let current_epoch: i64 = direct
        .query_one(
            "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read current epoch after promotion")
        .get(0);
    assert_ne!(
        current_epoch, original_epoch,
        "the required fragment's current epoch must have genuinely advanced"
    );
    assert_eq!(current_epoch, promotion_intent.epoch);

    let required = vec![RequiredFragment {
        hash,
        epoch: original_epoch,
    }];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();

    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 1 }
    );
}

/// CR-031:266's equivalence allowance is narrow: a successor epoch whose
/// manifest differs in `decoded_hash` or `payload_flags` describes different
/// content and must abort, even though the head is still readable and
/// `size_content`/`size_payload` are unchanged.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_the_new_epoch_describes_different_content() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    async fn stage_and_associate(
        coordinator: &PostgresFragmentCoordinator,
        repository_id: &[u8],
        context: &[u8],
        key_prefix: &str,
        seed: u8,
    ) -> (Vec<u8>, i64, FragmentManifest) {
        let hash = random_hash();
        let BeginOutcome::Admitted(stage_intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("{key_prefix}/staged"),
            seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
                .await
                .expect("commit staged"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
        (hash, stage_intent.epoch, staged_manifest)
    }

    let (hash_a, original_epoch_a, staged_manifest_a) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "content-changed/hash",
        0xE0,
    )
    .await;
    let (hash_b, original_epoch_b, staged_manifest_b) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "content-changed/flags",
        0xE1,
    )
    .await;

    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, "content-changed/bystander")
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "content-changed/bystander",
                    0xE9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // A: promote with a different decoded_hash.
    let BeginOutcome::Admitted(promotion_a) = coordinator
        .begin_promotion(&hash_a)
        .await
        .expect("begin promotion a")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_a = staged_manifest_a.clone();
    promoted_a.authority = EpochAuthority::Remote;
    promoted_a.object_key = "content-changed/promoted-hash".to_owned();
    promoted_a.manifest_id = vec![0xEA; 32];
    promoted_a.decoded_hash = vec![0xFF; 32];
    assert_ne!(promoted_a.decoded_hash, staged_manifest_a.decoded_hash);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_a, IoObservation::Valid(promoted_a))
            .await
            .expect("commit promotion a"),
        CommitVerdict::Published
    );

    // B: promote with a different payload_flags.
    let BeginOutcome::Admitted(promotion_b) = coordinator
        .begin_promotion(&hash_b)
        .await
        .expect("begin promotion b")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_b = staged_manifest_b.clone();
    promoted_b.authority = EpochAuthority::Remote;
    promoted_b.object_key = "content-changed/promoted-flags".to_owned();
    promoted_b.manifest_id = vec![0xEB; 32];
    promoted_b.payload_flags = staged_manifest_b.payload_flags ^ 0x01;
    assert_ne!(promoted_b.payload_flags, staged_manifest_b.payload_flags);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_b, IoObservation::Valid(promoted_b))
            .await
            .expect("commit promotion b"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so both revalidations below reach the
    // fallback branch rather than short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    for (hash, original_epoch, label) in [
        (hash_a, original_epoch_a, "decoded_hash"),
        (hash_b, original_epoch_b, "payload_flags"),
    ] {
        let current_epoch: i64 = direct
            .query_one(
                "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
                &[&hash],
            )
            .await
            .expect("read current epoch after promotion")
            .get(0);
        assert_ne!(
            current_epoch, original_epoch,
            "{label}: the epoch must have genuinely advanced, or this case would silently \
             degenerate into the exact-match path"
        );

        let required = vec![RequiredFragment {
            hash,
            epoch: original_epoch,
        }];
        let mut tx_client = own_transaction_client(&url).await;
        let tx = tx_client
            .transaction()
            .await
            .expect("open push-witness transaction");
        let mut sequence = LockSequence::new();

        let verdict = coordinator
            .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
            .await
            .expect("revalidate must not error");
        assert_eq!(
            verdict,
            PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_CHANGED
            },
            "{label} divergence must abort the push, not fall through the equivalence allowance"
        );
    }
}

/// P1-2 item 2: `acquire_staged_leases`/`release_staged_lease` round trip over
/// a **batch** of several staged fragments -- one lease row covering many
/// members is the whole design point, not one lease per fragment.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_and_release_round_trip_a_batch_with_a_monotonic_reader_fence() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let mut members = Vec::new();
    for seed in 0u8..3 {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("staged-lease/member-{seed}"),
            0xE0 + seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&intent, IoObservation::Valid(staged_manifest))
                .await
                .expect("commit staged member"),
            CommitVerdict::Published
        );
        members.push((hash, intent.epoch));
    }

    let lease_id_a = rand::random::<[u8; 16]>().to_vec();
    let deadline = SystemTime::now() + Duration::from_secs(60);
    let lease_a = coordinator
        .acquire_staged_leases(&lease_id_a, &members, deadline)
        .await
        .expect("acquire lease a");
    assert_eq!(lease_a.lease_id, lease_id_a);
    assert_eq!(lease_a.members, members);

    let member_count: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("count lease members")
        .get(0);
    assert_eq!(
        member_count,
        members.len() as i64,
        "every batched member must land"
    );

    let lease_row = direct
        .query_one(
            "SELECT reader_fence, terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("read lease row");
    let stored_fence: i64 = lease_row.get(0);
    let terminal: bool = lease_row.get(1);
    assert_eq!(stored_fence, lease_a.reader_fence);
    assert!(!terminal, "a fresh lease must not start terminal");

    // Monotonic reader fence: a second lease, over one member, gets a
    // strictly greater fence.
    let lease_id_b = rand::random::<[u8; 16]>().to_vec();
    let lease_b = coordinator
        .acquire_staged_leases(&lease_id_b, &members[..1], deadline)
        .await
        .expect("acquire lease b");
    assert!(
        lease_b.reader_fence > lease_a.reader_fence,
        "reader fences must be monotonic: a={} b={}",
        lease_a.reader_fence,
        lease_b.reader_fence
    );

    coordinator
        .release_staged_lease(&lease_id_a)
        .await
        .expect("release lease a");
    let released_terminal: bool = direct
        .query_one(
            "SELECT terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_a],
        )
        .await
        .expect("read released lease terminal flag")
        .get(0);
    assert!(released_terminal, "release must flip terminal");

    // Releasing lease A must not affect lease B.
    let lease_b_terminal: bool = direct
        .query_one(
            "SELECT terminal FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_b],
        )
        .await
        .expect("read lease b terminal flag")
        .get(0);
    assert!(!lease_b_terminal);
}

/// INV-EF P2-6: a `lease_id` whose length is not [`schema::STAGED_LEASE_ID_LEN`]
/// must be refused as [`DomainError::InvalidInput`] before any database work,
/// on both `acquire_staged_leases` and `release_staged_lease`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_lease_id_that_is_not_the_schema_length() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let short_id: Vec<u8> = vec![0u8; schema::STAGED_LEASE_ID_LEN - 1];
    let long_id: Vec<u8> = vec![0u8; schema::STAGED_LEASE_ID_LEN + 1];

    for bad_id in [short_id.clone(), long_id.clone()] {
        let result = coordinator
            .acquire_staged_leases(&bad_id, &[], deadline)
            .await;
        assert!(
            matches!(result, Err(DomainError::InvalidInput(_))),
            "expected InvalidInput for a {}-byte lease id, got {:?}",
            bad_id.len(),
            result
        );
        let lease_rows: i64 = direct
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
                &[&bad_id],
            )
            .await
            .expect("count lease rows for a wrong-length id")
            .get(0);
        assert_eq!(
            lease_rows, 0,
            "a wrong-length lease id must be refused before any database write"
        );
    }

    // `release_staged_lease` carries the same guard.
    let release_result = coordinator.release_staged_lease(&short_id).await;
    assert!(
        matches!(release_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput from release_staged_lease for a wrong-length id, got {:?}",
        release_result
    );
}

/// INV-EF P2-5: every member of an `acquire_staged_leases` batch must name a
/// row in `lore_fragment_epochs` carrying [`schema::AUTHORITY_STAGED`] -- a
/// `Remote` epoch and a fabricated `(hash, epoch)` naming nothing are both
/// refused, and an all-staged batch still succeeds.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_member_that_is_not_a_staged_epoch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    fn assert_member_not_staged(result: &Result<StagedReaderLease, DomainError>) {
        match result {
            Err(DomainError::PreconditionRejected {
                reason,
                reason_version,
            }) => {
                assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
                assert_eq!(*reason_version, 1);
            }
            other => panic!("expected STAGED_LEASE_MEMBER_NOT_STAGED, got {other:?}"),
        }
    }

    let staged_hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(&staged_hash)
        .await
        .expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "staged-lease-scope/staged",
                    0x11,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_member = (staged_hash, stage_intent.epoch);

    let remote_hash = random_hash();
    let BeginOutcome::Admitted(remote_intent) = coordinator
        .begin_direct_write(&remote_hash, "staged-lease-scope/remote")
        .await
        .expect("begin remote")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &remote_intent,
                IoObservation::Valid(manifest(
                    "staged-lease-scope/remote",
                    0x12,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit remote"),
        CommitVerdict::Published
    );
    let remote_member = (remote_hash, remote_intent.epoch);

    let fabricated_member = (random_hash(), 1i64);

    let lease_id_remote = rand::random::<[u8; 16]>().to_vec();
    let remote_result = coordinator
        .acquire_staged_leases(
            &lease_id_remote,
            &[staged_member.clone(), remote_member],
            deadline,
        )
        .await;
    assert_member_not_staged(&remote_result);
    let remote_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_remote],
        )
        .await
        .expect("count lease rows after a Remote-member refusal")
        .get(0);
    assert_eq!(remote_lease_rows, 0);
    let remote_member_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_remote],
        )
        .await
        .expect("count member rows after a Remote-member refusal")
        .get(0);
    assert_eq!(remote_member_rows, 0);

    let lease_id_fabricated = rand::random::<[u8; 16]>().to_vec();
    let fabricated_result = coordinator
        .acquire_staged_leases(
            &lease_id_fabricated,
            &[staged_member.clone(), fabricated_member],
            deadline,
        )
        .await;
    assert_member_not_staged(&fabricated_result);
    let fabricated_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_fabricated],
        )
        .await
        .expect("count lease rows after a fabricated-member refusal")
        .get(0);
    assert_eq!(fabricated_lease_rows, 0);
    let fabricated_member_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_fabricated],
        )
        .await
        .expect("count member rows after a fabricated-member refusal")
        .get(0);
    assert_eq!(fabricated_member_rows, 0);

    let lease_id_ok = rand::random::<[u8; 16]>().to_vec();
    let ok_lease = coordinator
        .acquire_staged_leases(&lease_id_ok, std::slice::from_ref(&staged_member), deadline)
        .await
        .expect("an all-staged batch must acquire");
    assert_eq!(ok_lease.members, vec![staged_member.clone()]);
    // The returned struct alone cannot fail here -- `StagedReaderLease.members`
    // is copied straight back from the input in `acquire_staged_leases`'s
    // success arm, so it would read correct even if zero member rows had been
    // written. Read the persisted row directly, the same way the refusal legs
    // above prove a NON-write.
    let ok_member_rows: Vec<(Vec<u8>, i64)> = direct
        .query(
            "SELECT hash, epoch FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id_ok],
        )
        .await
        .expect("read persisted members for the all-staged batch")
        .into_iter()
        .map(|row| (row.get("hash"), row.get("epoch")))
        .collect();
    assert_eq!(
        ok_member_rows,
        vec![staged_member],
        "the all-staged batch must actually persist its member row, not just echo the input"
    );
}

/// INV-EF P2-6: a duplicate `lease_id` faithfully replays the existing lease
/// (same fence, same deadline, order-independent member set) rather than
/// colliding on a bare primary key; a genuinely different member set or an
/// already-released lease are each refused with their own reason code.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_duplicate_staged_lease_id_replays_the_existing_lease_and_refuses_a_different_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let mut members = Vec::new();
    for seed in 0u8..2 {
        let hash = random_hash();
        let BeginOutcome::Admitted(intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        assert_eq!(
            coordinator
                .commit_staged(
                    &intent,
                    IoObservation::Valid(manifest(
                        &format!("duplicate-lease/member-{seed}"),
                        0x30 + seed,
                        EpochAuthority::Staged
                    ))
                )
                .await
                .expect("commit staged member"),
            CommitVerdict::Published
        );
        members.push((hash, intent.epoch));
    }
    let extra_hash = random_hash();
    let BeginOutcome::Admitted(extra_intent) = coordinator
        .begin_stage(&extra_hash)
        .await
        .expect("begin stage extra")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &extra_intent,
                IoObservation::Valid(manifest(
                    "duplicate-lease/extra",
                    0x32,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged extra"),
        CommitVerdict::Published
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let first_deadline = microsecond_deadline(Duration::from_secs(60));
    let first_lease = coordinator
        .acquire_staged_leases(&lease_id, &members, first_deadline)
        .await
        .expect("acquire first lease");

    // Re-acquire the SAME id with the same members in a DIFFERENT order and a
    // LATER deadline: a replay allocates no second fence and never extends.
    let mut reordered = members.clone();
    reordered.reverse();
    let later_deadline = microsecond_deadline(Duration::from_secs(3600));
    let replay = coordinator
        .acquire_staged_leases(&lease_id, &reordered, later_deadline)
        .await
        .expect("a faithful replay must succeed");
    assert_eq!(
        replay.reader_fence, first_lease.reader_fence,
        "a replay must not allocate a second reader fence"
    );
    assert_eq!(
        replay.deadline, first_lease.deadline,
        "a replay must not extend the deadline"
    );

    let stored_row = direct
        .query_one(
            "SELECT reader_fence, deadline FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id],
        )
        .await
        .expect("read stored lease row after replay");
    let stored_fence: i64 = stored_row.get(0);
    let stored_deadline: SystemTime = stored_row.get(1);
    assert_eq!(stored_fence, first_lease.reader_fence);
    assert_eq!(stored_deadline, first_lease.deadline);

    // A duplicate id over a DIFFERENT member set is an id collision, not a
    // retry.
    let mut different_members = members.clone();
    different_members.push((extra_hash, extra_intent.epoch));
    let mismatch_result = coordinator
        .acquire_staged_leases(&lease_id, &different_members, first_deadline)
        .await;
    match mismatch_result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_SET_MISMATCH);
            assert_eq!(reason_version, 1);
        }
        other => panic!("expected STAGED_LEASE_MEMBER_SET_MISMATCH, got {other:?}"),
    }

    // A duplicate id over an already-released lease must not be resurrected.
    coordinator
        .release_staged_lease(&lease_id)
        .await
        .expect("release lease");
    let released_result = coordinator
        .acquire_staged_leases(&lease_id, &members, first_deadline)
        .await;
    match released_result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_ALREADY_RELEASED);
            assert_eq!(reason_version, 1);
        }
        other => panic!("expected STAGED_LEASE_ALREADY_RELEASED, got {other:?}"),
    }
}

/// P1-2 item 3: `commit_obliterate` purges the epoch's disposition, deletes
/// the metering row, and moves the head to `Tombstoned`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn commit_obliterate_purges_the_epoch_disposition_deletes_metering_and_tombstones_the_head() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "obliterate-commit/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "obliterate-commit/key",
                    0xF0,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let published_epoch = intent.epoch;

    let metering_before: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count metering before")
        .get(0);
    assert_eq!(
        metering_before, 1,
        "a published fragment has a metering row"
    );

    let BeginOutcome::Admitted(obliterate_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate")
    else {
        panic!("a readable head must admit begin_obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate(&obliterate_intent)
            .await
            .expect("commit obliterate"),
        CommitVerdict::Published
    );

    let head_row = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after obliterate");
    let state: i16 = head_row.get(0);
    assert_eq!(state, FragmentLifecycleState::Tombstoned.bits());

    let disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &published_epoch],
        )
        .await
        .expect("read published epoch disposition")
        .get(0);
    assert_eq!(disposition, schema::DISPOSITION_PURGED);

    let metering_after: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("count metering after")
        .get(0);
    assert_eq!(metering_after, 0, "the metering row must be deleted");
}

/// P1-2 item 3 (fencing half): a stale obliterate intent -- one whose fence
/// was overtaken by a second `begin_obliterate` on the same head before its
/// own commit ran -- fences `commit_obliterate` and leaves the winner's
/// mutation exactly as it was.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn commit_obliterate_fences_a_stale_intent_and_mutates_nothing() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "obliterate-stale/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "obliterate-stale/key",
                    0xF1,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(stale_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate (stale)")
    else {
        panic!("a readable head must admit begin_obliterate");
    };
    // A second begin_obliterate on the same head -- still DeletingPayload, not
    // yet Tombstoned -- moves the fence again without publishing anything.
    let BeginOutcome::Admitted(winning_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate (winner)")
    else {
        panic!(
            "a DeletingPayload head is not yet Tombstoned and must still admit begin_obliterate"
        );
    };
    assert_ne!(stale_intent.fence, winning_intent.fence);

    assert_eq!(
        coordinator
            .commit_obliterate(&winning_intent)
            .await
            .expect("commit obliterate (winner)"),
        CommitVerdict::Published
    );

    let head_after_win = direct
        .query_one(
            "SELECT state, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after winner");
    let state_after_win: i16 = head_after_win.get(0);
    // `commit_obliterate` stamps a FRESH fence of its own on commit (not
    // `winning_intent.fence`, which was allocated at begin) -- captured here
    // only as the known-good baseline the stale attempt must not overwrite.
    let last_fence_after_win: i64 = head_after_win.get(1);
    assert_eq!(state_after_win, FragmentLifecycleState::Tombstoned.bits());
    let disposition_after_win: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &winning_intent.epoch],
        )
        .await
        .expect("read epoch disposition after winner")
        .get(0);

    let stale_result = coordinator
        .commit_obliterate(&stale_intent)
        .await
        .expect("stale commit obliterate must not error");
    assert_eq!(
        stale_result,
        CommitVerdict::Fenced,
        "a fence moved between the stale begin and its commit"
    );

    let head_after_stale = direct
        .query_one(
            "SELECT state, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after stale attempt");
    let state_after_stale: i16 = head_after_stale.get(0);
    let last_fence_after_stale: i64 = head_after_stale.get(1);
    assert_eq!(
        state_after_stale, state_after_win,
        "a fenced obliterate commit must leave the head exactly as the winner published it"
    );
    // The load-bearing check: `state`/`disposition` alone cannot discriminate
    // a wrongly-proceeding stale commit from the winner's, because a stale
    // commit that incorrectly proceeded would obliterate the SAME epoch to
    // the SAME Tombstoned/PURGED values. `last_fence` is the one field a
    // wrongly-proceeding loser would overwrite with its own freshly allocated
    // fence -- so an unchanged `last_fence` is what actually proves the stale
    // commit's UPDATE never ran.
    assert_eq!(
        last_fence_after_stale, last_fence_after_win,
        "a fenced obliterate commit must not stamp its own fence over the winner's"
    );
    let disposition_after_stale: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &winning_intent.epoch],
        )
        .await
        .expect("read epoch disposition after stale attempt")
        .get(0);
    assert_eq!(
        disposition_after_stale, disposition_after_win,
        "a fenced obliterate commit must not mutate the epoch disposition"
    );
}

/// P1-2 item 4: `enable_lifecycle` refuses with the typed `DomainError::NotReady`
/// on a cell that has not completed backfill and cutover, and succeeds once
/// the schema-state row genuinely satisfies cutover, residue classification,
/// and sequence headroom.
///
/// SCHEMA-118's Phase 2/3 surface has no coordinator method that advances
/// `backfill_state`/`cutover_at`/`residue_classified` -- that orchestrator is
/// a later phase, unlike SCHEMA-117's sibling in `domain/locks/coordinator.rs`.
/// The positive precondition is staged with the same direct-SQL technique this
/// file's own `an_absent_fragment_schema_routes_legacy_but_a_partial_one_is_refused`
/// already uses to stage schema-damage preconditions -- exercising the real
/// row `enable_lifecycle` reads and writes, not a hand-built
/// `FragmentLifecycleReadiness` fixture (that shape is already pinned by
/// `readiness_fails_closed_on_each_missing_precondition` in this crate's own
/// `mod tests`).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn enable_lifecycle_refuses_on_a_not_ready_cell_and_succeeds_once_ready() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    // A freshly bootstrapped cell (a real write: `bootstrap()`'s INSERT) has
    // not backfilled or cut over.
    let refusal = coordinator.enable_lifecycle().await;
    assert!(
        matches!(refusal, Err(DomainError::NotReady(_))),
        "expected the typed NotReady error, got {refusal:?}"
    );

    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1 \
              WHERE id = 1",
            &[&schema::BACKFILL_CUTOVER],
        )
        .await
        .expect("stage the cutover precondition");

    coordinator
        .enable_lifecycle()
        .await
        .expect("enable_lifecycle must succeed once every precondition holds");

    let enabled: bool = direct
        .query_one(
            "SELECT lifecycle_enabled FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read lifecycle_enabled")
        .get(0);
    assert!(enabled);
}

/// P2-1 (reviewer follow-up): the newer-schema diagnostic was moved ahead of
/// the general `ready_for_lifecycle()` verdict specifically so it becomes
/// reachable -- behind that verdict it was dead code, since
/// `ready_for_lifecycle()` already folds the same upper bound in. Stages a
/// cell that is otherwise fully ready (cutover, residue, headroom all
/// satisfied) except `schema_version` is one past what this binary compiles
/// against, and asserts the specific "roll the binary forward" diagnostic
/// fires -- not just any `NotReady`, which the general verdict would also
/// produce and which would leave the reordering unfalsifiable.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn enable_lifecycle_refuses_with_the_roll_forward_diagnostic_when_schema_version_exceeds_the_binary()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    direct
        .execute(
            "UPDATE lore_fragment_schema_state \
                SET backfill_state = $1, cutover_at = clock_timestamp(), \
                    residue_classified = true, sequence_headroom_fence = 1, \
                    schema_version = $2 \
              WHERE id = 1",
            &[
                &schema::BACKFILL_CUTOVER,
                &(schema::FRAGMENT_SCHEMA_VERSION + 1),
            ],
        )
        .await
        .expect("stage an otherwise-ready cell one schema version ahead of the binary");

    let refusal = coordinator
        .enable_lifecycle()
        .await
        .expect_err("a cell ahead of the binary must refuse, not silently enable");
    let DomainError::NotReady(message) = refusal else {
        panic!("expected the typed NotReady error, got {refusal:?}");
    };
    assert!(
        message.contains("roll the binary forward"),
        "an otherwise-ready cell one schema version ahead of the binary must surface the \
         roll-forward diagnostic specifically, not the general readiness dump: {message:?}"
    );

    let enabled: bool = direct
        .query_one(
            "SELECT lifecycle_enabled FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .expect("read lifecycle_enabled")
        .get(0);
    assert!(
        !enabled,
        "a refused enable_lifecycle must not flip the flag"
    );
}

/// P1-2 item 5: a promotion whose I/O comes back `Unusable` must leave the
/// head `Staged` and still readable, must not commit `Missing`, and must not
/// move any repository's `fragment_lifecycle_generation` -- the actual bug
/// this path was added to fix (a transient provider error demoting a good
/// staged fragment).
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn abandon_promotion_leaves_the_head_staged_and_readable_and_moves_no_repository_lifecycle_generation()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("abandon-promotion/staged", 0xA5, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate staged fragment"),
        CommitVerdict::Published
    );

    let witness_before = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness before promotion")
        .expect("repository must exist");

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let verdict = coordinator
        .commit_promotion(
            &promotion_intent,
            IoObservation::Unusable(MissingDiagnostic::Truncated),
        )
        .await
        .expect("commit promotion must not error");
    assert_eq!(verdict, CommitVerdict::Abandoned);
    assert!(verdict.left_representation_intact());

    let head_row = direct
        .query_one(
            "SELECT current_epoch, state, manifest_id FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after abandon");
    let current_epoch: i64 = head_row.get(0);
    let state: i16 = head_row.get(1);
    let manifest_id: Option<Vec<u8>> = head_row.get(2);
    assert_eq!(
        state,
        FragmentLifecycleState::Staged.bits(),
        "an abandoned promotion must leave the head Staged, not Missing"
    );
    assert_eq!(
        current_epoch, stage_intent.epoch,
        "the head must still name the staged epoch, not the abandoned promotion epoch"
    );
    assert_eq!(
        manifest_id,
        Some(staged_manifest.manifest_id.clone()),
        "the staged manifest must survive an abandoned promotion untouched"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve after abandoned promotion");
    let (_, resolved_manifest, _) = expect_readable(&resolved[0]);
    assert_eq!(
        resolved_manifest, &staged_manifest,
        "the fragment must remain readable under its original staged representation"
    );

    let witness_after = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness after promotion abandon")
        .expect("repository must exist");
    assert_eq!(
        witness_after, witness_before,
        "an abandoned promotion must move neither push-witness scalar for the associated \
         repository"
    );
}

/// P1-2 item 6 / P1-3: nothing else reads `lore_fragment_epochs.disposition`.
/// A successful repair publishing a greater epoch must quarantine the
/// predecessor epoch and leave the successor `DISPOSITION_CURRENT_ELIGIBLE`.
/// WP-118's acceptance line claimed this was tested; it was not, and this is
/// the test that makes the corrected line true.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_successful_repair_quarantines_the_predecessor_epoch_and_marks_the_successor_current_eligible()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "quarantine/predecessor")
        .await
        .expect("begin predecessor")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "quarantine/predecessor",
                    0xB0,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit predecessor"),
        CommitVerdict::Published
    );
    let predecessor_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let predecessor_disposition_before: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &predecessor_epoch],
        )
        .await
        .expect("read predecessor disposition before repair")
        .get(0);
    assert_eq!(
        predecessor_disposition_before,
        schema::DISPOSITION_CURRENT_ELIGIBLE,
        "a freshly published epoch is current-eligible until superseded"
    );

    let resolved = coordinator
        .resolve(&repository_id, &context, std::slice::from_ref(&hash))
        .await
        .expect("resolve before repair");
    let (witness, ..) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&witness, MissingDiagnostic::Absent)
            .await
            .expect("mark missing"),
        CommitVerdict::Published
    );

    let BeginOutcome::Admitted(repair_intent) =
        coordinator.claim_repair(&hash).await.expect("claim repair")
    else {
        panic!("a Missing head must admit a repair claim");
    };
    let successor_epoch = repair_intent.epoch;
    assert!(
        successor_epoch > predecessor_epoch,
        "epochs are allocated from a monotonic sequence"
    );
    assert_eq!(
        coordinator
            .commit_repair(
                &repair_intent,
                IoObservation::Valid(manifest(
                    "quarantine/successor",
                    0xB1,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit repair"),
        CommitVerdict::Published
    );

    let predecessor_disposition_after: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &predecessor_epoch],
        )
        .await
        .expect("read predecessor disposition after repair")
        .get(0);
    assert_eq!(
        predecessor_disposition_after,
        schema::DISPOSITION_QUARANTINED,
        "the predecessor epoch must be quarantined once a greater epoch publishes"
    );

    let successor_disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &successor_epoch],
        )
        .await
        .expect("read successor disposition")
        .get(0);
    assert_eq!(
        successor_disposition,
        schema::DISPOSITION_CURRENT_ELIGIBLE,
        "the successor epoch must be current-eligible"
    );
}

// ---------------------------------------------------------------------------
// INV-EF P1-1 regression: begin_obliterate's fanout race (fixed at 76033cb).
// ---------------------------------------------------------------------------

/// P1-1: a `create_association` landing between `begin_obliterate`'s unlocked
/// plan read and its head lock must not be silently tombstoned by a
/// transaction that never locked its repository row and moved no scalar for
/// it. `confirm_lifecycle_fanout` now runs unconditionally (not just
/// `if was_readable`) and detects the growth, so the whole obliterate
/// transaction refuses with retryable `Contention` and mutates nothing.
///
/// Deterministic interleaving, not timing: repository R is already
/// associated (so it IS in the planned fanout, giving `lock_lifecycle_fanout`
/// something to block on), and this test holds R's row locked externally for
/// exactly as long as it takes the racing `create_association` -- to a
/// DIFFERENT repository, R2, outside the plan -- to commit. `begin_obliterate`
/// cannot pass R until that external lock releases, and by then R2's
/// association, and the head lock `create_association` itself took and
/// released, are already durably committed -- so `begin_obliterate` resumes
/// straight into the window the finding describes.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_concurrent_create_association_landing_between_the_plan_and_the_head_lock_is_refused_with_zero_mutation()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_r = create_repository(&store).await;
    let repository_r2 = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    // A non-readable head: Missing, from a failed first write.
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "p1-1-race/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    // R is associated BEFORE the race, so it is in begin_obliterate's planned
    // fanout and its lock_lifecycle_fanout loop must take R's row lock.
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_r, &context)
            .await
            .expect("associate R"),
        CommitVerdict::Published
    );

    let witness_r_before = coordinator
        .capture_push_witness(&repository_r)
        .await
        .expect("capture R witness before")
        .expect("repository R must exist");
    let witness_r2_before = coordinator
        .capture_push_witness(&repository_r2)
        .await
        .expect("capture R2 witness before")
        .expect("repository R2 must exist");

    // Hold R's row lock externally, on its own connection/transaction, so
    // begin_obliterate's lock_lifecycle_fanout blocks on it deterministically.
    let mut lock_client = own_transaction_client(&url).await;
    let lock_tx = lock_client
        .transaction()
        .await
        .expect("open external repository-lock transaction");
    lock_tx
        .execute(
            "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
            &[&repository_r.as_slice()],
        )
        .await
        .expect("lock repository R externally");

    let obliterate_task = async { coordinator.begin_obliterate(&hash).await };
    let race_task = async {
        // begin_obliterate is blocked on R's external lock regardless of this
        // delay -- it exists only to give it a moment to actually reach and
        // start waiting on R before the race proceeds.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_r2, &context)
                .await
                .expect("racing create_association must not error"),
            CommitVerdict::Published,
            "the racing association to R2 (outside the plan) must land"
        );
        // R2's association -- and the head lock create_association itself
        // took and released -- are now durably committed. Only now release
        // R, letting begin_obliterate resume straight into the window.
        lock_tx
            .commit()
            .await
            .expect("release the external repository lock");
    };
    let (obliterate_result, ()) = tokio::join!(obliterate_task, race_task);

    let error = obliterate_result.expect_err(
        "a fanout that grew between the plan and the head lock must refuse, not silently \
         tombstone the racing association",
    );
    assert!(
        matches!(error, DomainError::Contention(_)),
        "expected Contention, got {error:?}"
    );
    assert!(error.is_retryable(), "Contention must be retryable");

    // Zero mutation: the whole obliterate transaction rolled back.
    let head_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head after the refused obliterate")
        .get(0);
    assert_eq!(
        head_state,
        FragmentLifecycleState::Missing.bits(),
        "a refused obliterate must not move the head out of Missing"
    );

    let r2_association_state: i16 = direct
        .query_one(
            "SELECT state FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[&hash, &repository_r2.as_slice(), &context],
        )
        .await
        .expect("read R2's association state")
        .get(0);
    assert_eq!(
        r2_association_state,
        schema::ASSOCIATION_LIVE,
        "the racing association must not have been silently tombstoned"
    );

    let witness_r_after = coordinator
        .capture_push_witness(&repository_r)
        .await
        .expect("capture R witness after")
        .expect("repository R must exist");
    let witness_r2_after = coordinator
        .capture_push_witness(&repository_r2)
        .await
        .expect("capture R2 witness after")
        .expect("repository R2 must exist");
    assert_eq!(
        witness_r_after, witness_r_before,
        "R's scalars must be exactly as they were: it was never locked by the refused \
         obliterate and moved nothing attributable to it"
    );
    // R2's own `create_association` legitimately bumps its association scalar
    // by one -- that mutation is real and expected. What must NOT have
    // happened is a second movement from the refused obliterate (which would
    // show as +2, or any lifecycle-scalar movement at all).
    assert_eq!(
        witness_r2_after.content_association_generation,
        witness_r2_before.content_association_generation + 1,
        "R2's association scalar must move exactly once, from its own successful \
         create_association -- not a second time from a tombstone that never happened"
    );
    assert_eq!(
        witness_r2_after.fragment_lifecycle_generation,
        witness_r2_before.fragment_lifecycle_generation,
        "R2's lifecycle scalar must not move: the refused obliterate rolled back entirely"
    );
}

/// P1-1 companion (non-racy): the growth check inside `confirm_lifecycle_fanout`
/// now runs on every `begin_obliterate`, not only `if was_readable`. A plain,
/// non-concurrent obliterate of a `Missing` head with two live associations
/// would have caught the original defect on its own: the association scalar
/// must move for exactly the associated repositories even though the head was
/// never readable and no lifecycle-generation scalar moves at all.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn begin_obliterate_on_a_non_readable_head_moves_the_association_scalar_for_every_live_associated_repository()
 {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_a = create_repository(&store).await;
    let repository_b = create_repository(&store).await;
    let context = random_context();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "p1-1-nonrace/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .expect("commit missing"),
        CommitVerdict::Published
    );
    for repository_id in [&repository_a, &repository_b] {
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, &context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
    }

    let before_a = coordinator
        .capture_push_witness(&repository_a)
        .await
        .expect("capture A before")
        .expect("repository A must exist");
    let before_b = coordinator
        .capture_push_witness(&repository_b)
        .await
        .expect("capture B before")
        .expect("repository B must exist");

    let BeginOutcome::Admitted(_obliterate_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate on a Missing head with live associations")
    else {
        panic!("a non-tombstoned head must admit begin_obliterate");
    };

    let after_a = coordinator
        .capture_push_witness(&repository_a)
        .await
        .expect("capture A after")
        .expect("repository A must exist");
    let after_b = coordinator
        .capture_push_witness(&repository_b)
        .await
        .expect("capture B after")
        .expect("repository B must exist");

    for (before, after, label) in [(before_a, after_a, "A"), (before_b, after_b, "B")] {
        assert_eq!(
            after.content_association_generation,
            before.content_association_generation + 1,
            "repository {label}'s association scalar must move exactly once"
        );
        assert_eq!(
            after.fragment_lifecycle_generation, before.fragment_lifecycle_generation,
            "a head that was never readable crosses no readability boundary, so repository \
             {label}'s lifecycle scalar must not move"
        );
    }
}

// ---------------------------------------------------------------------------
// WP-118 pre-Phase-5 hardening review: STAGED_LEASE_MEMBER_NOT_STAGED's
// disposition clause, validate_lease_members, and equivalent_epochs' all-or-
// nothing rule over a real multi-fragment batch.
// ---------------------------------------------------------------------------

/// Reviewer finding A1: a `Staged` epoch whose bytes have been proved gone
/// (`DISPOSITION_PURGED`, reached via `begin_obliterate`/`commit_obliterate`
/// on a `Staged` head) must be refused the same way a `Remote` or fabricated
/// member is -- a lease over purged bytes would report protection that
/// cannot exist.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_purged_staged_member() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "purged-staged-member/staged",
                    0x90,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;

    let BeginOutcome::Admitted(obliterate_intent) = coordinator
        .begin_obliterate(&hash)
        .await
        .expect("begin obliterate")
    else {
        panic!("a readable (Staged) head must admit begin_obliterate");
    };
    assert_eq!(
        coordinator
            .commit_obliterate(&obliterate_intent)
            .await
            .expect("commit obliterate"),
        CommitVerdict::Published
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let result = coordinator
        .acquire_staged_leases(&lease_id, &[(hash, staged_epoch)], deadline)
        .await;
    match result {
        Err(DomainError::PreconditionRejected {
            reason,
            reason_version,
        }) => {
            assert_eq!(reason, STAGED_LEASE_MEMBER_NOT_STAGED);
            assert_eq!(reason_version, 1);
        }
        other => panic!(
            "expected STAGED_LEASE_MEMBER_NOT_STAGED for a purged staged epoch, got {other:?}"
        ),
    }
}

/// Reviewer finding A1's other half: a `Staged` epoch that has been
/// quarantined by a later promotion (its successor now `Remote`, itself
/// still `DISPOSITION_QUARANTINED`, never `DISPOSITION_PURGED`) must still be
/// admitted. This is what stops the disposition clause from over-correcting
/// into refusing every superseded staged epoch, not only purged ones -- a
/// reader still mid-hydration against a quarantined staged epoch is exactly
/// what the lease protects.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_admits_a_quarantined_staged_member() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let BeginOutcome::Admitted(stage_intent) =
        coordinator.begin_stage(&hash).await.expect("begin stage")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(
                &stage_intent,
                IoObservation::Valid(manifest(
                    "quarantined-staged-member/staged",
                    0x91,
                    EpochAuthority::Staged
                ))
            )
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    let staged_epoch = stage_intent.epoch;

    let BeginOutcome::Admitted(promotion_intent) = coordinator
        .begin_promotion(&hash)
        .await
        .expect("begin promotion")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    assert_eq!(
        coordinator
            .commit_promotion(
                &promotion_intent,
                IoObservation::Valid(manifest(
                    "quarantined-staged-member/promoted",
                    0x92,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit promotion"),
        CommitVerdict::Published
    );

    // Confirm the staged epoch really is quarantined now -- not purged, and
    // not (still) current-eligible -- so this case cannot silently degenerate
    // into "any disposition is fine" or coincide with the purged case above.
    let disposition: i16 = direct
        .query_one(
            "SELECT disposition FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &staged_epoch],
        )
        .await
        .expect("read staged epoch disposition after promotion")
        .get(0);
    assert_eq!(
        disposition,
        schema::DISPOSITION_QUARANTINED,
        "the staged predecessor epoch must be quarantined once its promotion publishes"
    );

    let lease_id = rand::random::<[u8; 16]>().to_vec();
    let lease = coordinator
        .acquire_staged_leases(&lease_id, &[(hash.clone(), staged_epoch)], deadline)
        .await
        .expect("a quarantined staged epoch must still admit a lease");
    assert_eq!(lease.members, vec![(hash, staged_epoch)]);
}

/// `validate_lease_members` runs before any database work: a batch repeating
/// one hash at two epochs, and an empty batch, are both refused as
/// [`DomainError::InvalidInput`] with zero rows written. Neither epoch here
/// needs to be real -- the refusal is purely about the shape of the input
/// tuples, which is exactly what makes it a pure, DB-independent guard.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn acquire_staged_leases_refuses_a_duplicate_hash_batch_and_an_empty_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let deadline = microsecond_deadline(Duration::from_secs(60));

    let hash = random_hash();
    let duplicate_hash_batch = vec![(hash.clone(), 1i64), (hash, 2i64)];
    let lease_id_duplicate = rand::random::<[u8; 16]>().to_vec();
    let duplicate_result = coordinator
        .acquire_staged_leases(&lease_id_duplicate, &duplicate_hash_batch, deadline)
        .await;
    assert!(
        matches!(duplicate_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput for a duplicate-hash batch, got {duplicate_result:?}"
    );
    let duplicate_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_duplicate],
        )
        .await
        .expect("count lease rows for a duplicate-hash batch")
        .get(0);
    assert_eq!(
        duplicate_lease_rows, 0,
        "a duplicate-hash batch must be refused before any database write"
    );

    let lease_id_empty = rand::random::<[u8; 16]>().to_vec();
    let empty_result = coordinator
        .acquire_staged_leases(&lease_id_empty, &[], deadline)
        .await;
    assert!(
        matches!(empty_result, Err(DomainError::InvalidInput(_))),
        "expected InvalidInput for an empty batch, got {empty_result:?}"
    );
    let empty_lease_rows: i64 = direct
        .query_one(
            "SELECT count(*)::bigint FROM lore_fragment_staged_leases WHERE lease_id = $1",
            &[&lease_id_empty],
        )
        .await
        .expect("count lease rows for an empty batch")
        .get(0);
    assert_eq!(
        empty_lease_rows, 0,
        "an empty batch must be refused before any database write"
    );
}

/// A required fragment whose CAPTURED epoch was never published for that hash
/// at all (not merely superseded) must abort, even though the head is
/// genuinely readable at some other epoch. `equivalent_epochs` joins
/// `lore_fragment_epochs` on the captured epoch; when that row does not
/// exist, the join drops the pair, `matched` falls short of `divergent.len()`,
/// and the all-or-nothing rule aborts the whole push.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_aborts_when_the_captured_epoch_was_never_published() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository_id = create_repository(&store).await;
    let context = random_context();

    let hash = random_hash();
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, "captured-epoch-missing/key")
        .await
        .expect("begin")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(manifest(
                    "captured-epoch-missing/key",
                    0x93,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit"),
        CommitVerdict::Published
    );
    let real_epoch = intent.epoch;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository_id, &context)
            .await
            .expect("associate"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // Move the lifecycle scalar via a bystander so the call reaches the
    // fallback rather than short-circuiting on `Unchanged`.
    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, "captured-epoch-missing/bystander")
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "captured-epoch-missing/bystander",
                    0x94,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // A captured epoch guaranteed never published for this hash: far outside
    // any value this test's own fence sequence could reach, and distinct from
    // the real current epoch.
    let never_published_epoch = real_epoch + 1_000_000_000;
    assert_ne!(never_published_epoch, real_epoch);
    let required = vec![RequiredFragment {
        hash,
        epoch: never_published_epoch,
    }];

    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &required)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        }
    );
}

/// `equivalent_epochs`' all-or-nothing rule (`matched == divergent.len()`)
/// cannot be discriminated by a one-element `required` slice -- both branches
/// of the boolean collapse to the same answer at `len() == 1`. A genuine
/// two-fragment batch is required: two fragments both promoted equivalently
/// pins the exact `revalidated: 2` count, and swapping one of them for a
/// non-equivalent promotion must abort the WHOLE push, not just the one
/// fragment that diverged.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn revalidate_push_witness_all_or_nothing_over_a_mixed_divergent_batch() {
    let Some(url) = pg_url() else {
        panic!("runner must set LORE_TEST_PG_URL")
    };
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let repository_id = create_repository(&store).await;
    let context = random_context();

    async fn stage_and_associate(
        coordinator: &PostgresFragmentCoordinator,
        repository_id: &[u8],
        context: &[u8],
        key_prefix: &str,
        seed: u8,
    ) -> (Vec<u8>, i64, FragmentManifest) {
        let hash = random_hash();
        let BeginOutcome::Admitted(stage_intent) =
            coordinator.begin_stage(&hash).await.expect("begin stage")
        else {
            panic!("a fresh hash must admit a stage begin");
        };
        let staged_manifest = manifest(
            &format!("{key_prefix}/staged"),
            seed,
            EpochAuthority::Staged,
        );
        assert_eq!(
            coordinator
                .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
                .await
                .expect("commit staged"),
            CommitVerdict::Published
        );
        assert_eq!(
            coordinator
                .create_association(&hash, repository_id, context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );
        (hash, stage_intent.epoch, staged_manifest)
    }

    let (hash_a, original_epoch_a, staged_manifest_a) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/a-equivalent",
        0xA0,
    )
    .await;
    let (hash_b, original_epoch_b, staged_manifest_b) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/b-equivalent",
        0xA1,
    )
    .await;
    let (hash_c, original_epoch_c, staged_manifest_c) = stage_and_associate(
        &coordinator,
        &repository_id,
        &context,
        "mixed-batch/c-divergent",
        0xA2,
    )
    .await;

    let bystander_hash = random_hash();
    let BeginOutcome::Admitted(bystander_intent) = coordinator
        .begin_direct_write(&bystander_hash, "mixed-batch/bystander")
        .await
        .expect("begin bystander")
    else {
        panic!("a fresh hash must admit a direct write");
    };
    assert_eq!(
        coordinator
            .commit_remote(
                &bystander_intent,
                IoObservation::Valid(manifest(
                    "mixed-batch/bystander",
                    0xA9,
                    EpochAuthority::Remote
                ))
            )
            .await
            .expect("commit bystander"),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .create_association(&bystander_hash, &repository_id, &context)
            .await
            .expect("associate bystander"),
        CommitVerdict::Published
    );

    let captured = coordinator
        .capture_push_witness(&repository_id)
        .await
        .expect("capture witness")
        .expect("repository must exist");

    // A and B: promote equivalently (identical decoded_hash/size_content/
    // size_payload/payload_flags; different object_key and manifest_id).
    for (hash, staged_manifest, key) in [
        (&hash_a, &staged_manifest_a, "mixed-batch/a-promoted"),
        (&hash_b, &staged_manifest_b, "mixed-batch/b-promoted"),
    ] {
        let BeginOutcome::Admitted(promotion_intent) = coordinator
            .begin_promotion(hash)
            .await
            .expect("begin promotion")
        else {
            panic!("a Staged head must admit begin_promotion");
        };
        let mut promoted = staged_manifest.clone();
        promoted.authority = EpochAuthority::Remote;
        promoted.object_key = key.to_owned();
        promoted.manifest_id = vec![0xAF; 32];
        assert_eq!(
            coordinator
                .commit_promotion(&promotion_intent, IoObservation::Valid(promoted))
                .await
                .expect("commit promotion"),
            CommitVerdict::Published
        );
    }

    // C: promote with a different decoded_hash -- genuinely different content.
    let BeginOutcome::Admitted(promotion_c) = coordinator
        .begin_promotion(&hash_c)
        .await
        .expect("begin promotion c")
    else {
        panic!("a Staged head must admit begin_promotion");
    };
    let mut promoted_c = staged_manifest_c.clone();
    promoted_c.authority = EpochAuthority::Remote;
    promoted_c.object_key = "mixed-batch/c-promoted".to_owned();
    promoted_c.manifest_id = vec![0xCA; 32];
    promoted_c.decoded_hash = vec![0xFF; 32];
    assert_ne!(promoted_c.decoded_hash, staged_manifest_c.decoded_hash);
    assert_eq!(
        coordinator
            .commit_promotion(&promotion_c, IoObservation::Valid(promoted_c))
            .await
            .expect("commit promotion c"),
        CommitVerdict::Published
    );

    // Move the lifecycle scalar so both revalidations below reach the
    // fallback branch rather than short-circuiting on `Unchanged`.
    let resolved_bystander = coordinator
        .resolve(
            &repository_id,
            &context,
            std::slice::from_ref(&bystander_hash),
        )
        .await
        .expect("resolve bystander");
    let (bystander_witness, ..) = expect_readable(&resolved_bystander[0]);
    let bystander_witness = bystander_witness.clone();
    assert_eq!(
        coordinator
            .mark_missing(&bystander_witness, MissingDiagnostic::Absent)
            .await
            .expect("mark bystander missing"),
        CommitVerdict::Published
    );

    // Every epoch really did advance -- this is what stops the case from
    // silently degenerating into an exact-match path for any of the three.
    for (hash, original_epoch, label) in [
        (&hash_a, original_epoch_a, "a"),
        (&hash_b, original_epoch_b, "b"),
        (&hash_c, original_epoch_c, "c"),
    ] {
        let current_epoch: i64 = direct
            .query_one(
                "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash = $1",
                &[hash],
            )
            .await
            .expect("read current epoch after promotion")
            .get(0);
        assert_ne!(
            current_epoch, original_epoch,
            "{label}: the epoch must have genuinely advanced"
        );
    }

    // Part 1: two REQUIRED fragments, both promoted equivalently -- the
    // fallback's exact revalidated count is pinned at 2, not just some
    // positive number, or the length of an incidentally-1-element slice.
    let both_equivalent = vec![
        RequiredFragment {
            hash: hash_a.clone(),
            epoch: original_epoch_a,
        },
        RequiredFragment {
            hash: hash_b.clone(),
            epoch: original_epoch_b,
        },
    ];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(
            &tx,
            &mut sequence,
            &repository_id,
            captured,
            &both_equivalent,
        )
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::FallbackSatisfied { revalidated: 2 }
    );
    // Neither `tx` nor `tx_client` was ever committed, so `tx`'s `FOR UPDATE`
    // lock on hash_a's and hash_b's rows is still held until dropped. Part 2
    // below re-locks hash_a in a SEPARATE transaction on a separate pool --
    // without an explicit drop here, shadowing `tx`/`tx_client` with new `let`
    // bindings does not free them (Rust drops shadowed values at end of
    // scope, not at shadowing), and Part 2 would block forever waiting on a
    // lock this same test still holds. Revert-checked: removing these two
    // `drop`s reproduces the hang deterministically.
    drop(tx);
    drop(tx_client);

    // Part 2: swap B for C (non-equivalent). One equivalent member and one
    // non-equivalent member in the SAME batch must abort the whole push, not
    // just skip the bad one.
    let mixed = vec![
        RequiredFragment {
            hash: hash_a,
            epoch: original_epoch_a,
        },
        RequiredFragment {
            hash: hash_c,
            epoch: original_epoch_c,
        },
    ];
    let mut tx_client = own_transaction_client(&url).await;
    let tx = tx_client
        .transaction()
        .await
        .expect("open push-witness transaction");
    let mut sequence = LockSequence::new();
    let verdict = coordinator
        .revalidate_push_witness(&tx, &mut sequence, &repository_id, captured, &mixed)
        .await
        .expect("revalidate must not error");
    assert_eq!(
        verdict,
        PushWitnessVerdict::Aborted {
            reason: REQUIRED_FRAGMENT_CHANGED
        },
        "one non-equivalent member in an otherwise-equivalent batch must abort the whole push"
    );
}

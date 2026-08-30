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
use lore_postgres::domain::fragments::MissingDiagnostic;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
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

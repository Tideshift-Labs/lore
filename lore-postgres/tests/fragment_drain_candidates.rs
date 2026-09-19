// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live-Postgres proof for WP-122's `staged_drain_candidates` bounded plan
//! query on `PostgresFragmentCoordinator`.
//!
//! Unlike `write_behind_staging_lifecycle.rs`, this file is **not** Unix-gated.
//! `staged_drain_candidates` is a pure SQL plan query with no filesystem
//! interaction, and every fixture it needs (`begin_stage`/`commit_staged`,
//! `begin_promotion`, `begin_direct_write`/`commit_remote`, and raw fixture
//! rows for shapes those entry points don't produce) is Postgres-only. It must
//! run on Windows exactly as it does on Linux.
//!
//! Every case is `#[ignore]` and needs `LORE_TEST_PG_URL` -- run via
//! `cargo test -p lore-postgres --test fragment_drain_candidates -- --ignored`
//! or `tests/run-fragment-lifecycle-live.ps1`, which gives each case its own
//! fresh database.

use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::FragmentDrainCandidate;
use lore_postgres::domain::fragments::FragmentDrainCandidateBatch;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::FragmentWriteClaimInput;
use lore_postgres::domain::fragments::FragmentWriteSettlement;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers (self-contained: this file is its own compiled test binary, so
// these deliberately mirror rather than share `domain_fragment_lifecycle.rs`'s
// and `fragment_promotion_send_claim.rs`'s helpers of the same name).
// ---------------------------------------------------------------------------

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn store(url: &str) -> PostgresDomainStore {
    let store = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
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

fn random_hash() -> Vec<u8> {
    rand::random::<[u8; 32]>().to_vec()
}

fn legacy_key(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn manifest(object_key: &str, seed: u8, authority: EpochAuthority) -> FragmentManifest {
    FragmentManifest {
        authority,
        object_key: object_key.to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 100,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 7,
    }
}

/// A fresh write-claim input, generous deadlines by default.
fn write_claim() -> FragmentWriteClaimInput {
    FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        [0xA5; 32],
        1,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .expect("valid test write claim")
}

/// Stage and publish a hash so its head is `Staged` and eligible for a drain
/// candidate. Returns the staged epoch and manifest.
async fn stage_hash(
    coordinator: &PostgresFragmentCoordinator,
    hash: &[u8],
    seed: u8,
) -> (i64, FragmentManifest) {
    let BeginOutcome::Admitted(stage_intent) = coordinator
        .begin_stage(hash)
        .await
        .expect("begin stage on a fresh hash")
    else {
        panic!("a fresh hash must admit a stage begin");
    };
    let staged_manifest = manifest("drain-candidates/staged", seed, EpochAuthority::Staged);
    assert_eq!(
        coordinator
            .commit_staged(&stage_intent, IoObservation::Valid(staged_manifest.clone()))
            .await
            .expect("commit_staged against a fresh intent"),
        CommitVerdict::Published
    );
    (stage_intent.epoch, staged_manifest)
}

async fn candidates(
    coordinator: &PostgresFragmentCoordinator,
    max_candidates: u32,
) -> Vec<FragmentDrainCandidate> {
    coordinator
        .staged_drain_candidates(
            FragmentDrainCandidateBatch::new(max_candidates).expect("valid test batch"),
        )
        .await
        .expect("staged_drain_candidates")
}

fn hashes(returned: &[FragmentDrainCandidate]) -> Vec<Vec<u8>> {
    returned.iter().map(|c| c.hash().to_vec()).collect()
}

/// Insert a raw fixture head with no matching epoch row, for a non-Staged
/// state the coordinator's own public entry points don't cheaply produce
/// (`PreparingStage`, `Missing`, `Tombstoned`). `manifest_id` must be `NULL`
/// for these states -- `lore_fragment_lifecycle_readable_shape` makes any
/// other shape unrepresentable.
async fn insert_unreadable_head(direct: &Client, hash: &[u8], state: FragmentLifecycleState) {
    direct
        .execute(
            "INSERT INTO lore_fragment_lifecycle \
                 (hash, current_epoch, state, manifest_id, last_fence) \
             VALUES ($1, 1, $2, NULL, 1)",
            &[&hash, &state.bits()],
        )
        .await
        .expect("insert unreadable head fixture");
}

/// Insert a raw, live `Prepared` write-claim row on `hash`: `send_not_after`
/// one hour out, `hard_not_after` two hours out. This is the send-barrier the
/// anti-join in `staged_drain_candidates` excludes on.
async fn insert_live_prepared_claim(direct: &Client, hash: &[u8], seed: u8) {
    let logical_request_id = vec![seed; 16];
    let attempt_id = vec![seed.wrapping_add(1); 16];
    direct
        .execute(
            "INSERT INTO lore_fragment_write_claims ( \
                 logical_request_id, attempt_id, hash, epoch, fence, authority, \
                 object_key, body_blake3, body_size, state, send_not_after, \
                 hard_not_after, prepared_at \
             ) VALUES ( \
                 $1, $2, $3, 1, 1, 2, 'drain-barrier-fixture', $4, 1, 0, \
                 clock_timestamp() + interval '1 hour', \
                 clock_timestamp() + interval '2 hours', \
                 clock_timestamp() - interval '1 hour' \
             )",
            &[&logical_request_id, &attempt_id, &hash, &vec![seed; 32]],
        )
        .await
        .expect("insert prepared write claim fixture");
}

/// Elapse the barrier fixture's send window into the past (its
/// `hard_not_after`, set two hours out by [`insert_live_prepared_claim`],
/// stays comfortably ahead of it, satisfying `send_not_after < hard_not_after`).
async fn elapse_claim_send_window(direct: &Client, hash: &[u8]) {
    direct
        .execute(
            "UPDATE lore_fragment_write_claims \
                SET send_not_after = clock_timestamp() - interval '1 second' \
              WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("update claim send_not_after");
}

async fn epoch_row(
    direct: &Client,
    hash: &[u8],
    epoch: i64,
) -> (
    String,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
) {
    let row = direct
        .query_one(
            "SELECT object_key, manifest_id, size_payload, size_content, decoded_hash, \
                    payload_flags, provider_body_blake3, provider_body_size \
               FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &epoch],
        )
        .await
        .expect("read the durable epoch row");
    (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
        row.get(7),
    )
}

async fn lifecycle_row(direct: &Client, hash: &[u8]) -> (i64, i64) {
    let row = direct
        .query_one(
            "SELECT current_epoch, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read the durable lifecycle head");
    (row.get(0), row.get(1))
}

// ---------------------------------------------------------------------------
// Cases
//
// The offline `FragmentDrainCandidateBatch::new` bound is pinned once, in
// `fragment_drain_candidate_schema.rs`, not duplicated here.
// ---------------------------------------------------------------------------

/// Case 1: a `Staged` head with a current, current-eligible, `Staged`-authority
/// epoch whose manifest matches the head is returned, and every accessor
/// equals the durable row read back independently -- never the fixture's own
/// intent.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_staged_head_with_a_matching_current_epoch_is_returned_with_every_accessor_equal_to_the_durable_row()
 {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    let (epoch, _manifest) = stage_hash(&coordinator, &hash, 0x11).await;

    let returned = candidates(&coordinator, 10).await;
    let candidate = returned
        .iter()
        .find(|c| c.hash() == hash.as_slice())
        .expect("the staged head must be a drain candidate");

    let (current_epoch, last_fence) = lifecycle_row(&direct, &hash).await;
    let (
        object_key,
        manifest_id,
        size_payload,
        size_content,
        decoded_hash,
        payload_flags,
        provider_body_blake3,
        provider_body_size,
    ) = epoch_row(&direct, &hash, epoch).await;

    assert_eq!(candidate.epoch(), current_epoch);
    assert_eq!(candidate.last_fence(), last_fence);
    assert_eq!(candidate.object_key(), object_key);
    assert_eq!(candidate.manifest_id(), manifest_id.as_slice());
    assert_eq!(
        candidate.size_payload(),
        u64::try_from(size_payload).unwrap()
    );
    assert_eq!(candidate.size_content(), size_content);
    assert_eq!(candidate.decoded_hash(), decoded_hash.as_slice());
    assert_eq!(candidate.payload_flags(), payload_flags);
    assert_eq!(
        candidate.provider_body_blake3().map(|d| d.to_vec()),
        provider_body_blake3
    );
    assert_eq!(
        candidate.provider_body_size(),
        provider_body_size.map(|s| u64::try_from(s).unwrap())
    );
}

/// Case 2: a `Remote` head is not returned.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_remote_head_is_not_returned() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();

    let BeginOutcome::Admitted(intent) = coordinator
        .begin_direct_write(&hash, &legacy_key(&hash), write_claim())
        .await
        .expect("begin direct write on a fresh hash")
    else {
        panic!("a fresh hash must admit a direct write begin");
    };
    let claim = intent.write_claim().expect("direct write claim").clone();
    coordinator
        .authorize_write_claim(&claim)
        .await
        .expect("authorize direct write claim");
    let remote_manifest = manifest("drain-candidates/remote", 0x21, EpochAuthority::Remote);
    assert_eq!(
        coordinator
            .commit_remote(
                &intent,
                IoObservation::Valid(remote_manifest),
                FragmentWriteSettlement::Decisive,
            )
            .await
            .expect("commit_remote"),
        CommitVerdict::Published
    );

    let returned = candidates(&coordinator, 10).await;
    assert!(
        !hashes(&returned).contains(&hash),
        "a Remote head must never be a staged drain candidate"
    );
}

/// Case 3: a head in `PreparingStage`, `Missing`, and `Tombstoned` is not
/// returned. One assertion set over all three, per the dispatch spec.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn preparing_stage_missing_and_tombstoned_heads_are_not_returned() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;

    let preparing_stage = random_hash();
    let missing = random_hash();
    let tombstoned = random_hash();
    insert_unreadable_head(
        &direct,
        &preparing_stage,
        FragmentLifecycleState::PreparingStage,
    )
    .await;
    insert_unreadable_head(&direct, &missing, FragmentLifecycleState::Missing).await;
    insert_unreadable_head(&direct, &tombstoned, FragmentLifecycleState::Tombstoned).await;

    let returned = hashes(&candidates(&coordinator, 50).await);
    for (label, hash) in [
        ("PreparingStage", &preparing_stage),
        ("Missing", &missing),
        ("Tombstoned", &tombstoned),
    ] {
        assert!(
            !returned.contains(hash),
            "{label} head must never be a staged drain candidate"
        );
    }
}

/// Case 4: a `Staged` head whose `active_operation` is stamped -- via a real
/// `begin_promotion`, not a hand-written UPDATE -- is not returned. A real
/// promotion simultaneously stamps ownership AND creates a live write claim on
/// the same hash, so this head is also barrier-excluded; that is the real
/// production shape, not a test artifact, and the coordinator's own doc
/// comment states both exclusions exist for exactly this reason.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_staged_head_with_active_operation_stamped_by_a_real_promotion_is_not_returned() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x31).await;

    let BeginOutcome::Admitted(_intent) = coordinator
        .begin_promotion(&hash, write_claim())
        .await
        .expect("begin promotion on a Staged head")
    else {
        panic!("a Staged head must admit a promotion begin");
    };

    let returned = hashes(&candidates(&coordinator, 10).await);
    assert!(
        !returned.contains(&hash),
        "a head owned by an in-flight promotion must never be a staged drain candidate"
    );
}

/// Case 5: the barrier case, with its negative control. A `Staged` head whose
/// hash carries a live `Prepared` claim (`send_not_after` in the future) is
/// not returned; the SAME head with the claim's window elapsed IS returned.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_live_prepared_claim_blocks_the_hash_and_an_elapsed_one_releases_it() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x41).await;

    insert_live_prepared_claim(&direct, &hash, 0x42).await;
    let blocked = hashes(&candidates(&coordinator, 10).await);
    assert!(
        !blocked.contains(&hash),
        "a live Prepared claim (send_not_after in the future) must block the hash"
    );

    elapse_claim_send_window(&direct, &hash).await;
    let released = hashes(&candidates(&coordinator, 10).await);
    assert!(
        released.contains(&hash),
        "the SAME head, once the claim's send window has elapsed, must be a candidate again"
    );
}

/// Case 6: batch bound and order. With N+1 eligible staged heads and a batch
/// of N, exactly N rows come back, in ascending `hash` order.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn batch_bound_and_order_returns_exactly_n_in_ascending_hash_order() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();

    let mut fixture_hashes = Vec::new();
    for seed in 0u8..5 {
        let hash = random_hash();
        stage_hash(&coordinator, &hash, 0x50 + seed).await;
        fixture_hashes.push(hash);
    }
    let mut sorted = fixture_hashes.clone();
    sorted.sort();

    let batch_size = u32::try_from(fixture_hashes.len() - 1).expect("small fixture count");
    let returned = candidates(&coordinator, batch_size).await;
    assert_eq!(
        returned.len(),
        usize::try_from(batch_size).unwrap(),
        "exactly the batch bound must come back when more are eligible"
    );
    let returned_hashes = hashes(&returned);
    let expected_prefix = sorted[..usize::try_from(batch_size).unwrap()].to_vec();
    assert_eq!(
        returned_hashes, expected_prefix,
        "results must be exactly the lowest-hash prefix, in ascending order"
    );
}

/// Case 7: `provider_body_blake3()` is `None` on a candidate produced by the
/// real `commit_staged` path -- the C4 anchor fact the method's doc comment
/// depends on. Pinned separately from case 1 so a future change to the
/// staging path that starts populating this field cannot silently flip it
/// without a dedicated case failing.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_commit_staged_candidate_never_carries_a_provider_body_digest() {
    let url = pg_url().expect("runner must set LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let hash = random_hash();
    stage_hash(&coordinator, &hash, 0x61).await;

    let returned = candidates(&coordinator, 10).await;
    let candidate = returned
        .iter()
        .find(|c| c.hash() == hash.as_slice())
        .expect("the staged head must be a drain candidate");
    assert!(
        candidate.provider_body_blake3().is_none(),
        "commit_staged creates no write claim, so no epoch it produces can carry provider evidence"
    );
    assert!(candidate.provider_body_size().is_none());
}

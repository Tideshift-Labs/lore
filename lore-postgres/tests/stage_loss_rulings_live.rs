// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live-Postgres proof for `stage resolve-lost`'s database half
//! (`lore_postgres::domain::fragments::stage_loss`): the selection, the
//! confirm token against a real re-selection, the recorded ruling and its
//! refusals, and the drain's one-transaction carry-out, refresh and close.
//!
//! The drain's file half (its pinned miss, guard and echo evidence) is Unix
//! only and runs in `run-write-behind-linux.ps1`
//! (`adapter_tests::loss_ruling_tests`). These cases need no filesystem.
//!
//! Every case is `#[ignore]` and needs `LORE_TEST_PG_URL`; run them through
//! `tests/run-fragment-lifecycle-live.ps1`, which gives each case its own
//! fresh database.

#[path = "common/stage_policy.rs"]
mod stage_policy;

use std::time::Duration;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::CommitVerdict;
use lore_postgres::domain::fragments::EpochAuthority;
use lore_postgres::domain::fragments::EpochWitness;
use lore_postgres::domain::fragments::FragmentManifest;
use lore_postgres::domain::fragments::IoObservation;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::fragments::StageReservationInput;
use lore_postgres::domain::fragments::stage_loss::LossApply;
use lore_postgres::domain::fragments::stage_loss::LossApplyOutcome;
use lore_postgres::domain::fragments::stage_loss::LossApplyRefusal;
use lore_postgres::domain::fragments::stage_loss::LossEvidence;
use lore_postgres::domain::fragments::stage_loss::LossFilter;
use lore_postgres::domain::fragments::stage_loss::LossOutcome;
use lore_postgres::domain::fragments::stage_loss::LossRulingReader;
use lore_postgres::domain::fragments::stage_loss::MarkMissingOutcome;
use lore_postgres::domain::fragments::stage_loss::TokenRefusal;
use lore_postgres::domain::fragments::stage_loss::apply_loss_rulings;
use lore_postgres::domain::fragments::stage_loss::confirm_token;
use lore_postgres::domain::fragments::stage_loss::list_lost_staged;
use lore_postgres::domain::fragments::stage_loss::loss_rulings;
use lore_postgres::domain::fragments::states::FragmentLifecycleState;
use lore_postgres::domain::fragments::states::MissingDiagnostic;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;

const CELL: &str = "cell-loss";
const FRESH: Duration = Duration::from_secs(10);

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass")
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
    stage_policy::initialize(url, &store.fragment_coordinator()).await;
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

/// An operator-sized pool: one connection, as the command uses.
fn operator_pool(url: &str) -> lore_postgres::pool::Pool {
    lore_postgres::pool::build_pool(url, 1, &TlsConfig::default()).expect("operator pool")
}

fn hash(byte: u8) -> Vec<u8> {
    let mut hash = rand::random::<[u8; 32]>().to_vec();
    // A fixed first byte orders the cases' hashes for readable assertions.
    hash[0] = byte;
    hash
}

fn manifest(seed: u8) -> FragmentManifest {
    FragmentManifest {
        authority: EpochAuthority::Staged,
        object_key: "loss-rulings/staged".to_owned(),
        manifest_id: vec![seed; 32],
        size_payload: 128,
        size_content: 100,
        decoded_hash: vec![seed.wrapping_add(1); 32],
        payload_flags: 7,
    }
}

/// Stage and publish `hash` so its head is `Staged` with live custody.
async fn stage(coordinator: &PostgresFragmentCoordinator, hash: &[u8], seed: u8) -> i64 {
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(
            hash,
            StageReservationInput {
                size_payload: 128,
                original_flags: 7,
            },
        )
        .await
        .expect("begin stage")
    else {
        panic!("a fresh or Missing hash admits a stage begin");
    };
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest(seed)))
            .await
            .expect("commit staged"),
        CommitVerdict::Published
    );
    intent.epoch
}

async fn age(direct: &Client, hash: &[u8], hours: i32) {
    direct
        .execute(
            "UPDATE lore_fragment_epochs \
                SET created_at = clock_timestamp() - make_interval(hours => $2) WHERE hash = $1",
            &[&hash, &hours],
        )
        .await
        .expect("age the epoch row");
}

async fn record_stager(direct: &Client, hash: &[u8], epoch: i64, replica: &str, incarnation: &str) {
    direct
        .execute(
            "INSERT INTO lore_domain_write_behind_stagers (hash, epoch, replica_id, incarnation) \
             VALUES ($1, $2, $3, $4)",
            &[&hash, &epoch, &replica, &incarnation],
        )
        .await
        .expect("record the stager");
}

/// Publish `replica`'s liveness row in `CELL`, `published` seconds ago.
async fn publish_liveness(direct: &Client, replica: &str, incarnation: &str, published: i32) {
    publish_liveness_in(direct, CELL, replica, incarnation, published).await;
}

/// [`publish_liveness`] under any cell id.
async fn publish_liveness_in(
    direct: &Client,
    cell: &str,
    replica: &str,
    incarnation: &str,
    published: i32,
) {
    direct
        .execute(
            "INSERT INTO lore_domain_write_behind_stage_progress \
                 (cell_id, replica_id, incarnation, progress, progressed_at, published_at, role) \
             VALUES ($1, $2, $3, 1, clock_timestamp(), \
                     clock_timestamp() - make_interval(secs => $4), 'stage') \
             ON CONFLICT (cell_id, replica_id) DO UPDATE SET incarnation = EXCLUDED.incarnation, \
                 published_at = EXCLUDED.published_at",
            &[&cell, &replica, &incarnation, &f64::from(published)],
        )
        .await
        .expect("publish liveness");
}

async fn bind(coordinator: &PostgresFragmentCoordinator, direct: &Client, hash: &[u8], repo: u8) {
    direct
        .execute(
            "INSERT INTO lore_domain_repositories(repository_id,state,generation,name,\
             metadata_hash,default_branch_id,creation_fingerprint_version,\
             creation_fingerprint,created_at) \
             VALUES($1,0,1,'loss',$2,$3,1,$2,clock_timestamp()) ON CONFLICT DO NOTHING",
            &[&vec![repo; 16], &vec![0x78u8; 32], &vec![0x79u8; 16]],
        )
        .await
        .expect("repository row");
    assert_eq!(
        coordinator
            .create_association(hash, &[repo; 16], &[repo; 16])
            .await
            .expect("associate"),
        CommitVerdict::Published
    );
}

fn filter() -> LossFilter {
    LossFilter {
        hash: None,
        stager: None,
        repository: None,
        min_age: Duration::from_secs(3_600),
        limit: 1_000,
    }
}

async fn head(direct: &Client, hash: &[u8]) -> (i16, i64, i64) {
    let row = direct
        .query_one(
            "SELECT state, current_epoch, last_fence FROM lore_fragment_lifecycle WHERE hash = $1",
            &[&hash],
        )
        .await
        .expect("read head");
    (row.get(0), row.get(1), row.get(2))
}

async fn ruling_row(direct: &Client, hash: &[u8]) -> tokio_postgres::Row {
    direct
        .query_one(
            "SELECT ruling_id, outcome, evidence, attested, multi_repository, repositories, \
                    selection, actor, reason, token, drain_replica_id, drain_incarnation, \
                    decided_at IS NOT NULL AS decided, expires_at > created_at AS expiry_ok \
               FROM lore_domain_stage_loss_rulings WHERE hash = $1 ORDER BY ruling_id DESC LIMIT 1",
            &[&hash],
        )
        .await
        .expect("read ruling")
}

/// Move the newest ruling of `hash` past its expiry, as if a day went by.
/// The audit trigger refuses any change to a ruling column, so the fixture
/// bypasses it for this one statement (`session_replication_role = replica`
/// skips ordinary triggers; the test database's role is a superuser).
async fn expire(direct: &Client, hash: &[u8]) {
    direct
        .batch_execute(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             UPDATE lore_domain_stage_loss_rulings \
                SET created_at = clock_timestamp() - interval '2 days', \
                    expires_at = clock_timestamp() - interval '1 second' \
              WHERE hash = '\\x{}'::bytea AND outcome IS NULL; \
             COMMIT;",
            hex::encode(hash)
        ))
        .await
        .expect("expire the ruling");
}

fn reader() -> LossRulingReader {
    LossRulingReader {
        replica_id: "drain-1".to_owned(),
        incarnation: "drain-inc".to_owned(),
    }
}

async fn token_for(url: &str, filter: &LossFilter) -> (String, Vec<Vec<u8>>) {
    let pool = operator_pool(url);
    let client = pool.get().await.unwrap();
    let listing = list_lost_staged(&***client, CELL, FRESH, filter, None)
        .await
        .expect("list");
    (
        confirm_token(listing.as_of_ms, CELL, filter, &listing.files),
        listing.files.into_iter().map(|file| file.hash).collect(),
    )
}

async fn apply(
    url: &str,
    filter: &LossFilter,
    token: &str,
    attested: bool,
    multi_repository: bool,
) -> LossApplyOutcome {
    let pool = operator_pool(url);
    let mut client = pool.get().await.unwrap();
    apply_loss_rulings(
        &mut client,
        CELL,
        FRESH,
        filter,
        &LossApply {
            actor: "kv",
            reason: "drain host and web hosts mount checked",
            attested,
            multi_repository,
            token,
        },
    )
    .await
    .expect("apply")
}

/// The selection is the drain guard's kept set: `Staged`, live custody, at
/// least an hour old, and no stager row or a stager that is not fresh. Each
/// filter narrows it; `--repository` selects by association.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn list_selects_only_old_kept_heads_whose_stager_is_absent_or_not_fresh() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (none, gone, live, young) = (hash(0x10), hash(0x20), hash(0x30), hash(0x40));
    let mut epochs = Vec::new();
    for (seed, hash) in [(1u8, &none), (2, &gone), (3, &live), (4, &young)] {
        epochs.push(stage(&coordinator, hash, seed).await);
    }
    for hash in [&none, &gone, &live] {
        age(&direct, hash, 2).await;
    }
    record_stager(&direct, &gone, epochs[1], "web-gone", "inc-gone").await;
    record_stager(&direct, &live, epochs[2], "web-live", "inc-live").await;
    publish_liveness(&direct, "web-live", "inc-live", 1).await;
    // A row for the departed replica's id, but stale: not fresh.
    publish_liveness(&direct, "web-gone", "inc-gone", 30).await;
    bind(&coordinator, &direct, &gone, 0x61).await;

    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    let listing = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap();
    let listed: Vec<&[u8]> = listing
        .files
        .iter()
        .map(|file| file.hash.as_slice())
        .collect();
    assert_eq!(
        listed,
        vec![none.as_slice(), gone.as_slice()],
        "a fresh stager and a young representation are not listed"
    );
    assert!(listing.files[0].stager.is_none());
    assert_eq!(
        listing.files[1]
            .stager
            .as_ref()
            .map(|s| s.replica_id.as_str()),
        Some("web-gone")
    );
    assert_eq!(listing.files[1].repositories, 1);
    assert!(
        listing
            .files
            .iter()
            .all(|file| file.age >= Duration::from_secs(3_600))
    );

    let by_stager = LossFilter {
        stager: Some("web-gone".to_owned()),
        ..filter()
    };
    let by_hash = LossFilter {
        hash: Some(none.clone()),
        ..filter()
    };
    let by_repository = LossFilter {
        repository: Some(vec![0x61; 16]),
        ..filter()
    };
    for (what, narrowed, expected) in [
        ("stager", by_stager, &gone),
        ("hash", by_hash, &none),
        ("repository", by_repository, &gone),
    ] {
        let files = list_lost_staged(&***client, CELL, FRESH, &narrowed, None)
            .await
            .unwrap()
            .files;
        assert_eq!(files.len(), 1, "{what}");
        assert_eq!(&files[0].hash, expected, "{what}");
    }
    // The stale replica comes back: its files leave the list.
    publish_liveness(&direct, "web-gone", "inc-gone", 0).await;
    let files = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap()
        .files;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].hash, none);
    // The age floor is not lowerable.
    let young_filter = LossFilter {
        min_age: Duration::from_secs(60),
        ..filter()
    };
    assert!(
        list_lost_staged(&***client, CELL, FRESH, &young_filter, None)
            .await
            .is_err()
    );
}

/// `apply` records one ruling per file and writes nothing on a refusal: no
/// attestation for a file with no stager, and no `--multi-repository` for a file
/// in two repositories. The database refuses an unattested no-stager row on
/// its own too.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn apply_records_rulings_and_refuses_without_attestation_or_multi_repository() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (none, shared) = (hash(0x10), hash(0x20));
    stage(&coordinator, &none, 1).await;
    let shared_epoch = stage(&coordinator, &shared, 2).await;
    age(&direct, &none, 2).await;
    age(&direct, &shared, 2).await;
    record_stager(&direct, &shared, shared_epoch, "web-gone", "inc-gone").await;
    bind(&coordinator, &direct, &shared, 0x61).await;
    bind(&coordinator, &direct, &shared, 0x62).await;

    let only_none = LossFilter {
        hash: Some(none.clone()),
        ..filter()
    };
    let (token, _) = token_for(&url, &only_none).await;
    assert_eq!(
        apply(&url, &only_none, &token, false, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::NeedsAttestation(vec![none.clone()]))
    );
    let count: i64 = direct
        .query_one("SELECT count(*) FROM lore_domain_stage_loss_rulings", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "a refusal writes nothing");
    let LossApplyOutcome::Applied {
        rulings,
        already_open,
    } = apply(&url, &only_none, &token, true, false).await
    else {
        panic!("attested apply");
    };
    assert_eq!(rulings.len(), 1);
    assert!(already_open.is_empty());
    let row = ruling_row(&direct, &none).await;
    assert_eq!(row.get::<_, Option<String>>("outcome"), None);
    assert!(row.get::<_, bool>("attested"));
    assert!(!row.get::<_, bool>("multi_repository"));
    assert_eq!(row.get::<_, String>("selection"), "no_stager");
    assert_eq!(row.get::<_, String>("actor"), "kv");
    assert_eq!(row.get::<_, String>("token"), token);
    assert!(row.get::<_, bool>("expiry_ok"));
    // The same token again is a replay: refused, nothing written.
    assert_eq!(
        apply(&url, &only_none, &token, true, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::Token(TokenRefusal::Replayed))
    );
    assert_eq!(
        direct
            .query_one("SELECT count(*) FROM lore_domain_stage_loss_rulings", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "a replayed token writes nothing"
    );
    // The same set under a new token: the open ruling is kept, not doubled.
    let (token, _) = token_for(&url, &only_none).await;
    let LossApplyOutcome::Applied {
        rulings,
        already_open,
    } = apply(&url, &only_none, &token, true, false).await
    else {
        panic!("re-apply");
    };
    assert!(rulings.is_empty());
    assert_eq!(
        already_open,
        vec![(none.clone(), head(&direct, &none).await.1)]
    );

    let only_shared = LossFilter {
        hash: Some(shared.clone()),
        ..filter()
    };
    let (token, _) = token_for(&url, &only_shared).await;
    assert_eq!(
        apply(&url, &only_shared, &token, false, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::NeedsMultiRepository(vec![shared.clone()]))
    );
    let LossApplyOutcome::Applied { rulings, .. } =
        apply(&url, &only_shared, &token, false, true).await
    else {
        panic!("multi-repository apply");
    };
    assert_eq!(rulings.len(), 1);
    let row = ruling_row(&direct, &shared).await;
    assert!(row.get::<_, bool>("multi_repository"));
    assert!(!row.get::<_, bool>("attested"));
    assert_eq!(row.get::<_, i64>("repositories"), 2);
    assert_eq!(row.get::<_, String>("selection"), "stager_not_fresh");

    // The table refuses an unattested no-stager ruling by itself.
    let refused = direct
        .execute(
            "INSERT INTO lore_domain_stage_loss_rulings (hash, epoch, manifest_id, selection, \
                 actor, reason, attested, multi_repository, repositories, min_age_ms, token, \
                 created_at, expires_at) \
             VALUES ($1, 1, $1, 'no_stager', 'a', 'r', false, false, 1, 3600000, 't', \
                 clock_timestamp(), clock_timestamp() + interval '1 hour')",
            &[&vec![7u8; 32]],
        )
        .await;
    assert!(refused.is_err(), "the CHECK refuses it");
    let short = direct
        .execute(
            "INSERT INTO lore_domain_stage_loss_rulings (hash, epoch, manifest_id, selection, \
                 actor, reason, attested, multi_repository, repositories, min_age_ms, token, \
                 created_at, expires_at) \
             VALUES ($1, 1, $1, 'no_stager', 'a', 'r', true, false, 1, 60000, 't', \
                 clock_timestamp(), clock_timestamp() + interval '1 hour')",
            &[&vec![7u8; 32]],
        )
        .await;
    assert!(short.is_err(), "the one-hour floor is in the table too");
}

/// The token binds the set: a stager that came back changes it, a token
/// older than 15 minutes is refused, and a made-up token is malformed.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn apply_refuses_a_changed_set_an_expired_token_and_a_malformed_one() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (a, b) = (hash(0x10), hash(0x20));
    let epoch_a = stage(&coordinator, &a, 1).await;
    stage(&coordinator, &b, 2).await;
    age(&direct, &a, 2).await;
    age(&direct, &b, 2).await;
    record_stager(&direct, &a, epoch_a, "web-a", "inc-a").await;

    let (token, listed) = token_for(&url, &filter()).await;
    assert_eq!(listed, vec![a.clone(), b.clone()]);
    publish_liveness(&direct, "web-a", "inc-a", 0).await;
    assert_eq!(
        apply(&url, &filter(), &token, true, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::Token(TokenRefusal::SetChanged))
    );
    // A file that ages past the cutoff after list does not change the set:
    // the re-selection is anchored at the token's issue time. `c` is 5 s
    // short of the floor at list and past it at apply.
    let c = hash(0x30);
    stage(&coordinator, &c, 3).await;
    direct
        .execute(
            "UPDATE lore_fragment_epochs \
                SET created_at = clock_timestamp() - interval '59 minutes 55 seconds' \
              WHERE hash = $1",
            &[&c],
        )
        .await
        .unwrap();
    let (token_b, listed) = token_for(&url, &filter()).await;
    assert_eq!(listed, vec![b.clone()], "a is fresh again, c is too young");
    tokio::time::sleep(Duration::from_secs(7)).await;
    let LossApplyOutcome::Applied { rulings, .. } =
        apply(&url, &filter(), &token_b, true, false).await
    else {
        panic!("the anchored re-selection is the listed set");
    };
    assert_eq!(rulings.len(), 1);
    assert_eq!(rulings[0].hash, b);

    // An expired token: issued 16 minutes before the database clock.
    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    let now = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap()
        .db_now_ms;
    let issued = now - 16 * 60 * 1_000;
    let old = list_lost_staged(&***client, CELL, FRESH, &filter(), Some(issued))
        .await
        .unwrap();
    let stale = confirm_token(issued, CELL, &filter(), &old.files);
    assert_eq!(
        apply(&url, &filter(), &stale, true, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::Token(TokenRefusal::Expired))
    );
    assert_eq!(
        apply(&url, &filter(), "v1-1-nothex", true, false).await,
        LossApplyOutcome::Refused(LossApplyRefusal::Token(TokenRefusal::Malformed))
    );
}

/// Record one attested ruling for a staged hash with a departed stager and
/// return `(hash, epoch, fence, ruling_id)`.
async fn ruled(
    url: &str,
    coordinator: &PostgresFragmentCoordinator,
    direct: &Client,
    byte: u8,
    attested: bool,
) -> (Vec<u8>, i64, i64, i64) {
    let hash = hash(byte);
    let epoch = stage(coordinator, &hash, byte).await;
    age(direct, &hash, 2).await;
    record_stager(direct, &hash, epoch, "web-gone", "inc-gone").await;
    let only = LossFilter {
        hash: Some(hash.clone()),
        ..filter()
    };
    let (token, _) = token_for(url, &only).await;
    let LossApplyOutcome::Applied { rulings, .. } =
        apply(url, &only, &token, attested, false).await
    else {
        panic!("apply");
    };
    let (_, _, fence) = head(direct, &hash).await;
    (hash, epoch, fence, rulings[0].ruling_id)
}

fn witness(hash: &[u8], epoch: i64, fence: i64, seed: u8) -> EpochWitness {
    EpochWitness {
        hash: hash.to_vec(),
        epoch,
        state: FragmentLifecycleState::Staged,
        manifest_id: Some(vec![seed; 32]),
        fence,
    }
}

/// The carry-out marks the fragment `Missing` and closes the ruling
/// `marked_missing`, with the evidence and the drain recorded, together.
/// A later refresh no longer reads it as open.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_carried_out_ruling_marks_missing_and_closes_in_one_transaction() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, fence, ruling_id) = ruled(&url, &coordinator, &direct, 0x51, false).await;

    let refresh = coordinator
        .refresh_loss_rulings(1_000, &reader())
        .await
        .unwrap();
    assert_eq!(refresh.open, vec![(hash.clone(), epoch)]);
    assert!(refresh.closed.is_empty());
    let open = coordinator
        .open_loss_ruling(&hash, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(open.ruling_id, ruling_id);
    assert!(open.old_enough && !open.attested);
    assert_eq!(open.stager.unwrap().incarnation, "inc-gone");

    assert_eq!(
        coordinator
            .carry_out_loss_ruling(
                &witness(&hash, epoch, fence, 0x51),
                ruling_id,
                LossEvidence::Echo,
                &reader()
            )
            .await
            .unwrap(),
        MarkMissingOutcome::Published
    );
    assert_eq!(
        head(&direct, &hash).await.0,
        FragmentLifecycleState::Missing.bits()
    );
    let row = ruling_row(&direct, &hash).await;
    assert_eq!(
        row.get::<_, Option<String>>("outcome").as_deref(),
        Some("marked_missing")
    );
    assert_eq!(
        row.get::<_, Option<String>>("evidence").as_deref(),
        Some("echo")
    );
    assert_eq!(
        row.get::<_, Option<String>>("drain_replica_id").as_deref(),
        Some("drain-1")
    );
    assert_eq!(
        row.get::<_, Option<String>>("drain_incarnation").as_deref(),
        Some("drain-inc")
    );
    assert!(row.get::<_, bool>("decided"));
    let refresh = coordinator
        .refresh_loss_rulings(1_000, &reader())
        .await
        .unwrap();
    assert!(refresh.open.is_empty() && refresh.closed.is_empty());
    // The head is no longer listed either.
    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    assert!(
        list_lost_staged(&***client, CELL, FRESH, &filter(), None)
            .await
            .unwrap()
            .files
            .is_empty()
    );
    // The custody of the Missing epoch is a cleanup candidate (no leak).
    let candidates = coordinator
        .stage_cleanup_candidates(None, 16)
        .await
        .unwrap();
    assert!(
        candidates.contains(&(hash.clone(), epoch)),
        "{candidates:?}"
    );
}

/// Nothing is written when the ruling cannot be carried out: no evidence on
/// an unattested ruling, a representation younger than the floor, or a head
/// that moved. A head that left the ruled epoch closes it `fenced` at the
/// next refresh.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_ruling_without_evidence_age_or_a_matching_head_writes_nothing() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, fence, ruling_id) = ruled(&url, &coordinator, &direct, 0x52, false).await;
    let carry = |evidence, fence| {
        let witness = witness(&hash, epoch, fence, 0x52);
        let coordinator = coordinator.clone();
        async move {
            coordinator
                .carry_out_loss_ruling(&witness, ruling_id, evidence, &reader())
                .await
                .unwrap()
        }
    };
    assert_eq!(
        carry(LossEvidence::None, fence).await,
        MarkMissingOutcome::RulingNotEligible,
        "no echo and no attestation"
    );
    assert_eq!(
        carry(LossEvidence::Echo, fence + 1_000).await,
        MarkMissingOutcome::HeadMoved,
        "a stale fence"
    );
    age(&direct, &hash, 0).await;
    assert_eq!(
        carry(LossEvidence::Echo, fence).await,
        MarkMissingOutcome::RulingNotEligible,
        "younger than the one-hour floor by the database clock"
    );
    assert_eq!(
        head(&direct, &hash).await.0,
        FragmentLifecycleState::Staged.bits()
    );
    assert_eq!(
        ruling_row(&direct, &hash)
            .await
            .get::<_, Option<String>>("outcome"),
        None
    );

    // Another path marks it Missing (a confirmed GET): the ruling is fenced.
    age(&direct, &hash, 2).await;
    assert_eq!(
        coordinator
            .mark_missing(
                &witness(&hash, epoch, fence, 0x52),
                MissingDiagnostic::Absent
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let refresh = coordinator
        .refresh_loss_rulings(1_000, &reader())
        .await
        .unwrap();
    assert!(refresh.open.is_empty());
    assert_eq!(refresh.closed.len(), 1);
    assert_eq!(refresh.closed[0].outcome, LossOutcome::Fenced);
    assert_eq!(
        ruling_row(&direct, &hash)
            .await
            .get::<_, Option<String>>("outcome")
            .as_deref(),
        Some("fenced")
    );
    // And it never takes a second decision.
    assert!(
        !coordinator
            .close_loss_ruling(ruling_id, LossOutcome::Found, &reader())
            .await
            .unwrap()
    );
}

/// An attested ruling needs no echo. A ruling past its expiry closes
/// `expired` at the refresh; `found` closes once and never twice; the
/// drain's close refuses the outcomes it does not own.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn attestation_expiry_and_found_close_rulings_as_recorded() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, fence, ruling_id) = ruled(&url, &coordinator, &direct, 0x53, true).await;
    assert_eq!(
        coordinator
            .carry_out_loss_ruling(
                &witness(&hash, epoch, fence, 0x53),
                ruling_id,
                LossEvidence::None,
                &reader()
            )
            .await
            .unwrap(),
        MarkMissingOutcome::Published
    );
    assert_eq!(
        ruling_row(&direct, &hash)
            .await
            .get::<_, Option<String>>("evidence")
            .as_deref(),
        Some("none")
    );

    let (expiring, _, _, _) = ruled(&url, &coordinator, &direct, 0x54, true).await;
    expire(&direct, &expiring).await;
    let refresh = coordinator
        .refresh_loss_rulings(1_000, &reader())
        .await
        .unwrap();
    assert_eq!(refresh.closed.len(), 1);
    assert_eq!(refresh.closed[0].outcome, LossOutcome::Expired);
    assert_eq!(
        ruling_row(&direct, &expiring)
            .await
            .get::<_, Option<String>>("outcome")
            .as_deref(),
        Some("expired")
    );

    let (found, _, _, found_id) = ruled(&url, &coordinator, &direct, 0x55, true).await;
    assert!(
        coordinator
            .close_loss_ruling(found_id, LossOutcome::Found, &reader())
            .await
            .unwrap()
    );
    assert!(
        !coordinator
            .close_loss_ruling(found_id, LossOutcome::NoEvidence, &reader())
            .await
            .unwrap(),
        "decided once"
    );
    assert_eq!(
        head(&direct, &found).await.0,
        FragmentLifecycleState::Staged.bits()
    );
    for owned_elsewhere in [LossOutcome::MarkedMissing, LossOutcome::Expired] {
        assert!(
            coordinator
                .close_loss_ruling(found_id, owned_elsewhere, &reader())
                .await
                .is_err()
        );
    }
    let all = {
        let pool = operator_pool(&url);
        let client = pool.get().await.unwrap();
        loss_rulings(&***client, None, false, 1_000).await.unwrap()
    };
    assert_eq!(all.len(), 3, "a ruling row is never deleted");
}

/// `Missing` is not reversible for that epoch, but a new upload of the same
/// bytes repairs it into a new epoch. The decided ruling stays as evidence.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_missing_fragment_is_repaired_into_a_new_epoch() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, fence, ruling_id) = ruled(&url, &coordinator, &direct, 0x56, true).await;
    assert_eq!(
        coordinator
            .carry_out_loss_ruling(
                &witness(&hash, epoch, fence, 0x56),
                ruling_id,
                LossEvidence::None,
                &reader()
            )
            .await
            .unwrap(),
        MarkMissingOutcome::Published
    );
    let repaired = stage(&coordinator, &hash, 0x57).await;
    assert!(repaired > epoch, "a repair takes a new epoch");
    let (state, current, _) = head(&direct, &hash).await;
    assert_eq!(state, FragmentLifecycleState::Staged.bits());
    assert_eq!(current, repaired);
    assert_eq!(
        ruling_row(&direct, &hash)
            .await
            .get::<_, Option<String>>("outcome")
            .as_deref(),
        Some("marked_missing")
    );
    assert!(
        coordinator
            .open_loss_ruling(&hash, repaired)
            .await
            .unwrap()
            .is_none(),
        "the ruling names the old epoch only"
    );
}

/// Review O1: stager freshness is read under ANY cell id. A replica whose
/// configuration names another cell id (a typo) still publishes a fresh
/// progress row for its stager in this database, so its files are not
/// listed; once that row goes stale under every cell id they are.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn list_reads_stager_freshness_under_any_cell_id() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let typo = hash(0x10);
    let epoch = stage(&coordinator, &typo, 1).await;
    age(&direct, &typo, 2).await;
    record_stager(&direct, &typo, epoch, "web-typo", "inc-typo").await;
    publish_liveness_in(&direct, "cell-l0ss", "web-typo", "inc-typo", 0).await;

    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    let listed = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap()
        .files;
    assert!(
        listed.is_empty(),
        "a stager fresh under a mistyped cell id is live: {listed:?}"
    );
    publish_liveness_in(&direct, "cell-l0ss", "web-typo", "inc-typo", 30).await;
    let listed = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap()
        .files;
    assert_eq!(listed.len(), 1, "stale under every cell id: listed");
    assert_eq!(listed[0].hash, typo);
}

/// Review O5: the list never shows a head the drain never picks up. A head
/// held by another operation is skipped; the drain's own promotion marker
/// is not.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn list_skips_a_head_the_drain_candidate_query_skips() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (busy, promoting) = (hash(0x10), hash(0x20));
    for (seed, hash) in [(1u8, &busy), (2, &promoting)] {
        stage(&coordinator, hash, seed).await;
        age(&direct, hash, 2).await;
    }
    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    assert_eq!(
        list_lost_staged(&***client, CELL, FRESH, &filter(), None)
            .await
            .unwrap()
            .files
            .len(),
        2,
        "control: both are listed while idle"
    );
    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = $2 WHERE hash = $1",
            &[&busy, &vec![0x42u8; 16]],
        )
        .await
        .unwrap();
    direct
        .execute(
            "UPDATE lore_fragment_lifecycle SET active_operation = $2 WHERE hash = $1",
            &[&promoting, &b"wp115-promote-v1".to_vec()],
        )
        .await
        .unwrap();
    let listed: Vec<Vec<u8>> = list_lost_staged(&***client, CELL, FRESH, &filter(), None)
        .await
        .unwrap()
        .files
        .into_iter()
        .map(|file| file.hash)
        .collect();
    assert_eq!(
        listed,
        vec![promoting],
        "another operation's head is skipped, the drain's own promotion is not"
    );
}

/// Review O3: an undecided ruling past its expiry is not open. `status
/// --open` leaves it out, the full status names it pending, the list shows
/// no open ruling, and a new `apply` records a fresh ruling after writing the
/// old one's `expired` outcome with no drain identity. Nothing is deleted.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn an_expired_undecided_ruling_is_not_open_and_a_new_apply_replaces_it() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, _fence, old_id) = ruled(&url, &coordinator, &direct, 0x57, true).await;
    expire(&direct, &hash).await;

    let pool = operator_pool(&url);
    let client = pool.get().await.unwrap();
    assert!(
        loss_rulings(&***client, None, true, 1_000)
            .await
            .unwrap()
            .is_empty(),
        "status --open leaves an expired ruling out"
    );
    let all = loss_rulings(&***client, None, false, 1_000).await.unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].expired_pending && all[0].outcome.is_none());
    let only = LossFilter {
        hash: Some(hash.clone()),
        ..filter()
    };
    let listed = list_lost_staged(&***client, CELL, FRESH, &only, None)
        .await
        .unwrap()
        .files;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].open_ruling, None, "an expired ruling is not open");
    drop(client);

    let (token, _) = token_for(&url, &only).await;
    let LossApplyOutcome::Applied {
        rulings,
        already_open,
    } = apply(&url, &only, &token, true, false).await
    else {
        panic!("a new apply after expiry");
    };
    assert!(already_open.is_empty(), "the expired ruling held no slot");
    assert_eq!(rulings.len(), 1);
    assert_ne!(rulings[0].ruling_id, old_id);
    let old = direct
        .query_one(
            "SELECT outcome, drain_replica_id, decided_at IS NOT NULL \
               FROM lore_domain_stage_loss_rulings WHERE ruling_id = $1",
            &[&old_id],
        )
        .await
        .unwrap();
    assert_eq!(old.get::<_, Option<String>>(0).as_deref(), Some("expired"));
    assert_eq!(old.get::<_, Option<String>>(1), None, "closed by apply");
    assert!(old.get::<_, bool>(2));
    let open = coordinator
        .open_loss_ruling(&hash, epoch)
        .await
        .unwrap()
        .expect("the new ruling is open");
    assert_eq!(open.ruling_id, rulings[0].ruling_id);
}

/// Review O4: the audit rule is the database's. A ruling row cannot be
/// deleted or truncated, its ruling columns never change, the outcome moves
/// once from NULL to a decided value and never again, no outcome column is
/// written while the outcome is NULL, and `marked_missing` needs the drain.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn the_ruling_table_refuses_delete_and_every_rewrite() {
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (open_hash, _, _, open_id) = ruled(&url, &coordinator, &direct, 0x58, true).await;
    let (_decided_hash, _, _, decided_id) = ruled(&url, &coordinator, &direct, 0x59, true).await;
    assert!(
        coordinator
            .close_loss_ruling(decided_id, LossOutcome::Found, &reader())
            .await
            .unwrap()
    );
    let count = || async {
        direct
            .query_one("SELECT count(*) FROM lore_domain_stage_loss_rulings", &[])
            .await
            .unwrap()
            .get::<_, i64>(0)
    };
    assert_eq!(count().await, 2);

    for (what, sql, id) in [
        (
            "delete an open ruling",
            "DELETE FROM lore_domain_stage_loss_rulings WHERE ruling_id = $1",
            open_id,
        ),
        (
            "delete a decided ruling",
            "DELETE FROM lore_domain_stage_loss_rulings WHERE ruling_id = $1",
            decided_id,
        ),
        (
            "rewrite a ruling column",
            "UPDATE lore_domain_stage_loss_rulings SET actor = 'someone' WHERE ruling_id = $1",
            open_id,
        ),
        (
            "extend the expiry",
            "UPDATE lore_domain_stage_loss_rulings \
                SET expires_at = expires_at + interval '1 day' WHERE ruling_id = $1",
            open_id,
        ),
        (
            "rewrite a decided outcome",
            "UPDATE lore_domain_stage_loss_rulings SET outcome = 'fenced' WHERE ruling_id = $1",
            decided_id,
        ),
        (
            "reopen a decided ruling",
            "UPDATE lore_domain_stage_loss_rulings \
                SET outcome = NULL, decided_at = NULL, drain_replica_id = NULL, \
                    drain_incarnation = NULL WHERE ruling_id = $1",
            decided_id,
        ),
        (
            "write evidence while undecided",
            "UPDATE lore_domain_stage_loss_rulings SET evidence = 'echo' WHERE ruling_id = $1",
            open_id,
        ),
        (
            "write a drain while undecided",
            "UPDATE lore_domain_stage_loss_rulings \
                SET drain_replica_id = 'drain-1' WHERE ruling_id = $1",
            open_id,
        ),
        (
            "marked_missing without a drain",
            "UPDATE lore_domain_stage_loss_rulings \
                SET outcome = 'marked_missing', evidence = 'none', \
                    decided_at = clock_timestamp(), drain_incarnation = 'drain-inc' \
              WHERE ruling_id = $1",
            open_id,
        ),
    ] {
        let refused = direct.execute(sql, &[&id]).await;
        assert!(refused.is_err(), "{what} must be refused");
    }
    assert!(
        direct
            .batch_execute("TRUNCATE lore_domain_stage_loss_rulings")
            .await
            .is_err(),
        "truncate must be refused"
    );
    assert_eq!(count().await, 2, "no ruling row was removed");
    let open = ruling_row(&direct, &open_hash).await;
    assert_eq!(open.get::<_, Option<String>>("outcome"), None);
    assert_eq!(open.get::<_, String>("actor"), "kv");
    // Control: the one allowed change, NULL to a decided outcome, once.
    assert_eq!(
        direct
            .execute(
                "UPDATE lore_domain_stage_loss_rulings \
                    SET outcome = 'no_evidence', decided_at = clock_timestamp(), \
                        drain_replica_id = 'drain-1', drain_incarnation = 'drain-inc' \
                  WHERE ruling_id = $1",
                &[&open_id],
            )
            .await
            .expect("an open ruling takes one decision"),
        1
    );

    // Fix round 2 (F3): a row is inserted open. Every other column is valid,
    // so only the insert guard can refuse it.
    let decided_insert = "INSERT INTO lore_domain_stage_loss_rulings (hash, epoch, manifest_id, \
             selection, actor, reason, attested, multi_repository, repositories, min_age_ms, \
             token, created_at, expires_at, outcome, decided_at, drain_replica_id, \
             drain_incarnation) \
         VALUES ($1, 1, $1, 'no_stager', 'a', 'r', true, false, 1, 3600000, 't', \
             clock_timestamp(), clock_timestamp() + interval '1 hour', 'found', \
             clock_timestamp(), 'drain-1', 'drain-inc')";
    let inserted = direct.execute(decided_insert, &[&vec![0x5bu8; 32]]).await;
    assert!(
        inserted.is_err(),
        "an insert of a decided ruling must be refused"
    );
    assert_eq!(count().await, 2, "no decided row was inserted");

    // Fix round 2 (F2): a disabled guard is enabled again by the next install.
    let enabled = || async {
        direct
            .query(
                "SELECT tgname::text, tgenabled::text FROM pg_trigger \
                  WHERE tgrelid = 'lore_domain_stage_loss_rulings'::regclass \
                    AND NOT tgisinternal ORDER BY tgname",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>()
    };
    let all_on = vec![
        (
            "lore_domain_stage_loss_rulings_guard_insert".to_owned(),
            "O".to_owned(),
        ),
        (
            "lore_domain_stage_loss_rulings_guard_row".to_owned(),
            "O".to_owned(),
        ),
        (
            "lore_domain_stage_loss_rulings_guard_truncate".to_owned(),
            "O".to_owned(),
        ),
    ];
    assert_eq!(enabled().await, all_on);
    direct
        .batch_execute(
            "ALTER TABLE lore_domain_stage_loss_rulings DISABLE TRIGGER \
                 lore_domain_stage_loss_rulings_guard_row; \
             ALTER TABLE lore_domain_stage_loss_rulings DISABLE TRIGGER \
                 lore_domain_stage_loss_rulings_guard_truncate; \
             ALTER TABLE lore_domain_stage_loss_rulings DISABLE TRIGGER \
                 lore_domain_stage_loss_rulings_guard_insert",
        )
        .await
        .expect("the owner can disable the guards");
    assert!(
        enabled().await.iter().all(|(_, state)| state == "D"),
        "the fixture disabled every guard"
    );
    let _reinstalled = PostgresDomainStore::connect(&url, 8, &TlsConfig::default())
        .await
        .expect("reinstall the domain schema");
    assert_eq!(
        enabled().await,
        all_on,
        "the install enabled every guard again"
    );
    assert!(
        direct
            .execute(
                "DELETE FROM lore_domain_stage_loss_rulings WHERE ruling_id = $1",
                &[&decided_id],
            )
            .await
            .is_err(),
        "the re-enabled guard refuses a delete again"
    );
    assert!(
        direct
            .execute(decided_insert, &[&vec![0x5bu8; 32]])
            .await
            .is_err(),
        "the re-enabled guard refuses a decided insert again"
    );
    assert_eq!(count().await, 2);
}

/// Review D4: a candidate that names another manifest than the ruling does
/// not close it while the locked head still is the ruled representation;
/// once the head left it, the same call closes it `fenced`.
#[tokio::test]
#[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
async fn a_stale_candidate_never_fences_a_ruling_whose_head_still_matches() {
    use lore_postgres::domain::fragments::stage_loss::LossRulingFence;
    let url = pg_url();
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let direct = client(&url).await;
    let (hash, epoch, fence, ruling_id) = ruled(&url, &coordinator, &direct, 0x5a, true).await;
    assert_eq!(
        coordinator
            .fence_loss_ruling_if_head_moved(ruling_id, &reader())
            .await
            .unwrap(),
        LossRulingFence::StillStaged
    );
    assert_eq!(
        ruling_row(&direct, &hash)
            .await
            .get::<_, Option<String>>("outcome"),
        None,
        "the ruling stays open"
    );
    assert_eq!(
        coordinator
            .mark_missing(
                &witness(&hash, epoch, fence, 0x5a),
                MissingDiagnostic::Absent
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(
        coordinator
            .fence_loss_ruling_if_head_moved(ruling_id, &reader())
            .await
            .unwrap(),
        LossRulingFence::Fenced
    );
    let row = ruling_row(&direct, &hash).await;
    assert_eq!(
        row.get::<_, Option<String>>("outcome").as_deref(),
        Some("fenced")
    );
    assert_eq!(
        coordinator
            .fence_loss_ruling_if_head_moved(ruling_id, &reader())
            .await
            .unwrap(),
        LossRulingFence::NotOpen
    );
}

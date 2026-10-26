// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `cleanup_pass` wiring of the stage tombstone work: the sweep runs, a full
//! stage skips a late file instead of ending the pass, and a failing sweep does
//! not stop the scan. Each case checks the usage ledger against the custody rows.
use super::*;

/// The usage counters must equal what the custody rows hold.
async fn assert_ledger_matches_custody(fixture: &Fixture) {
    let row = fixture
        .admin
        .query_one(
            "SELECT u.metadata_rows, u.metadata_bytes, u.live_files, u.live_bytes, \
                    (SELECT count(*) FROM lore_fragment_stage_custody)::bigint, \
                    (SELECT coalesce(sum(metadata_bytes),0) FROM lore_fragment_stage_custody)::bigint, \
                    (SELECT count(*) FROM lore_fragment_stage_custody WHERE state<>3)::bigint, \
                    (SELECT coalesce(sum(size_payload),0) FROM lore_fragment_stage_custody WHERE state<>3)::bigint \
             FROM lore_fragment_stage_usage u WHERE u.singleton",
            &[],
        )
        .await
        .unwrap();
    let get = |index: usize| row.get::<_, i64>(index);
    assert_eq!(get(0), get(4), "metadata_rows vs custody rows");
    assert_eq!(get(1), get(5), "metadata_bytes vs custody bytes");
    assert_eq!(get(2), get(6), "live_files vs live custody rows");
    assert_eq!(get(3), get(7), "live_bytes vs live custody payload");
}

async fn custody_rows(fixture: &Fixture, hash: &[u8], epoch: i64) -> i64 {
    fixture
        .admin
        .query_one(
            "SELECT count(*) FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2",
            &[&hash, &epoch],
        )
        .await
        .unwrap()
        .get(0)
}

/// `(metadata_rows, metadata_bytes)` straight from the usage row.
async fn metadata_usage(fixture: &Fixture) -> (i64, i64) {
    let row = fixture
        .admin
        .query_one(
            "SELECT metadata_rows, metadata_bytes FROM lore_fragment_stage_usage WHERE singleton",
            &[],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// The shape a release before the tombstone work left behind: a state=3 custody
/// row, counted in the ledger.
async fn plant_legacy_tombstone(fixture: &Fixture, hash: &[u8], epoch: i64) {
    fixture
        .admin
        .execute(
            "INSERT INTO lore_fragment_stage_custody \
             (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes,purged_at) \
             VALUES($1,$2,nextval('lore_fragment_fence_seq'),NULL,0,clock_timestamp(),3,256,clock_timestamp())",
            &[&hash, &epoch],
        )
        .await
        .unwrap();
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_stage_usage SET metadata_bytes=metadata_bytes+256, \
             metadata_rows=metadata_rows+1 WHERE singleton",
            &[],
        )
        .await
        .unwrap();
}

/// Promote the fixture's staged source and clean its predecessor by hand. The
/// epoch is then PURGED and its custody row deleted. Returns `(hash, epoch)`.
async fn promote_and_clean_predecessor(fixture: &Fixture) -> (Vec<u8>, i64) {
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    let hash = fixture.address.hash.data().to_vec();
    let epoch = fixture.source_epoch;
    let coordinator = &fixture.handle.coordinator;
    let intent = coordinator
        .begin_stage_cleanup(&hash, epoch)
        .await
        .unwrap()
        .expect("the quarantined predecessor is reclaimed");
    fixture.stage.purge_placement(intent.target()).unwrap();
    coordinator.commit_stage_cleanup(&intent).await.unwrap();
    assert_eq!(custody_rows(fixture, &hash, epoch).await, 0);
    (hash, epoch)
}

/// Write a staged file no database row names: no head, no epoch, no custody.
fn plant_orphan_file(fixture: &Fixture, hash: [u8; 32], epoch: i64) -> PathBuf {
    let key = format!("{}.s{epoch}", hex::encode(hash));
    let directory = fixture
        .root
        .join("stage/staged")
        .join(&key[..2])
        .join(&key[2..4]);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(&key);
    std::fs::write(&path, b"late residue").unwrap();
    path
}

/// Run passes until `done` holds, so the asynchronous inventory scan has
/// reached the planted file. Every pass must return `Ok`.
async fn pass_until(fixture: &Fixture, what: &str, done: impl Fn(&Fixture) -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            fixture
                .handle
                .cleanup_pass(8)
                .await
                .unwrap_or_else(|error| {
                    panic!("cleanup_pass must not fail while {what}: {error:?}")
                });
            if done(fixture) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
}

/// One pass deletes a redundant legacy tombstone and gives its row back.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn cleanup_pass_sweeps_a_redundant_legacy_tombstone() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let (hash, epoch) = promote_and_clean_predecessor(&fixture).await;
    assert_eq!(metadata_usage(&fixture).await, (0, 0));
    plant_legacy_tombstone(&fixture, &hash, epoch).await;
    assert_eq!(metadata_usage(&fixture).await, (1, 256));
    assert_ledger_matches_custody(&fixture).await;

    fixture.handle.cleanup_pass(8).await.unwrap();

    assert_eq!(
        custody_rows(&fixture, &hash, epoch).await,
        0,
        "the sweep deleted the tombstone"
    );
    assert_eq!(metadata_usage(&fixture).await, (0, 0));
    assert_eq!(
        fixture.handle.cleanup_skips(),
        CleanupSkips::default(),
        "a clean sweep skips nothing"
    );
    assert_ledger_matches_custody(&fixture).await;
}

/// A late file that needs a fresh 256 KiB charge meets a full stage. The pass
/// returns `Ok`, counts the skip, leaves the file, and cleans it once the
/// drain has freed room.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn cleanup_pass_counts_a_full_stage_skip_and_reclaims_the_file_once_room_frees() {
    // The policy follows the hard limit. 262145 bytes holds one reclaim charge
    // (262144) only while the stage is otherwise empty, and the fixture's own
    // 17408-byte source is resident.
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| {
            settings.watermarks.low_bytes = 100_000;
            settings.watermarks.high_bytes = 200_000;
            settings.watermarks.hard_bytes = 262_145;
        },
    )
    .await;
    let orphan_hash = [0xd1; 32];
    let orphan_epoch = 9000;
    let orphan = plant_orphan_file(&fixture, orphan_hash, orphan_epoch);
    let before = metadata_usage(&fixture).await;

    pass_until(&fixture, "the full stage skips the late file", |fixture| {
        fixture.handle.cleanup_skips().stage_capacity >= 1
    })
    .await;
    assert!(orphan.exists(), "a skipped file is left for a later pass");
    assert_eq!(
        custody_rows(&fixture, &orphan_hash, orphan_epoch).await,
        0,
        "a refused reserve leaves no row"
    );
    assert_eq!(metadata_usage(&fixture).await, before);
    assert_eq!(fixture.handle.cleanup_skips().stage_key_taken, 0);
    assert_ledger_matches_custody(&fixture).await;

    // The drain promotes the source; its predecessor is then reclaimed by the
    // same pass, which frees the room the late file needs.
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    pass_until(&fixture, "the late file is reclaimed", |_| !orphan.exists()).await;
    assert_eq!(
        custody_rows(&fixture, &orphan_hash, orphan_epoch).await,
        0,
        "the reclaim's row is deleted by its own release"
    );
    pass_until(&fixture, "the predecessor row is gone", |_| true).await;
    let (rows, bytes) = metadata_usage(&fixture).await;
    assert_eq!((rows, bytes), (0, 0));
    assert_ledger_matches_custody(&fixture).await;
}

/// The sweep's delete fails. The pass still returns `Ok`, counts the failure,
/// and the scan reclaims a late file in the same passes. Once the fault is
/// removed the sweep deletes the tombstone.
///
/// Fault: a BEFORE DELETE trigger that refuses only the planted tombstone's
/// row, so the reclaim's own release of another key is not affected.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_failing_tombstone_sweep_does_not_stop_the_stage_scan() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let (hash, epoch) = promote_and_clean_predecessor(&fixture).await;
    plant_legacy_tombstone(&fixture, &hash, epoch).await;
    fixture
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION refuse_tombstone_delete() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF OLD.state = 3 AND OLD.hash = '\\x{}'::bytea THEN \
               RAISE EXCEPTION 'TEST_REFUSE_TOMBSTONE_DELETE'; END IF; RETURN OLD; END $$; \
             CREATE TRIGGER refuse_tombstone_delete BEFORE DELETE ON lore_fragment_stage_custody \
               FOR EACH ROW EXECUTE FUNCTION refuse_tombstone_delete();",
            hex::encode(&hash)
        ))
        .await
        .unwrap();
    let orphan_hash = [0xd2; 32];
    let orphan = plant_orphan_file(&fixture, orphan_hash, 9001);

    pass_until(
        &fixture,
        "the scan reclaims the late file past a failing sweep",
        |_| !orphan.exists(),
    )
    .await;
    assert!(
        fixture.handle.cleanup_skips().tombstone_sweep_failed >= 1,
        "the failed sweep batch is counted: {:?}",
        fixture.handle.cleanup_skips()
    );
    assert_eq!(
        custody_rows(&fixture, &hash, epoch).await,
        1,
        "the refused delete left the tombstone"
    );
    assert_eq!(custody_rows(&fixture, &orphan_hash, 9001).await, 0);
    assert_ledger_matches_custody(&fixture).await;

    fixture
        .admin
        .batch_execute(
            "DROP TRIGGER refuse_tombstone_delete ON lore_fragment_stage_custody; \
             DROP FUNCTION refuse_tombstone_delete();",
        )
        .await
        .unwrap();
    pass_until(&fixture, "the sweep recovers", |_| true).await;
    assert_eq!(custody_rows(&fixture, &hash, epoch).await, 0);
    assert_ledger_matches_custody(&fixture).await;
}

/// The drain policy's retired floor, straight from the cell database.
async fn retired_floor(fixture: &Fixture) -> i64 {
    fixture
        .admin
        .query_one(
            "SELECT retired_floor_ms FROM object_store_retention.drain_policies WHERE cell='adapter-cell'",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

async fn database_now_ms(fixture: &Fixture) -> i64 {
    fixture
        .admin
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// Every pass advances the retired floor once (WP-115 f2): the floor is the spool's only way to
/// notice a body whose custody row is gone, and nothing but this pass drives it.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn cleanup_pass_advances_the_retired_floor_and_counts_no_skip() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .admin
        .execute(
            "UPDATE object_store_retention.drain_policies SET retired_floor_ms=0 WHERE cell='adapter-cell'",
            &[],
        )
        .await
        .unwrap();
    let before = database_now_ms(&fixture).await;

    fixture.handle.cleanup_pass(8).await.unwrap();

    let floor = retired_floor(&fixture).await;
    let after = database_now_ms(&fixture).await;
    assert!(
        (before - 900_000..=after - 900_000).contains(&floor),
        "one pass raised the floor to now minus 15 minutes: {floor} not in [{}, {}]",
        before - 900_000,
        after - 900_000
    );
    assert_eq!(
        fixture.handle.cleanup_skips().spool_retire_failed,
        0,
        "a clean advance counts no retire failure"
    );
    assert_eq!(
        fixture.handle.cleanup_skips(),
        CleanupSkips::default(),
        "and no other skip either"
    );
    assert_ledger_matches_custody(&fixture).await;
}

/// The retire step fails (the floor update is refused by the database). The pass still returns
/// `Ok`, counts one `spool_retire_failed` per pass, and keeps doing its other work; once the fault
/// is removed the next pass advances the floor.
///
/// Fault: a BEFORE UPDATE trigger that refuses only a change to `retired_floor_ms`, so the rest of
/// the pass's writes to the policy row are not affected.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_failing_retire_step_is_counted_and_does_not_fail_the_pass() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .admin
        .batch_execute(
            "UPDATE object_store_retention.drain_policies SET retired_floor_ms=0 WHERE cell='adapter-cell'; \
             CREATE FUNCTION refuse_floor_advance() RETURNS trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF NEW.retired_floor_ms IS DISTINCT FROM OLD.retired_floor_ms THEN \
               RAISE EXCEPTION 'TEST_REFUSE_FLOOR_ADVANCE'; END IF; RETURN NEW; END $$; \
             CREATE TRIGGER refuse_floor_advance BEFORE UPDATE ON object_store_retention.drain_policies \
               FOR EACH ROW EXECUTE FUNCTION refuse_floor_advance();",
        )
        .await
        .unwrap();
    let orphan_hash = [0xd3; 32];
    let orphan = plant_orphan_file(&fixture, orphan_hash, 9002);

    for pass in 1..=3_u64 {
        fixture
            .handle
            .cleanup_pass(8)
            .await
            .unwrap_or_else(|error| {
                panic!("pass {pass} must not fail on a retire failure: {error:?}")
            });
        assert_eq!(
            fixture.handle.cleanup_skips().spool_retire_failed,
            pass,
            "the retire step runs once per pass and each failure is counted"
        );
    }
    assert_eq!(
        retired_floor(&fixture).await,
        0,
        "the refused advance left the floor"
    );
    // The rest of the pass still ran: the scan reclaims the late stage file past the failure.
    pass_until(&fixture, "the scan runs past a failing retire step", |_| {
        !orphan.exists()
    })
    .await;
    assert!(fixture.handle.cleanup_skips().spool_retire_failed >= 3);
    assert_ledger_matches_custody(&fixture).await;

    fixture
        .admin
        .batch_execute(
            "DROP TRIGGER refuse_floor_advance ON object_store_retention.drain_policies; \
             DROP FUNCTION refuse_floor_advance();",
        )
        .await
        .unwrap();
    let failures = fixture.handle.cleanup_skips().spool_retire_failed;
    fixture.handle.cleanup_pass(8).await.unwrap();
    assert!(
        retired_floor(&fixture).await > 0,
        "the retire step recovers"
    );
    assert_eq!(
        fixture.handle.cleanup_skips().spool_retire_failed,
        failures,
        "a successful retire step counts nothing"
    );
}

/// A contended advance is not a failure (WP-115 f2 round 4): the pass returns `Ok`, counts
/// `spool_retire_contended`, and leaves `spool_retire_failed` alone. It starts the retire interval
/// like a successful step, so the next pass does not retry and does not wait on the locked row
/// again; once the interval has passed the pass retries. A FAILED step still retries every pass
/// (`a_failing_retire_step_is_counted_and_does_not_fail_the_pass`).
///
/// Contention: another session holds the policy row lock, so the advance's floor update waits out
/// the dispatch pool's lock timeout and reports a lock failure.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_contended_floor_advance_is_counted_apart_and_waits_the_retire_interval() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .admin
        .execute(
            "UPDATE object_store_retention.drain_policies SET retired_floor_ms=0 WHERE cell='adapter-cell'",
            &[],
        )
        .await
        .unwrap();
    fixture
        .admin
        .batch_execute(
            "BEGIN; SELECT 1 FROM object_store_retention.drain_policies WHERE cell='adapter-cell' FOR UPDATE;",
        )
        .await
        .unwrap();

    let started = std::time::Instant::now();
    fixture
        .handle
        .cleanup_pass(8)
        .await
        .unwrap_or_else(|error| panic!("pass 1 must not fail on contention: {error:?}"));
    let first = started.elapsed();
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(skips.spool_retire_contended, 1, "{skips:?}");
    assert_eq!(
        skips.spool_retire_failed, 0,
        "contention is not a failure: {skips:?}"
    );

    // Inside the interval the retire step is not tried, so it neither counts nor waits on the lock.
    let started = std::time::Instant::now();
    fixture
        .handle
        .cleanup_pass(8)
        .await
        .unwrap_or_else(|error| panic!("pass 2 must not fail on contention: {error:?}"));
    let second = started.elapsed();
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(
        skips.spool_retire_contended, 1,
        "an immediate pass does not retry: {skips:?}"
    );
    assert_eq!(skips.spool_retire_failed, 0, "{skips:?}");
    assert!(
        second * 2 < first,
        "pass 2 must not wait on the locked row (pass 1 {first:?}, pass 2 {second:?})"
    );
    assert_eq!(
        retired_floor(&fixture).await,
        0,
        "the locked row kept the floor"
    );

    // Once the interval passes the step runs again and loses the race again.
    fixture.handle.expire_spool_retire_interval().await;
    fixture
        .handle
        .cleanup_pass(8)
        .await
        .unwrap_or_else(|error| panic!("pass 3 must not fail on contention: {error:?}"));
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(
        skips.spool_retire_contended, 2,
        "an expired interval retries: {skips:?}"
    );
    assert_eq!(skips.spool_retire_failed, 0, "{skips:?}");

    fixture.admin.batch_execute("ROLLBACK").await.unwrap();
    fixture.handle.expire_spool_retire_interval().await;
    fixture.handle.cleanup_pass(8).await.unwrap();
    assert!(
        retired_floor(&fixture).await > 0,
        "the next pass after the lock cleared and the interval passed advances the floor"
    );
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(skips.spool_retire_contended, 2, "{skips:?}");
    assert_eq!(skips.spool_retire_failed, 0, "{skips:?}");
}

/// The retired-floor age (WP-115 f2) reads in-memory state only. Before any advance it is the
/// handle's age plus the 15 minute window the floor always trails by. After an advance it is the
/// distance from the last floor to the clock. A later contended pass cannot reset or lower it: the
/// age keeps counting from the last good floor.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn the_retired_floor_age_counts_from_the_last_good_floor_through_a_contended_pass() {
    const WINDOW: Duration = Duration::from_secs(900);
    const SLACK: Duration = Duration::from_secs(30);
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .admin
        .execute(
            "UPDATE object_store_retention.drain_policies SET retired_floor_ms=0 WHERE cell='adapter-cell'",
            &[],
        )
        .await
        .unwrap();

    let unseen = fixture.handle.spool_retired_floor_age();
    assert!(
        (WINDOW..WINDOW + SLACK).contains(&unseen),
        "before any advance the age is the window plus the handle's age: {unseen:?}"
    );

    let before = database_now_ms(&fixture).await;
    fixture.handle.cleanup_pass(8).await.unwrap();
    let after = database_now_ms(&fixture).await;
    let floor = retired_floor(&fixture).await;
    assert!(floor > 0, "the pass advanced the floor");
    let advanced = fixture.handle.spool_retired_floor_age();
    // The floor is (database now - 15 min) at the advance; the age is read afterwards, so it lies
    // between the window and the window plus the time the pass and the clock reads took.
    let elapsed = Duration::from_millis(u64::try_from(after - before).unwrap_or(0));
    assert!(
        advanced >= WINDOW - SLACK && advanced <= WINDOW + elapsed + SLACK,
        "after an advance the age is about the window: {advanced:?} (db clock moved {elapsed:?})"
    );

    // A contended pass leaves the floor alone, so the age must keep growing from it.
    fixture
        .admin
        .batch_execute(
            "BEGIN; SELECT 1 FROM object_store_retention.drain_policies WHERE cell='adapter-cell' FOR UPDATE;",
        )
        .await
        .unwrap();
    fixture.handle.expire_spool_retire_interval().await;
    fixture.handle.cleanup_pass(8).await.unwrap();
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(skips.spool_retire_contended, 1, "{skips:?}");
    let contended = fixture.handle.spool_retired_floor_age();
    assert!(
        contended >= advanced,
        "a contended pass does not reset or lower the age: {advanced:?} then {contended:?}"
    );
    assert!(
        contended <= WINDOW + elapsed + SLACK + Duration::from_secs(20),
        "and it is still computed from the last good floor: {contended:?}"
    );
    assert_eq!(
        retired_floor(&fixture).await,
        floor,
        "the locked row kept the floor"
    );
    fixture.admin.batch_execute("ROLLBACK").await.unwrap();
}

/// A live custody row pins the retired floor (WP-115 f2): the advance raises the floor to the
/// oldest custody row's attempt time, not to `now - 15 min`, so the floor age is the row's age and
/// a spool row left open for hours reads past the 1 hour alert threshold. The advance is not a
/// failure and not contended.
///
/// The row is planted by an admin INSERT shaped like the forward-upgrade suite's seed rows. It is
/// deleted before the end. The stage ledger the assertions check is a different table, so the
/// planted row does not disturb `assert_ledger_matches_custody`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_live_custody_row_pins_the_retired_floor_to_its_attempt_time() {
    const ROW_AGE_MS: i64 = 7_200_000;
    const SLACK: Duration = Duration::from_secs(60);
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let attempt_ms = database_now_ms(&fixture).await - ROW_AGE_MS;
    // A UUIDv7: 48 bits of unix ms, version 7, variant 10xx.
    let hex = format!("{attempt_ms:012x}");
    let attempt = format!("{}-{}-7abc-8def-0123456789ab", &hex[..8], &hex[8..]);
    fixture
        .admin
        .execute(
            "UPDATE object_store_retention.drain_policies SET retired_floor_ms=$1 WHERE cell='adapter-cell'",
            &[&(attempt_ms - 3_600_000)],
        )
        .await
        .unwrap();
    let planted = fixture
        .admin
        .execute(
            "INSERT INTO object_store_retention.drain_spool_custody \
             (spool_id, boundary, cell, service, logical_id, attempt_id, descriptor, canonical, \
              digest, cleanup_not_before, state, cleanup_fence, metadata_bytes) \
             SELECT gen_random_uuid(), p.boundary, p.cell, 'pinned-service', gen_random_uuid(), \
                    $1::text::uuid, \
                    jsonb_build_object('policy_revision', p.revision, 'policy_digest', encode(p.digest,'hex')), \
                    decode('aa','hex'), decode(repeat('11',32),'hex'), 4102444800000, 1, 0, 16384 \
             FROM object_store_retention.drain_policies p WHERE p.cell='adapter-cell'",
            &[&attempt],
        )
        .await
        .unwrap();
    assert_eq!(planted, 1, "the custody row was planted");

    fixture.handle.cleanup_pass(8).await.unwrap();

    let floor = retired_floor(&fixture).await;
    let now = database_now_ms(&fixture).await;
    assert_eq!(
        floor,
        attempt_ms,
        "the floor stops at the oldest custody row's attempt time (now minus 15 minutes would be {})",
        now - 900_000
    );
    let skips = fixture.handle.cleanup_skips();
    assert_eq!(skips.spool_retire_failed, 0, "{skips:?}");
    assert_eq!(skips.spool_retire_contended, 0, "{skips:?}");
    let age = fixture.handle.spool_retired_floor_age();
    let expected = Duration::from_millis(u64::try_from(ROW_AGE_MS).unwrap_or(0));
    assert!(
        age >= expected.saturating_sub(SLACK) && age <= expected + SLACK,
        "the age is about the row's age ({expected:?}): {age:?}"
    );
    assert!(
        age > Duration::from_secs(3600),
        "well above the 1 hour alert threshold: {age:?}"
    );

    fixture
        .admin
        .execute(
            "DELETE FROM object_store_retention.drain_spool_custody WHERE service='pinned-service'",
            &[],
        )
        .await
        .unwrap();
    assert_ledger_matches_custody(&fixture).await;
}

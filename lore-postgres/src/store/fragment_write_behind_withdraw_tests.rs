// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A staged put that fails before its rename withdraws its own preparation.
//!
//! Without the withdrawal the `PreparingStage` head fences every retry of the
//! hash ("stage preparation is still live") until `prepare_ttl` runs out.
use std::time::Instant;

use super::*;
use crate::domain::fragments::StageReservationInput;
use crate::store::write_behind::finalize::test_faults;
use crate::store::write_behind::root::derived_staged_key;

fn address_of(bytes: &Bytes) -> Address {
    Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(bytes).as_bytes().as_slice()),
    }
}

/// `(epoch, state, operation_fence)` for every custody row of the hash.
async fn custody(fixture: &Fixture, address: Address) -> Vec<(i64, i16, i64)> {
    fixture
        .admin
        .query(
            "SELECT epoch,state,operation_fence FROM lore_fragment_stage_custody \
             WHERE hash=$1 ORDER BY epoch",
            &[&address.hash.data().as_slice()],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

/// `(state, current_epoch, last_fence)` of the lifecycle head.
async fn head(fixture: &Fixture, address: Address) -> (i16, i64, i64) {
    let row = fixture
        .admin
        .query_one(
            "SELECT state,current_epoch,last_fence FROM lore_fragment_lifecycle WHERE hash=$1",
            &[&address.hash.data().as_slice()],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

async fn put(fixture: &Fixture, bytes: &Bytes) -> Result<EpochWitness, StoreError> {
    fixture
        .store
        .put_staged(
            &fixture.handle.coordinator,
            &fixture.stage,
            address_of(bytes),
            raw_fragment(bytes),
            bytes.clone(),
        )
        .await
}

const PREPARING_STAGE: i16 = 1;
const CUSTODY_PREPARING: i16 = 0;
const CUSTODY_SEALED: i16 = 2;

/// Red before withdrawal: the retry was fenced by the failed attempt's live
/// preparation and returned `SlowDown`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn pre_rename_failure_withdraws_so_an_immediate_retry_is_admitted() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("pre-rename fault payload repeated ".repeat(512));
    let address = address_of(&bytes);
    test_faults::install(address.hash.data(), test_faults::Fault::PreDurableError);
    let failed = put(&fixture, &bytes).await;
    assert!(
        matches!(&failed, Err(error) if error.is_slow_down()),
        "a staging I/O failure stays retryable backpressure: {failed:?}"
    );
    // Observed now, asserted after the retry, so the behavior under test
    // decides first.
    let rows = custody(&fixture, address).await;
    let (head_state, head_epoch, head_fence) = head(&fixture, address).await;
    let retried = put(&fixture, &bytes)
        .await
        .expect("the retry is admitted at once, not fenced by the withdrawn attempt");
    assert_eq!(retried.state, FragmentLifecycleState::Staged);
    assert_eq!(rows.len(), 1, "one reservation for the failed attempt");
    let (withdrawn_epoch, state, operation_fence) = rows[0];
    assert_eq!(
        state, CUSTODY_SEALED,
        "the withdrawn reservation is sealed for fenced cleanup"
    );
    assert_eq!(
        (head_state, head_epoch),
        (PREPARING_STAGE, withdrawn_epoch),
        "withdrawal leaves the head in place for the next begin to replace"
    );
    assert_ne!(
        head_fence, operation_fence,
        "withdrawal burns the attempt's fence"
    );
    assert!(
        retried.epoch > withdrawn_epoch,
        "the retry takes a new epoch"
    );
}

/// The release path end to end: the finalizer claims the rename, the rename
/// fails, the claim is released, and the put withdraws its preparation.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_failed_rename_releases_its_claim_and_the_put_withdraws() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("rename fault payload repeated ".repeat(512));
    let address = address_of(&bytes);
    test_faults::install(address.hash.data(), test_faults::Fault::RenameError);
    let failed = put(&fixture, &bytes).await;
    assert!(
        matches!(&failed, Err(error) if error.is_slow_down()),
        "{failed:?}"
    );
    let rows = custody(&fixture, address).await;
    let retried = put(&fixture, &bytes)
        .await
        .expect("the retry is admitted at once after the released claim withdrew");
    assert_eq!(rows.len(), 1);
    let (epoch, state, _) = rows[0];
    assert_eq!(
        state, CUSTODY_SEALED,
        "the released claim let the put withdraw"
    );
    let key = derived_staged_key(address.hash.data(), epoch).unwrap();
    assert!(
        matches!(
            fixture
                .stage
                .read_staged(address.hash.data(), epoch, &key)
                .await,
            StagedRead::Absent
        ),
        "the failed rename placed nothing"
    );
    assert!(retried.epoch > epoch);
}

/// More cancellations than withdrawal permits: the excess skips its database
/// withdrawal, is counted, and falls back to the prepare deadline. The
/// skipped attempt is still marked withdrawn, so its finalizer never renames.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_cancellation_over_the_withdraw_bound_falls_back_to_the_prepare_deadline() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("bounded cancellation payload repeated ".repeat(512));
    let address = address_of(&bytes);
    let held = fixture
        .store
        .cancel_withdrawals
        .exhaust()
        .expect("every withdrawal permit is held, as by a burst in flight");
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    test_faults::install(
        address.hash.data(),
        test_faults::Fault::PreDurablePause {
            entered: entered_tx,
            release: release_rx,
        },
    );
    {
        let pending = put(&fixture, &bytes);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("the paused put completed: {result:?}"),
            entered = entered_rx => entered.unwrap(),
        }
    }
    assert_eq!(
        fixture.store.cancel_withdrawals.skipped(),
        1,
        "the cancellation over the bound is counted"
    );
    drop(held);
    release_tx.send(()).unwrap();
    let rows = custody(&fixture, address).await;
    assert_eq!(rows.len(), 1);
    let (epoch, _, _) = rows[0];
    let key = derived_staged_key(address.hash.data(), epoch).unwrap();
    let temporary = fixture.stage.root().incoming().join(format!("{key}.tmp"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while temporary.exists() {
        assert!(Instant::now() < deadline, "the finalizer finished");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        custody(&fixture, address).await[0].1,
        CUSTODY_PREPARING,
        "a skipped withdrawal writes nothing"
    );
    assert!(
        matches!(
            fixture
                .stage
                .read_staged(address.hash.data(), epoch, &key)
                .await,
            StagedRead::Absent
        ),
        "the skipped attempt is still withdrawn in memory and never renames"
    );
    let fenced = put(&fixture, &bytes).await;
    assert!(
        matches!(&fenced, Err(error) if error.is_slow_down()),
        "the retry waits for the prepare deadline: {fenced:?}"
    );
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_stage_custody SET prepare_deadline = clock_timestamp() \
             WHERE hash=$1",
            &[&address.hash.data().as_slice()],
        )
        .await
        .unwrap();
    let retried = put(&fixture, &bytes)
        .await
        .expect("the retry is admitted once the prepare deadline passes");
    assert!(retried.epoch > epoch);
}

/// The withdrawn intent cannot be published afterwards, whatever it observed.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_late_writer_of_a_withdrawn_epoch_is_refused() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let coordinator = &fixture.handle.coordinator;
    let bytes = Bytes::from("late writer payload repeated ".repeat(512));
    let address = address_of(&bytes);
    let reservation = StageReservationInput {
        size_payload: bytes.len() as u64,
        original_flags: 0,
    };
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(address.hash.data(), reservation)
        .await
        .unwrap()
    else {
        panic!("first stage admitted")
    };
    assert!(coordinator.withdraw_stage(&intent).await.unwrap());
    assert!(
        !coordinator.withdraw_stage(&intent).await.unwrap(),
        "a second withdrawal finds nothing it owns"
    );
    // The late writer still finishes its file, then tries to publish it.
    fixture
        .stage
        .stage(
            address.hash.data(),
            intent.epoch,
            &intent.object_key,
            &bytes,
        )
        .await
        .unwrap();
    let manifest = PostgresImmutableStore::epoch_manifest(
        &intent,
        address,
        raw_fragment(&bytes),
        &bytes,
        EpochAuthority::Staged,
    )
    .unwrap();
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest))
            .await
            .unwrap(),
        CommitVerdict::Fenced
    );
    assert_eq!(
        coordinator
            .commit_staged(&intent, IoObservation::Unusable(MissingDiagnostic::Absent))
            .await
            .unwrap(),
        CommitVerdict::Fenced,
        "nor can it publish Missing over the burned epoch"
    );
    let rows = custody(&fixture, address).await;
    assert_eq!(rows, vec![(intent.epoch, CUSTODY_SEALED, intent.fence)]);
    let BeginOutcome::Admitted(retry) = coordinator
        .begin_stage(address.hash.data(), reservation)
        .await
        .unwrap()
    else {
        panic!("a retry after withdrawal is admitted")
    };
    assert!(retry.epoch > intent.epoch);
}

/// After the rename the file may be durable, so the preparation is left alone
/// and the retry stays fenced until the prepare deadline.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn post_rename_failure_does_not_withdraw() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("post-rename fault payload repeated ".repeat(512));
    let address = address_of(&bytes);
    test_faults::install(address.hash.data(), test_faults::Fault::PostDurableError);
    let failed = put(&fixture, &bytes).await;
    assert!(
        matches!(&failed, Err(error) if error.is_slow_down()),
        "{failed:?}"
    );
    let rows = custody(&fixture, address).await;
    assert_eq!(rows.len(), 1);
    let (epoch, state, operation_fence) = rows[0];
    assert_eq!(state, CUSTODY_PREPARING, "the preparation is not withdrawn");
    assert_eq!(
        head(&fixture, address).await,
        (PREPARING_STAGE, epoch, operation_fence),
        "the head keeps the attempt's own fence"
    );
    let key = derived_staged_key(address.hash.data(), epoch).unwrap();
    assert!(
        matches!(
            fixture
                .stage
                .read_staged(address.hash.data(), epoch, &key)
                .await,
            StagedRead::Found(_)
        ),
        "the renamed file is still in place"
    );
    let fenced = put(&fixture, &bytes).await;
    assert!(
        matches!(&fenced, Err(error) if error.is_slow_down()),
        "the retry is fenced by the live preparation: {fenced:?}"
    );
}

/// A withdrawal the database refuses leaves today's behavior: the caller gets
/// its own error, and the preparation lives until its deadline.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn withdraw_database_failure_falls_back_to_the_prepare_deadline() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .admin
        .batch_execute(
            "CREATE FUNCTION refuse_stage_withdraw() RETURNS trigger LANGUAGE plpgsql AS \
             $$BEGIN RAISE EXCEPTION 'withdraw refused by test'; END$$; \
             CREATE TRIGGER refuse_stage_withdraw BEFORE UPDATE ON lore_fragment_stage_custody \
             FOR EACH ROW WHEN (OLD.state = 0 AND NEW.state = 2) \
             EXECUTE FUNCTION refuse_stage_withdraw();",
        )
        .await
        .unwrap();
    let bytes = Bytes::from("withdraw refused payload repeated ".repeat(512));
    let address = address_of(&bytes);
    test_faults::install(address.hash.data(), test_faults::Fault::PreDurableError);
    let failed = put(&fixture, &bytes).await;
    assert!(
        matches!(&failed, Err(error) if error.is_slow_down()),
        "the caller sees the staging failure, not the withdrawal failure: {failed:?}"
    );
    let rows = custody(&fixture, address).await;
    assert_eq!(rows.len(), 1);
    let (epoch, state, operation_fence) = rows[0];
    assert_eq!(
        state, CUSTODY_PREPARING,
        "the refused withdrawal wrote nothing"
    );
    assert_eq!(
        head(&fixture, address).await,
        (PREPARING_STAGE, epoch, operation_fence)
    );
    let fenced = put(&fixture, &bytes).await;
    assert!(
        matches!(&fenced, Err(error) if error.is_slow_down()),
        "{fenced:?}"
    );
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_stage_custody SET prepare_deadline = clock_timestamp() \
             WHERE hash=$1",
            &[&address.hash.data().as_slice()],
        )
        .await
        .unwrap();
    let retried = put(&fixture, &bytes)
        .await
        .expect("the retry is admitted once the prepare deadline passes");
    assert!(retried.epoch > epoch);
}

/// A cancelled put withdraws without waiting, and its still-running finalizer
/// does not rename afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn cancelled_put_before_rename_withdraws_and_its_finalizer_does_not_rename() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("cancelled put payload repeated ".repeat(512));
    let address = address_of(&bytes);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    test_faults::install(
        address.hash.data(),
        test_faults::Fault::PreDurablePause {
            entered: entered_tx,
            release: release_rx,
        },
    );
    {
        let pending = put(&fixture, &bytes);
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("the paused put completed: {result:?}"),
            entered = entered_rx => entered.unwrap(),
        }
        // Dropping the future is the cancellation.
    }
    let rows = custody(&fixture, address).await;
    assert_eq!(rows.len(), 1);
    let (epoch, _, _) = rows[0];
    let deadline = Instant::now() + Duration::from_secs(10);
    while custody(&fixture, address).await[0].1 != CUSTODY_SEALED {
        assert!(
            Instant::now() < deadline,
            "the cancelled put withdrew its preparation"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    release_tx.send(()).unwrap();
    let key = derived_staged_key(address.hash.data(), epoch).unwrap();
    let temporary = fixture.stage.root().incoming().join(format!("{key}.tmp"));
    while temporary.exists() {
        assert!(Instant::now() < deadline, "the finalizer finished");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        matches!(
            fixture
                .stage
                .read_staged(address.hash.data(), epoch, &key)
                .await,
            StagedRead::Absent
        ),
        "a withdrawn attempt never places its file"
    );
    let retried = put(&fixture, &bytes)
        .await
        .expect("the retry is admitted after the cancelled attempt withdrew");
    assert!(retried.epoch > epoch);
}

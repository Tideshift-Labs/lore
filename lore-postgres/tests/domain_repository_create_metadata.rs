// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP118 create metadata witness transaction tests; schema-valid provider observations are fixture-only.
//! Real provider upload is proved separately by clean_init_single_server_rpc.
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::MissingDiagnostic;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use tokio_postgres::Client;
#[path = "common/create_metadata_fixture.rs"]
mod setup;
#[path = "common/create_metadata_witness.rs"]
mod witness;
async fn fixture() -> (PostgresDomainStore, Client) {
    let (_, store, direct) = setup::fixture(true).await;
    store
        .fragment_coordinator()
        .initialize_empty(
            &CleanCellInitialization::new("fixture-empty".into(), "scoped-writer-v1".into())
                .unwrap(),
        )
        .await
        .unwrap();
    lore_postgres::domain::outbox::stamp_cutover(&direct, "create-metadata-test")
        .await
        .unwrap();
    (store, direct)
}
async fn operation(store: &PostgresDomainStore) -> GovernedOperation {
    operation_named(store, "repository.create").await
}
async fn operation_named(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let elapsed = store
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let key = ReceiptKey {
        verified_issuer: "https://metadata-test.invalid".into(),
        authenticated_subject: "fixture".into(),
        tenant_scope_key: vec![8; 16],
        operation_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            elapsed.as_secs(),
            elapsed.subsec_nanos(),
        )),
    };
    let binding = OperationBinding {
        method: method.into(),
        scope: vec![8; 16],
        fingerprint_version: 1,
        fingerprint: vec![4; 32],
        canonical_intent_digest: vec![5; 32],
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap()
    else {
        panic!("prepare")
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}
async fn input(store: &PostgresDomainStore) -> RepositoryCreateInput {
    let repository = uuid::Uuid::now_v7().as_bytes().to_vec();
    let branch = uuid::Uuid::now_v7().as_bytes().to_vec();
    let first = uuid::Uuid::now_v7().as_bytes().repeat(2);
    let second = uuid::Uuid::now_v7().as_bytes().repeat(2);
    let name = format!("metadata-{}", uuid::Uuid::now_v7());
    let witnesses = vec![
        witness::publish(store, &first).await,
        witness::publish(store, &second).await,
    ];
    let events = vec![
        lore_postgres::domain::outbox::builders::repository_published(
            "create-metadata-test",
            &repository,
            &name,
            &branch,
            "main",
        )
        .unwrap(),
        lore_postgres::domain::outbox::builders::branch_created(
            "create-metadata-test",
            &repository,
            &branch,
            "main",
            &[0; 32],
        )
        .unwrap(),
    ];
    RepositoryCreateInput {
        repository_id: repository.clone(),
        name,
        metadata_hash: first,
        default_branch_id: branch,
        default_branch_name: "main".into(),
        default_branch_metadata_hash: second,
        default_branch_latest_hash: vec![0; 32],
        creation_fingerprint: vec![6; 32],
        creation_fingerprint_version: 1,
        metadata_witnesses: witnesses,
        projection: vec![ProjectionWrite {
            partition: repository,
            key_type: 0,
            key: vec![7; 32],
            value: Some(vec![9; 32]),
        }],
        events,
    }
}
async fn counts(direct: &Client, input: &RepositoryCreateInput) -> Vec<i64> {
    let row=direct.query_one("SELECT (SELECT count(*) FROM lore_domain_repositories WHERE repository_id=$1), (SELECT count(*) FROM lore_domain_branches WHERE repository_id=$1), (SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1), (SELECT count(*) FROM lore_mutable WHERE partition=$1), (SELECT count(*) FROM lore_outbox_events WHERE cell_id='create-metadata-test')",&[&input.repository_id]).await.unwrap();
    (0..5).map(|i| row.get(i)).collect()
}
fn metadata_refusal(error: DomainOutcome) {
    assert!(
        matches!(&error,DomainOutcome::NotApplied{reason,reason_version:1} if reason.starts_with("repository_create_metadata")),
        "{error:?}"
    );
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn fresh_create_binds_exact_metadata_with_projection_receipt_and_events() {
    let (store, direct) = fixture().await;
    let input = input(&store).await;
    let op = operation(&store).await;
    assert_eq!(
        store.repository_create(&op, &input).await.unwrap().outcome,
        DomainOutcome::Applied
    );
    assert_eq!(counts(&direct, &input).await, vec![1, 1, 2, 1, 4]);
    let event_kinds: Vec<String> = direct.query("SELECT event_kind FROM lore_outbox_events WHERE cell_id='create-metadata-test' ORDER BY event_kind", &[]).await.unwrap().iter().map(|row| row.get(0)).collect();
    assert_eq!(
        event_kinds,
        [
            "association.generation_advanced",
            "association.generation_advanced",
            "branch.created",
            "repository.published"
        ]
    );
    let rows=direct.query("SELECT hash,context FROM lore_fragment_associations WHERE repository_id=$1 ORDER BY hash",&[&input.repository_id]).await.unwrap();
    let mut hashes = vec![
        input.metadata_hash.clone(),
        input.default_branch_metadata_hash.clone(),
    ];
    hashes.sort();
    for (row, hash) in rows.iter().zip(hashes) {
        assert_eq!(row.get::<_, Vec<u8>>(0), hash);
        assert_eq!(row.get::<_, Vec<u8>>(1), vec![0; 16]);
    }
    let same = store.repository_create(&op, &input).await.unwrap();
    assert_eq!(same.outcome, DomainOutcome::Applied);
    assert_eq!(counts(&direct, &input).await, vec![1, 1, 2, 1, 4]);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn active_create_requires_complete_bounded_exact_witness_inventory() {
    let (store, direct) = fixture().await;
    for shape in 0..6 {
        let mut input = input(&store).await;
        let valid_input = input.clone();
        match shape {
            0 => input.metadata_witnesses.clear(),
            1 => {
                input.metadata_witnesses.pop();
            }
            2 => input
                .metadata_witnesses
                .push(input.metadata_witnesses[0].clone()),
            3 => input.metadata_witnesses[0].hash = vec![0x55; 32],
            4 => input.default_branch_latest_hash = vec![0x56; 32],
            _ => input.events.push(input.events[0].clone()),
        };
        let op = operation(&store).await;
        let error = store.repository_create(&op, &input).await.unwrap().outcome;
        metadata_refusal(error);
        // Repairing speculative evidence cannot turn the already-decisive receipt into success.
        metadata_refusal(
            store
                .repository_create(&op, &valid_input)
                .await
                .unwrap()
                .outcome,
        );
        assert_eq!(counts(&direct, &input).await, vec![0, 0, 0, 0, 0]);
    }
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn identical_metadata_hashes_require_one_witness_and_one_binding() {
    let (store, direct) = fixture().await;
    let mut input = input(&store).await;
    input.default_branch_metadata_hash = input.metadata_hash.clone();
    input.metadata_witnesses.truncate(1);
    assert_eq!(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    assert_eq!(counts(&direct, &input).await, vec![1, 1, 1, 1, 3]);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn unreadable_metadata_refuses_create_without_publication() {
    let (store, direct) = fixture().await;
    let input = input(&store).await;
    store
        .fragment_coordinator()
        .mark_missing(&input.metadata_witnesses[0], MissingDiagnostic::Absent)
        .await
        .unwrap();
    metadata_refusal(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .unwrap()
            .outcome,
    );
    assert_eq!(counts(&direct, &input).await, vec![0, 0, 0, 0, 0]);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn readable_epoch_drift_refuses_create_and_rolls_back_all_effects() {
    let (store, direct) = fixture().await;
    let input = input(&store).await;
    let old = &input.metadata_witnesses[1];
    store
        .fragment_coordinator()
        .mark_missing(old, MissingDiagnostic::Absent)
        .await
        .unwrap();
    let new = witness::publish(&store, &old.hash).await;
    assert_ne!(&new, old);
    assert!(new.state.is_readable());
    metadata_refusal(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .unwrap()
            .outcome,
    );
    assert_eq!(counts(&direct, &input).await, vec![0, 0, 0, 0, 0]);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn receipt_and_fingerprint_replay_ignore_speculative_later_witnesses() {
    let (store, direct) = fixture().await;
    let mut input = input(&store).await;
    let op = operation(&store).await;
    assert_eq!(
        store.repository_create(&op, &input).await.unwrap().outcome,
        DomainOutcome::Applied
    );
    let before = counts(&direct, &input).await;
    input.metadata_witnesses.clear();
    input.metadata_hash = vec![0x72; 32];
    input.default_branch_metadata_hash = vec![0x73; 32];
    assert_eq!(
        store.repository_create(&op, &input).await.unwrap().outcome,
        DomainOutcome::Applied
    );
    assert_eq!(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    assert_eq!(counts(&direct, &input).await, before);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn name_conflict_never_binds_preuploaded_metadata() {
    let (store, direct) = fixture().await;
    let first = input(&store).await;
    assert_eq!(
        store
            .repository_create(&operation(&store).await, &first)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let mut second = input(&store).await;
    second.name = first.name.clone();
    assert!(matches!(
        store
            .repository_create(&operation(&store).await, &second)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::NotApplied { .. }
    ));
    assert_eq!(counts(&direct, &second).await, vec![0, 0, 0, 0, 4]);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn conflicting_same_identity_and_tombstone_never_bind_speculative_metadata() {
    let (store, direct) = fixture().await;
    let first = input(&store).await;
    assert_eq!(
        store
            .repository_create(&operation(&store).await, &first)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let mut speculative = input(&store).await;
    speculative.repository_id = first.repository_id.clone();
    speculative.creation_fingerprint = vec![0x61; 32];
    let before = counts(&direct, &first).await;
    assert!(matches!(
        store
            .repository_create(&operation(&store).await, &speculative)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::NotApplied { .. }
    ));
    assert_eq!(counts(&direct, &first).await, before);
    let delete = lore_postgres::domain::coordinator::RepositoryDeleteInput {
        repository_id: first.repository_id.clone(),
        expected_generation: Some(1),
        delete_proof: vec![0x62; 32],
        projection: Vec::new(),
        events: Vec::new(),
    };
    assert_eq!(
        store
            .repository_delete(&operation_named(&store, "repository.delete").await, &delete)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    let after_delete = counts(&direct, &first).await;
    assert!(matches!(
        store
            .repository_create(&operation(&store).await, &speculative)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::NotApplied { .. }
    ));
    assert_eq!(counts(&direct, &first).await, after_delete);
    assert!(
        !direct
            .query_one(
                "SELECT state=0 FROM lore_domain_repositories WHERE repository_id=$1",
                &[&first.repository_id]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert_eq!(direct.query_one("SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1 AND hash=ANY($2)",&[&first.repository_id,&vec![speculative.metadata_hash,speculative.default_branch_metadata_hash]]).await.unwrap().get::<_,i64>(0),0);
}
#[tokio::test]
#[ignore = "owned PostgreSQL; run run-repository-create-metadata-live.ps1"]
async fn failure_after_metadata_binding_rolls_back_associations_and_publication() {
    let (store, direct) = fixture().await;
    let input = input(&store).await;
    // Projection is after metadata binding. A real SQL exception there must undo every earlier insert.
    direct.batch_execute("CREATE SEQUENCE fixture_bound_seen; CREATE FUNCTION fixture_projection_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM lore_fragment_associations WHERE repository_id=NEW.partition) = 2 THEN PERFORM nextval('fixture_bound_seen'); END IF; RAISE EXCEPTION 'fixture projection failure' USING ERRCODE='23514'; END $$; CREATE TRIGGER fixture_projection_failure BEFORE INSERT ON lore_mutable FOR EACH ROW EXECUTE FUNCTION fixture_projection_failure()").await.unwrap();
    assert!(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .is_err()
    );
    assert_eq!(counts(&direct, &input).await, vec![0, 0, 0, 0, 0]);
    assert!(
        direct
            .query_one("SELECT is_called FROM fixture_bound_seen", &[])
            .await
            .unwrap()
            .get::<_, bool>(0),
        "projection failure must observe both transaction-local bindings"
    );
    direct
        .batch_execute("DROP TRIGGER fixture_projection_failure ON lore_mutable")
        .await
        .unwrap();
    assert_eq!(
        store
            .repository_create(&operation(&store).await, &input)
            .await
            .unwrap()
            .outcome,
        DomainOutcome::Applied
    );
    assert_eq!(counts(&direct, &input).await, vec![1, 1, 2, 1, 4]);
}

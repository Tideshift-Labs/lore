// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
// Included inside domain::tests to reuse its verified-echo and admission fixtures.
use lore_postgres::domain::errors::DomainError;

fn branch_create_assert_frozen(
    actual: lore_postgres::domain::coordinator::BranchCreateResult,
    expected: &lore_postgres::domain::coordinator::BranchCreateResult,
) {
    assert!(actual.replayed);
    assert_eq!(actual.outcome, expected.outcome);
    assert_eq!(actual.public_result, expected.public_result);
}

fn branch_create_admission(ctx: &DomainContext, attempt: Uuid) -> AdmittedOperation {
    let mut metadata = human_metadata();
    metadata.insert("lore-attempt-id", attempt.to_string().parse().unwrap());
    ctx.admit(
        &metadata,
        Some(&human_token()),
        direct_scope_ctx(&test_repository_id()),
    )
    .unwrap()
    .unwrap()
}

fn branch_create_frozen() -> lore_postgres::domain::coordinator::BranchCreateResult {
    let response = lore_proto::lore::revision::v1::BranchCreateResponse {
        branch: Some(lore_proto::lore::model::v1::Branch {
            id: vec![1; 16].into(),
            creator: "original-foreign-creator".into(),
            latest: vec![2; 32].into(),
            metadata: vec![3; 32].into(),
            created: 123,
            ..Default::default()
        }),
    };
    let mut bytes = vec![1];
    prost::Message::encode(&response, &mut bytes).unwrap();
    lore_postgres::domain::coordinator::BranchCreateResult {
        replayed: true,
        outcome: DomainOutcome::Applied,
        public_result: Some(bytes),
    }
}

#[tokio::test]
async fn branch_create_internal_prepare_uses_client_attempt_as_stable_key() {
    let store = Arc::new(super::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let attempt = Uuid::now_v7();
    let first = branch_create_admission(&ctx, attempt);
    let second = branch_create_admission(&ctx, attempt);
    assert_ne!(
        first.key.operation_id, second.key.operation_id,
        "admission initially mints distinct keys"
    );
    for admitted in [first, second] {
        let prepared = GovernedBranchCreate::prepare(&ctx, admitted, vec![7; 32])
            .await
            .unwrap();
        let BranchCreateAdmission::Prepared(operation) = prepared.admission else {
            panic!("expected Prepared")
        };
        assert_eq!(operation.key.operation_id, attempt);
    }
    let calls = store.direct_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for (key, binding, id) in calls.iter() {
        assert_eq!(key.operation_id, attempt);
        assert_eq!(*id, Some(attempt));
        assert_eq!(binding.method, "branch.create");
        assert_eq!(binding.canonical_intent_digest, vec![7; 32]);
    }
    assert_eq!(verifier.call_count(), 2);
}

#[tokio::test]
async fn branch_create_frozen_terminal_replays_before_fresh_authorization_even_after_downgrade() {
    for downgraded in [false, true] {
        let store = Arc::new(super::test_support::PreparingDomainStore::default());
        let verifier = Arc::new(if downgraded {
            DirectVerifierDouble::erroring(Status::permission_denied("role downgraded"))
        } else {
            DirectVerifierDouble::echo()
        });
        let ctx = Arc::new(
            DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
        );
        let frozen = branch_create_frozen();
        store
            .branch_terminal_replies
            .lock()
            .unwrap()
            .push_back(Ok(Some(frozen.clone())));
        let governed = GovernedBranchCreate::prepare(
            &ctx,
            branch_create_admission(&ctx, Uuid::now_v7()),
            vec![7; 32],
        )
        .await
        .unwrap();
        branch_create_assert_frozen(governed.replay().await.unwrap().unwrap(), &frozen);
        assert_eq!(verifier.call_count(), 0);
        assert!(store.direct_calls.lock().unwrap().is_empty());
        assert!(matches!(
            governed.admission,
            BranchCreateAdmission::Terminal(_)
        ));
    }
}

#[tokio::test]
async fn branch_create_prepare_already_committed_rechecks_exact_terminal() {
    let store = Arc::new(super::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let frozen = branch_create_frozen();
    store
        .branch_terminal_replies
        .lock()
        .unwrap()
        .extend([Ok(None), Ok(Some(frozen.clone()))]);
    *store.direct_result.lock().unwrap() = Some(PrepareResult::Committed(DomainOutcome::Applied));
    let attempt = Uuid::now_v7();
    let governed =
        GovernedBranchCreate::prepare(&ctx, branch_create_admission(&ctx, attempt), vec![7; 32])
            .await
            .unwrap();
    branch_create_assert_frozen(governed.replay().await.unwrap().unwrap(), &frozen);
    assert_eq!(verifier.call_count(), 1);
    let calls = store.branch_terminal_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, calls[1].0);
    assert_eq!(calls[0].1, calls[1].1);
    assert_eq!(calls[0].0.operation_id, attempt);
}

#[tokio::test]
async fn branch_create_terminal_lookup_preserves_conflict_and_unknown_classification() {
    for unknown in [false, true] {
        let store = Arc::new(super::test_support::PreparingDomainStore::default());
        let verifier = Arc::new(DirectVerifierDouble::echo());
        let ctx = Arc::new(
            DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
        );
        store
            .branch_terminal_replies
            .lock()
            .unwrap()
            .push_back(Err(if unknown {
                DomainError::OutcomeUnknown("expired or unavailable payload".into())
            } else {
                DomainError::InvalidInput("binding mismatch".into())
            }));
        let error = GovernedBranchCreate::prepare(
            &ctx,
            branch_create_admission(&ctx, Uuid::now_v7()),
            vec![8; 32],
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            error.code(),
            if unknown {
                Code::Aborted
            } else {
                Code::InvalidArgument
            }
        );
        assert_eq!(
            error
                .metadata()
                .get(lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY)
                .is_some(),
            unknown
        );
        assert_eq!(
            lore_transport::error::ProtocolError::from(error).is_outcome_unknown(),
            unknown
        );
        assert_eq!(verifier.call_count(), 0);
        assert!(store.direct_calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn branch_create_missing_attempt_refuses_before_terminal_lookup_or_verifier() {
    let store = Arc::new(super::test_support::PreparingDomainStore::default());
    let verifier = Arc::new(DirectVerifierDouble::echo());
    let ctx = Arc::new(
        DomainContext::new(store.clone(), true).with_operation_verifier(Some(verifier.clone())),
    );
    let admitted = ctx
        .admit(
            &human_metadata(),
            Some(&human_token()),
            direct_scope_ctx(&test_repository_id()),
        )
        .unwrap()
        .unwrap();
    let error = GovernedBranchCreate::prepare(&ctx, admitted, vec![7; 32])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(store.branch_terminal_calls.lock().unwrap().is_empty());
    assert_eq!(verifier.call_count(), 0);
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::coordinator::BranchCreateResult;
use lore_postgres::domain::errors::DomainOutcome;
use lore_proto::lore::model::v1::Branch;
use lore_proto::lore::model::v1::BranchPoint;
use lore_proto::lore::revision::v1::BranchCreateResponse;
use prost::Message;

use super::decode_governed_result;

async fn governed_fixture(
    replay: Option<BranchCreateResult>,
) -> (
    crate::domain::GovernedBranchCreate,
    std::sync::Arc<crate::domain::test_support::ScriptedDomainStore>,
    std::sync::Arc<lore_revision::repository::RepositoryContext>,
) {
    use std::sync::Arc;

    use lore_postgres::domain::coordinator::MutationResult;
    use lore_postgres::domain::receipts::ReceiptKey;

    use crate::domain::AdmissionSource;
    use crate::domain::AdmittedOperation;
    use crate::domain::DomainContext;
    use crate::domain::GovernedBranchCreate;
    use crate::grpc::domain_operation_metadata::DomainOperationMetadata;
    let script = Arc::new(crate::domain::test_support::ScriptedDomainStore::new(
        MutationResult::rejected("unexpected"),
    ));
    *script.branch_create_replay_result.lock().unwrap() = replay.map(|mut result| {
        result.replayed = true;
        result
    });
    let domain = Arc::new(DomainContext::new(script.clone(), true));
    let operation_id = uuid::Uuid::now_v7();
    let admitted = AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://branch-create.invalid".into(),
            authenticated_subject: "verified".into(),
            tenant_scope_key: vec![7; 16],
            operation_id,
        },
        source: AdmissionSource::Carried(Box::new(DomainOperationMetadata {
            operation_id,
            fingerprint_version: 1,
            fingerprint: vec![4; 32],
            prepare_token: [5; 32],
            mediated_scope: None,
            claim_witness: None,
        })),
    };
    let governed = GovernedBranchCreate::prepare(&domain, admitted, vec![6; 32])
        .await
        .unwrap();
    let (immutable, mutable, _execution) = crate::store::test_store_create().await.unwrap();
    let repository = Arc::new(
        lore_revision::repository::RepositoryContext::new_server_context(
            immutable,
            mutable,
            rand::random::<lore_revision::lore::RepositoryId>(),
        ),
    );
    (governed, script, repository)
}

#[tokio::test]
async fn exact_replay_precedes_request_validation_and_every_repository_read() {
    let expected = response();
    let (governed, script, repository) = governed_fixture(Some(stored(&expected))).await;
    // Empty stores and an unconfigured snapshot double make any speculative read fail.
    let invalid_request = lore_proto::lore::revision::v1::BranchCreateRequest {
        id: vec![0; 1].into(),
        name: "x".repeat(1001),
        creator: Some("foreign".into()),
        ..Default::default()
    };
    let actual =
        super::governed_branch_create(&governed, &invalid_request, repository, "verified", false)
            .await
            .unwrap();
    assert_eq!(actual.response, expected);
    assert!(!actual.newly_applied);
    assert!(script.branch_create_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn frozen_foreign_creator_survives_role_downgrade_without_new_publication() {
    let mut expected = response();
    expected.branch.as_mut().unwrap().creator = "previously-authorized-foreign".into();
    let (governed, script, repository) = governed_fixture(Some(stored(&expected))).await;
    let request = lore_proto::lore::revision::v1::BranchCreateRequest {
        creator: Some("previously-authorized-foreign".into()),
        ..Default::default()
    };
    let replay = super::governed_branch_create(&governed, &request, repository, "verified", false)
        .await
        .unwrap();
    assert_eq!(replay.response, expected);
    assert!(!replay.newly_applied);
    assert!(script.branch_create_calls.lock().unwrap().is_empty());
}

#[test]
fn creator_policy_preserves_foreign_identity_only_with_verified_permission() {
    for (requested, allowed, expected) in [
        (None, false, "verified"),
        (None, true, "verified"),
        (Some("verified"), false, "verified"),
        (Some("foreign"), false, "verified"),
        (Some("foreign"), true, "foreign"),
        (Some(""), false, "verified"),
        (Some(""), true, ""),
    ] {
        assert_eq!(
            super::effective_creator(requested, "verified", allowed),
            expected
        );
    }
}

#[tokio::test]
async fn authenticated_handler_persists_creator_from_exact_repository_permissions() {
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_revision::branch;
    use lore_revision::repository;

    use crate::auth::jwt::AuthorizationToken;
    use crate::auth::jwt::ResourcePermission;

    struct Instruments;
    impl lore_telemetry::InstrumentProvider for Instruments {
        fn namespace(&self) -> &'static str {
            "creator-policy"
        }
        fn labels(&self) -> &[opentelemetry::KeyValue] {
            &[]
        }
    }
    // These extensions stand in for already-verified auth middleware. This test does not verify JWTs.
    for (permission, resource_scope, requested, expected) in [
        ("write", "exact", Some("foreign"), "verified"),
        ("write", "exact", None, "verified"),
        ("write", "exact", Some("verified"), "verified"),
        ("owner", "exact", Some("foreign"), "foreign"),
        ("admin", "exact", Some("foreign"), "foreign"),
        ("admin", "other", Some("foreign"), "verified"),
        ("owner", "wildcard", Some("foreign"), "verified"),
        ("read", "exact", Some("foreign"), "verified"),
    ] {
        let repo = rand::random::<lore_revision::lore::RepositoryId>();
        let other = rand::random::<lore_revision::lore::RepositoryId>();
        let (immutable, mutable, execution) = crate::store::test_store_create().await.unwrap();
        let context = Arc::new(repository::RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            repo,
        ));
        let mut notifications = crate::notification::testing::MockNotificationSender::new();
        notifications
            .expect_branch_created()
            .times(1)
            .returning(|_, _| ());
        LORE_CONTEXT
            .scope(execution, async {
                let mut request =
                    tonic::Request::new(lore_proto::lore::revision::v1::BranchCreateRequest {
                        id: uuid::Uuid::now_v7().as_bytes().to_vec().into(),
                        name: "main".into(),
                        creator: requested.map(str::to_owned),
                        ..Default::default()
                    });
                request.metadata_mut().insert_bin(
                    lore_transport::grpc::REPOSITORY_ID_KEY,
                    tonic::metadata::BinaryMetadataValue::from_bytes(repo.data()),
                );
                let resource_id = match resource_scope {
                    "exact" => format!("urc-{repo}"),
                    "other" => format!("urc-{other}"),
                    "wildcard" => "urc-*".into(),
                    _ => unreachable!(),
                };
                request.extensions_mut().insert(AuthorizationToken {
                    user_id: "verified".into(),
                    resources: Some(vec![ResourcePermission {
                        resource_id,
                        permission: vec![permission.into()],
                    }]),
                    ..Default::default()
                });
                let response = super::handler(
                    request,
                    immutable,
                    mutable,
                    Arc::new(notifications),
                    &None,
                    &crate::hooks::HookDispatcher::empty(),
                    &Instruments,
                )
                .await
                .unwrap()
                .into_inner()
                .branch
                .unwrap();
                assert_eq!(response.creator, expected, "{permission}/{resource_scope}");
                let metadata = branch::load_metadata(context, response.metadata.as_ref().into())
                    .await
                    .unwrap();
                assert_eq!(
                    branch::creator(&metadata).unwrap(),
                    expected,
                    "persisted {permission}/{resource_scope}"
                );
            })
            .await;
    }
}

#[tokio::test]
async fn concurrent_receipt_dispositions_emit_exactly_one_creation_notification() {
    struct Instruments;
    impl lore_telemetry::InstrumentProvider for Instruments {
        fn namespace(&self) -> &'static str {
            "branch-create-test"
        }
        fn labels(&self) -> &[opentelemetry::KeyValue] {
            &[]
        }
    }
    let response = response();
    let fresh = super::completed_creation(stored(&response)).unwrap();
    let mut durable_replay = stored(&response);
    durable_replay.replayed = true;
    let replay = super::completed_creation(durable_replay).unwrap();
    assert!(fresh.newly_applied);
    assert!(!replay.newly_applied);
    assert_eq!(fresh.response, replay.response);
    let mut notifications = crate::notification::testing::MockNotificationSender::new();
    notifications
        .expect_branch_created()
        .times(1)
        .returning(|_, _| ());
    let hooks = crate::hooks::HookDispatcher::empty();
    let repository = rand::random::<lore_revision::lore::RepositoryId>();
    let branch = rand::random::<lore_revision::lore::BranchId>();
    let hook = || {
        crate::hooks::HookContext::builder()
            .correlation_id("retry-race")
            .hook_point(crate::hooks::HookPoint::BranchCreate)
            .repository(repository)
            .user("verified")
            .branch(branch)
            .build()
    };
    tokio::join!(
        super::emit_governed_branch_created(
            &fresh,
            &notifications,
            &hooks,
            &Instruments,
            hook(),
            repository,
            branch
        ),
        super::emit_governed_branch_created(
            &replay,
            &notifications,
            &hooks,
            &Instruments,
            hook(),
            repository,
            branch
        )
    );
}

fn response() -> BranchCreateResponse {
    BranchCreateResponse {
        branch: Some(Branch {
            id: vec![1; 16].into(),
            name: "historical-name".into(),
            creator: "creator".into(),
            category: "feature".into(),
            created: 1234,
            latest: vec![2; 32].into(),
            deleted: false,
            metadata: vec![3; 32].into(),
            stack: vec![BranchPoint {
                branch_id: vec![4; 16].into(),
                revision_signature: vec![5; 32].into(),
            }],
            protected: true,
        }),
    }
}

fn stored(response: &BranchCreateResponse) -> BranchCreateResult {
    let mut bytes = vec![1];
    response.encode(&mut bytes).unwrap();
    BranchCreateResult {
        replayed: false,
        outcome: DomainOutcome::Applied,
        public_result: Some(bytes),
    }
}

#[test]
fn durable_response_preserves_every_server_assigned_and_historical_field() {
    let expected = response();
    assert_eq!(decode_governed_result(stored(&expected)).unwrap(), expected);
}

#[test]
fn full_durable_response_bound_includes_the_version_byte() {
    let mut response = response();
    // At this size both nested protobuf length prefixes are already two bytes.
    response.branch.as_mut().unwrap().name = "x".repeat(3800);
    let overhead = stored(&response).public_result.unwrap().len() - 3800;
    response.branch.as_mut().unwrap().name = "x".repeat(4096 - overhead);
    let at_limit = stored(&response);
    assert_eq!(at_limit.public_result.as_ref().unwrap().len(), 4096);
    assert_eq!(decode_governed_result(at_limit).unwrap(), response);
    response.branch.as_mut().unwrap().name.push('x');
    let over_limit = stored(&response);
    assert_eq!(over_limit.public_result.as_ref().unwrap().len(), 4097);
    assert_eq!(
        decode_governed_result(over_limit).unwrap_err().code(),
        tonic::Code::DataLoss
    );
}

#[test]
fn missing_unknown_truncated_or_overlong_receipts_fail_closed() {
    for bytes in [
        None,
        Some(vec![]),
        Some(vec![2]),
        Some(vec![1]),
        Some(vec![1, 10, 255]),
        Some(vec![1; 4097]),
    ] {
        let result = BranchCreateResult {
            replayed: false,
            outcome: DomainOutcome::Applied,
            public_result: bytes,
        };
        assert_eq!(
            decode_governed_result(result).unwrap_err().code(),
            tonic::Code::DataLoss
        );
    }
}

#[test]
fn every_durable_branch_identity_and_pointer_width_is_checked() {
    for shape in 0..5 {
        for width_delta in [-1isize, 1] {
            let mut response = response();
            let branch = response.branch.as_mut().unwrap();
            let bytes = match shape {
                0 => &mut branch.id,
                1 => &mut branch.metadata,
                2 => &mut branch.latest,
                3 => &mut branch.stack[0].branch_id,
                _ => &mut branch.stack[0].revision_signature,
            };
            *bytes = vec![0; bytes.len().checked_add_signed(width_delta).unwrap()].into();
            assert_eq!(
                decode_governed_result(stored(&response))
                    .unwrap_err()
                    .code(),
                tonic::Code::DataLoss
            );
        }
    }
}

#[test]
fn terminal_rejections_keep_their_public_status_without_response_bytes() {
    use lore_postgres::domain::coordinator::NAME_TAKEN_V1;
    use lore_postgres::domain::coordinator::NOT_FOUND_V1;
    use lore_postgres::domain::coordinator::TOMBSTONED_V1;
    for (reason, code) in [
        (NAME_TAKEN_V1, tonic::Code::AlreadyExists),
        (TOMBSTONED_V1, tonic::Code::AlreadyExists),
        ("branch_create_id_exists_v1", tonic::Code::AlreadyExists),
        (NOT_FOUND_V1, tonic::Code::NotFound),
        (
            "branch_create_read_set_changed_v1",
            tonic::Code::FailedPrecondition,
        ),
        (
            "branch_create_response_too_large_v1",
            tonic::Code::InvalidArgument,
        ),
    ] {
        let result = BranchCreateResult {
            replayed: false,
            outcome: DomainOutcome::NotApplied {
                reason_version: 1,
                reason: reason.into(),
            },
            public_result: None,
        };
        assert_eq!(decode_governed_result(result).unwrap_err().code(), code);
    }
}

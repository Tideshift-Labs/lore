// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Direct authorization evidence against disposable Postgres. Run with
//! LORE_TEST_PG_URL and --ignored. Each test creates its own database.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::DirectAuthorizationEvidence;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::receipts::{self};
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use tokio_postgres::NoTls;
use uuid::Uuid;

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    lore_base::lore_spawn!(async move { connection.await.unwrap() });
    client
}

async fn fixture() -> (
    String,
    PostgresDomainStore,
    Client,
    ReceiptKey,
    OperationBinding,
    DirectAuthorizationEvidence,
) {
    let url = std::env::var("LORE_TEST_PG_URL").expect("live PostgreSQL URL required");
    let admin = connect(&url).await;
    let database = format!("p029_direct_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let (base, query) = url
        .split_once('?')
        .map_or((url.as_str(), None), |(base, query)| (base, Some(query)));
    let prefix = &base[..base.rfind('/').expect("URL database path")];
    let url = format!(
        "{prefix}/{database}{}",
        query.map_or(String::new(), |q| format!("?{q}"))
    );
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .unwrap();
    let client = connect(&url).await;
    let key = ReceiptKey {
        verified_issuer: "https://p029.test".into(),
        authenticated_subject: "human".into(),
        tenant_scope_key: vec![0x31; 24],
        operation_id: Uuid::now_v7(),
    };
    let binding = OperationBinding {
        method: "branch.push".into(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: vec![0x41; 32],
        canonical_intent_digest: vec![0x51; 32],
    };
    let evidence = DirectAuthorizationEvidence {
        authorization_id: key.operation_id.as_bytes().to_vec(),
        authorization_revision: 1,
        verification_nonce: vec![0x61; 32],
        bound_fields_digest: vec![0x71; 32],
    };
    (url, store, client, key, binding, evidence)
}

async fn stored_evidence(client: &Client, key: &ReceiptKey) -> Option<DirectAuthorizationEvidence> {
    let row = client
        .query_one(
            "SELECT direct_authorization_id, direct_authorization_revision::text,
        direct_verification_nonce, direct_bound_fields_digest FROM lore_domain_operation_receipts
        WHERE operation_id=$1",
            &[&key.operation_id.as_bytes().as_slice()],
        )
        .await
        .unwrap();
    row.get::<_, Option<Vec<u8>>>(0)
        .map(|authorization_id| DirectAuthorizationEvidence {
            authorization_id,
            authorization_revision: row.get::<_, String>(1).parse().unwrap(),
            verification_nonce: row.get(2),
            bound_fields_digest: row.get(3),
        })
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with CREATEDB; LORE_TEST_PG_URL"]
async fn direct_prepare_persists_evidence_through_commit_without_a_mediated_fence() {
    let (_, store, mut client, key, binding, evidence) = fixture().await;
    let attempt = Uuid::now_v7();
    let prepared = store
        .domain_operation_prepare_direct(&key, &binding, &evidence, Some(attempt))
        .await
        .unwrap();
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("must prepare")
    };
    assert_eq!(stored_evidence(&client, &key).await, Some(evidence.clone()));
    let tx = client.transaction().await.unwrap();
    assert!(matches!(
        receipts::consume(&tx, &key, &binding, &token)
            .await
            .unwrap(),
        receipts::ConsumeResult::Admitted(_)
    ));
    let clock = receipts::admission_clock(&tx).await.unwrap();
    receipts::commit_terminal(
        &tx,
        &key,
        &DomainOutcome::Applied,
        Some(b"public result"),
        clock,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(stored_evidence(&client, &key).await, Some(evidence.clone()));
    assert!(matches!(
        store
            .domain_operation_prepare_direct(&key, &binding, &evidence, None)
            .await
            .unwrap(),
        PrepareResult::Committed(DomainOutcome::Applied)
    ));
    let changed = DirectAuthorizationEvidence {
        verification_nonce: vec![0x99; 32],
        ..evidence
    };
    assert!(matches!(
        store
            .domain_operation_prepare_direct(&key, &binding, &changed, None)
            .await
            .unwrap(),
        PrepareResult::Mismatch
    ));
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_dispatch_possibility_fences",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    assert!(matches!(
        store
            .domain_operation_receipt_get(&key, &binding)
            .await
            .unwrap(),
        ReceiptLookup::Committed {
            outcome: DomainOutcome::Applied,
            from_future_marker: false
        }
    ));
    let receipts::AttemptReceipt { lookup, method } = store
        .domain_operation_attempt_receipt_get(
            &key.verified_issuer,
            &key.authenticated_subject,
            &attempt,
        )
        .await
        .unwrap();
    assert!(matches!(
        lookup,
        ReceiptLookup::Committed {
            outcome: DomainOutcome::Applied,
            ..
        }
    ));
    assert_eq!(method.as_deref(), Some("branch.push"));
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with CREATEDB; LORE_TEST_PG_URL"]
async fn direct_prepare_replay_requires_immutable_evidence_and_cannot_reclassify_legacy_rows() {
    let (_, store, client, key, binding, evidence) = fixture().await;
    let first = store
        .domain_operation_prepare_direct(&key, &binding, &evidence, None)
        .await
        .unwrap();
    let second = store
        .domain_operation_prepare_direct(&key, &binding, &evidence, None)
        .await
        .unwrap();
    match (first, second) {
        (
            PrepareResult::Prepared {
                token: first,
                hard_expires_at: first_expiry,
            },
            PrepareResult::Prepared {
                token: second,
                hard_expires_at: second_expiry,
            },
        ) => {
            assert_eq!(first, second);
            assert_eq!(first_expiry, second_expiry);
        }
        _ => panic!("exact replay must remain prepared"),
    }
    for changed in [
        DirectAuthorizationEvidence {
            authorization_id: vec![0x99; 16],
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            authorization_revision: 2,
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            verification_nonce: vec![0x99; 32],
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            bound_fields_digest: vec![0x99; 32],
            ..evidence.clone()
        },
    ] {
        assert!(matches!(
            store
                .domain_operation_prepare_direct(&key, &binding, &changed, None)
                .await
                .unwrap(),
            PrepareResult::Mismatch
        ));
    }
    assert!(matches!(
        store
            .domain_operation_prepare(&key, &binding, None, None)
            .await
            .unwrap(),
        PrepareResult::Mismatch
    ));
    assert_eq!(stored_evidence(&client, &key).await, Some(evidence));
    let legacy_key = ReceiptKey {
        operation_id: Uuid::now_v7(),
        ..key
    };
    assert!(matches!(
        store
            .domain_operation_prepare(&legacy_key, &binding, None, None)
            .await
            .unwrap(),
        PrepareResult::Prepared { .. }
    ));
    let legacy_evidence = DirectAuthorizationEvidence {
        authorization_id: legacy_key.operation_id.as_bytes().to_vec(),
        authorization_revision: 1,
        verification_nonce: vec![0x61; 32],
        bound_fields_digest: vec![0x71; 32],
    };
    assert!(matches!(
        store
            .domain_operation_prepare_direct(&legacy_key, &binding, &legacy_evidence, None)
            .await
            .unwrap(),
        PrepareResult::Mismatch
    ));
    assert_eq!(stored_evidence(&client, &legacy_key).await, None);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with CREATEDB; LORE_TEST_PG_URL"]
async fn direct_evidence_checks_reject_partial_mixed_invalid_identity_width_and_revision() {
    let (_, store, client, key, binding, evidence) = fixture().await;
    for invalid in [
        DirectAuthorizationEvidence {
            authorization_id: vec![],
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            authorization_revision: 0,
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            verification_nonce: vec![1; 31],
            ..evidence.clone()
        },
        DirectAuthorizationEvidence {
            bound_fields_digest: vec![1; 33],
            ..evidence.clone()
        },
    ] {
        assert!(matches!(
            store
                .domain_operation_prepare_direct(&key, &binding, &invalid, None)
                .await
                .unwrap(),
            PrepareResult::Mismatch
        ));
        let count: i64 = client
            .query_one("SELECT count(*) FROM lore_domain_operation_receipts", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
    }
    store
        .domain_operation_prepare_direct(&key, &binding, &evidence, None)
        .await
        .unwrap();
    let columns = [
        "direct_authorization_id",
        "direct_authorization_revision",
        "direct_verification_nonce",
        "direct_bound_fields_digest",
    ];
    for mask in 1..15 {
        let assignments = columns
            .iter()
            .enumerate()
            .map(|(bit, column)| {
                format!(
                    "{column}={}",
                    if mask & (1 << bit) == 0 {
                        "NULL"
                    } else {
                        column
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let error = client
            .batch_execute(&format!(
                "UPDATE lore_domain_operation_receipts SET {assignments}"
            ))
            .await
            .expect_err("every partial presence mask must fail");
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "mask {mask}"
        );
    }
    for change in [
        "direct_authorization_id=NULL",
        "direct_authorization_revision=NULL",
        "direct_verification_nonce=NULL",
        "direct_bound_fields_digest=NULL",
        "direct_authorization_id=decode(repeat('aa',16),'hex')",
        "direct_authorization_id=decode(repeat('aa',15),'hex')",
        "direct_authorization_revision=0",
        "direct_authorization_revision=18446744073709551616",
        "direct_verification_nonce=decode(repeat('aa',31),'hex')",
        "direct_bound_fields_digest=decode(repeat('aa',33),'hex')",
        "authorization_id=operation_id, authorization_revision=1, verification_nonce=decode(repeat('aa',32),'hex'), bound_fields_digest=decode(repeat('aa',32),'hex'), consumed_ticket_sha256=decode(repeat('aa',32),'hex')",
    ] {
        let error = client
            .batch_execute(&format!(
                "UPDATE lore_domain_operation_receipts SET {change}"
            ))
            .await
            .expect_err(change);
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "{change}: {error}"
        );
    }
    assert_eq!(stored_evidence(&client, &key).await, Some(evidence));
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with CREATEDB; LORE_TEST_PG_URL"]
async fn direct_evidence_upgrade_is_rerunnable_and_keeps_historical_receipts_without_evidence() {
    let (url, store, client, key, binding, _) = fixture().await;
    store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap();
    drop(store);
    client
        .batch_execute(
            "ALTER TABLE lore_domain_operation_receipts
        DROP COLUMN direct_authorization_id, DROP COLUMN direct_authorization_revision,
        DROP COLUMN direct_verification_nonce, DROP COLUMN direct_bound_fields_digest",
        )
        .await
        .unwrap();
    for _ in 0..2 {
        let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .unwrap();
        assert!(matches!(
            store
                .domain_operation_receipt_get(&key, &binding)
                .await
                .unwrap(),
            ReceiptLookup::Prepared { .. }
        ));
        assert_eq!(stored_evidence(&client, &key).await, None);
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with CREATEDB; LORE_TEST_PG_URL"]
async fn direct_evidence_retains_full_unsigned_revision_when_prepared_receipt_expires() {
    let (_, store, client, key, binding, mut evidence) = fixture().await;
    evidence.authorization_revision = u64::MAX;
    assert!(matches!(
        store
            .domain_operation_prepare_direct(&key, &binding, &evidence, None)
            .await
            .unwrap(),
        PrepareResult::Prepared { .. }
    ));
    client.batch_execute("UPDATE lore_domain_operation_receipts SET hard_expires_at=clock_timestamp()-interval '1 second'").await.unwrap();
    assert!(matches!(
        store
            .domain_operation_prepare_direct(&key, &binding, &evidence, None)
            .await
            .unwrap(),
        PrepareResult::Committed(DomainOutcome::NotApplied { .. })
    ));
    assert_eq!(stored_evidence(&client, &key).await, Some(evidence));
}

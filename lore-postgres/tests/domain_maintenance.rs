// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Live-Postgres acceptance tests for CR-029's private maintenance rail.
//!
//! Run the checked-in isolated live tier with:
//! `pwsh -File lore-postgres/tests/run-domain-maintenance-live.ps1`.
//! It gives every exact case a distinct database and invokes the cases serially.

#[path = "common/domain_maintenance_live_proxy.rs"]
mod domain_maintenance_live_proxy;

use std::time::Duration;
use std::time::SystemTime;

use domain_maintenance_live_proxy::DomainMaintenanceFaultProxy;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::maintenance::ProofNamespaceKey;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeStatus;
use lore_postgres::domain::maintenance::ProofNamespaceRetireInput;
use lore_postgres::domain::maintenance::ProofNamespaceRetireStatus;
use lore_postgres::domain::maintenance::TerminalStatusAttachAction;
use lore_postgres::domain::maintenance::TerminalStatusAttachInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachPhase;
use lore_postgres::domain::maintenance::TerminalStatusAttachStatus;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus;
use lore_postgres::domain::maintenance::proof_namespace_final_range_set_digest;
use lore_postgres::domain::proof_namespace_read::ProofNamespaceState;
use lore_postgres::domain::proof_namespace_read::ProofNamespaceStateInput;
use lore_postgres::domain::proof_namespace_read::ProofNamespaceStateReader;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::ConsumeResult;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::WIRE_TERMINAL_OUTCOME_APPLIED;
use lore_postgres::domain::receipts::WIRE_TERMINAL_OUTCOME_NOT_APPLIED;
use lore_postgres::domain::receipts::WireTerminalOutcome;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::commit_terminal;
use lore_postgres::domain::receipts::consume;
use lore_postgres::domain::schema::RECEIPT_OUTCOME_APPLIED;
use lore_postgres::domain::schema::RECEIPT_OUTCOME_NOT_APPLIED;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

fn namespace_state_input(materialize: &ProofNamespaceMaterializeInput) -> ProofNamespaceStateInput {
    ProofNamespaceStateInput {
        key: materialize.key.clone(),
        protocol_revision: materialize.protocol_revision,
        namespace_epoch: materialize.namespace_epoch.clone(),
        namespace_claim_revision: materialize.namespace_claim_revision,
        namespace_claim_nonce: materialize.namespace_claim_nonce.clone(),
    }
}

// Include row versions: even a value-preserving UPDATE violates this RPC's read-only contract.
async fn domain_rows(client: &Client) -> Vec<(String, Vec<String>)> {
    let tables = client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'lore_domain_%' ORDER BY tablename", &[]).await.unwrap();
    let mut snapshot = Vec::new();
    for table in tables {
        let name: String = table.get(0);
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let sql =
            format!("SELECT row_to_json(t)::text || ':' || xmin::text FROM {name} t ORDER BY 1");
        let rows = client
            .query(&sql, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        snapshot.push((name, rows));
    }
    snapshot
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn namespace_state_absent_and_binding_mismatch_never_mutate() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    let store = store(&url).await;
    let direct = client(&url).await;
    let materialize = materialize_input(namespace_key(), 0, 1);
    let input = namespace_state_input(&materialize);
    let before = domain_rows(&direct).await;
    assert_eq!(
        store.proof_namespace_state_get(&input).await.unwrap(),
        ProofNamespaceState::Absent
    );
    assert_eq!(
        domain_rows(&direct).await,
        before,
        "absence must not provision counters or namespace"
    );
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&materialize)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    let before = domain_rows(&direct).await;
    for field in 0..4 {
        let mut changed = input.clone();
        match field {
            0 => changed.key.org_uuid[0] ^= 1,
            1 => changed.namespace_epoch[0] ^= 1,
            2 => changed.namespace_claim_revision += 1,
            _ => changed.namespace_claim_nonce[0] ^= 1,
        }
        assert_eq!(
            store.proof_namespace_state_get(&changed).await.unwrap(),
            ProofNamespaceState::Mismatch,
            "binding field {field}"
        );
        assert_eq!(domain_rows(&direct).await, before);
    }
    for field in 0..3 {
        let mut other = input.clone();
        match field {
            0 => other.key.verified_issuer.push_str("/other"),
            1 => other.key.authenticated_subject.push_str("-other"),
            _ => other.key.tenant_scope_key[0] ^= 1,
        }
        assert_eq!(
            store.proof_namespace_state_get(&other).await.unwrap(),
            ProofNamespaceState::Absent
        );
        assert_eq!(domain_rows(&direct).await, before);
    }
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn namespace_state_quiescent_and_outstanding_vectors_are_read_only() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    let store = store(&url).await;
    let direct = client(&url).await;
    let materialize = materialize_input(namespace_key(), 0, 1);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .unwrap();
    let input = namespace_state_input(&materialize);
    let before = domain_rows(&direct).await;
    assert_eq!(
        store.proof_namespace_state_get(&input).await.unwrap(),
        ProofNamespaceState::MatchedQuiescent {
            quota_revision: 1,
            final_high_water: 0,
            final_range_set_digest: retire_input(&materialize).final_range_set_digest,
        }
    );
    assert_eq!(domain_rows(&direct).await, before);
    for column in ["retained_marker_count", "outstanding_proof_claims"] {
        let (retained, outstanding) = if column == "retained_marker_count" {
            (1_i64, 0_i64)
        } else {
            (0_i64, 1_i64)
        };
        direct.execute("UPDATE lore_domain_proof_namespaces SET retained_marker_count=$1, outstanding_proof_claims=$2", &[&retained, &outstanding]).await.unwrap();
        let before = domain_rows(&direct).await;
        assert_eq!(
            store.proof_namespace_state_get(&input).await.unwrap(),
            ProofNamespaceState::MatchedNotQuiescent { quota_revision: 1 },
            "{column}"
        );
        assert_eq!(domain_rows(&direct).await, before);
    }
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn namespace_state_missing_coverage_is_nonquiescent_and_never_repaired() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    let store = store(&url).await;
    let direct = client(&url).await;
    let materialize = materialize_input(namespace_key(), 0, 1);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .unwrap();
    direct
        .execute(
            "UPDATE lore_domain_proof_namespaces SET high_water=1, next_sequence=2",
            &[],
        )
        .await
        .unwrap();
    let before = domain_rows(&direct).await;
    assert_eq!(
        store
            .proof_namespace_state_get(&namespace_state_input(&materialize))
            .await
            .unwrap(),
        ProofNamespaceState::MatchedNotQuiescent { quota_revision: 1 }
    );
    assert_eq!(
        domain_rows(&direct).await,
        before,
        "read must not repair missing coverage"
    );
    direct
        .execute(
            "UPDATE lore_domain_proof_namespaces SET fragment_count=1",
            &[],
        )
        .await
        .unwrap();
    let before = domain_rows(&direct).await;
    assert_eq!(
        store
            .proof_namespace_state_get(&namespace_state_input(&materialize))
            .await
            .unwrap_err(),
        DomainError::Internal("corrupt proof namespace state".into())
    );
    assert_eq!(
        domain_rows(&direct).await,
        before,
        "corrupt count must not be repaired"
    );
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn namespace_state_reads_one_snapshot_across_concurrent_retirement() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    let store = std::sync::Arc::new(store(&url).await);
    let mut writer = client(&url).await;
    let observer = client(&url).await;
    let materialize = materialize_input(namespace_key(), 0, 1);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .unwrap();
    let key = &materialize.key;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    for part in [
        b"domain-marker-prune-interval-v3\0".as_slice(),
        key.tenant_scope_key.as_slice(),
        materialize.namespace_epoch.as_slice(),
        &2_u64.to_be_bytes(),
        &1_u64.to_be_bytes(),
        &3_u64.to_be_bytes(),
        &1_u64.to_be_bytes(),
        &1_u64.to_be_bytes(),
        &1_u64.to_be_bytes(),
        &1_u64.to_be_bytes(),
    ] {
        hasher.update(part);
    }
    let range_digest = hasher.finish().as_ref().to_vec();
    let byte_charge = (key.verified_issuer.len()
        + key.authenticated_subject.len()
        + key.tenant_scope_key.len()
        + 16
        + 6 * 8
        + 32) as i64;
    writer.execute("INSERT INTO lore_domain_tombstone_marker_prune_ranges (verified_issuer, authenticated_subject, tenant_scope_key, epoch, protocol_revision, quota_revision, marker_interval_schema_revision, start_sequence, end_sequence, sequence_count, generation, created_at_ms, row_charge, byte_charge, interval_digest) VALUES ($1,$2,$3,$4,2,1,3,1,1,1,1,0,1,$5,$6)", &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &materialize.namespace_epoch, &byte_charge, &range_digest]).await.unwrap();
    writer
        .execute(
            "UPDATE lore_domain_proof_namespaces SET high_water=1,next_sequence=2,fragment_count=1",
            &[],
        )
        .await
        .unwrap();
    let expected = ProofNamespaceState::MatchedQuiescent {
        quota_revision: 1,
        final_high_water: 1,
        final_range_set_digest: proof_namespace_final_range_set_digest(
            &key.tenant_scope_key,
            &materialize.namespace_epoch,
            2,
            1,
            1,
            &[lore_postgres::domain::maintenance::ProofRange {
                start_sequence: 1,
                end_sequence: 1,
                generation: 1,
                digest: range_digest.clone(),
            }],
        )
        .unwrap(),
    };
    let input = namespace_state_input(&materialize);
    assert_eq!(
        store.proof_namespace_state_get(&input).await.unwrap(),
        expected
    );
    writer
        .execute(
            "UPDATE lore_domain_tombstone_marker_prune_ranges SET interval_digest=$1",
            &[&vec![0xff_u8; 32]],
        )
        .await
        .unwrap();
    let before = domain_rows(&observer).await;
    assert_eq!(
        store.proof_namespace_state_get(&input).await.unwrap_err(),
        DomainError::Internal("corrupt proof namespace state".into())
    );
    assert_eq!(
        domain_rows(&observer).await,
        before,
        "corrupt digest must not be repaired"
    );
    writer
        .execute(
            "UPDATE lore_domain_tombstone_marker_prune_ranges SET interval_digest=$1",
            &[&range_digest],
        )
        .await
        .unwrap();
    let tx = writer.transaction().await.unwrap();
    // Hold only the range relation. The reader must first take its namespace snapshot,
    // then demonstrably block at its range read before we publish retirement.
    tx.batch_execute(
        "LOCK TABLE lore_domain_tombstone_marker_prune_ranges IN ACCESS EXCLUSIVE MODE",
    )
    .await
    .unwrap();
    let reading_store = store.clone();
    let reading_input = input.clone();
    let read = lore_base::lore_spawn!(async move {
        reading_store
            .proof_namespace_state_get(&reading_input)
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = observer.query_one("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT start_sequence%')", &[]).await.unwrap().get(0);
            if waiting { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("reader must reach range query after snapshotting namespace");
    tx.batch_execute("DELETE FROM lore_domain_tombstone_marker_prune_ranges; DELETE FROM lore_domain_proof_namespaces").await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        expected,
        "read may not combine old namespace with retired range inventory"
    );
    assert_eq!(
        store.proof_namespace_state_get(&input).await.unwrap(),
        ProofNamespaceState::Absent
    );
}

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn store(url: &str) -> PostgresDomainStore {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct setup client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn upstream_address(url: &str) -> (String, u16) {
    let config = url
        .parse::<tokio_postgres::Config>()
        .expect("valid PostgreSQL URL");
    let [tokio_postgres::config::Host::Tcp(host)] = config.get_hosts() else {
        panic!("maintenance test URL has one TCP host")
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    (host.clone(), port)
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

fn stale_input(clock: SystemTime) -> VerifiedStaleFinalizeInput {
    let operation_id = uuid_v7_at(clock - Duration::from_secs(366 * 24 * 60 * 60));
    let expected_claim_identity_digest = rand::random::<[u8; 32]>().to_vec();
    VerifiedStaleFinalizeInput {
        key: ReceiptKey {
            verified_issuer: format!(
                "https://issuer.example/maintenance/{:016x}",
                rand::random::<u64>()
            ),
            authenticated_subject: "svc:maintenance-test".into(),
            tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
            operation_id,
        },
        binding: OperationBinding {
            method: "lore.domain.v1.test/Maintenance".into(),
            scope: rand::random::<[u8; 16]>().to_vec(),
            fingerprint_version: 1,
            fingerprint: rand::random::<[u8; 32]>().to_vec(),
            canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
        },
        witness: AuthorizationWitness {
            authorization_id: operation_id.as_bytes().to_vec(),
            authorization_revision: 7,
            verification_nonce: rand::random::<[u8; 32]>().to_vec(),
            bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
            consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
            expected_claim_identity_digest: expected_claim_identity_digest.clone(),
        },
        expected_claim_identity_digest,
        stale_finalize_permit: rand::random::<[u8; 32]>().to_vec(),
        stale_finalize_permit_revision: 11,
        permit_verification_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

fn namespace_key() -> ProofNamespaceKey {
    ProofNamespaceKey {
        verified_issuer: format!(
            "https://issuer.example/namespace/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "svc:maintenance-test".into(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
    }
}

async fn prepare_terminal_fixture_by_the_rail(
    store: &PostgresDomainStore,
    client: &mut Client,
    stale: &VerifiedStaleFinalizeInput,
) -> Vec<u8> {
    prepare_terminal_fixture_by_the_rail_with_outcome(
        store,
        client,
        stale,
        &DomainOutcome::Applied,
        b"rail-produced-applied-receipt-v1",
    )
    .await
}

/// Same rail-produced fixture as [`prepare_terminal_fixture_by_the_rail`], but committed with a
/// caller-chosen STORAGE-domain outcome. Exists so a Phase-1 exactness case can pin the wire/storage
/// mapping against a receipt stored `NotApplied` (storage `1`) as well as the default `Applied`
/// (storage `0`).
async fn prepare_terminal_fixture_by_the_rail_with_outcome(
    store: &PostgresDomainStore,
    client: &mut Client,
    stale: &VerifiedStaleFinalizeInput,
    outcome: &DomainOutcome,
    public_result: &[u8],
) -> Vec<u8> {
    let tx = client.transaction().await.expect("begin rail fixture tx");
    let clock = admission_clock(&tx).await.expect("read admission clock");
    tx.rollback().await.expect("finish clock sample");

    let current_operation_id = uuid_v7_at(clock);
    let mut current_key = stale.key.clone();
    current_key.operation_id = current_operation_id;
    let mut current_witness = stale.witness.clone();
    current_witness.authorization_id = current_operation_id.as_bytes().to_vec();
    current_witness.expected_claim_identity_digest = stale.expected_claim_identity_digest.clone();
    let prepared = store
        .domain_operation_prepare(&current_key, &stale.binding, Some(&current_witness), None)
        .await
        .expect("rail prepares the terminal fixture");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("rail terminal fixture must prepare, got {prepared:?}");
    };

    let public_result = public_result.to_vec();
    let tx = client.transaction().await.expect("begin rail terminal tx");
    let consumed = consume(&tx, &current_key, &stale.binding, &token)
        .await
        .expect("consume rail fixture");
    let ConsumeResult::Admitted(consumed) = consumed else {
        panic!("prepared fixture must be consumable");
    };
    commit_terminal(
        &tx,
        &current_key,
        outcome,
        Some(&public_result),
        consumed.admission_clock,
    )
    .await
    .expect("terminalize rail fixture");
    tx.commit().await.expect("commit rail terminal fixture");

    let stale_operation_id = stale.key.operation_id.as_bytes().as_slice();
    let current_operation_id = current_operation_id.as_bytes().as_slice();
    let stale_authorization_id = stale.witness.authorization_id.as_slice();
    let current_authorization_id = current_witness.authorization_id.as_slice();
    let tx = client
        .transaction()
        .await
        .expect("begin deterministic aging tx");
    tx.execute(
        "UPDATE lore_domain_operation_receipts \
            SET operation_id=$1, authorization_id=$2, \
                uuid_timestamp=clock_timestamp()-interval '366 days' \
          WHERE verified_issuer=$3 AND authenticated_subject=$4 \
            AND tenant_scope_key=$5 AND operation_id=$6 AND authorization_id=$7",
        &[
            &stale_operation_id,
            &stale_authorization_id,
            &stale.key.verified_issuer,
            &stale.key.authenticated_subject,
            &stale.key.tenant_scope_key,
            &current_operation_id,
            &current_authorization_id,
        ],
    )
    .await
    .expect("age the rail receipt identity without hand-seeding it");
    tx.execute(
        "UPDATE lore_domain_operation_dispatch_possibility_fences \
            SET operation_id=$1, authorization_id=$2 \
          WHERE verified_issuer=$3 AND authenticated_subject=$4 \
            AND tenant_scope_key=$5 AND operation_id=$6 AND authorization_id=$7",
        &[
            &stale_operation_id,
            &stale_authorization_id,
            &stale.key.verified_issuer,
            &stale.key.authenticated_subject,
            &stale.key.tenant_scope_key,
            &current_operation_id,
            &current_authorization_id,
        ],
    )
    .await
    .expect("age the prepare-created fence identity without hand-seeding it");
    tx.commit()
        .await
        .expect("commit deterministic fixture aging");
    public_result
}

fn terminal_phase1_input(
    stale: &VerifiedStaleFinalizeInput,
    public_result: &[u8],
) -> TerminalStatusAttachInput {
    TerminalStatusAttachInput {
        key: stale.key.clone(),
        authorization_id: stale.witness.authorization_id.clone(),
        authorization_revision: stale.witness.authorization_revision,
        claim_id: rand::random::<[u8; 16]>().to_vec(),
        claim_revision: 17,
        terminal_outcome: WireTerminalOutcome::APPLIED,
        terminal_receipt_sha256: ring::digest::digest(&ring::digest::SHA256, public_result)
            .as_ref()
            .to_vec(),
        platform_terminal_status_revision: 19,
        acknowledged_at: SystemTime::now() - Duration::from_secs(2 * 365 * 24 * 60 * 60),
        phase: TerminalStatusAttachPhase::Phase1TerminalAck,
        action: TerminalStatusAttachAction::None,
        reserve_charge_revision: 23,
        reserve_charge_nonce: rand::random::<[u8; 32]>().to_vec(),
        release_tombstone_digest: None,
        active_release_intent_revision: None,
        active_release_intent_nonce: None,
        tombstone_reservation_revision: 29,
        tombstone_reservation_nonce: rand::random::<[u8; 32]>().to_vec(),
        final_prune_digest: None,
        tombstone_release_intent_revision: None,
        tombstone_release_intent_nonce: None,
        release_proof_reservation_revision: 31,
        release_proof_reservation_nonce: rand::random::<[u8; 32]>().to_vec(),
        completion_marker_sequence: 1,
        expected_completion_marker_digest: None,
        request_digest: rand::random::<[u8; 32]>().to_vec(),
        verification_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

fn completion_marker_digest(
    input: &TerminalStatusAttachInput,
    epoch: &[u8],
    tombstone_digest: &[u8],
) -> Vec<u8> {
    use ring::digest::Context;
    use ring::digest::SHA256;

    let mut digest = Context::new(&SHA256);
    for part in [
        b"domain-tombstone-release-completion-marker-v1\0".as_slice(),
        input.key.verified_issuer.as_bytes(),
        input.key.authenticated_subject.as_bytes(),
        input.key.tenant_scope_key.as_slice(),
        input.key.operation_id.as_bytes(),
        epoch,
        &input.authorization_revision.to_be_bytes(),
        &input.claim_revision.to_be_bytes(),
        &input.tombstone_reservation_revision.to_be_bytes(),
        input.tombstone_reservation_nonce.as_slice(),
        &input.release_proof_reservation_revision.to_be_bytes(),
        input.release_proof_reservation_nonce.as_slice(),
        &input.completion_marker_sequence.to_be_bytes(),
        input.terminal_receipt_sha256.as_slice(),
        tombstone_digest,
        &input
            .active_release_intent_revision
            .unwrap_or_default()
            .to_be_bytes(),
        input
            .active_release_intent_nonce
            .as_deref()
            .unwrap_or_default(),
        input.final_prune_digest.as_deref().unwrap_or_default(),
        &input
            .tombstone_release_intent_revision
            .unwrap_or_default()
            .to_be_bytes(),
        input
            .tombstone_release_intent_nonce
            .as_deref()
            .unwrap_or_default(),
        input.request_digest.as_slice(),
    ] {
        let length = u32::try_from(part.len())
            .expect("completion-marker test field must fit the canonical u32 frame");
        digest.update(&length.to_be_bytes());
        digest.update(part);
    }
    digest.finish().as_ref().to_vec()
}

async fn provision_capacity(client: &Client, org_uuid: &[u8]) -> (i64, i64) {
    let counter_revision = 7_i64;
    let quota_revision = 7_i32;
    client
        .execute(
            "INSERT INTO lore_domain_proof_global_counters (id, counter_revision, quota_revision, \
                represented_namespace_rows, retained_marker_count, outstanding_proof_claims, \
                fragment_count, fragment_bytes, marker_bytes, updated_at) \
             VALUES (1,$1,$2,0,0,0,0,0,0,clock_timestamp()) \
             ON CONFLICT (id) DO UPDATE SET counter_revision=EXCLUDED.counter_revision, \
                quota_revision=EXCLUDED.quota_revision, represented_namespace_rows=0, \
                retained_marker_count=0, outstanding_proof_claims=0, fragment_count=0, \
                fragment_bytes=0, marker_bytes=0, updated_at=EXCLUDED.updated_at",
            &[&counter_revision, &quota_revision],
        )
        .await
        .expect("provision global proof capacity authority");
    client
        .execute(
            "INSERT INTO lore_domain_proof_org_counters (org_uuid, counter_revision, quota_revision, \
                represented_namespace_rows, retained_marker_count, fragment_count, fragment_bytes, \
                marker_bytes, updated_at) VALUES ($1,$2,$3,0,0,0,0,0,clock_timestamp()) \
             ON CONFLICT (org_uuid) DO UPDATE SET counter_revision=EXCLUDED.counter_revision, \
                quota_revision=EXCLUDED.quota_revision, represented_namespace_rows=0, \
                retained_marker_count=0, fragment_count=0, fragment_bytes=0, marker_bytes=0, \
                updated_at=EXCLUDED.updated_at",
            &[&org_uuid, &counter_revision, &quota_revision],
        )
        .await
        .expect("provision organization proof capacity authority");
    (counter_revision, i64::from(quota_revision))
}

async fn capacity_pair(client: &Client) -> (i64, i64) {
    let row = client
        .query_one(
            "SELECT counter_revision, quota_revision::bigint AS quota_revision \
             FROM lore_domain_proof_global_counters WHERE id=1",
            &[],
        )
        .await
        .expect("read provisioned proof capacity");
    (row.get(0), row.get(1))
}

async fn completion_state(
    client: &Client,
    key: &ReceiptKey,
    materialize: &ProofNamespaceMaterializeInput,
) -> Vec<i64> {
    let row = client
        .query_one(
            "SELECT \
                (SELECT count(*) FROM lore_domain_operation_reserve_release_tombstones \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                   AND tenant_scope_key=$3 AND operation_id=$4), \
                (SELECT count(*) FROM lore_domain_operation_tombstone_release_completion_markers \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                   AND tenant_scope_key=$3 AND operation_id=$4), \
                (SELECT high_water FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                   AND tenant_scope_key=$3 AND epoch=$5), \
                (SELECT next_sequence FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                   AND tenant_scope_key=$3 AND epoch=$5), \
                (SELECT retained_marker_count FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                   AND tenant_scope_key=$3 AND epoch=$5), \
                (SELECT retained_marker_count FROM lore_domain_proof_global_counters WHERE id=1), \
                (SELECT marker_bytes FROM lore_domain_proof_global_counters WHERE id=1), \
                (SELECT retained_marker_count FROM lore_domain_proof_org_counters WHERE org_uuid=$6), \
                (SELECT marker_bytes FROM lore_domain_proof_org_counters WHERE org_uuid=$6)",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
                &materialize.namespace_epoch,
                &materialize.key.org_uuid,
            ],
        )
        .await
        .expect("read completion mutation state");
    (0..9).map(|column| row.get(column)).collect()
}

fn materialize_input(
    key: ProofNamespaceKey,
    counter_revision: i64,
    quota_revision: i64,
) -> ProofNamespaceMaterializeInput {
    ProofNamespaceMaterializeInput {
        key,
        protocol_revision: 2,
        namespace_epoch: rand::random::<[u8; 16]>().to_vec(),
        namespace_claim_revision: 13,
        namespace_claim_nonce: rand::random::<[u8; 32]>().to_vec(),
        platform_capacity_revision: quota_revision,
        lore_local_capacity_revision: counter_revision,
        request_digest: rand::random::<[u8; 32]>().to_vec(),
        verification_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

fn retire_input(materialize: &ProofNamespaceMaterializeInput) -> ProofNamespaceRetireInput {
    let final_range_set_digest = proof_namespace_final_range_set_digest(
        &materialize.key.tenant_scope_key,
        &materialize.namespace_epoch,
        materialize.protocol_revision,
        materialize.platform_capacity_revision as i32,
        0,
        &[],
    )
    .expect("canonical empty final range-set digest");
    ProofNamespaceRetireInput {
        key: materialize.key.clone(),
        protocol_revision: 2,
        namespace_epoch: materialize.namespace_epoch.clone(),
        quota_revision: materialize.platform_capacity_revision as i32,
        final_range_set_digest,
        final_high_water: 0,
        retirement_fence_generation: 1,
        retirement_permit_revision: 1,
        issued_at: SystemTime::now() - Duration::from_secs(1),
        expires_at: SystemTime::now() + Duration::from_secs(60),
        zero_platform_state_digest: rand::random::<[u8; 32]>().to_vec(),
        request_digest: rand::random::<[u8; 32]>().to_vec(),
        namespace_claim_revision: materialize.namespace_claim_revision,
        namespace_claim_nonce: materialize.namespace_claim_nonce.clone(),
        verification_digest: rand::random::<[u8; 32]>().to_vec(),
    }
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn stale_finalize_commits_once_replays_exactly_and_isolates_binding() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let input = stale_input(clock);

    let first = store
        .domain_operation_verified_stale_finalize(&input)
        .await
        .expect("first finalization");
    assert_eq!(first.status, VerifiedStaleFinalizeStatus::Committed);
    assert!(!first.committed_receipt_canonical.is_empty());

    let replay = store
        .domain_operation_verified_stale_finalize(&input)
        .await
        .expect("exact replay");
    assert_eq!(
        replay, first,
        "exact replay must return the committed bytes"
    );

    let mut substitutions = Vec::new();
    let mut changed = input.clone();
    changed.binding.method.push_str(".changed");
    substitutions.push(("method", changed));
    let mut changed = input.clone();
    changed.binding.scope[0] ^= 0xff;
    substitutions.push(("scope", changed));
    let mut changed = input.clone();
    changed.binding.fingerprint_version += 1;
    substitutions.push(("fingerprint_version", changed));
    let mut changed = input.clone();
    changed.binding.fingerprint[0] ^= 0xff;
    substitutions.push(("fingerprint", changed));
    let mut changed = input.clone();
    changed.binding.canonical_intent_digest[0] ^= 0xff;
    substitutions.push(("canonical_intent_digest", changed));
    let mut changed = input.clone();
    changed.witness.authorization_id[0] ^= 0xff;
    substitutions.push(("authorization_id", changed));
    let mut changed = input.clone();
    changed.witness.authorization_revision += 1;
    substitutions.push(("authorization_revision", changed));
    let mut changed = input.clone();
    changed.witness.verification_nonce[0] ^= 0xff;
    substitutions.push(("verification_nonce", changed));
    let mut changed = input.clone();
    changed.witness.bound_fields_digest[0] ^= 0xff;
    substitutions.push(("bound_fields_digest", changed));
    let mut changed = input.clone();
    changed.witness.consumed_ticket_sha256[0] ^= 0xff;
    substitutions.push(("consumed_ticket_sha256", changed));
    let mut changed = input.clone();
    changed.expected_claim_identity_digest[0] ^= 0xff;
    substitutions.push(("expected_claim_identity_digest", changed));
    let mut changed = input.clone();
    changed.stale_finalize_permit[0] ^= 0xff;
    substitutions.push(("stale_finalize_permit", changed));
    let mut changed = input.clone();
    changed.stale_finalize_permit_revision += 1;
    substitutions.push(("stale_finalize_permit_revision", changed));
    let mut changed = input.clone();
    changed.permit_verification_digest[0] ^= 0xff;
    substitutions.push(("permit_verification_digest", changed));

    for (field, substitution) in substitutions {
        let rejected = store
            .domain_operation_verified_stale_finalize(&substitution)
            .await
            .unwrap_or_else(|error| panic!("{field} substitution must be decisive: {error:?}"));
        assert_eq!(
            rejected.status,
            VerifiedStaleFinalizeStatus::Mismatch,
            "changed {field} must not replay the committed result"
        );
    }
    let replay_after_substitutions = store
        .domain_operation_verified_stale_finalize(&input)
        .await
        .expect("exact replay after adversarial substitutions");
    assert_eq!(
        replay_after_substitutions, first,
        "rejected substitutions must not mutate the exact replay"
    );

    let contested = stale_input(clock);
    let mut competing = contested.clone();
    competing.binding.canonical_intent_digest[0] ^= 0xff;
    let contender_a = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect first conflicting finalizer");
    let contender_b = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect second conflicting finalizer");
    let (result_a, result_b) = tokio::join!(
        contender_a.domain_operation_verified_stale_finalize(&contested),
        contender_b.domain_operation_verified_stale_finalize(&competing),
    );
    let result_a = result_a.expect("first conflicting finalizer result");
    let result_b = result_b.expect("second conflicting finalizer result");
    assert!(
        matches!(
            (result_a.status, result_b.status),
            (
                VerifiedStaleFinalizeStatus::Committed,
                VerifiedStaleFinalizeStatus::Mismatch
            ) | (
                VerifiedStaleFinalizeStatus::Mismatch,
                VerifiedStaleFinalizeStatus::Committed
            )
        ),
        "one conflicting Phase 1 insert must win and the other must observe Mismatch: {result_a:?}, {result_b:?}"
    );

    let direct = client(&url).await;
    let persisted = direct
        .query_one(
            "SELECT canonical_intent_digest FROM lore_domain_operation_receipts \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &contested.key.verified_issuer,
                &contested.key.authenticated_subject,
                &contested.key.tenant_scope_key,
                &contested.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read contested Phase 1 winner");
    let winner_digest: Vec<u8> = persisted.get(0);
    assert!(
        winner_digest == contested.binding.canonical_intent_digest
            || winner_digest == competing.binding.canonical_intent_digest,
        "conflict handling must preserve one complete contender, never overwrite a partial row"
    );
}

#[tokio::test]
#[ignore = "needs live non-mTLS Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn stale_finalize_lost_commit_ack_is_unknown_then_authoritative_replay_adopts_commit() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let (host, port) = upstream_address(&url);
    let proxy = DomainMaintenanceFaultProxy::start(host, port).await;
    let proxied_url = proxy.postgres_url(&url);
    let faulted_store = store(&proxied_url).await;
    let authoritative_store = store(&url).await;
    let clock = authoritative_store
        .domain_operation_clock_get()
        .await
        .expect("authoritative DB clock");
    let input = stale_input(clock);

    proxy.drop_next_commit_response();
    let result = faulted_store
        .domain_operation_verified_stale_finalize(&input)
        .await;
    let fault_fired = proxy.wait_for_commit_fault(Duration::from_secs(1)).await;
    let error = match result {
        Err(error) => error,
        Ok(value) => panic!(
            "lost COMMIT acknowledgement must remain OutcomeUnknown; fault_fired={fault_fired}; result={value:?}"
        ),
    };
    assert!(
        matches!(error, DomainError::OutcomeUnknown(_)),
        "post-COMMIT disconnect must not be reported as a decisive rollback: {error:?}"
    );
    assert!(
        fault_fired,
        "lost-COMMIT evidence is valid only if exact frontend Q/COMMIT and backend C/COMMIT + Z/idle frames fired"
    );

    let replay = faulted_store
        .domain_operation_verified_stale_finalize(&input)
        .await
        .expect("same client exact retry after lost acknowledgement");
    assert_eq!(replay.status, VerifiedStaleFinalizeStatus::Committed);
    assert!(!replay.committed_receipt_canonical.is_empty());

    let authoritative = client(&url).await;
    let rows = authoritative
        .query(
            "SELECT public_result \
             FROM lore_domain_operation_receipts \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read authoritative post-fault receipt");
    assert_eq!(
        rows.len(),
        1,
        "lost acknowledgement plus exact retry must leave one receipt"
    );
    assert_eq!(
        rows[0].get::<_, Option<Vec<u8>>>(0).as_deref(),
        Some(replay.committed_receipt_canonical.as_slice()),
        "retry must adopt the exact committed receipt rather than replace it"
    );
    proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase1_replays_then_atomically_exchanges_receipt_fence_for_tombstone() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let stale = stale_input(clock);
    let public_result = prepare_terminal_fixture_by_the_rail(&store, &mut direct, &stale).await;
    let phase1 = terminal_phase1_input(&stale, &public_result);

    let pending = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("attach terminal status before retention");
    assert_eq!(
        pending.status,
        TerminalStatusAttachStatus::Phase1PendingRetention
    );
    assert!(
        pending.fields[0]
            .as_ref()
            .is_some_and(|value| !value.is_empty()),
        "Phase 1 must return its canonical acknowledgement"
    );
    let replay = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("exact Phase 1 replay");
    assert_eq!(replay, pending);

    let mut mismatch = phase1.clone();
    mismatch.request_digest[0] ^= 0xff;
    let rejected = store
        .domain_operation_terminal_status_attach(&mismatch)
        .await
        .expect("changed Phase 1 request is decisive");
    assert_eq!(rejected.status, TerminalStatusAttachStatus::Mismatch);

    direct
        .execute(
            "UPDATE lore_domain_operation_receipts SET compact_expires_at=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age receipt retention");
    let ready = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("final Phase 1 exchange");
    assert_eq!(
        ready.status,
        TerminalStatusAttachStatus::Phase1TombstoneReady
    );
    assert!(
        ready.fields[4]
            .as_ref()
            .is_some_and(|digest| digest.len() == 32)
    );
    let ready_replay = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("Phase 1 tombstone replay");
    assert_eq!(
        ready_replay, ready,
        "tombstone replay must preserve exact ack"
    );

    let stale_after_tombstone = store
        .domain_operation_verified_stale_finalize(&stale)
        .await
        .expect("tombstone must decide stale-finalize replay");
    assert_eq!(
        stale_after_tombstone.status,
        VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
        "an exact tombstone proves prior terminal lifecycle before UUID staleness"
    );
    let mut stale_tombstone_mismatch = stale.clone();
    stale_tombstone_mismatch.binding.scope[0] ^= 0xff;
    let stale_tombstone_mismatch = store
        .domain_operation_verified_stale_finalize(&stale_tombstone_mismatch)
        .await
        .expect("tombstone binding mismatch is decisive");
    assert_eq!(
        stale_tombstone_mismatch.status,
        VerifiedStaleFinalizeStatus::Mismatch
    );
    let receipt_count: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count receipts after tombstone stale-finalize probes")
        .get(0);
    assert_eq!(
        receipt_count, 0,
        "neither tombstone result may manufacture a stale NOT_APPLIED receipt"
    );

    let row = direct
        .query_one(
            "SELECT \
                (SELECT count(*) FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4), \
                (SELECT count(*) FROM lore_domain_operation_dispatch_possibility_fences WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4), \
                (SELECT count(*) FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4)",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read atomic exchange state");
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 0, 1)
    );

    let namespace = ProofNamespaceKey {
        verified_issuer: stale.key.verified_issuer.clone(),
        authenticated_subject: stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize completion namespace");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let mut phase2 = phase1;
    phase2.phase = TerminalStatusAttachPhase::Phase2ReleaseAck;
    phase2.action = TerminalStatusAttachAction::ActiveReleaseIntentAck;
    phase2.release_tombstone_digest = ready.fields[4].clone();
    phase2.active_release_intent_revision = Some(37);
    phase2.active_release_intent_nonce = Some(rand::random::<[u8; 32]>().to_vec());
    phase2.request_digest = rand::random::<[u8; 32]>().to_vec();
    let active = store
        .domain_operation_terminal_status_attach(&phase2)
        .await
        .expect("acknowledge active release intent");
    assert_eq!(
        active.status,
        TerminalStatusAttachStatus::Phase2ActiveReleaseAcked
    );
    let active_replay = store
        .domain_operation_terminal_status_attach(&phase2)
        .await
        .expect("exact active release replay");
    assert_eq!(
        active_replay, active,
        "active-release replay must preserve exact ack"
    );

    let active_before = direct
        .query_one(
            "SELECT active_release_intent_digest, active_release_intent_ack_at \
             FROM lore_domain_operation_reserve_release_tombstones \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read acknowledged active release intent");
    let active_digest_before: Vec<u8> = active_before.get(0);
    let active_ack_at_before: SystemTime = active_before.get(1);

    let mut changed_revision = phase2.clone();
    changed_revision.active_release_intent_revision = Some(
        changed_revision
            .active_release_intent_revision
            .expect("active intent revision")
            + 1,
    );
    let rejected = store
        .domain_operation_terminal_status_attach(&changed_revision)
        .await
        .expect("changed active release revision is decisive");
    assert_eq!(rejected.status, TerminalStatusAttachStatus::Mismatch);

    let mut changed_nonce = phase2.clone();
    changed_nonce
        .active_release_intent_nonce
        .as_mut()
        .expect("active intent nonce")[0] ^= 0xff;
    let rejected = store
        .domain_operation_terminal_status_attach(&changed_nonce)
        .await
        .expect("changed active release nonce is decisive");
    assert_eq!(rejected.status, TerminalStatusAttachStatus::Mismatch);

    let active_after = direct
        .query_one(
            "SELECT active_release_intent_digest, active_release_intent_ack_at \
             FROM lore_domain_operation_reserve_release_tombstones \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("read active release intent after rejected substitutions");
    assert_eq!(
        active_after.get::<_, Vec<u8>>(0),
        active_digest_before,
        "rejected active-intent substitutions must not replace the digest"
    );
    assert_eq!(
        active_after.get::<_, SystemTime>(1),
        active_ack_at_before,
        "rejected active-intent substitutions must not change acknowledgement time"
    );

    let mut poll = phase2.clone();
    poll.action = TerminalStatusAttachAction::TombstonePrunePoll;
    poll.request_digest = rand::random::<[u8; 32]>().to_vec();
    let retention = store
        .domain_operation_terminal_status_attach(&poll)
        .await
        .expect("poll tombstone retention");
    assert_eq!(
        retention.status,
        TerminalStatusAttachStatus::Phase2TombstoneRetentionPending
    );
    direct
        .execute(
            "UPDATE lore_domain_operation_reserve_release_tombstones \
             SET created_at=clock_timestamp()-interval '3 seconds', \
                 compact_after=clock_timestamp()-interval '2 seconds', \
                 final_prune_after=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age tombstone retention");
    let pruned = store
        .domain_operation_terminal_status_attach(&poll)
        .await
        .expect("poll after tombstone retention");
    assert_eq!(
        pruned.status,
        TerminalStatusAttachStatus::Phase2TombstoneFinalPruned
    );

    let mut complete = phase2.clone();
    complete.action = TerminalStatusAttachAction::TombstoneReleaseIntentComplete;
    complete.final_prune_digest = Some(rand::random::<[u8; 32]>().to_vec());
    complete.tombstone_release_intent_revision = Some(41);
    complete.tombstone_release_intent_nonce = Some(rand::random::<[u8; 32]>().to_vec());
    complete.request_digest = rand::random::<[u8; 32]>().to_vec();
    complete.expected_completion_marker_digest = Some(completion_marker_digest(
        &complete,
        &materialize.namespace_epoch,
        ready.fields[4]
            .as_deref()
            .expect("Phase 1 returns tombstone digest"),
    ));
    let completion_before = completion_state(&direct, &stale.key, &materialize).await;

    let mut changed_completion_revision = complete.clone();
    changed_completion_revision.active_release_intent_revision = Some(
        changed_completion_revision
            .active_release_intent_revision
            .expect("completion active intent revision")
            + 1,
    );
    changed_completion_revision.expected_completion_marker_digest = Some(completion_marker_digest(
        &changed_completion_revision,
        &materialize.namespace_epoch,
        ready.fields[4]
            .as_deref()
            .expect("Phase 1 returns tombstone digest"),
    ));
    let rejected = store
        .domain_operation_terminal_status_attach(&changed_completion_revision)
        .await
        .expect("changed completion active-intent revision is decisive");
    assert_eq!(rejected.status, TerminalStatusAttachStatus::Mismatch);

    let mut changed_completion_nonce = complete.clone();
    changed_completion_nonce
        .active_release_intent_nonce
        .as_mut()
        .expect("completion active intent nonce")[0] ^= 0xff;
    changed_completion_nonce.expected_completion_marker_digest = Some(completion_marker_digest(
        &changed_completion_nonce,
        &materialize.namespace_epoch,
        ready.fields[4]
            .as_deref()
            .expect("Phase 1 returns tombstone digest"),
    ));
    let rejected = store
        .domain_operation_terminal_status_attach(&changed_completion_nonce)
        .await
        .expect("changed completion active-intent nonce is decisive");
    assert_eq!(rejected.status, TerminalStatusAttachStatus::Mismatch);
    assert_eq!(
        completion_state(&direct, &stale.key, &materialize).await,
        completion_before,
        "rejected completion substitutions must not mutate tombstone, marker, namespace, or counters"
    );

    let completed = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("complete tombstone release intent");
    assert_eq!(
        completed.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
    );
    assert_eq!(completed.completion_marker_sequence, 1);
    assert_eq!(
        completed.fields[8], complete.expected_completion_marker_digest,
        "completion response must return the independently derived marker digest"
    );
    let completed_replay = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("exact completion replay");
    assert_eq!(completed_replay, completed);

    direct
        .execute(
            "DELETE FROM lore_domain_operation_reserve_release_tombstones \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("isolate completion-marker stale-finalize evidence");
    let stale_after_completion = store
        .domain_operation_verified_stale_finalize(&stale)
        .await
        .expect("completion marker must decide stale-finalize replay");
    assert_eq!(
        stale_after_completion.status,
        VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
        "an exact completion marker proves prior terminal lifecycle before UUID staleness"
    );
    let mut stale_completion_changed_binding = stale.clone();
    stale_completion_changed_binding.binding.fingerprint[0] ^= 0xff;
    let stale_completion_changed_binding = store
        .domain_operation_verified_stale_finalize(&stale_completion_changed_binding)
        .await
        .expect("completion-marker existence remains decisive");
    assert_eq!(
        stale_completion_changed_binding.status,
        VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
        "the marker retains proof identity, not reconstructable method/scope/fingerprint binding"
    );
    let receipt_count: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_domain_operation_receipts \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("count receipts after completion-marker stale-finalize probes")
        .get(0);
    assert_eq!(
        receipt_count, 0,
        "neither completion-marker result may manufacture a stale NOT_APPLIED receipt"
    );

    direct
        .execute(
            "UPDATE lore_domain_operation_tombstone_release_completion_markers \
             SET created_at=clock_timestamp()-interval '2 seconds', \
                 retain_until=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age completion marker retention");
    let recovered = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("exact completion replay prunes marker into range");
    assert_eq!(
        recovered.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    assert_eq!(
        recovered
            .range
            .as_ref()
            .map(|range| (range.start_sequence, range.end_sequence)),
        Some((1, 1))
    );
    let recovered_replay = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("exact post-prune recovery from containing range");
    assert_eq!(
        recovered_replay.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    assert_eq!(recovered_replay.range, recovered.range);
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase1_mismatch_leaves_the_dispatch_fence_untouched() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let stale = stale_input(clock);
    let public_result = prepare_terminal_fixture_by_the_rail(&store, &mut direct, &stale).await;
    let phase1 = terminal_phase1_input(&stale, &public_result);
    let key = &[
        &stale.key.verified_issuer as &(dyn tokio_postgres::types::ToSql + Sync),
        &stale.key.authenticated_subject,
        &stale.key.tenant_scope_key,
        &stale.key.operation_id.as_bytes().as_slice(),
    ];
    direct
        .execute(
            "UPDATE lore_domain_operation_receipts \
             SET compact_expires_at=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            key,
        )
        .await
        .expect("age receipt retention");

    direct
        .execute(
            "CREATE TABLE wp116_saved_receipt AS \
         SELECT * FROM lore_domain_operation_receipts \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 \
           AND tenant_scope_key=$3 AND operation_id=$4",
            key,
        )
        .await
        .expect("save receipt before exchange");
    direct
        .execute(
            "CREATE TABLE wp116_saved_fence AS \
         SELECT * FROM lore_domain_operation_dispatch_possibility_fences \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 \
           AND tenant_scope_key=$3 AND operation_id=$4",
            key,
        )
        .await
        .expect("save fence before exchange");
    let ready = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("create a real conflicting tombstone");
    assert_eq!(
        ready.status,
        TerminalStatusAttachStatus::Phase1TombstoneReady
    );
    direct
        .execute(
            "INSERT INTO lore_domain_operation_receipts SELECT * FROM wp116_saved_receipt",
            &[],
        )
        .await
        .expect("restore saved receipt");
    direct
        .execute(
            "INSERT INTO lore_domain_operation_dispatch_possibility_fences \
         SELECT * FROM wp116_saved_fence",
            &[],
        )
        .await
        .expect("restore saved fence without an acknowledgement");
    direct
        .execute(
            "UPDATE lore_domain_operation_reserve_release_tombstones \
         SET claim_revision=claim_revision+1 \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 \
           AND tenant_scope_key=$3 AND operation_id=$4",
            key,
        )
        .await
        .expect("make the real tombstone conflict non-exact");

    let mismatch = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("conflicting tombstone is decisive");
    assert_eq!(mismatch.status, TerminalStatusAttachStatus::Mismatch);
    let fence = direct
        .query_one(
            "SELECT terminal_status_ack_digest, terminal_status_revision, terminal_status_ack_at \
             FROM lore_domain_operation_dispatch_possibility_fences \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4",
            key,
        )
        .await
        .expect("read restored fence after mismatch");
    assert!(
        fence.get::<_, Option<Vec<u8>>>(0).is_none()
            && fence.get::<_, Option<i64>>(1).is_none()
            && fence.get::<_, Option<SystemTime>>(2).is_none(),
        "Mismatch must not acknowledge or otherwise mutate the dispatch fence"
    );
}

/// A single operation carried through Phase 1 and the Phase-2 active-release acknowledgement,
/// with its reserve-release tombstone aged so `TombstoneReleaseIntentComplete` no longer refuses
/// on retention -- ready for a completion attempt at any sequence the caller supplies. CR-029's
/// D2 amendment (`docs/lore-change-requests/cr-029-delete-and-maintenance-amendments.md`, Part 3).
struct CompletionReadyOperation {
    stale: VerifiedStaleFinalizeInput,
    phase2_active: TerminalStatusAttachInput,
    tombstone_digest: Vec<u8>,
}

/// Drive one operation identity through Phase 1 (fixture -> pending -> aged -> tombstone-ready)
/// and the Phase-2 active-release acknowledgement, exactly as
/// `terminal_phase1_replays_then_atomically_exchanges_receipt_fence_for_tombstone` does inline,
/// but factored so the D2 sequence-ordering tests below can drive more than one operation through
/// it and, via `shared_identity`, share one namespace (verified_issuer/authenticated_subject/
/// tenant_scope_key) across them the way real assignments in one namespace would.
async fn prepare_operation_ready_for_completion(
    store: &PostgresDomainStore,
    direct: &mut Client,
    clock: SystemTime,
    shared_identity: Option<&ReceiptKey>,
) -> CompletionReadyOperation {
    let mut stale = stale_input(clock);
    if let Some(shared) = shared_identity {
        stale.key.verified_issuer = shared.verified_issuer.clone();
        stale.key.authenticated_subject = shared.authenticated_subject.clone();
        stale.key.tenant_scope_key = shared.tenant_scope_key.clone();
        stale.witness.authorization_id = stale.key.operation_id.as_bytes().to_vec();
    }
    let public_result = prepare_terminal_fixture_by_the_rail(store, direct, &stale).await;
    let phase1 = terminal_phase1_input(&stale, &public_result);
    store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("phase1 pending attach");
    direct
        .execute(
            "UPDATE lore_domain_operation_receipts SET compact_expires_at=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age receipt retention");
    let ready = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("phase1 exchange to tombstone");
    assert_eq!(
        ready.status,
        TerminalStatusAttachStatus::Phase1TombstoneReady
    );
    let tombstone_digest = ready.fields[4]
        .clone()
        .expect("phase1 must return the tombstone digest");

    let mut phase2 = phase1;
    phase2.phase = TerminalStatusAttachPhase::Phase2ReleaseAck;
    phase2.action = TerminalStatusAttachAction::ActiveReleaseIntentAck;
    phase2.release_tombstone_digest = Some(tombstone_digest.clone());
    phase2.active_release_intent_revision = Some(37);
    phase2.active_release_intent_nonce = Some(rand::random::<[u8; 32]>().to_vec());
    phase2.request_digest = rand::random::<[u8; 32]>().to_vec();
    let active = store
        .domain_operation_terminal_status_attach(&phase2)
        .await
        .expect("acknowledge active release intent");
    assert_eq!(
        active.status,
        TerminalStatusAttachStatus::Phase2ActiveReleaseAcked
    );

    direct
        .execute(
            "UPDATE lore_domain_operation_reserve_release_tombstones \
             SET created_at=clock_timestamp()-interval '3 seconds', \
                 compact_after=clock_timestamp()-interval '2 seconds', \
                 final_prune_after=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[
                &stale.key.verified_issuer,
                &stale.key.authenticated_subject,
                &stale.key.tenant_scope_key,
                &stale.key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .expect("age tombstone retention past final prune");

    CompletionReadyOperation {
        stale,
        phase2_active: phase2,
        tombstone_digest,
    }
}

/// Build a `TombstoneReleaseIntentComplete` request for `op` claiming `sequence`, with a correctly
/// derived `expected_completion_marker_digest` for that exact sequence -- so a not-ready or
/// out-of-order rejection below is decided by the D2 sequence gate itself, never by a coincidental
/// digest mismatch.
fn completion_request(
    op: &CompletionReadyOperation,
    epoch: &[u8],
    sequence: i64,
) -> TerminalStatusAttachInput {
    let mut complete = op.phase2_active.clone();
    complete.action = TerminalStatusAttachAction::TombstoneReleaseIntentComplete;
    complete.final_prune_digest = Some(rand::random::<[u8; 32]>().to_vec());
    complete.tombstone_release_intent_revision = Some(41);
    complete.tombstone_release_intent_nonce = Some(rand::random::<[u8; 32]>().to_vec());
    complete.request_digest = rand::random::<[u8; 32]>().to_vec();
    complete.completion_marker_sequence = sequence;
    complete.expected_completion_marker_digest = Some(completion_marker_digest(
        &complete,
        epoch,
        &op.tombstone_digest,
    ));
    complete
}

async fn counter_revisions(client: &Client, org_uuid: &[u8]) -> (i64, i64) {
    let row = client
        .query_one(
            "SELECT (SELECT counter_revision FROM lore_domain_proof_global_counters WHERE id=1), \
                     (SELECT counter_revision FROM lore_domain_proof_org_counters WHERE org_uuid=$1)",
            &[&org_uuid],
        )
        .await
        .expect("read global/org counter revisions");
    (row.get(0), row.get(1))
}

/// Independently reimplements `finish_terminal_ack`'s response-digest framing
/// (`domain-terminal-status-attachment-response-v1`, BLAKE3, u32be length-prefixed
/// `status_code || operation_id || request_digest || verification_digest`), the same way
/// `completion_marker_digest` above independently reimplements the marker digest, so the D2
/// amendment's new status code (11) is pinned by its own byte-exact digest, not merely by the
/// returned `status` enum discriminant. `finish_terminal_ack` itself is crate-private with no
/// unit-test module in `maintenance.rs`, so this is the only reachable way to pin its digest
/// framing for the new code today.
fn terminal_ack_response_digest(status_code: u8, input: &TerminalStatusAttachInput) -> Vec<u8> {
    let mut canonical = Vec::new();
    for part in [
        b"domain-terminal-status-attachment-response-v1".as_slice(),
        &[status_code],
        input.key.operation_id.as_bytes(),
        input.request_digest.as_slice(),
        input.verification_digest.as_slice(),
    ] {
        let length =
            u32::try_from(part.len()).expect("terminal ack response test field fits u32 frame");
        canonical.extend_from_slice(&length.to_be_bytes());
        canonical.extend_from_slice(part);
    }
    blake3::hash(&canonical).as_bytes().to_vec()
}

/// CR-029 D2 amendment (head-of-line blocking): a single operation's own tombstone is ready to
/// complete, but its assigned sequence is one past the namespace's `next_sequence`. The completion
/// attempt must be refused with `Phase2SequenceNotReady`, not `Mismatch`, and must mutate nothing:
/// no completion marker row, the reserve-release tombstone still present, the namespace's
/// `high_water`/`next_sequence` untouched, and neither proof counter's revision/retained-count/byte
/// total moved. `next_sequence` only ever advances inside the same transaction that inserts a
/// marker (there is no other writer of it in this file); asserting it is untouched here is that
/// proof for this call, satisfying D2's "never skip a sequence because its operation timed out".
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase2_completion_head_of_line_blocks_and_mutates_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");

    let op = prepare_operation_ready_for_completion(&store, &mut direct, clock, None).await;
    let namespace = ProofNamespaceKey {
        verified_issuer: op.stale.key.verified_issuer.clone(),
        authenticated_subject: op.stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: op.stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize namespace");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let not_ready = completion_request(&op, &materialize.namespace_epoch, 2);
    let before_state = completion_state(&direct, &op.stale.key, &materialize).await;
    let before_revisions = counter_revisions(&direct, &materialize.key.org_uuid).await;

    let refused = store
        .domain_operation_terminal_status_attach(&not_ready)
        .await
        .expect("a valid but not-yet-eligible sequence must not error");
    assert_eq!(
        refused.status,
        TerminalStatusAttachStatus::Phase2SequenceNotReady,
        "sequence 2 against a namespace whose next eligible sequence is 1 must be nonterminal, \
         not Mismatch"
    );
    assert_eq!(
        refused.response_digest,
        terminal_ack_response_digest(11, &not_ready),
        "the Phase2SequenceNotReady ack must use response-digest code 11"
    );
    assert_eq!(
        completion_state(&direct, &op.stale.key, &materialize).await,
        before_state,
        "a not-yet-eligible completion must insert no marker, release no reserve, and leave the \
         tombstone, namespace high_water/next_sequence, and retained-marker counts untouched"
    );
    assert_eq!(
        counter_revisions(&direct, &materialize.key.org_uuid).await,
        before_revisions,
        "a not-yet-eligible completion must not advance either proof counter revision"
    );

    let replay = store
        .domain_operation_terminal_status_attach(&not_ready)
        .await
        .expect("replay of the same not-yet-eligible request");
    assert_eq!(
        replay, refused,
        "an identical not-ready request must replay to the exact same ack"
    );
    assert_eq!(
        completion_state(&direct, &op.stale.key, &materialize).await,
        before_state,
        "the replay must not mutate state either"
    );
}

/// CR-029 D2 amendment (unblocking + retained assignment): once the predecessor sequence
/// completes, the exact same previously-refused higher-sequence request -- unchanged, not
/// reconstructed -- now succeeds with `Phase2ReleaseCompletionReady`, retaining the assignment and
/// binding it was refused with. `high_water`/`next_sequence` advance exactly 1 -> 2 -> 3 across the
/// two completions.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase2_completion_unblocks_after_predecessor_retaining_assignment() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");

    let op1 = prepare_operation_ready_for_completion(&store, &mut direct, clock, None).await;
    let shared_key = op1.stale.key.clone();
    let op2 = prepare_operation_ready_for_completion(
        &store,
        &mut direct,
        clock + Duration::from_secs(5),
        Some(&shared_key),
    )
    .await;
    assert_ne!(
        op1.stale.key.operation_id, op2.stale.key.operation_id,
        "the two operations sharing a namespace must still be distinct operations"
    );

    let namespace = ProofNamespaceKey {
        verified_issuer: shared_key.verified_issuer.clone(),
        authenticated_subject: shared_key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: shared_key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize shared namespace");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let complete_1 = completion_request(&op1, &materialize.namespace_epoch, 1);
    let complete_2 = completion_request(&op2, &materialize.namespace_epoch, 2);

    let refused = store
        .domain_operation_terminal_status_attach(&complete_2)
        .await
        .expect("higher sequence must be refused, not error");
    assert_eq!(
        refused.status,
        TerminalStatusAttachStatus::Phase2SequenceNotReady
    );
    let op2_state_while_blocked = completion_state(&direct, &op2.stale.key, &materialize).await;
    assert_eq!(
        op2_state_while_blocked[0], 1,
        "op2's own tombstone must still be present while it is blocked"
    );
    assert_eq!(
        op2_state_while_blocked[1], 0,
        "op2 must have no completion marker while it is blocked"
    );

    let completed_1 = store
        .domain_operation_terminal_status_attach(&complete_1)
        .await
        .expect("predecessor sequence completes");
    assert_eq!(
        completed_1.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
    );
    let after_first = completion_state(&direct, &op1.stale.key, &materialize).await;
    assert_eq!(after_first[2], 1, "high_water must advance to 1");
    assert_eq!(after_first[3], 2, "next_sequence must advance to 2");

    let unblocked = store
        .domain_operation_terminal_status_attach(&complete_2)
        .await
        .expect("the exact previously-refused request now completes");
    assert_eq!(
        unblocked.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady,
        "the retained assignment must be honored once its predecessor is complete"
    );
    assert_eq!(
        unblocked.fields[8], complete_2.expected_completion_marker_digest,
        "unblocking must complete using the exact same marker digest/binding it was refused with"
    );
    let after_second = completion_state(&direct, &op2.stale.key, &materialize).await;
    assert_eq!(after_second[0], 0, "op2's tombstone must now be deleted");
    assert_eq!(after_second[1], 1, "op2 must now have exactly one marker");
    assert_eq!(after_second[2], 2, "high_water must advance to 2");
    assert_eq!(after_second[3], 3, "next_sequence must advance to 3");
}

/// CR-029 D2 amendment (ordering is strict, not a window): a sequence far past `next_sequence`
/// (not merely one past it) is refused exactly the same way as the head-of-line case, covering "a
/// valid higher sequence" generally rather than only an immediately-adjacent one, and must not be
/// silently accepted or dropped.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase2_completion_far_future_sequence_is_not_ready_not_mismatch() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");

    let op = prepare_operation_ready_for_completion(&store, &mut direct, clock, None).await;
    let namespace = ProofNamespaceKey {
        verified_issuer: op.stale.key.verified_issuer.clone(),
        authenticated_subject: op.stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: op.stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize namespace");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let before_state = completion_state(&direct, &op.stale.key, &materialize).await;
    let far_future = completion_request(&op, &materialize.namespace_epoch, 5);
    let refused = store
        .domain_operation_terminal_status_attach(&far_future)
        .await
        .expect("a far-future sequence must not error");
    assert_eq!(
        refused.status,
        TerminalStatusAttachStatus::Phase2SequenceNotReady,
        "a sequence far past next_sequence is still nonterminal, never Mismatch and never accepted"
    );
    assert_eq!(
        completion_state(&direct, &op.stale.key, &materialize).await,
        before_state
    );
}

/// CR-029 D2 amendment (lower sequence keeps today's rules): a sequence below `next_sequence` that
/// is not an existing marker stays `Mismatch`, exactly as before this amendment -- only the `>`
/// case gained a new status; `<` is untouched. After the correct sequence completes, an exact
/// replay of that same completion request (its own marker now exists, its tombstone is gone) must
/// keep the current behaviour of `Phase2ReleaseCompletionReady`; this amendment does not touch
/// that already-existing marker-replay code path.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_phase2_completion_lower_sequence_and_replay_pin_current_behaviour() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");

    let op = prepare_operation_ready_for_completion(&store, &mut direct, clock, None).await;
    let namespace = ProofNamespaceKey {
        verified_issuer: op.stale.key.verified_issuer.clone(),
        authenticated_subject: op.stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: op.stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize namespace");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let before_state = completion_state(&direct, &op.stale.key, &materialize).await;
    let too_low = completion_request(&op, &materialize.namespace_epoch, 0);
    let rejected = store
        .domain_operation_terminal_status_attach(&too_low)
        .await
        .expect("a below-next sequence with no existing marker must not error");
    assert_eq!(
        rejected.status,
        TerminalStatusAttachStatus::Mismatch,
        "a sequence below next_sequence with no marker for it keeps the frozen Mismatch behaviour"
    );
    assert_eq!(
        completion_state(&direct, &op.stale.key, &materialize).await,
        before_state,
        "a rejected below-next sequence must not mutate anything either"
    );

    let complete = completion_request(&op, &materialize.namespace_epoch, 1);
    let completed = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("the correct sequence completes");
    assert_eq!(
        completed.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
    );

    let replay = store
        .domain_operation_terminal_status_attach(&complete)
        .await
        .expect("exact replay of the now-completed sequence");
    assert_eq!(
        replay.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady,
        "an exact replay after the tombstone is gone and the marker exists keeps today's success \
         reply -- this amendment does not add a Mismatch here"
    );
    assert_eq!(
        replay, completed,
        "the replay must return the exact same ack as the original completion"
    );
}

/// Pure, offline pin over `WireTerminalOutcome` alone -- no `LORE_TEST_PG_URL` needed, so this
/// runs (and would fail) with a plain `cargo test -p lore-postgres`, unlike every case around it
/// that silently skips without a live Postgres.
///
/// The defect this whole cluster of tests guards against was not merely "every honest attach gets
/// refused". A raw `stored_outcome_i16 == wire_terminal_outcome_i16` compare is wrong in BOTH
/// directions: `WIRE_TERMINAL_OUTCOME_APPLIED` (1) never equals `RECEIPT_OUTCOME_APPLIED` (0), so
/// an honest APPLIED attach against a receipt stored APPLIED was always refused -- but
/// `WIRE_TERMINAL_OUTCOME_APPLIED` (1) and `RECEIPT_OUTCOME_NOT_APPLIED` (1) are the SAME number,
/// so the same raw compare would have silently ACCEPTED a platform claiming APPLIED against a
/// receipt this crate had actually committed NOT_APPLIED. That numeric collision, not just the
/// refusal, is why the mapping has to be a real function and not a raw integer compare.
#[test]
fn wire_terminal_outcome_never_matches_the_receipt_column_raw() {
    // Round trip: as_wire is the exact inverse of from_wire over the frozen pair.
    assert_eq!(WireTerminalOutcome::from_wire(1).as_wire(), 1);
    assert_eq!(WireTerminalOutcome::from_wire(2).as_wire(), 2);
    assert_eq!(
        WireTerminalOutcome::APPLIED.as_wire(),
        WIRE_TERMINAL_OUTCOME_APPLIED
    );
    assert_eq!(
        WireTerminalOutcome::NOT_APPLIED.as_wire(),
        WIRE_TERMINAL_OUTCOME_NOT_APPLIED
    );

    // The one canonical mapping onto the storage domain.
    assert_eq!(
        WireTerminalOutcome::APPLIED.receipt_outcome(),
        Some(RECEIPT_OUTCOME_APPLIED)
    );
    assert_eq!(
        WireTerminalOutcome::NOT_APPLIED.receipt_outcome(),
        Some(RECEIPT_OUTCOME_NOT_APPLIED)
    );

    // Everything outside the frozen wire pair maps to None, never silently coerced to either
    // storage code.
    for out_of_domain in [0_i16, 3, -1, i16::MIN, i16::MAX] {
        assert_eq!(
            WireTerminalOutcome::from_wire(out_of_domain).receipt_outcome(),
            None,
            "wire value {out_of_domain} must not resolve to a storage outcome"
        );
    }

    // The two encodings are different bases; the same raw integer never means the same thing in
    // both, and one specific number means opposite things in each.
    assert_ne!(WIRE_TERMINAL_OUTCOME_APPLIED, RECEIPT_OUTCOME_APPLIED);
    assert_eq!(
        WIRE_TERMINAL_OUTCOME_APPLIED, RECEIPT_OUTCOME_NOT_APPLIED,
        "this collision is exactly why a raw compare would have accepted a wire-APPLIED attach \
         against a receipt actually stored NOT_APPLIED"
    );
}

/// CR-029's Phase-1 exactness compare must resolve the caller's WIRE-domain `terminal_outcome`
/// (`WireTerminalOutcome::APPLIED` == 1) to the STORAGE-domain code the receipt was actually
/// committed under (`RECEIPT_OUTCOME_APPLIED` == 0) before comparing, rather than comparing the raw
/// wire value against the raw stored column. A correct platform sending wire APPLIED against a
/// receipt this rail commits with `DomainOutcome::Applied` must be accepted.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_attach_accepts_wire_applied_against_stored_applied_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let stale = stale_input(clock);
    let public_result = prepare_terminal_fixture_by_the_rail_with_outcome(
        &store,
        &mut direct,
        &stale,
        &DomainOutcome::Applied,
        b"wire-applied-vs-stored-applied-v1",
    )
    .await;
    let mut phase1 = terminal_phase1_input(&stale, &public_result);
    phase1.terminal_outcome = WireTerminalOutcome::APPLIED;

    let ack = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("attach a wire-applied outcome against a stored-applied receipt");
    assert_eq!(
        ack.status,
        TerminalStatusAttachStatus::Phase1PendingRetention,
        "a correct platform-sent wire APPLIED must be accepted against a receipt stored APPLIED"
    );
}

/// Companion to the APPLIED acceptance case: wire NOT_APPLIED (2) must resolve to the storage code
/// `RECEIPT_OUTCOME_NOT_APPLIED` (1) and be accepted against a receipt this rail commits with
/// `DomainOutcome::NotApplied`.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_attach_accepts_wire_not_applied_against_stored_not_applied_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let stale = stale_input(clock);
    let stored_outcome = DomainOutcome::NotApplied {
        reason_version: 1,
        reason: "WIRE_ATTACH_TEST_NOT_APPLIED_V1".into(),
    };
    let public_result = prepare_terminal_fixture_by_the_rail_with_outcome(
        &store,
        &mut direct,
        &stale,
        &stored_outcome,
        b"wire-not-applied-vs-stored-not-applied-v1",
    )
    .await;
    let mut phase1 = terminal_phase1_input(&stale, &public_result);
    phase1.terminal_outcome = WireTerminalOutcome::NOT_APPLIED;

    let ack = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("attach a wire-not-applied outcome against a stored-not-applied receipt");
    assert_eq!(
        ack.status,
        TerminalStatusAttachStatus::Phase1PendingRetention,
        "a correct platform-sent wire NOT_APPLIED must be accepted against a receipt stored \
         NOT_APPLIED"
    );
}

/// `WireTerminalOutcome::from_wire(0)` is the STORAGE encoding for APPLIED, and is unreachable from
/// the wire (the gRPC seam only ever produces 1 or 2; `strict_codec.rs` refuses anything else before
/// this coordinator is ever called). This is exactly the value the fixture used to hand-build before
/// this fix -- pin that it is now refused, not silently accepted by a raw-value coincidence.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_attach_refuses_a_storage_encoded_terminal_outcome() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");
    let stale = stale_input(clock);
    let public_result = prepare_terminal_fixture_by_the_rail(&store, &mut direct, &stale).await;
    let mut phase1 = terminal_phase1_input(&stale, &public_result);
    phase1.terminal_outcome = WireTerminalOutcome::from_wire(0);

    let ack = store
        .domain_operation_terminal_status_attach(&phase1)
        .await
        .expect("attach a storage-encoded outcome against a stored-applied receipt");
    assert_eq!(
        ack.status,
        TerminalStatusAttachStatus::Mismatch,
        "a storage-encoded value is unreachable from the wire and must be refused"
    );
}

/// Two more refusal pins: wire APPLIED against a receipt actually stored NOT_APPLIED must be
/// Mismatch (the two are genuinely different outcomes, not a coincidental raw-value collision like
/// the storage-encoding case above), and an out-of-domain wire value (neither 1 nor 2) must be
/// Mismatch regardless of what the receipt stores, because `WireTerminalOutcome::receipt_outcome()`
/// returns `None` for it before the stored-outcome compare ever runs.
#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn terminal_attach_refuses_a_wire_outcome_disagreeing_with_the_stored_receipt() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.expect("DB clock");

    // wire APPLIED=1 against a receipt stored NotApplied(1) must be Mismatch.
    let cross_stale = stale_input(clock);
    let cross_outcome = DomainOutcome::NotApplied {
        reason_version: 1,
        reason: "WIRE_ATTACH_TEST_CROSS_MISMATCH_V1".into(),
    };
    let cross_public_result = prepare_terminal_fixture_by_the_rail_with_outcome(
        &store,
        &mut direct,
        &cross_stale,
        &cross_outcome,
        b"wire-applied-vs-stored-not-applied-v1",
    )
    .await;
    let mut cross_phase1 = terminal_phase1_input(&cross_stale, &cross_public_result);
    cross_phase1.terminal_outcome = WireTerminalOutcome::APPLIED;
    let cross_ack = store
        .domain_operation_terminal_status_attach(&cross_phase1)
        .await
        .expect("attach a wire-applied outcome against a stored-not-applied receipt");
    assert_eq!(
        cross_ack.status,
        TerminalStatusAttachStatus::Mismatch,
        "wire APPLIED disagreeing with a stored NOT_APPLIED receipt must be refused"
    );

    // An out-of-domain wire value (3) must be refused before the stored-outcome compare, on an
    // otherwise-exact fixture.
    let out_of_domain_stale = stale_input(clock);
    let out_of_domain_public_result =
        prepare_terminal_fixture_by_the_rail(&store, &mut direct, &out_of_domain_stale).await;
    let mut out_of_domain_phase1 =
        terminal_phase1_input(&out_of_domain_stale, &out_of_domain_public_result);
    out_of_domain_phase1.terminal_outcome = WireTerminalOutcome::from_wire(3);
    let out_of_domain_ack = store
        .domain_operation_terminal_status_attach(&out_of_domain_phase1)
        .await
        .expect("attach an out-of-domain wire outcome");
    assert_eq!(
        out_of_domain_ack.status,
        TerminalStatusAttachStatus::Mismatch,
        "an out-of-domain wire outcome must be refused regardless of the stored receipt"
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn materialize_replay_preserves_receipt_and_changed_claim_mismatches() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let input = materialize_input(namespace, counter, quota);

    let first = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("materialize namespace");
    assert_eq!(first.status, ProofNamespaceMaterializeStatus::Materialized);

    let org_after_first = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&input.key.org_uuid],
        )
        .await
        .expect("read organization proof counter after materialization");
    assert_eq!(
        (
            org_after_first.get::<_, i64>(0),
            org_after_first.get::<_, i64>(1)
        ),
        (first.lore_org_counter_revision, 1),
        "first materialization must charge exactly one organization namespace"
    );

    let replay = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("exact materialize replay");
    assert_eq!(
        replay, first,
        "replay must preserve all canonical receipt fields"
    );
    let org_after_replay = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&input.key.org_uuid],
        )
        .await
        .expect("read organization proof counter after replay");
    assert_eq!(
        (
            org_after_replay.get::<_, i64>(0),
            org_after_replay.get::<_, i64>(1)
        ),
        (first.lore_org_counter_revision, 1),
        "exact replay must not increment the organization counter again"
    );

    let mut mismatch = input.clone();
    mismatch.namespace_claim_nonce[0] ^= 0xff;
    let rejected = store
        .domain_operation_proof_namespace_materialize(&mismatch)
        .await
        .expect("changed claim is decisive");
    assert_eq!(rejected.status, ProofNamespaceMaterializeStatus::Mismatch);

    let mut changed_request = input;
    changed_request.request_digest[0] ^= 0xff;
    let rejected = store
        .domain_operation_proof_namespace_materialize(&changed_request)
        .await
        .expect("changed request digest is decisive");
    assert_eq!(rejected.status, ProofNamespaceMaterializeStatus::Mismatch);
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn materialize_replay_with_a_null_receipt_is_mismatch_not_a_panic() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping nullable materialization receipt test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let input = materialize_input(namespace, counter, quota);
    let first = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("materialize setup namespace");
    assert_eq!(first.status, ProofNamespaceMaterializeStatus::Materialized);

    direct
        .execute(
            "UPDATE lore_domain_proof_namespaces SET materialization_receipt=NULL \
              WHERE verified_issuer=$1 AND authenticated_subject=$2 \
                AND tenant_scope_key=$3 AND epoch=$4",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
            ],
        )
        .await
        .expect("exercise the schema-permitted nullable receipt state");

    let replay = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("nullable receipt must be handled without Row::get panic");
    assert_eq!(
        replay.status,
        ProofNamespaceMaterializeStatus::Mismatch,
        "a matching row with no canonical receipt cannot claim a replay"
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn materialize_capacity_revision_mismatch_writes_no_namespace() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let seed_key = namespace_key();
    let (initial_counter, initial_quota) = provision_capacity(&direct, &seed_key.org_uuid).await;
    let seed = materialize_input(seed_key, initial_counter, initial_quota);
    let seeded = store
        .domain_operation_proof_namespace_materialize(&seed)
        .await
        .expect("seed the capacity counter");
    assert_eq!(seeded.status, ProofNamespaceMaterializeStatus::Materialized);
    let (counter, quota) = capacity_pair(&direct).await;
    let mut input_key = namespace_key();
    input_key.org_uuid = seed.key.org_uuid.clone();
    let input = materialize_input(input_key, counter + 1, quota);
    let blocked = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("capacity mismatch is decisive");
    assert_eq!(
        blocked.status,
        ProofNamespaceMaterializeStatus::CapacityBlocked
    );
    let count: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
            ],
        )
        .await
        .expect("count namespaces")
        .get(0);
    assert_eq!(count, 0, "capacity rejection must not claim an epoch");
}

#[tokio::test]
#[ignore = "needs a fresh disposable live Postgres database; run via run-domain-maintenance-live.ps1"]
async fn fresh_cell_seeds_global_counter_and_first_materialize_provisions_org_counter() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let global = direct
        .query_one(
            "SELECT counter_revision, quota_revision, represented_namespace_rows, \
                    retained_marker_count, outstanding_proof_claims, fragment_count, \
                    fragment_bytes, marker_bytes \
             FROM lore_domain_proof_global_counters WHERE id=1",
            &[],
        )
        .await
        .expect("mediated schema setup must seed the singleton global proof counter");
    assert_eq!(global.get::<_, i64>(0), 0);
    assert_eq!(global.get::<_, i32>(1), 1);
    for column in 2..8 {
        assert_eq!(
            global.get::<_, i64>(column),
            0,
            "fresh global proof counter column {column} must start at zero"
        );
    }
    let org_rows: i64 = direct
        .query_one("SELECT count(*) FROM lore_domain_proof_org_counters", &[])
        .await
        .expect("count organization counters")
        .get(0);
    assert_eq!(org_rows, 0, "fresh setup must not invent organization rows");

    let input = materialize_input(namespace_key(), 0, 1);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("first-use organization provisioning and materialization succeed");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    let org = direct
        .query_one(
            "SELECT counter_revision, quota_revision, represented_namespace_rows, \
                    retained_marker_count, fragment_count, fragment_bytes, marker_bytes \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&input.key.org_uuid],
        )
        .await
        .expect("first materialization must create the organization counter");
    assert_eq!(
        (
            org.get::<_, i64>(0),
            org.get::<_, i32>(1),
            org.get::<_, i64>(2)
        ),
        (1, 1, 1),
        "the first charge must advance the authoritative zero revision/count exactly once"
    );
    for column in 3..7 {
        assert_eq!(
            org.get::<_, i64>(column),
            0,
            "new organization counter column {column} must retain its zero baseline"
        );
    }
}

#[tokio::test]
#[ignore = "needs a fresh disposable live Postgres database; run via run-domain-maintenance-live.ps1"]
async fn materialize_changed_org_replay_mismatches_without_provisioning_wrong_org() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let input = materialize_input(namespace_key(), 0, 1);
    let materialized = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("first materialization succeeds");
    assert_eq!(
        materialized.status,
        ProofNamespaceMaterializeStatus::Materialized
    );

    let mut changed_org = input.clone();
    changed_org.key.org_uuid = rand::random::<[u8; 16]>().to_vec();
    changed_org.lore_local_capacity_revision = materialized.lore_global_counter_revision;
    assert_ne!(changed_org.key.org_uuid, input.key.org_uuid);
    let state = |row: tokio_postgres::Row| {
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3),
            row.get::<_, i64>(4),
            row.get::<_, i64>(5),
        )
    };
    let state_query = "SELECT \
            (SELECT counter_revision FROM lore_domain_proof_global_counters WHERE id=1), \
            (SELECT represented_namespace_rows FROM lore_domain_proof_global_counters WHERE id=1), \
            (SELECT counter_revision FROM lore_domain_proof_org_counters WHERE org_uuid=$1), \
            (SELECT represented_namespace_rows FROM lore_domain_proof_org_counters WHERE org_uuid=$1), \
            (SELECT count(*) FROM lore_domain_proof_org_counters), \
            (SELECT count(*) FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$2 AND authenticated_subject=$3 AND tenant_scope_key=$4)";
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &input.key.org_uuid,
        &input.key.verified_issuer,
        &input.key.authenticated_subject,
        &input.key.tenant_scope_key,
    ];
    let before = state(
        direct
            .query_one(state_query, params)
            .await
            .expect("read pre-mismatch namespace and counter state"),
    );

    let mismatch = store
        .domain_operation_proof_namespace_materialize(&changed_org)
        .await
        .expect("changed organization is a decisive mismatch");
    assert_eq!(mismatch.status, ProofNamespaceMaterializeStatus::Mismatch);

    let after = state(
        direct
            .query_one(state_query, params)
            .await
            .expect("read post-mismatch namespace and counter state"),
    );
    assert_eq!(after, before, "mismatch must not mutate original authority");
    let changed_org_rows: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&changed_org.key.org_uuid],
        )
        .await
        .expect("count wrong-organization counters")
        .get(0);
    assert_eq!(
        changed_org_rows, 0,
        "a changed-org replay must not provision a zero counter for the wrong organization"
    );
    let stored_org: Vec<u8> = direct
        .query_one(
            "SELECT org_uuid FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
            ],
        )
        .await
        .expect("read immutable namespace organization")
        .get(0);
    assert_eq!(stored_org, input.key.org_uuid);
}

#[tokio::test]
#[ignore = "needs a fresh disposable live Postgres database; run via run-domain-maintenance-live.ps1"]
async fn fresh_org_stale_capacity_revision_blocks_without_provisioning_org_counter() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let input = materialize_input(namespace_key(), 1, 1);

    let blocked = store
        .domain_operation_proof_namespace_materialize(&input)
        .await
        .expect("stale Lore-local revision is a decisive capacity result");
    assert_eq!(
        blocked.status,
        ProofNamespaceMaterializeStatus::CapacityBlocked
    );
    let state = direct
        .query_one(
            "SELECT \
                (SELECT counter_revision FROM lore_domain_proof_global_counters WHERE id=1), \
                (SELECT quota_revision FROM lore_domain_proof_global_counters WHERE id=1), \
                (SELECT represented_namespace_rows FROM lore_domain_proof_global_counters WHERE id=1), \
                (SELECT count(*) FROM lore_domain_proof_org_counters WHERE org_uuid=$1), \
                (SELECT count(*) FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$2 AND authenticated_subject=$3 AND tenant_scope_key=$4)",
            &[
                &input.key.org_uuid,
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
            ],
        )
        .await
        .expect("read capacity rejection state");
    assert_eq!(state.get::<_, i64>(0), 0);
    assert_eq!(state.get::<_, i32>(1), 1);
    assert_eq!(state.get::<_, i64>(2), 0);
    assert_eq!(
        state.get::<_, i64>(3),
        0,
        "a stale caller revision must not provision a fresh organization counter"
    );
    assert_eq!(
        state.get::<_, i64>(4),
        0,
        "capacity rejection must not claim a namespace"
    );
}

#[tokio::test]
#[ignore = "needs a fresh disposable live Postgres database; run via run-domain-maintenance-live.ps1"]
async fn retire_with_missing_org_counter_returns_mismatch_not_internal() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let result = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize setup");
    assert_eq!(result.status, ProofNamespaceMaterializeStatus::Materialized);
    direct
        .execute(
            "DELETE FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&materialize.key.org_uuid],
        )
        .await
        .expect("remove organization counter to exercise corruption posture");

    let outcome = store
        .domain_operation_proof_namespace_retire(&retire_input(&materialize))
        .await
        .expect("missing organization counter must be a decisive domain status");
    assert_eq!(outcome.status, ProofNamespaceRetireStatus::Mismatch);
}

#[tokio::test]
#[ignore = "needs a fresh disposable live Postgres database; run via run-domain-maintenance-live.ps1"]
async fn retire_with_missing_global_counter_returns_mismatch_not_internal() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    let result = store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize setup");
    assert_eq!(result.status, ProofNamespaceMaterializeStatus::Materialized);
    direct
        .execute(
            "DELETE FROM lore_domain_proof_global_counters WHERE id=1",
            &[],
        )
        .await
        .expect("remove global counter to exercise corruption posture");

    let outcome = store
        .domain_operation_proof_namespace_retire(&retire_input(&materialize))
        .await
        .expect("missing global counter must be a decisive domain status");
    assert_eq!(outcome.status, ProofNamespaceRetireStatus::Mismatch);
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn retire_is_atomic_replays_absence_and_rejects_expired_permit() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize setup");
    let global_before = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_global_counters WHERE id=1",
            &[],
        )
        .await
        .expect("read global counter before retirement");
    let org_before = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&materialize.key.org_uuid],
        )
        .await
        .expect("read organization counter before retirement");
    let mut retire = retire_input(&materialize);
    retire.retirement_permit_revision = 3;

    let first = store
        .domain_operation_proof_namespace_retire(&retire)
        .await
        .expect("retire namespace");
    assert_eq!(first.status, ProofNamespaceRetireStatus::Retired);
    let replay = store
        .domain_operation_proof_namespace_retire(&retire)
        .await
        .expect("retirement replay");
    assert_eq!(replay.status, ProofNamespaceRetireStatus::RetiredOrAbsent);

    let global_after = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_global_counters WHERE id=1",
            &[],
        )
        .await
        .expect("read global counter after retirement");
    let org_after = direct
        .query_one(
            "SELECT counter_revision, represented_namespace_rows \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1",
            &[&materialize.key.org_uuid],
        )
        .await
        .expect("read organization counter after retirement");
    assert_eq!(
        (global_after.get::<_, i64>(0), global_after.get::<_, i64>(1)),
        (
            global_before.get::<_, i64>(0) + 1,
            global_before.get::<_, i64>(1) - 1
        ),
        "retirement must atomically remove one global represented namespace"
    );
    assert_eq!(
        (org_after.get::<_, i64>(0), org_after.get::<_, i64>(1)),
        (
            org_before.get::<_, i64>(0) + 1,
            org_before.get::<_, i64>(1) - 1
        ),
        "retirement must atomically remove one organization represented namespace"
    );

    let mut expired = retire.clone();
    expired.key = namespace_key();
    expired.expires_at = SystemTime::now();
    let rejected = store
        .domain_operation_proof_namespace_retire(&expired)
        .await
        .expect("expired permit is decisive");
    assert_eq!(rejected.status, ProofNamespaceRetireStatus::Expired);
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn retire_requires_exact_fence_generation_and_final_range_digest() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize setup");
    let mut retire = retire_input(&materialize);
    retire.retirement_permit_revision = 3;

    let mut wrong_digest = retire.clone();
    wrong_digest.final_range_set_digest[0] ^= 0xff;
    let digest = store
        .domain_operation_proof_namespace_retire(&wrong_digest)
        .await
        .expect("range digest mismatch is decisive");
    assert_eq!(digest.status, ProofNamespaceRetireStatus::Mismatch);

    let independent_revisions = store
        .domain_operation_proof_namespace_retire(&retire)
        .await
        .expect("independently verified fence generation and permit revision");
    assert_eq!(
        independent_revisions.status,
        ProofNamespaceRetireStatus::Retired,
        "fence generation and permit revision are independent verifier-approved fields"
    );
}

#[tokio::test]
#[ignore = "needs live Postgres env; run this test target serially with -- --ignored --test-threads=1"]
async fn retire_rejects_nonquiescent_namespace_and_changed_epoch_claim_without_mutation() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping maintenance test");
        return;
    };
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    store
        .domain_operation_proof_namespace_materialize(&materialize)
        .await
        .expect("materialize setup");
    direct
        .execute(
            "UPDATE lore_domain_proof_namespaces SET retained_marker_count=1 \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND epoch=$4",
            &[
                &materialize.key.verified_issuer,
                &materialize.key.authenticated_subject,
                &materialize.key.tenant_scope_key,
                &materialize.namespace_epoch,
            ],
        )
        .await
        .expect("seed one retained marker charge");

    let retire = retire_input(&materialize);
    let pending = store
        .domain_operation_proof_namespace_retire(&retire)
        .await
        .expect("nonquiescent result");
    assert_eq!(pending.status, ProofNamespaceRetireStatus::NotQuiescent);

    let mut changed_claim = retire;
    changed_claim.namespace_claim_nonce[0] ^= 0xff;
    let mismatch = store
        .domain_operation_proof_namespace_retire(&changed_claim)
        .await
        .expect("claim mismatch result");
    assert_eq!(mismatch.status, ProofNamespaceRetireStatus::Mismatch);

    let remaining: i64 = direct
        .query_one(
            "SELECT count(*) FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND epoch=$4",
            &[
                &materialize.key.verified_issuer,
                &materialize.key.authenticated_subject,
                &materialize.key.tenant_scope_key,
                &materialize.namespace_epoch,
            ],
        )
        .await
        .expect("count surviving namespace")
        .get(0);
    assert_eq!(remaining, 1, "neither rejection may delete the namespace");
}

/// Build real committed markers in one namespace. Deadline ageing is fixture-only;
/// the production 365-day retention policy remains in force.
async fn completed_marker_fixture(
    store: &PostgresDomainStore,
    direct: &mut Client,
    count: usize,
) -> (
    ProofNamespaceMaterializeInput,
    Vec<TerminalStatusAttachInput>,
) {
    let clock = store.domain_operation_clock_get().await.unwrap();
    let first = prepare_operation_ready_for_completion(store, direct, clock, None).await;
    let namespace = ProofNamespaceKey {
        verified_issuer: first.stale.key.verified_issuer.clone(),
        authenticated_subject: first.stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: first.stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&materialize)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    let mut requests = vec![completion_request(&first, &materialize.namespace_epoch, 1)];
    for ordinal in 1..count {
        let operation = prepare_operation_ready_for_completion(
            store,
            direct,
            clock + Duration::from_secs(ordinal as u64),
            Some(&first.stale.key),
        )
        .await;
        requests.push(completion_request(
            &operation,
            &materialize.namespace_epoch,
            ordinal as i64 + 1,
        ));
    }
    for request in &requests {
        assert_eq!(
            store
                .domain_operation_terminal_status_attach(request)
                .await
                .unwrap()
                .status,
            TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
        );
        let key = &request.key;
        direct.execute(
            "UPDATE lore_domain_operation_tombstone_release_completion_markers \
             SET created_at=to_timestamp(1000 + sequence), retain_until=to_timestamp(2000) \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()],
        ).await.unwrap();
    }
    (materialize, requests)
}

async fn assert_corrupt_neighbor_refused(column: &str, replay_pruned: bool) {
    let url =
        pg_url().expect("owned Postgres URL is required for an explicitly selected live test");
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let (_, requests) = completed_marker_fixture(&store, &mut direct, 2).await;
    let first = store
        .domain_operation_terminal_status_attach(&requests[0])
        .await
        .unwrap();
    assert_eq!(
        first.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    let replacement = match column {
        "protocol_revision" => "protocol_revision + 1",
        "quota_revision" => "quota_revision + 1",
        "interval_digest" => "decode(repeat('ff', 32), 'hex')",
        _ => panic!("unknown fixture corruption"),
    };
    let key = &requests[0].key;
    let sql = format!(
        "UPDATE lore_domain_tombstone_marker_prune_ranges SET {column}={replacement} \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND start_sequence=1"
    );
    assert_eq!(
        direct
            .execute(
                &sql,
                &[
                    &key.verified_issuer,
                    &key.authenticated_subject,
                    &key.tenant_scope_key
                ]
            )
            .await
            .unwrap(),
        1
    );
    let before = domain_rows(&direct).await;
    let request = &requests[usize::from(!replay_pruned)];
    let result = store.domain_operation_terminal_status_attach(request).await;
    assert!(
        matches!(result, Err(DomainError::Internal(_))),
        "corrupt adjacent {column} must fail closed instead of being normalized by a merge: {result:?}"
    );
    assert_eq!(
        domain_rows(&direct).await,
        before,
        "refused merge must leave every domain row and counter unchanged"
    );
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_prune_rejects_neighbor_protocol_revision_without_mutation() {
    assert_corrupt_neighbor_refused("protocol_revision", false).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_prune_rejects_neighbor_quota_revision_without_mutation() {
    assert_corrupt_neighbor_refused("quota_revision", false).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_prune_rejects_neighbor_digest_without_mutation() {
    assert_corrupt_neighbor_refused("interval_digest", false).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_recovery_rejects_range_protocol_revision_without_mutation() {
    assert_corrupt_neighbor_refused("protocol_revision", true).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_recovery_rejects_range_quota_revision_without_mutation() {
    assert_corrupt_neighbor_refused("quota_revision", true).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_recovery_rejects_range_digest_without_mutation() {
    assert_corrupt_neighbor_refused("interval_digest", true).await;
}

fn expected_range_digest(
    materialize: &ProofNamespaceMaterializeInput,
    start: u64,
    end: u64,
) -> Vec<u8> {
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    for part in [
        b"domain-marker-prune-interval-v3\0".as_slice(),
        materialize.key.tenant_scope_key.as_slice(),
        materialize.namespace_epoch.as_slice(),
        &2_u64.to_be_bytes(),
        &(materialize.platform_capacity_revision as u64).to_be_bytes(),
        &3_u64.to_be_bytes(),
        &start.to_be_bytes(),
        &end.to_be_bytes(),
        &(end - start + 1).to_be_bytes(),
        &end.to_be_bytes(),
    ] {
        hasher.update(part);
    }
    hasher.finish().as_ref().to_vec()
}

#[test]
fn interval_digest_matches_independent_raw_concat_golden_vector() {
    let mut materialize = materialize_input(namespace_key(), 0, 1);
    materialize.key.tenant_scope_key = (0_u8..16).collect();
    materialize.namespace_epoch = (16_u8..32).collect();
    // Independently computed with .NET SHA256 over a literal 120-byte CR-029
    // preimage, not produced by either the Lore helper or this test encoder.
    assert_eq!(
        expected_range_digest(&materialize, 5, 9),
        [
            0x74, 0xd5, 0xb1, 0x5a, 0x4b, 0xe9, 0xb0, 0x5f, 0x29, 0xd9, 0x0a, 0xdb, 0xe4, 0xcd,
            0x31, 0xa3, 0xb8, 0xaf, 0xe6, 0x26, 0x55, 0x23, 0xdf, 0x19, 0xe6, 0xea, 0x4a, 0x56,
            0xd5, 0xa8, 0x2e, 0x38
        ]
    );
}

async fn assert_completion_merge_order(order: [usize; 3]) {
    let url = pg_url().expect("owned Postgres URL");
    let store = store(&url).await;
    let mut direct = client(&url).await;
    {
        let (materialize, requests) = completed_marker_fixture(&store, &mut direct, 5).await;
        let key = &materialize.key;
        let successor = store
            .domain_operation_terminal_status_attach(&requests[4])
            .await
            .unwrap();
        assert_eq!(
            successor.status,
            TerminalStatusAttachStatus::Phase2PostPruneRecovery
        );
        let successor_sql = "SELECT row_to_json(r)::text || ':' || xmin::text FROM lore_domain_tombstone_marker_prune_ranges r \
            WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND start_sequence=5";
        let successor_before: String = direct
            .query_one(
                successor_sql,
                &[
                    &key.verified_issuer,
                    &key.authenticated_subject,
                    &key.tenant_scope_key,
                ],
            )
            .await
            .unwrap()
            .get(0);
        let mut singleton_times = Vec::new();
        for index in order {
            let lower: i64 = direct
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            let pruned = store
                .domain_operation_terminal_status_attach(&requests[index])
                .await
                .unwrap();
            assert_eq!(
                pruned.status,
                TerminalStatusAttachStatus::Phase2PostPruneRecovery
            );
            let upper: i64 = direct
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            let range = pruned.range.unwrap();
            let created: i64 = direct.query_one(
                "SELECT created_at_ms FROM lore_domain_tombstone_marker_prune_ranges WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND start_sequence=$4",
                &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &range.start_sequence],
            ).await.unwrap().get(0);
            if range.start_sequence == range.end_sequence {
                assert!(
                    (lower..=upper).contains(&created),
                    "singleton stores prune DB clock, not the aged marker clock: {created} outside {lower}..={upper}"
                );
                singleton_times.push(created);
            }
        }
        let successor_after: String = direct
            .query_one(
                successor_sql,
                &[
                    &key.verified_issuer,
                    &key.authenticated_subject,
                    &key.tenant_scope_key,
                ],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            successor_after, successor_before,
            "a merge must not rewrite a non-adjacent successor"
        );
        let ranges = direct.query(
            "SELECT start_sequence,end_sequence,sequence_count,generation,created_at_ms,row_charge,byte_charge,interval_digest \
             FROM lore_domain_tombstone_marker_prune_ranges WHERE verified_issuer=$1 AND authenticated_subject=$2 \
             AND tenant_scope_key=$3 ORDER BY start_sequence",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key],
        ).await.unwrap();
        assert_eq!(ranges.len(), 2);
        let merged = &ranges[0];
        let values: Vec<i64> = (0..5).map(|column| merged.get(column)).collect();
        assert_eq!(
            values,
            vec![1, 3, 3, 3, *singleton_times.iter().min().unwrap()]
        );
        assert_eq!(merged.get::<_, i32>(5), 1);
        let expected_bytes = (key.verified_issuer.len()
            + key.authenticated_subject.len()
            + key.tenant_scope_key.len()
            + 16
            + 6 * 8
            + 32) as i64;
        assert_eq!(merged.get::<_, i64>(6), expected_bytes);
        assert_eq!(
            merged.get::<_, Vec<u8>>(7),
            expected_range_digest(&materialize, 1, 3)
        );
        let counters = direct.query_one(
            "SELECT (SELECT retained_marker_count FROM lore_domain_proof_namespaces WHERE epoch=$1), \
             (SELECT fragment_count FROM lore_domain_proof_namespaces WHERE epoch=$1), \
             g.retained_marker_count,g.fragment_count,g.fragment_bytes,g.marker_bytes, \
             o.retained_marker_count,o.fragment_count,o.fragment_bytes,o.marker_bytes, \
             (SELECT byte_charge FROM lore_domain_operation_tombstone_release_completion_markers WHERE namespace_epoch=$1 AND sequence=4) \
             FROM lore_domain_proof_global_counters g CROSS JOIN lore_domain_proof_org_counters o WHERE g.id=1 AND o.org_uuid=$2",
            &[&materialize.namespace_epoch, &key.org_uuid],
        ).await.unwrap();
        let marker_bytes: i64 = counters.get(10);
        let actual: Vec<i64> = (0..10).map(|column| counters.get(column)).collect();
        assert_eq!(
            actual,
            vec![
                1,
                2,
                1,
                2,
                expected_bytes * 2,
                marker_bytes,
                1,
                2,
                expected_bytes * 2,
                marker_bytes
            ]
        );
        let replay = store
            .domain_operation_terminal_status_attach(&requests[0])
            .await
            .unwrap();
        assert_eq!(
            replay.range.unwrap().digest,
            expected_range_digest(&materialize, 1, 3)
        );
    }
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_prune_bridge_merge_preserves_distant_successor_and_counters() {
    assert_completion_merge_order([0, 2, 1]).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_prune_reverse_merge_preserves_distant_successor_and_counters() {
    assert_completion_merge_order([2, 1, 0]).await;
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_recovery_response_digest_tracks_merged_interval_while_marker_replay_is_stable()
{
    let url = pg_url().expect("owned Postgres URL");
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let (_, requests) = completed_marker_fixture(&store, &mut direct, 2).await;
    let key = &requests[0].key;
    direct.execute("UPDATE lore_domain_operation_tombstone_release_completion_markers SET retain_until=clock_timestamp()+interval '5 minutes' WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND sequence=1",
        &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key]).await.unwrap();
    let retained = store
        .domain_operation_terminal_status_attach(&requests[0])
        .await
        .unwrap();
    assert_eq!(
        retained.status,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
    );
    assert_eq!(
        store
            .domain_operation_terminal_status_attach(&requests[0])
            .await
            .unwrap(),
        retained
    );
    direct.execute("UPDATE lore_domain_operation_tombstone_release_completion_markers SET retain_until=clock_timestamp()-interval '1 second' WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND sequence=1",
        &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key]).await.unwrap();
    let singleton = store
        .domain_operation_terminal_status_attach(&requests[0])
        .await
        .unwrap();
    assert_eq!(
        singleton.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    assert_eq!(
        store
            .domain_operation_terminal_status_attach(&requests[0])
            .await
            .unwrap(),
        singleton
    );
    let merged = store
        .domain_operation_terminal_status_attach(&requests[1])
        .await
        .unwrap();
    assert_eq!(
        merged.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    let after_merge = store
        .domain_operation_terminal_status_attach(&requests[0])
        .await
        .unwrap();
    assert_eq!(
        after_merge.status,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery
    );
    assert_ne!(
        after_merge.range, singleton.range,
        "the same exact request now observes the merged interval"
    );
    assert_ne!(
        after_merge.response_digest, singleton.response_digest,
        "post-prune response digest must bind the current interval digest/generation"
    );
    assert_eq!(
        store
            .domain_operation_terminal_status_attach(&requests[0])
            .await
            .unwrap(),
        after_merge
    );
}

#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn materialization_replay_from_retired_epoch_cannot_resurrect_or_charge_new_epoch() {
    let url = pg_url().expect("owned Postgres URL");
    let store = store(&url).await;
    let direct = client(&url).await;
    let namespace = namespace_key();
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let old = materialize_input(namespace.clone(), counter, quota);
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&old)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    assert_eq!(
        store
            .domain_operation_proof_namespace_retire(&retire_input(&old))
            .await
            .unwrap()
            .status,
        ProofNamespaceRetireStatus::Retired
    );
    let (counter, quota) = capacity_pair(&direct).await;
    let new = materialize_input(namespace, counter, quota);
    assert_ne!(new.namespace_epoch, old.namespace_epoch);
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&new)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    let before = domain_rows(&direct).await;
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&old)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Mismatch
    );
    assert_eq!(domain_rows(&direct).await, before);
}

/// The real writer chooses each retention arm once. Only after checking those
/// persisted deadlines do we shorten this fixture's deadline to exercise the
/// reader on either side. This is bounded transition proof, not a live-year wait.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn completion_retention_persists_each_later_of_arm_and_refuses_early_prune() {
    let url = pg_url().expect("owned Postgres URL");
    let store = store(&url).await;
    let mut direct = client(&url).await;
    let clock = store.domain_operation_clock_get().await.unwrap();
    let old = prepare_operation_ready_for_completion(&store, &mut direct, clock, None).await;
    let current = prepare_operation_ready_for_completion(
        &store,
        &mut direct,
        clock + Duration::from_secs(366 * 24 * 60 * 60),
        Some(&old.stale.key),
    )
    .await;
    let namespace = ProofNamespaceKey {
        verified_issuer: old.stale.key.verified_issuer.clone(),
        authenticated_subject: old.stale.key.authenticated_subject.clone(),
        org_uuid: rand::random::<[u8; 16]>().to_vec(),
        tenant_scope_key: old.stale.key.tenant_scope_key.clone(),
    };
    let (counter, quota) = provision_capacity(&direct, &namespace.org_uuid).await;
    let materialize = materialize_input(namespace, counter, quota);
    assert_eq!(
        store
            .domain_operation_proof_namespace_materialize(&materialize)
            .await
            .unwrap()
            .status,
        ProofNamespaceMaterializeStatus::Materialized
    );
    for (ordinal, operation) in [old, current].iter().enumerate() {
        let request =
            completion_request(operation, &materialize.namespace_epoch, ordinal as i64 + 1);
        assert_eq!(
            store
                .domain_operation_terminal_status_attach(&request)
                .await
                .unwrap()
                .status,
            TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
        );
        let key = &request.key;
        let uuid_time =
            lore_postgres::domain::receipts::uuid_v7_timestamp(&key.operation_id).unwrap();
        let row = direct.query_one(
            "SELECT retain_until=GREATEST(created_at+interval '365 days',$5::timestamptz+interval '366 days'), \
             $5::timestamptz+interval '366 days' > created_at+interval '365 days' \
             FROM lore_domain_operation_tombstone_release_completion_markers \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice(), &uuid_time],
        ).await.unwrap();
        assert!(
            row.get::<_, bool>(0),
            "persisted deadline must preserve both 365d and UUID+366d blockers"
        );
        assert_eq!(
            row.get::<_, bool>(1),
            ordinal == 1,
            "each later-of arm must win once"
        );
        direct.execute(
            "UPDATE lore_domain_operation_tombstone_release_completion_markers SET retain_until=clock_timestamp()+interval '5 minutes' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()],
        ).await.unwrap();
        let before = domain_rows(&direct).await;
        assert_eq!(
            store
                .domain_operation_terminal_status_attach(&request)
                .await
                .unwrap()
                .status,
            TerminalStatusAttachStatus::Phase2ReleaseCompletionReady
        );
        assert_eq!(
            domain_rows(&direct).await,
            before,
            "future deadline must preserve the marker and every charge"
        );
        direct.execute(
            "UPDATE lore_domain_operation_tombstone_release_completion_markers \
             SET created_at=clock_timestamp()-interval '2 seconds',retain_until=clock_timestamp()-interval '1 second' \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
            &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()],
        ).await.unwrap();
        assert_eq!(
            store
                .domain_operation_terminal_status_attach(&request)
                .await
                .unwrap()
                .status,
            TerminalStatusAttachStatus::Phase2PostPruneRecovery
        );
    }
}

/// Only this owned test transaction resolves clock_timestamp through a database
/// fixture. The shipped coordinator and database defaults keep their real clock.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn stale_finalize_database_clock_equality_then_one_millisecond_commits_exactly_once() {
    let url = pg_url().expect("owned Postgres URL");
    let _store = store(&url).await;
    let mut direct = client(&url).await;
    direct.batch_execute(
        "CREATE SCHEMA wp115_clock; \
         CREATE TABLE wp115_clock.instant (singleton boolean PRIMARY KEY CHECK(singleton), now timestamptz NOT NULL); \
         CREATE FUNCTION wp115_clock.clock_timestamp() RETURNS timestamptz LANGUAGE SQL VOLATILE \
         AS 'SELECT now FROM wp115_clock.instant WHERE singleton';"
    ).await.unwrap();
    let clock = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    direct
        .execute(
            "INSERT INTO wp115_clock.instant VALUES (true,$1)",
            &[&clock],
        )
        .await
        .unwrap();
    let input = stale_input(clock + Duration::from_secs(24 * 60 * 60));
    assert_eq!(
        lore_postgres::domain::receipts::uuid_v7_timestamp(&input.key.operation_id).unwrap(),
        clock - Duration::from_secs(365 * 24 * 60 * 60)
    );
    let before = domain_rows(&direct).await;
    let tx = direct.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL search_path=wp115_clock,pg_catalog,public")
        .await
        .unwrap();
    assert_eq!(
        admission_clock(&tx).await.unwrap(),
        clock,
        "the unchanged production SQL must resolve the held database clock"
    );
    let equality = lore_postgres::domain::maintenance::verified_stale_finalize(&tx, &input)
        .await
        .unwrap();
    assert_eq!(
        equality.status,
        VerifiedStaleFinalizeStatus::NotEligibleNotStale
    );
    assert_eq!(equality.stale_finalize_clock, Some(clock));
    tx.commit().await.unwrap();
    assert_eq!(
        domain_rows(&direct).await,
        before,
        "equality cannot manufacture any receipt, fence, or charge"
    );

    // Treat the equality reply as lost: retain the exact request and permit,
    // advance only the database fixture clock, and invoke the production body.
    direct
        .execute(
            "UPDATE wp115_clock.instant SET now=now+interval '1 millisecond'",
            &[],
        )
        .await
        .unwrap();
    let later = clock + Duration::from_millis(1);
    let tx = direct.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL search_path=wp115_clock,pg_catalog,public")
        .await
        .unwrap();
    assert_eq!(admission_clock(&tx).await.unwrap(), later);
    let committed = lore_postgres::domain::maintenance::verified_stale_finalize(&tx, &input)
        .await
        .unwrap();
    assert_eq!(committed.status, VerifiedStaleFinalizeStatus::Committed);
    assert_eq!(committed.stale_finalize_clock, Some(later));
    tx.commit().await.unwrap();
    let after_commit = domain_rows(&direct).await;
    let tx = direct.transaction().await.unwrap();
    tx.batch_execute("SET LOCAL search_path=wp115_clock,pg_catalog,public")
        .await
        .unwrap();
    let replay = lore_postgres::domain::maintenance::verified_stale_finalize(&tx, &input)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        replay, committed,
        "same permit and request must replay the original committed bytes"
    );
    assert_eq!(domain_rows(&direct).await, after_commit);
    let count: i64 = direct
        .query_one("SELECT count(*) FROM lore_domain_operation_receipts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let tx = direct.transaction().await.unwrap();
    let real_clock = admission_clock(&tx).await.unwrap();
    tx.rollback().await.unwrap();
    let actual: SystemTime = direct
        .query_one("SELECT pg_catalog.clock_timestamp()", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        actual.duration_since(real_clock).unwrap() < Duration::from_secs(5),
        "SET LOCAL must not leak the fixture clock into later transactions"
    );
}

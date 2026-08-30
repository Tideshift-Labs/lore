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
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::ConsumeResult;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::admission_clock;
use lore_postgres::domain::receipts::commit_terminal;
use lore_postgres::domain::receipts::consume;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

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
        .domain_operation_prepare(&current_key, &stale.binding, Some(&current_witness))
        .await
        .expect("rail prepares the terminal fixture");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("rail terminal fixture must prepare, got {prepared:?}");
    };

    let public_result = b"rail-produced-applied-receipt-v1".to_vec();
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
        &DomainOutcome::Applied,
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
        terminal_outcome: 0,
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

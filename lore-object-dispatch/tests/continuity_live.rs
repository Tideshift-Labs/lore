// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Explicit live contract for a disposable, preprovisioned continuity database.
//!
//! Required environment:
//! - `LORE_TEST_CONTINUITY_PG_URL`: single-DNS-host PostgreSQL URL with `sslmode=require`.
//! - `LORE_TEST_CONTINUITY_ROOT_CA_PEM_PATH`: continuity server root CA PEM file.
//! - `LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH`: boundary client certificate-chain PEM file.
//! - `LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH`: matching boundary private-key PEM file.
//! - `LORE_TEST_CONTINUITY_RECONCILER_PG_URL`: PostgreSQL URL whose login is exactly
//!   `object_dispatch_continuity_reconciler`.
//! - `LORE_TEST_CONTINUITY_RECONCILER_CLIENT_CERT_PEM_PATH`: reconciler certificate-chain PEM.
//! - `LORE_TEST_CONTINUITY_RECONCILER_CLIENT_KEY_PEM_PATH`: matching reconciler private-key PEM.
//! - `LORE_TEST_CONTINUITY_SNAPSHOT_QUOTA_OWNERSHIP_BLAKE3_HEX`: lowercase hex digest
//!   precomputed by disposable setup for policy/boundary from this environment, quota class
//!   `LIVE_TEST`, quotas 1/1/1, cell `live-test-snapshot-cell`, and tenant
//!   `live-test-snapshot-tenant`. Runtime and reconciler roles need no table grants.
//! - `LORE_TEST_CONTINUITY_EPOCH_BOUNDARY_ID`: dedicated one-shot boundary provisioned at epoch 1
//!   with high-water/counters zero, no intents or snapshots, and no epoch namespace at or above 2.
//! - `LORE_TEST_CONTINUITY_NEXT_EPOCH_NAMESPACE_BLAKE3_HEX`: exact lowercase namespace digest for
//!   epoch 2 on that dedicated boundary. The boundary must be rebuilt before rerunning the test.
//! - `LORE_TEST_CONTINUITY_ARCHIVE_BOUNDARY_ID`,
//!   `LORE_TEST_CONTINUITY_ARCHIVE_AUTHORITY_EPOCH`,
//!   `LORE_TEST_CONTINUITY_ARCHIVE_CONTINUITY_SEQ`, and
//!   `LORE_TEST_CONTINUITY_ARCHIVE_TOKEN_ID`: exact identity of one dedicated admin-seeded,
//!   retention-eligible terminal row with released ownership.
//! - `LORE_TEST_CONTINUITY_ARCHIVE_ROW_BLAKE3_HEX`,
//!   `LORE_TEST_CONTINUITY_ARCHIVE_RELEASE_RECEIPT_BLAKE3_HEX`, and
//!   `LORE_TEST_CONTINUITY_ARCHIVE_PROOF_BLAKE3_HEX`: exact lowercase digests for that row, its
//!   canonically validated release receipt, and proof bytes `live-test-archive-proof-v1`.
//! - `LORE_TEST_CONTINUITY_BOUNDARY_ID`: boundary mapped to the certificate login role.
//! - `LORE_TEST_CONTINUITY_AUTHORITY_EPOCH`: active preprovisioned authority epoch.
//! - `LORE_TEST_CONTINUITY_POLICY_REVISION`: installed policy revision for that epoch.
//!
//! Run only against a disposable database:
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_begin_replay_get_and_no_local_effect_cleanup`
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_adjudicates_quarantined_and_ambiguous_intents`
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_records_snapshot_and_releases_bound_ownership`
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_allocates_dedicated_drained_epoch_one_to_two`
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_archives_one_admin_seeded_retention_eligible_detail`

use std::fs;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_object_dispatch::continuity::AllocateEpochRequest;
use lore_object_dispatch::continuity::ArchivePruneRequest;
use lore_object_dispatch::continuity::BeginIntentRequest;
use lore_object_dispatch::continuity::CompleteAdjudicationRequest;
use lore_object_dispatch::continuity::ContinuityAdjudicationKind;
use lore_object_dispatch::continuity::ContinuityClient;
use lore_object_dispatch::continuity::ContinuityEpochState;
use lore_object_dispatch::continuity::ContinuityError;
use lore_object_dispatch::continuity::ContinuityIntentIdentity;
use lore_object_dispatch::continuity::ContinuityIntentKind;
use lore_object_dispatch::continuity::ContinuityOwnershipState;
use lore_object_dispatch::continuity::ContinuityProcedureResult;
use lore_object_dispatch::continuity::ContinuityResultCode;
use lore_object_dispatch::continuity::ContinuityState;
use lore_object_dispatch::continuity::ContinuityTlsConfig;
use lore_object_dispatch::continuity::ContinuityTokenLookup;
use lore_object_dispatch::continuity::CoveredReleaseState;
use lore_object_dispatch::continuity::MarkAmbiguousDispatchRequest;
use lore_object_dispatch::continuity::MarkBoundRequest;
use lore_object_dispatch::continuity::MarkNoLocalEffectRequest;
use lore_object_dispatch::continuity::PrepareAdjudicationRequest;
use lore_object_dispatch::continuity::QuarantinePriorState;
use lore_object_dispatch::continuity::QuarantineRequest;
use lore_object_dispatch::continuity::ReadShadowReleaseReceiptRequest;
use lore_object_dispatch::continuity::ReconciliationState;
use lore_object_dispatch::continuity::RecordSnapshotRequest;
use lore_object_dispatch::continuity::ReleaseShadowOwnershipRequest;
use uuid::Uuid;

fn required_env(name: &'static str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("required live-test environment is missing: {name}"))
}

fn required_pem(name: &'static str) -> String {
    let path = required_env(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read live-test PEM from {name}: {error}"))
}

fn required_blake3_hex(name: &'static str) -> [u8; 32] {
    let value = required_env(name);
    assert_eq!(
        value.len(),
        64,
        "{name} must be exactly 64 lowercase hexadecimal characters"
    );
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{name} must be canonical lowercase hexadecimal text"
    );
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .unwrap_or_else(|_| panic!("{name} must contain only hexadecimal octets"));
    }
    digest
}

fn assert_same_row(left: &ContinuityProcedureResult, right: &ContinuityProcedureResult) {
    assert_eq!(left.state, right.state);
    assert_eq!(left.ownership_state, right.ownership_state);
    assert_eq!(left.authority_epoch, right.authority_epoch);
    assert_eq!(left.continuity_seq, right.continuity_seq);
    assert_eq!(left.continuity_token_id, right.continuity_token_id);
    assert_eq!(left.row_blake3, right.row_blake3);
    assert_eq!(
        left.external_committed_at_unix_ms,
        right.external_committed_at_unix_ms
    );
}

fn require_found(lookup: ContinuityTokenLookup) -> ContinuityProcedureResult {
    match lookup {
        ContinuityTokenLookup::Found(result) => result,
        ContinuityTokenLookup::NotFound { .. } => panic!("expected the continuity token to exist"),
    }
}

fn tls_config(
    url_env: &'static str,
    cert_env: &'static str,
    key_env: &'static str,
) -> ContinuityTlsConfig {
    ContinuityTlsConfig {
        postgres_url: required_env(url_env),
        root_ca_pem: required_pem("LORE_TEST_CONTINUITY_ROOT_CA_PEM_PATH"),
        client_certificate_chain_pem: required_pem(cert_env),
        private_key_pem: required_pem(key_env),
        connect_timeout: Duration::from_secs(10),
    }
}

fn live_begin_request(
    boundary_id: &str,
    authority_epoch: u64,
    policy_revision: &str,
    label: &str,
) -> BeginIntentRequest {
    let continuity_token_id = Uuid::now_v7();
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after the Unix epoch")
        .as_millis();
    let retention_deadline_unix_ms = i64::try_from(now_unix_ms + 86_400_000)
        .expect("live-test retention deadline must fit bigint");
    BeginIntentRequest {
        provider_boundary_id: boundary_id.to_string(),
        expected_authority_epoch: authority_epoch,
        continuity_token_id,
        intent_kind: ContinuityIntentKind::DispatchCas,
        authenticated_cell_id: format!("live-test-{label}-cell-{continuity_token_id}"),
        authenticated_tenant_id: format!("live-test-{label}-tenant-{continuity_token_id}"),
        operation_quota_class: "LIVE_TEST".to_string(),
        logical_request_id: Uuid::now_v7(),
        attempt_id: Uuid::now_v7(),
        selected_fingerprint: [0x61; 32],
        continuity_policy_revision: policy_revision.to_string(),
        quota_bytes: 1,
        quota_rows: 1,
        quota_concurrency: 1,
        retention_deadline_unix_ms,
    }
}

fn intent_identity(
    request: &BeginIntentRequest,
    created: &ContinuityProcedureResult,
) -> ContinuityIntentIdentity {
    ContinuityIntentIdentity {
        provider_boundary_id: request.provider_boundary_id.clone(),
        authority_epoch: created.authority_epoch,
        continuity_seq: created.continuity_seq,
        continuity_token_id: request.continuity_token_id,
        authenticated_cell_id: request.authenticated_cell_id.clone(),
        authenticated_tenant_id: request.authenticated_tenant_id.clone(),
        logical_request_id: request.logical_request_id,
        attempt_id: request.attempt_id,
        intent_kind: request.intent_kind,
        selected_fingerprint: request.selected_fingerprint,
    }
}

async fn assert_reconciler_readback(
    client: &ContinuityClient,
    boundary_id: &str,
    expected: &ContinuityProcedureResult,
) {
    let readback = require_found(
        client
            .get_by_token(boundary_id, expected.continuity_token_id)
            .await
            .expect("the reconciler must read back the transitioned token"),
    );
    assert_eq!(readback.result_code, ContinuityResultCode::Found);
    assert_same_row(expected, &readback);
}

fn require_reconciliation_state(state: Option<ReconciliationState>) -> ReconciliationState {
    state.unwrap_or_else(|| panic!("expected reconciliation state for the active boundary epoch"))
}

fn require_epoch_state(state: Option<ContinuityEpochState>) -> ContinuityEpochState {
    state.unwrap_or_else(|| panic!("expected the active boundary epoch to exist"))
}

#[ignore = "requires a disposable, preprovisioned continuity PostgreSQL database over mTLS"]
#[tokio::test]
async fn live_mtls_begin_replay_get_and_no_local_effect_cleanup() {
    let authority_epoch = required_env("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH")
        .parse::<u64>()
        .expect("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH must be canonical uint64 text");
    assert!(authority_epoch > 0, "authority epoch must be positive");
    let boundary_id = required_env("LORE_TEST_CONTINUITY_BOUNDARY_ID");
    let policy_revision = required_env("LORE_TEST_CONTINUITY_POLICY_REVISION");
    let config = ContinuityTlsConfig {
        postgres_url: required_env("LORE_TEST_CONTINUITY_PG_URL"),
        root_ca_pem: required_pem("LORE_TEST_CONTINUITY_ROOT_CA_PEM_PATH"),
        client_certificate_chain_pem: required_pem("LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH"),
        private_key_pem: required_pem("LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH"),
        connect_timeout: Duration::from_secs(10),
    };
    let client = ContinuityClient::connect(&config)
        .await
        .expect("live continuity mTLS connection must succeed");

    let absent_token = Uuid::now_v7();
    let absent = client
        .get_by_token(&boundary_id, absent_token)
        .await
        .expect("an unknown token must return modeled absence");
    match absent {
        ContinuityTokenLookup::NotFound {
            continuity_token_id,
            observed_at_unix_ms,
        } => {
            assert_eq!(continuity_token_id, absent_token);
            assert!(observed_at_unix_ms >= 0);
        }
        ContinuityTokenLookup::Found(_) => panic!("a fresh random token unexpectedly existed"),
    }

    let continuity_token_id = Uuid::now_v7();
    let logical_request_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after the Unix epoch")
        .as_millis();
    let retention_deadline_unix_ms = i64::try_from(now_unix_ms + 86_400_000)
        .expect("live-test retention deadline must fit bigint");
    let request = BeginIntentRequest {
        provider_boundary_id: boundary_id.clone(),
        expected_authority_epoch: authority_epoch,
        continuity_token_id,
        intent_kind: ContinuityIntentKind::DispatchCas,
        authenticated_cell_id: format!("live-test-cell-{continuity_token_id}"),
        authenticated_tenant_id: format!("live-test-tenant-{continuity_token_id}"),
        operation_quota_class: "LIVE_TEST".to_string(),
        logical_request_id,
        attempt_id,
        selected_fingerprint: [0x31; 32],
        continuity_policy_revision: policy_revision,
        quota_bytes: 1,
        quota_rows: 1,
        quota_concurrency: 1,
        retention_deadline_unix_ms,
    };

    let created = client
        .begin(&request)
        .await
        .expect("first exact begin must create an intent");
    assert_eq!(created.result_code, ContinuityResultCode::Created);
    assert_eq!(created.state, ContinuityState::Intent);
    assert_eq!(
        created.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    assert_eq!(created.continuity_token_id, continuity_token_id);
    assert_eq!(created.authority_epoch, authority_epoch);
    assert!(created.continuity_seq > 0);

    let replay = client
        .begin(&request)
        .await
        .expect("an exact begin replay must succeed");
    assert_eq!(replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&created, &replay);

    let found = require_found(
        client
            .get_by_token(&boundary_id, continuity_token_id)
            .await
            .expect("the created token must be readable through the boundary role"),
    );
    assert_eq!(found.result_code, ContinuityResultCode::Found);
    assert_same_row(&created, &found);

    let cleanup = MarkNoLocalEffectRequest {
        identity: ContinuityIntentIdentity {
            provider_boundary_id: boundary_id.clone(),
            authority_epoch,
            continuity_seq: created.continuity_seq,
            continuity_token_id,
            authenticated_cell_id: request.authenticated_cell_id.clone(),
            authenticated_tenant_id: request.authenticated_tenant_id.clone(),
            logical_request_id,
            attempt_id,
            intent_kind: request.intent_kind,
            selected_fingerprint: request.selected_fingerprint,
        },
        expected_prior_row_blake3: created.row_blake3,
        terminal_evidence_blake3: [0x41; 32],
        release_id: Uuid::now_v7(),
        release_basis_id: format!("live-test-no-local-effect:{continuity_token_id}"),
        release_basis_blake3: [0x51; 32],
    };
    let released = client
        .mark_no_local_effect(&cleanup)
        .await
        .expect("decisive no-local-effect cleanup must release shadow ownership");
    assert_eq!(released.result_code, ContinuityResultCode::Updated);
    assert_eq!(released.state, ContinuityState::NoLocalEffect);
    assert_eq!(
        released.ownership_state,
        ContinuityOwnershipState::OwnershipReleased
    );

    let cleanup_replay = client
        .mark_no_local_effect(&cleanup)
        .await
        .expect("exact cleanup replay must succeed");
    assert_eq!(cleanup_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&released, &cleanup_replay);

    let final_read = require_found(
        client
            .get_by_token(&boundary_id, continuity_token_id)
            .await
            .expect("the released token must remain exactly readable"),
    );
    assert_eq!(final_read.result_code, ContinuityResultCode::Found);
    assert_same_row(&released, &final_read);
}

#[ignore = "requires disposable continuity PostgreSQL with distinct boundary and reconciler mTLS identities"]
#[tokio::test]
async fn live_mtls_reconciler_adjudicates_quarantined_and_ambiguous_intents() {
    let authority_epoch = required_env("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH")
        .parse::<u64>()
        .expect("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH must be canonical uint64 text");
    assert!(authority_epoch > 0, "authority epoch must be positive");
    let boundary_id = required_env("LORE_TEST_CONTINUITY_BOUNDARY_ID");
    let policy_revision = required_env("LORE_TEST_CONTINUITY_POLICY_REVISION");
    let boundary = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_PG_URL",
        "LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("boundary continuity mTLS connection must succeed");
    let reconciler = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_RECONCILER_PG_URL",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("exact reconciler continuity mTLS connection must succeed");

    let no_local_effect_begin = live_begin_request(
        &boundary_id,
        authority_epoch,
        &policy_revision,
        "quarantine",
    );
    let no_local_effect_intent = boundary
        .begin(&no_local_effect_begin)
        .await
        .expect("boundary role must seed the quarantine INTENT");
    assert_eq!(
        no_local_effect_intent.result_code,
        ContinuityResultCode::Created
    );
    assert_eq!(no_local_effect_intent.state, ContinuityState::Intent);
    assert_eq!(
        no_local_effect_intent.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let no_local_effect_intent_replay = boundary
        .begin(&no_local_effect_begin)
        .await
        .expect("exact quarantine INTENT replay must succeed");
    assert_eq!(
        no_local_effect_intent_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_local_effect_intent, &no_local_effect_intent_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_local_effect_intent).await;

    let quarantine_evidence = [0x71; 32];
    let quarantine_request = QuarantineRequest {
        identity: intent_identity(&no_local_effect_begin, &no_local_effect_intent),
        expected_prior_row_blake3: no_local_effect_intent.row_blake3,
        prior_state: QuarantinePriorState::Intent,
        terminal_evidence_blake3: quarantine_evidence,
    };
    let quarantined = reconciler
        .quarantine(&quarantine_request)
        .await
        .expect("reconciler must quarantine the exact INTENT");
    assert_eq!(quarantined.result_code, ContinuityResultCode::Updated);
    assert_eq!(quarantined.state, ContinuityState::Quarantined);
    assert_eq!(
        quarantined.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let quarantined_replay = reconciler
        .quarantine(&quarantine_request)
        .await
        .expect("exact quarantine replay must succeed");
    assert_eq!(quarantined_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&quarantined, &quarantined_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &quarantined).await;

    let prepare_no_local_effect = PrepareAdjudicationRequest {
        identity: intent_identity(&no_local_effect_begin, &no_local_effect_intent),
        expected_prior_row_blake3: quarantined.row_blake3,
        adjudication_kind: ContinuityAdjudicationKind::NoLocalEffect,
        local_binding_blake3: None,
        terminal_evidence_blake3: quarantine_evidence,
    };
    let no_local_effect_prepared = reconciler
        .prepare_adjudication(&prepare_no_local_effect)
        .await
        .expect("reconciler must prepare NO_LOCAL_EFFECT adjudication");
    assert_eq!(
        no_local_effect_prepared.result_code,
        ContinuityResultCode::Updated
    );
    assert_eq!(
        no_local_effect_prepared.state,
        ContinuityState::AdjudicationPrepared
    );
    assert_eq!(
        no_local_effect_prepared.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let no_local_effect_prepare_replay = reconciler
        .prepare_adjudication(&prepare_no_local_effect)
        .await
        .expect("exact NO_LOCAL_EFFECT prepare replay must succeed");
    assert_eq!(
        no_local_effect_prepare_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_local_effect_prepared, &no_local_effect_prepare_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_local_effect_prepared).await;

    let complete_no_local_effect = CompleteAdjudicationRequest {
        identity: intent_identity(&no_local_effect_begin, &no_local_effect_intent),
        expected_prior_row_blake3: no_local_effect_prepared.row_blake3,
        adjudication_kind: ContinuityAdjudicationKind::NoLocalEffect,
        local_binding_blake3: None,
        terminal_evidence_blake3: quarantine_evidence,
        release_id: Uuid::now_v7(),
        release_basis_id: format!(
            "live-test-final-no-local-effect:{}",
            no_local_effect_begin.continuity_token_id
        ),
        release_basis_blake3: [0x72; 32],
    };
    let no_local_effect_completed = reconciler
        .complete_adjudication(&complete_no_local_effect)
        .await
        .expect("reconciler must complete NO_LOCAL_EFFECT adjudication");
    assert_eq!(
        no_local_effect_completed.result_code,
        ContinuityResultCode::Updated
    );
    assert_eq!(
        no_local_effect_completed.state,
        ContinuityState::AdjudicatedNoLocalEffect
    );
    assert_eq!(
        no_local_effect_completed.ownership_state,
        ContinuityOwnershipState::OwnershipReleased
    );
    let no_local_effect_complete_replay = reconciler
        .complete_adjudication(&complete_no_local_effect)
        .await
        .expect("exact NO_LOCAL_EFFECT completion replay must succeed");
    assert_eq!(
        no_local_effect_complete_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_local_effect_completed, &no_local_effect_complete_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_local_effect_completed).await;
    let no_local_effect_final_begin_replay = boundary
        .begin(&no_local_effect_begin)
        .await
        .expect("original begin must replay the final NO_LOCAL_EFFECT adjudication row");
    assert_eq!(
        no_local_effect_final_begin_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(
        &no_local_effect_completed,
        &no_local_effect_final_begin_replay,
    );
    assert_reconciler_readback(
        &reconciler,
        &boundary_id,
        &no_local_effect_final_begin_replay,
    )
    .await;

    let no_dispatch_begin =
        live_begin_request(&boundary_id, authority_epoch, &policy_revision, "ambiguous");
    let no_dispatch_intent = boundary
        .begin(&no_dispatch_begin)
        .await
        .expect("boundary role must seed the ambiguity INTENT");
    assert_eq!(
        no_dispatch_intent.result_code,
        ContinuityResultCode::Created
    );
    assert_eq!(no_dispatch_intent.state, ContinuityState::Intent);
    assert_eq!(
        no_dispatch_intent.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let no_dispatch_intent_replay = boundary
        .begin(&no_dispatch_begin)
        .await
        .expect("exact ambiguity INTENT replay must succeed");
    assert_eq!(
        no_dispatch_intent_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_dispatch_intent, &no_dispatch_intent_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_dispatch_intent).await;
    let local_binding_blake3 = [0x81; 32];
    let mark_bound = MarkBoundRequest {
        identity: intent_identity(&no_dispatch_begin, &no_dispatch_intent),
        expected_prior_row_blake3: no_dispatch_intent.row_blake3,
        local_binding_blake3,
    };
    let bound = boundary
        .mark_bound(&mark_bound)
        .await
        .expect("boundary role must seed the exact BOUND state");
    assert_eq!(bound.result_code, ContinuityResultCode::Updated);
    assert_eq!(bound.state, ContinuityState::Bound);
    assert_eq!(
        bound.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let bound_replay = boundary
        .mark_bound(&mark_bound)
        .await
        .expect("exact BOUND replay must succeed");
    assert_eq!(bound_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&bound, &bound_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &bound).await;

    let ambiguity_evidence = [0x82; 32];
    let mark_ambiguous = MarkAmbiguousDispatchRequest {
        identity: intent_identity(&no_dispatch_begin, &no_dispatch_intent),
        expected_prior_row_blake3: bound.row_blake3,
        local_binding_blake3,
        terminal_evidence_blake3: ambiguity_evidence,
    };
    let ambiguous = reconciler
        .mark_ambiguous_dispatch(&mark_ambiguous)
        .await
        .expect("reconciler must mark the exact BOUND dispatch ambiguous");
    assert_eq!(ambiguous.result_code, ContinuityResultCode::Updated);
    assert_eq!(ambiguous.state, ContinuityState::AmbiguousDispatch);
    assert_eq!(
        ambiguous.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let ambiguous_replay = reconciler
        .mark_ambiguous_dispatch(&mark_ambiguous)
        .await
        .expect("exact ambiguous-dispatch replay must succeed");
    assert_eq!(ambiguous_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&ambiguous, &ambiguous_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &ambiguous).await;

    let prepare_no_dispatch = PrepareAdjudicationRequest {
        identity: intent_identity(&no_dispatch_begin, &no_dispatch_intent),
        expected_prior_row_blake3: ambiguous.row_blake3,
        adjudication_kind: ContinuityAdjudicationKind::NoDispatch,
        local_binding_blake3: Some(local_binding_blake3),
        terminal_evidence_blake3: ambiguity_evidence,
    };
    let no_dispatch_prepared = reconciler
        .prepare_adjudication(&prepare_no_dispatch)
        .await
        .expect("reconciler must prepare NO_DISPATCH adjudication");
    assert_eq!(
        no_dispatch_prepared.result_code,
        ContinuityResultCode::Updated
    );
    assert_eq!(
        no_dispatch_prepared.state,
        ContinuityState::AdjudicationPrepared
    );
    assert_eq!(
        no_dispatch_prepared.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    let no_dispatch_prepare_replay = reconciler
        .prepare_adjudication(&prepare_no_dispatch)
        .await
        .expect("exact NO_DISPATCH prepare replay must succeed");
    assert_eq!(
        no_dispatch_prepare_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_dispatch_prepared, &no_dispatch_prepare_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_dispatch_prepared).await;

    let complete_no_dispatch = CompleteAdjudicationRequest {
        identity: intent_identity(&no_dispatch_begin, &no_dispatch_intent),
        expected_prior_row_blake3: no_dispatch_prepared.row_blake3,
        adjudication_kind: ContinuityAdjudicationKind::NoDispatch,
        local_binding_blake3: Some(local_binding_blake3),
        terminal_evidence_blake3: ambiguity_evidence,
        release_id: Uuid::now_v7(),
        release_basis_id: format!(
            "live-test-final-no-dispatch:{}",
            no_dispatch_begin.continuity_token_id
        ),
        release_basis_blake3: [0x83; 32],
    };
    let no_dispatch_completed = reconciler
        .complete_adjudication(&complete_no_dispatch)
        .await
        .expect("reconciler must complete NO_DISPATCH adjudication");
    assert_eq!(
        no_dispatch_completed.result_code,
        ContinuityResultCode::Updated
    );
    assert_eq!(
        no_dispatch_completed.state,
        ContinuityState::AdjudicatedNoDispatch
    );
    assert_eq!(
        no_dispatch_completed.ownership_state,
        ContinuityOwnershipState::OwnershipReleased
    );
    let no_dispatch_complete_replay = reconciler
        .complete_adjudication(&complete_no_dispatch)
        .await
        .expect("exact NO_DISPATCH completion replay must succeed");
    assert_eq!(
        no_dispatch_complete_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_dispatch_completed, &no_dispatch_complete_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_dispatch_completed).await;
    let no_dispatch_final_begin_replay = boundary
        .begin(&no_dispatch_begin)
        .await
        .expect("original begin must replay the final NO_DISPATCH adjudication row");
    assert_eq!(
        no_dispatch_final_begin_replay.result_code,
        ContinuityResultCode::Replay
    );
    assert_same_row(&no_dispatch_completed, &no_dispatch_final_begin_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &no_dispatch_final_begin_replay).await;
}

#[ignore = "requires disposable continuity PostgreSQL, boundary/reconciler mTLS, and an admin-precomputed ownership digest"]
#[tokio::test]
async fn live_mtls_reconciler_records_snapshot_and_releases_bound_ownership() {
    let authority_epoch = required_env("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH")
        .parse::<u64>()
        .expect("LORE_TEST_CONTINUITY_AUTHORITY_EPOCH must be canonical uint64 text");
    assert!(authority_epoch > 0, "authority epoch must be positive");
    let boundary_id = required_env("LORE_TEST_CONTINUITY_BOUNDARY_ID");
    let policy_revision = required_env("LORE_TEST_CONTINUITY_POLICY_REVISION");
    let local_quota_ownership_blake3 =
        required_blake3_hex("LORE_TEST_CONTINUITY_SNAPSHOT_QUOTA_OWNERSHIP_BLAKE3_HEX");
    let boundary = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_PG_URL",
        "LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("boundary continuity mTLS connection must succeed");
    let reconciler = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_RECONCILER_PG_URL",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("exact reconciler continuity mTLS connection must succeed");

    let mut begin_request =
        live_begin_request(&boundary_id, authority_epoch, &policy_revision, "snapshot");
    begin_request.authenticated_cell_id = "live-test-snapshot-cell".to_string();
    begin_request.authenticated_tenant_id = "live-test-snapshot-tenant".to_string();
    let intent = boundary
        .begin(&begin_request)
        .await
        .expect("boundary role must seed the snapshot INTENT");
    assert_eq!(intent.result_code, ContinuityResultCode::Created);
    assert_eq!(intent.state, ContinuityState::Intent);
    assert_eq!(
        intent.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );

    let local_binding_blake3 = [0x91; 32];
    let mark_bound = MarkBoundRequest {
        identity: intent_identity(&begin_request, &intent),
        expected_prior_row_blake3: intent.row_blake3,
        local_binding_blake3,
    };
    let bound = boundary
        .mark_bound(&mark_bound)
        .await
        .expect("boundary role must seed the snapshot BOUND state");
    assert_eq!(bound.result_code, ContinuityResultCode::Updated);
    assert_eq!(bound.state, ContinuityState::Bound);
    assert_eq!(
        bound.ownership_state,
        ContinuityOwnershipState::ShadowReserved
    );
    assert_reconciler_readback(&reconciler, &boundary_id, &bound).await;

    let epoch_before = require_epoch_state(
        reconciler
            .read_epoch(&boundary_id)
            .await
            .expect("reconciler epoch read must succeed"),
    );
    assert_eq!(epoch_before.authority_epoch, authority_epoch);
    assert!(
        epoch_before.continuity_seq_high_water >= bound.continuity_seq,
        "epoch high-water must cover the BOUND token"
    );
    let reconciliation_before = require_reconciliation_state(
        reconciler
            .read_reconciliation_state(&boundary_id, authority_epoch)
            .await
            .expect("reconciler state read before snapshot must succeed"),
    );
    assert_eq!(
        reconciliation_before.current_authority_epoch,
        authority_epoch
    );
    assert_eq!(
        reconciliation_before.continuity_seq_high_water,
        epoch_before.continuity_seq_high_water
    );
    assert!(reconciliation_before.owned_rows >= 1);
    assert!(reconciliation_before.owned_bytes >= 1);
    assert!(reconciliation_before.owned_concurrency >= 1);

    let snapshot_request = RecordSnapshotRequest {
        snapshot_id: Uuid::now_v7(),
        provider_boundary_id: boundary_id.clone(),
        authority_epoch,
        through_continuity_seq: epoch_before.continuity_seq_high_water,
        // PostgreSQL's active WAL position is necessarily above 0/1 after cluster bootstrap.
        // A nonzero value discriminates the u64-to-pg_lsn encoding seam without coupling the
        // contract probe to an additional privileged WAL-read API.
        authority_lsn: 1,
        manifest_blake3: [0x92; 32],
        continuity_seq: bound.continuity_seq,
        continuity_token_id: bound.continuity_token_id,
        local_binding_blake3,
        local_state_blake3: [0x93; 32],
        local_quota_ownership_blake3,
        local_counter_revision: 1,
    };
    let snapshot = reconciler
        .record_snapshot(&snapshot_request)
        .await
        .expect("reconciler must record exact BOUND snapshot coverage");
    assert_eq!(snapshot.accepted_snapshot_id, snapshot_request.snapshot_id);
    assert_eq!(
        snapshot.accepted_through_continuity_seq,
        snapshot_request.through_continuity_seq
    );
    assert_eq!(
        snapshot.accepted_manifest_blake3,
        snapshot_request.manifest_blake3
    );
    assert_ne!(snapshot.accepted_coverage_blake3, [0; 32]);
    assert!(snapshot.recorded_at_unix_ms >= 0);
    let snapshot_replay = reconciler
        .record_snapshot(&snapshot_request)
        .await
        .expect("exact snapshot replay must succeed");
    assert_eq!(snapshot_replay, snapshot);

    let reconciliation_with_snapshot = require_reconciliation_state(
        reconciler
            .read_reconciliation_state(&boundary_id, authority_epoch)
            .await
            .expect("reconciler state read after snapshot must succeed"),
    );
    assert_eq!(
        reconciliation_with_snapshot.current_authority_epoch,
        authority_epoch
    );
    assert_eq!(
        reconciliation_with_snapshot.continuity_seq_high_water,
        reconciliation_before.continuity_seq_high_water
    );
    assert_eq!(
        reconciliation_with_snapshot.owned_rows,
        reconciliation_before.owned_rows
    );
    assert_eq!(
        reconciliation_with_snapshot.owned_bytes,
        reconciliation_before.owned_bytes
    );
    assert_eq!(
        reconciliation_with_snapshot.owned_concurrency,
        reconciliation_before.owned_concurrency
    );
    let latest_snapshot = reconciliation_with_snapshot
        .latest_snapshot
        .as_ref()
        .expect("the recorded snapshot must become the latest snapshot");
    assert_eq!(latest_snapshot.snapshot_id, snapshot.accepted_snapshot_id);
    assert_eq!(
        latest_snapshot.through_continuity_seq,
        snapshot.accepted_through_continuity_seq
    );
    assert_eq!(
        latest_snapshot.manifest_blake3,
        snapshot.accepted_manifest_blake3
    );

    let release_request = ReleaseShadowOwnershipRequest {
        identity: intent_identity(&begin_request, &intent),
        expected_prior_row_blake3: bound.row_blake3,
        expected_state: CoveredReleaseState::Bound,
        snapshot_id: snapshot.accepted_snapshot_id,
        expected_manifest_blake3: snapshot.accepted_manifest_blake3,
        expected_coverage_blake3: snapshot.accepted_coverage_blake3,
        release_id: Uuid::now_v7(),
    };
    let released = reconciler
        .release_shadow_ownership(&release_request)
        .await
        .expect("covered BOUND snapshot must release shadow ownership");
    assert_eq!(released.result_code, ContinuityResultCode::Updated);
    assert_eq!(released.state, ContinuityState::Bound);
    assert_eq!(
        released.ownership_state,
        ContinuityOwnershipState::OwnershipReleased
    );
    let release_replay = reconciler
        .release_shadow_ownership(&release_request)
        .await
        .expect("exact covered BOUND release replay must succeed");
    assert_eq!(release_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&released, &release_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &released).await;

    let receipt_request = ReadShadowReleaseReceiptRequest {
        provider_boundary_id: boundary_id.clone(),
        authority_epoch: released.authority_epoch,
        continuity_seq: released.continuity_seq,
        continuity_token_id: released.continuity_token_id,
    };
    let receipt = reconciler
        .read_shadow_release_receipt(&receipt_request)
        .await
        .expect("reconciler must read and canonically validate the exact release receipt")
        .expect("the released BOUND row must have one release receipt");
    assert_eq!(
        receipt.provider_boundary_id,
        receipt_request.provider_boundary_id
    );
    assert_eq!(receipt.authority_epoch, receipt_request.authority_epoch);
    assert_eq!(receipt.continuity_seq, receipt_request.continuity_seq);
    assert_eq!(
        receipt.continuity_token_id,
        receipt_request.continuity_token_id
    );
    assert_eq!(receipt.release_id, release_request.release_id);
    assert_ne!(receipt.receipt_blake3, [0; 32]);
    assert_eq!(
        receipt.released_at_unix_ms, released.external_committed_at_unix_ms,
        "the receipt and released row must identify the same committed release"
    );

    let receipt_after_replay = reconciler
        .read_shadow_release_receipt(&receipt_request)
        .await
        .expect("receipt readback after exact release replay must succeed")
        .expect("exact release replay must preserve the receipt");
    assert_eq!(receipt_after_replay, receipt);

    for absent_identity in [
        ReadShadowReleaseReceiptRequest {
            provider_boundary_id: format!("{boundary_id}-mismatch"),
            authority_epoch: receipt_request.authority_epoch,
            continuity_seq: receipt_request.continuity_seq,
            continuity_token_id: receipt_request.continuity_token_id,
        },
        ReadShadowReleaseReceiptRequest {
            provider_boundary_id: boundary_id.clone(),
            authority_epoch: receipt_request.authority_epoch,
            continuity_seq: receipt_request
                .continuity_seq
                .checked_add(1)
                .expect("live sequence must leave room for an isolation probe"),
            continuity_token_id: receipt_request.continuity_token_id,
        },
        ReadShadowReleaseReceiptRequest {
            provider_boundary_id: boundary_id.clone(),
            authority_epoch: receipt_request.authority_epoch,
            continuity_seq: receipt_request.continuity_seq,
            continuity_token_id: Uuid::now_v7(),
        },
    ] {
        assert_eq!(
            reconciler
                .read_shadow_release_receipt(&absent_identity)
                .await
                .expect("mismatched receipt identity must return typed absence"),
            None,
            "one mismatched identity component must not disclose another receipt"
        );
    }

    let boundary_receipt_error = boundary
        .read_shadow_release_receipt(&receipt_request)
        .await
        .expect_err("boundary runtime identity must not execute the reconciler receipt read");
    assert!(matches!(
        boundary_receipt_error,
        ContinuityError::Postgres { transient: false }
    ));

    let begin_replay = boundary
        .begin(&begin_request)
        .await
        .expect("original begin must replay the released BOUND row");
    assert_eq!(begin_replay.result_code, ContinuityResultCode::Replay);
    assert_same_row(&released, &begin_replay);
    assert_reconciler_readback(&reconciler, &boundary_id, &begin_replay).await;

    let reconciliation_after = require_reconciliation_state(
        reconciler
            .read_reconciliation_state(&boundary_id, authority_epoch)
            .await
            .expect("reconciler state read after release must succeed"),
    );
    assert_eq!(
        reconciliation_after.continuity_seq_high_water,
        reconciliation_before.continuity_seq_high_water
    );
    assert_eq!(
        reconciliation_after.owned_rows,
        reconciliation_before
            .owned_rows
            .checked_sub(1)
            .expect("seeded ownership must make the row counter positive")
    );
    assert_eq!(
        reconciliation_after.owned_bytes,
        reconciliation_before
            .owned_bytes
            .checked_sub(1)
            .expect("seeded ownership must make the byte counter positive")
    );
    assert_eq!(
        reconciliation_after.owned_concurrency,
        reconciliation_before
            .owned_concurrency
            .checked_sub(1)
            .expect("seeded ownership must make the concurrency counter positive")
    );
    assert_eq!(
        reconciliation_after.latest_snapshot,
        reconciliation_with_snapshot.latest_snapshot
    );
    let epoch_after = require_epoch_state(
        reconciler
            .read_epoch(&boundary_id)
            .await
            .expect("reconciler epoch read after release must succeed"),
    );
    assert_eq!(epoch_after, epoch_before);
}

#[ignore = "requires a disposable, dedicated, one-shot drained epoch-1 boundary over reconciler mTLS"]
#[tokio::test]
async fn live_mtls_reconciler_allocates_dedicated_drained_epoch_one_to_two() {
    let boundary_id = required_env("LORE_TEST_CONTINUITY_EPOCH_BOUNDARY_ID");
    let next_epoch_namespace_blake3 =
        required_blake3_hex("LORE_TEST_CONTINUITY_NEXT_EPOCH_NAMESPACE_BLAKE3_HEX");
    let reconciler = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_RECONCILER_PG_URL",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("exact reconciler continuity mTLS connection must succeed");

    let epoch_one = require_epoch_state(
        reconciler
            .read_epoch(&boundary_id)
            .await
            .expect("dedicated boundary epoch read must succeed"),
    );
    assert_eq!(
        epoch_one,
        ContinuityEpochState {
            authority_epoch: 1,
            continuity_seq_high_water: 0,
        },
        "epoch allocation fixture must start as a fresh drained epoch 1"
    );
    let reconciliation_one = require_reconciliation_state(
        reconciler
            .read_reconciliation_state(&boundary_id, 1)
            .await
            .expect("epoch-1 reconciliation read must succeed before allocation"),
    );
    assert_eq!(reconciliation_one.current_authority_epoch, 1);
    assert_eq!(reconciliation_one.continuity_seq_high_water, 0);
    assert_eq!(reconciliation_one.owned_rows, 0);
    assert_eq!(reconciliation_one.owned_bytes, 0);
    assert_eq!(reconciliation_one.owned_concurrency, 0);
    assert_eq!(reconciliation_one.latest_snapshot, None);

    let allocation_request = AllocateEpochRequest {
        provider_boundary_id: boundary_id.clone(),
        expected_current_epoch: 1,
        next_epoch: 2,
        epoch_namespace_blake3: next_epoch_namespace_blake3,
    };
    assert_eq!(
        allocation_request.epoch_namespace_blake3,
        next_epoch_namespace_blake3
    );
    let allocated = reconciler
        .allocate_epoch(&allocation_request)
        .await
        .expect("reconciler must allocate drained epoch 1 to epoch 2");
    assert_eq!(
        allocated,
        ContinuityEpochState {
            authority_epoch: 2,
            continuity_seq_high_water: 0,
        }
    );

    let epoch_two = require_epoch_state(
        reconciler
            .read_epoch(&boundary_id)
            .await
            .expect("current epoch read must succeed after allocation"),
    );
    assert_eq!(epoch_two, allocated);
    let reconciliation_two = require_reconciliation_state(
        reconciler
            .read_reconciliation_state(&boundary_id, 2)
            .await
            .expect("epoch-2 reconciliation read must succeed after allocation"),
    );
    assert_eq!(reconciliation_two.current_authority_epoch, 2);
    assert_eq!(reconciliation_two.continuity_seq_high_water, 0);
    assert_eq!(reconciliation_two.owned_rows, 0);
    assert_eq!(reconciliation_two.owned_bytes, 0);
    assert_eq!(reconciliation_two.owned_concurrency, 0);
    assert_eq!(reconciliation_two.latest_snapshot, None);

    let old_epoch_reconciliation = reconciler
        .read_reconciliation_state(&boundary_id, 1)
        .await
        .expect("old-epoch reconciliation query must return modeled absence");
    assert_eq!(
        old_epoch_reconciliation, None,
        "the current read surface deliberately exposes reconciliation state only for the active epoch"
    );

    let exact_replay_error = reconciler
        .allocate_epoch(&allocation_request)
        .await
        .expect_err("epoch allocation has CAS failure semantics, not successful replay semantics");
    assert!(matches!(
        exact_replay_error,
        ContinuityError::Postgres { transient: true }
    ));

    let invalid_order = AllocateEpochRequest {
        provider_boundary_id: boundary_id,
        expected_current_epoch: 2,
        next_epoch: 2,
        epoch_namespace_blake3: next_epoch_namespace_blake3,
    };
    let invalid_order_error = reconciler
        .allocate_epoch(&invalid_order)
        .await
        .expect_err("next epoch equal to current must fail before database access");
    assert!(matches!(
        invalid_order_error,
        ContinuityError::InvalidConfiguration(
            "epoch allocation identity and ordering must be valid"
        )
    ));
}

#[ignore = "requires a disposable, dedicated, admin-seeded retention-eligible archive fixture over mTLS"]
#[tokio::test]
async fn live_mtls_reconciler_archives_one_admin_seeded_retention_eligible_detail() {
    const ARCHIVE_PROOF_BYTES: &[u8] = b"live-test-archive-proof-v1";

    let boundary_id = required_env("LORE_TEST_CONTINUITY_ARCHIVE_BOUNDARY_ID");
    let authority_epoch = required_env("LORE_TEST_CONTINUITY_ARCHIVE_AUTHORITY_EPOCH")
        .parse::<u64>()
        .expect("LORE_TEST_CONTINUITY_ARCHIVE_AUTHORITY_EPOCH must be uint64 text");
    let continuity_seq = required_env("LORE_TEST_CONTINUITY_ARCHIVE_CONTINUITY_SEQ")
        .parse::<u64>()
        .expect("LORE_TEST_CONTINUITY_ARCHIVE_CONTINUITY_SEQ must be uint64 text");
    let continuity_token_id = required_env("LORE_TEST_CONTINUITY_ARCHIVE_TOKEN_ID")
        .parse::<Uuid>()
        .expect("LORE_TEST_CONTINUITY_ARCHIVE_TOKEN_ID must be a UUID");
    let expected_row_blake3 = required_blake3_hex("LORE_TEST_CONTINUITY_ARCHIVE_ROW_BLAKE3_HEX");
    let expected_release_receipt_blake3 =
        required_blake3_hex("LORE_TEST_CONTINUITY_ARCHIVE_RELEASE_RECEIPT_BLAKE3_HEX");
    let archive_proof_blake3 = required_blake3_hex("LORE_TEST_CONTINUITY_ARCHIVE_PROOF_BLAKE3_HEX");
    assert!(authority_epoch > 0, "archive epoch must be positive");
    assert!(continuity_seq > 0, "archive sequence must be positive");

    let reconciler = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_RECONCILER_PG_URL",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_RECONCILER_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("exact reconciler continuity mTLS connection must succeed");
    let boundary = ContinuityClient::connect(&tls_config(
        "LORE_TEST_CONTINUITY_PG_URL",
        "LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH",
        "LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH",
    ))
    .await
    .expect("exact boundary continuity mTLS connection must succeed");

    let seeded = require_found(
        reconciler
            .get_by_token(&boundary_id, continuity_token_id)
            .await
            .expect("reconciler must read the admin-seeded archive fixture"),
    );
    assert_eq!(seeded.authority_epoch, authority_epoch);
    assert_eq!(seeded.continuity_seq, continuity_seq);
    assert_eq!(seeded.continuity_token_id, continuity_token_id);
    assert_eq!(seeded.row_blake3, expected_row_blake3);

    let request = ArchivePruneRequest {
        provider_boundary_id: boundary_id.clone(),
        authority_epoch,
        continuity_seq,
        continuity_token_id,
        expected_row_blake3,
        expected_release_receipt_blake3,
        archive_proof_bytes: ARCHIVE_PROOF_BYTES.to_vec(),
        archive_proof_blake3,
    };
    let boundary_error = boundary
        .archive_prune(&request)
        .await
        .expect_err("boundary runtime identity must not execute reconciler archive/prune");
    assert!(matches!(
        boundary_error,
        ContinuityError::Postgres { transient: false }
    ));

    let archived = reconciler
        .archive_prune(&request)
        .await
        .expect("reconciler must archive the exact retention-eligible detail");
    assert_eq!(archived.accepted_start_sequence, continuity_seq);
    assert_eq!(archived.accepted_end_sequence, continuity_seq);
    assert_eq!(archived.accepted_row_count, 1);
    assert_eq!(archived.prune_commit_sequence, 1);
    assert_ne!(archived.accepted_interval_blake3, [0; 32]);

    let lookup_after_archive = reconciler
        .get_by_token(&boundary_id, continuity_token_id)
        .await
        .expect("archived detail lookup must return modeled absence");
    assert!(matches!(
        lookup_after_archive,
        ContinuityTokenLookup::NotFound {
            continuity_token_id: missing_token,
            ..
        } if missing_token == continuity_token_id
    ));
}

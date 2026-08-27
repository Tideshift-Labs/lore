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
//! - `LORE_TEST_CONTINUITY_BOUNDARY_ID`: boundary mapped to the certificate login role.
//! - `LORE_TEST_CONTINUITY_AUTHORITY_EPOCH`: active preprovisioned authority epoch.
//! - `LORE_TEST_CONTINUITY_POLICY_REVISION`: installed policy revision for that epoch.
//!
//! Run only against a disposable database:
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_begin_replay_get_and_no_local_effect_cleanup`
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_reconciler_adjudicates_quarantined_and_ambiguous_intents`

use std::fs;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_object_dispatch::continuity::BeginIntentRequest;
use lore_object_dispatch::continuity::CompleteAdjudicationRequest;
use lore_object_dispatch::continuity::ContinuityAdjudicationKind;
use lore_object_dispatch::continuity::ContinuityClient;
use lore_object_dispatch::continuity::ContinuityIntentIdentity;
use lore_object_dispatch::continuity::ContinuityIntentKind;
use lore_object_dispatch::continuity::ContinuityOwnershipState;
use lore_object_dispatch::continuity::ContinuityProcedureResult;
use lore_object_dispatch::continuity::ContinuityResultCode;
use lore_object_dispatch::continuity::ContinuityState;
use lore_object_dispatch::continuity::ContinuityTlsConfig;
use lore_object_dispatch::continuity::ContinuityTokenLookup;
use lore_object_dispatch::continuity::MarkAmbiguousDispatchRequest;
use lore_object_dispatch::continuity::MarkBoundRequest;
use lore_object_dispatch::continuity::MarkNoLocalEffectRequest;
use lore_object_dispatch::continuity::PrepareAdjudicationRequest;
use lore_object_dispatch::continuity::QuarantinePriorState;
use lore_object_dispatch::continuity::QuarantineRequest;
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

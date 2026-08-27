// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Explicit live contract for a disposable, preprovisioned continuity database.
//!
//! Required environment:
//! - `LORE_TEST_CONTINUITY_PG_URL`: single-DNS-host PostgreSQL URL with `sslmode=require`.
//! - `LORE_TEST_CONTINUITY_ROOT_CA_PEM_PATH`: continuity server root CA PEM file.
//! - `LORE_TEST_CONTINUITY_CLIENT_CERT_PEM_PATH`: boundary client certificate-chain PEM file.
//! - `LORE_TEST_CONTINUITY_CLIENT_KEY_PEM_PATH`: matching boundary private-key PEM file.
//! - `LORE_TEST_CONTINUITY_BOUNDARY_ID`: boundary mapped to the certificate login role.
//! - `LORE_TEST_CONTINUITY_AUTHORITY_EPOCH`: active preprovisioned authority epoch.
//! - `LORE_TEST_CONTINUITY_POLICY_REVISION`: installed policy revision for that epoch.
//!
//! Run only against a disposable database:
//! `cargo test -p lore-object-dispatch --test continuity_live -- --ignored --exact live_mtls_begin_replay_get_and_no_local_effect_cleanup`

use std::fs;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_object_dispatch::continuity::BeginIntentRequest;
use lore_object_dispatch::continuity::ContinuityClient;
use lore_object_dispatch::continuity::ContinuityIntentIdentity;
use lore_object_dispatch::continuity::ContinuityIntentKind;
use lore_object_dispatch::continuity::ContinuityOwnershipState;
use lore_object_dispatch::continuity::ContinuityProcedureResult;
use lore_object_dispatch::continuity::ContinuityResultCode;
use lore_object_dispatch::continuity::ContinuityState;
use lore_object_dispatch::continuity::ContinuityTlsConfig;
use lore_object_dispatch::continuity::ContinuityTokenLookup;
use lore_object_dispatch::continuity::MarkNoLocalEffectRequest;
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

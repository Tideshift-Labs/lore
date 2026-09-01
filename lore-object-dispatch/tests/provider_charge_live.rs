// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live PostgreSQL 16 evidence for WP-114 CD-4's shared cell-local limiter.

use std::env;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::PostgresProviderChargeAuthority;
use lore_object_dispatch::PostgresProviderChargeConfig;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptLedger;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;
use tokio_postgres::Client;
use tokio_postgres::IsolationLevel;
use tokio_postgres::NoTls;
use tokio_postgres::error::SqlState;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const MIGRATION_0002: &str =
    include_str!("../migrations/0002_object_store_retention_authority.sql");
const MIGRATION_0003: &str =
    include_str!("../migrations/0003_object_store_retention_provisioning.sql");
const MIGRATION_0007: &str =
    include_str!("../migrations/0007_object_store_dispatch_authority_core.sql");
const MIGRATION_0008: &str =
    include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql");
const MIGRATION_0009: &str =
    include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql");
const MIGRATION_0010: &str =
    include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql");
const MIGRATION_0011: &str =
    include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql");
const MIGRATION_0012: &str =
    include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql");
const MIGRATION_0013: &str =
    include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql");
const MIGRATION_0014: &str =
    include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql");
const MIGRATION_0015: &str =
    include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql");
const MIGRATION_0016: &str =
    include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql");
const MIGRATION_0017: &str =
    include_str!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql");
const MIGRATION_0018: &str =
    include_str!("../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql");
const MIGRATION_0019: &str =
    include_str!("../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql");
const MIGRATION_0020: &str =
    include_str!("../migrations/0020_object_store_dispatch_dispatcher_registration.sql");
const MIGRATION_0021: &str =
    include_str!("../migrations/0021_object_store_dispatch_budget_limiter_schema.sql");
const MIGRATION_0022: &str =
    include_str!("../migrations/0022_object_store_dispatch_budget_limiter_provisioning.sql");

const BOUNDARY: &str = "cell.test.shared-budget";
const REVISION: &str = "Budget.Rev_1-a";
const FENCE: u64 = 1;
const INTERVAL_MS: u64 = 1_000_000_000;

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_last_unit_charges_are_atomic_and_fail_closed() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;

    set_available(&admin, 1, 1).await;
    set_available(&admin, 2, 1).await;
    let (first, second) = competing_charges(&url, 1, 1).await;
    assert_eq!(sorted(&first, &second), ["BUDGET_EXHAUSTED", "GRANTED"]);
    assert_eq!(grant_count(&admin).await, 1);

    reset_grants(&admin).await;
    set_available(&admin, 1, 2).await;
    set_available(&admin, 2, 1).await;
    let (first, second) = competing_charges(&url, 1, 1).await;
    assert_eq!(sorted(&first, &second), ["CLASS_CAP_EXHAUSTED", "GRANTED"]);
    assert_eq!(grant_count(&admin).await, 1);

    reset_grants(&admin).await;
    set_available(&admin, 1, 1).await;
    set_available(&admin, 2, 0).await;
    let before = bucket_state(&admin, 1).await;
    let refusal = charge(
        &url,
        1,
        1,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    )
    .await;
    assert_eq!(refusal, "CLASS_CAP_EXHAUSTED");
    assert_eq!(
        bucket_state(&admin, 1).await,
        before,
        "shared debit must roll back"
    );
    assert_eq!(grant_count(&admin).await, 0);

    set_available(&admin, 1, 2).await;
    set_available(&admin, 2, 2).await;
    set_available(&admin, 7, 0).await;
    let shared_before_listing_refusal = bucket_state(&admin, 1).await;
    let listing = charge(
        &url,
        1,
        9,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    )
    .await;
    assert_eq!(listing, "CLASS_CAP_EXHAUSTED");
    assert_eq!(
        bucket_state(&admin, 1).await,
        shared_before_listing_refusal,
        "a listing-cap refusal must not partially debit the shared bucket"
    );
    assert_eq!(grant_count(&admin).await, 0);

    set_available(&admin, 1, 2).await;
    set_available(&admin, 2, 2).await;
    set_available(&admin, 7, 1).await;
    let shared_before_listing_race = bucket_state(&admin, 1).await;
    let (first, second) = competing_charges(&url, 1, 9).await;
    assert_eq!(sorted(&first, &second), ["CLASS_CAP_EXHAUSTED", "GRANTED"]);
    let shared_after_listing_race = bucket_state(&admin, 1).await;
    assert_eq!(
        shared_after_listing_race.1,
        shared_before_listing_race.1 + 1,
        "only the winning listing charge may update the shared bucket"
    );
    assert_eq!(grant_count(&admin).await, 1);
    reset_grants(&admin).await;

    let deadline = charge(&url, 1, 1, Uuid::now_v7(), Uuid::now_v7(), 0).await;
    assert_eq!(deadline, "DEADLINE_EXCEEDED");
    let database_now: i64 = admin
        .query_one("SELECT object_store_retention.clock_unix_ms_v1()", &[])
        .await
        .expect("read database clock for deadline bound")
        .get(0);
    assert_eq!(
        charge(
            &url,
            1,
            1,
            Uuid::now_v7(),
            Uuid::now_v7(),
            database_now + 600_000,
        )
        .await,
        "DEADLINE_EXCEEDED"
    );

    let logical_request_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    let valid_deadline = future_deadline();
    assert_eq!(
        charge(&url, 1, 1, logical_request_id, attempt_id, valid_deadline,).await,
        "GRANTED"
    );
    let (durable_grant_id, granted_at) = grant_record(&admin, logical_request_id, attempt_id).await;
    assert_ne!(durable_grant_id, attempt_id);
    assert_eq!(durable_grant_id.get_version_num(), 7);
    assert!(granted_at < valid_deadline);
    assert_eq!(
        charge(
            &url,
            1,
            1,
            logical_request_id,
            attempt_id,
            future_deadline(),
        )
        .await,
        "ATTEMPT_ALREADY_CHARGED"
    );
    assert_eq!(
        charge_with_pin(
            &url,
            1,
            1,
            Uuid::now_v7(),
            Uuid::now_v7(),
            future_deadline(),
            "other-revision",
            FENCE,
        )
        .await,
        "BUDGET_PIN_REJECTED"
    );
    reset_grants(&admin).await;

    admin
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_caps \
             SET refill_units = 18446744073709551615, refill_interval_ms = 1 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND cap_class = 1; \
             UPDATE object_store_retention.object_dispatch_budget_bucket_state \
             SET available_scaled = 0, updated_at_unix_ms = 0 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND cap_class = 1; \
             UPDATE object_store_retention.object_dispatch_budget_configurations \
             SET cap_budgets = jsonb_set(jsonb_set(cap_budgets, '{{0,refillUnits}}', \
                 '18446744073709551615'::jsonb), '{{0,refillIntervalMs}}', '1'::jsonb) \
             WHERE provider_boundary_id = '{BOUNDARY}';"
        ))
        .await
        .expect("install arithmetic-edge fixture");
    let overflow = charge(
        &url,
        1,
        1,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    )
    .await;
    assert_eq!(overflow, "CONFIGURATION_UNRESOLVED");
    assert_eq!(grant_count(&admin).await, 0);

    admin
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_configurations \
             SET cap_budgets = '{{}}'::jsonb \
             WHERE provider_boundary_id = '{BOUNDARY}'"
        ))
        .await
        .expect("install malformed stored JSON fixture");
    let malformed = charge(
        &url,
        1,
        1,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    )
    .await;
    assert_eq!(malformed, "CONFIGURATION_UNRESOLVED");
    assert_eq!(grant_count(&admin).await, 0);
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_frozen_revision_grammar_and_idempotent_publication_replay() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;

    let invalid_first = connect(&url).await;
    let error = invalid_first
        .batch_execute(&first_publication_sql(i64::MAX, 2))
        .await
        .expect_err("a first publication must use fence one");
    assert_eq!(error.code(), Some(&SqlState::INVALID_PARAMETER_VALUE));
    drop(invalid_first);

    for accepted in ["a", "0", "A0._-z", &"x".repeat(128)] {
        admin
            .query_one(
                "SELECT object_store_retention.assert_dispatch_budget_revision_v1($1)",
                &[&accepted],
            )
            .await
            .unwrap_or_else(|error| panic!("accepted revision {accepted:?}: {error:?}"));
    }
    for rejected in [
        "",
        ".leading",
        "-leading",
        "_leading",
        "a@b",
        "a b",
        "é",
        &"x".repeat(129),
    ] {
        let error = admin
            .query_one(
                "SELECT object_store_retention.assert_dispatch_budget_revision_v1($1)",
                &[&rejected],
            )
            .await
            .expect_err("invalid revision must be rejected");
        assert_eq!(error.code(), Some(&SqlState::INVALID_PARAMETER_VALUE));
    }
    let null_revision: Option<&str> = None;
    admin
        .query_one(
            "SELECT object_store_retention.assert_dispatch_budget_revision_v1($1)",
            &[&null_revision],
        )
        .await
        .expect("NULL means no optional revision token and must remain accepted");
    seed_configuration(&admin).await;
    seed_configuration(&admin).await;
    assert_eq!(
        charge_with_pin(
            &url,
            1,
            1,
            Uuid::now_v7(),
            Uuid::now_v7(),
            future_deadline(),
            "budget.Rev_1-a",
            FENCE,
        )
        .await,
        "BUDGET_PIN_REJECTED",
        "revision pins compare byte-for-byte without case folding or normalization"
    );
    let count: i64 = admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_budget_configurations",
            &[],
        )
        .await
        .expect("count replayed configurations")
        .get(0);
    assert_eq!(
        count, 1,
        "an exact replay must not create a second configuration"
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_charge_refuses_a_non_serializable_caller() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;
    let caller = connect(&url).await;
    caller
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_runtime")
        .await
        .expect("assume runtime fixture identity");
    let sql = charge_sql(
        1,
        1,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
        REVISION,
        FENCE,
    );

    let error = caller
        .query_one(&sql, &[])
        .await
        .expect_err("READ COMMITTED caller must be refused before charging");

    assert_eq!(error.code(), Some(&SqlState::INVALID_TRANSACTION_STATE));
    assert_eq!(grant_count(&admin).await, 0);
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_successor_fence_and_stage3_publication_matrix() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;

    set_available(&admin, 1, 1).await;
    assert_eq!(
        publish_successor(&admin, "Budget.Rev_2", 2, SuccessorMutation::None).await,
        Ok("PUBLISHED".to_string())
    );
    let carried_available = bucket_available_at(&admin, "Budget.Rev_2", 2, 1)
        .await
        .parse::<u64>()
        .expect("scaled availability fits u64");
    assert!(
        (INTERVAL_MS..3 * INTERVAL_MS).contains(&carried_available),
        "rotation must carry consumed capacity, allowing only elapsed refill: {carried_available}"
    );
    assert!(
        publish_successor(&admin, REVISION, 3, SuccessorMutation::None)
            .await
            .is_err(),
        "a revision token cannot be reused after an intervening configuration"
    );
    admin
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_configurations \
             SET disposition_revision = 2 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND allocation_fence = 1"
        ))
        .await
        .expect("corrupt predecessor disposition revision");
    assert_eq!(
        charge_with_pin(
            &url,
            1,
            1,
            Uuid::now_v7(),
            Uuid::now_v7(),
            future_deadline(),
            "Budget.Rev_2",
            2,
        )
        .await,
        "CONFIGURATION_UNRESOLVED",
        "a successor must resolve its predecessor disposition revision as exact prior-plus-one"
    );
    admin
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_configurations \
             SET disposition_revision = 1 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND allocation_fence = 1"
        ))
        .await
        .expect("restore predecessor disposition revision");
    for (label, revision, fence, mutation) in [
        ("repeat", "Budget.Repeat", 2, SuccessorMutation::None),
        ("regress", "Budget.Regress", 1, SuccessorMutation::None),
        ("skip", "Budget.Skip", 4, SuccessorMutation::None),
        (
            "target identity",
            "Budget.Target",
            3,
            SuccessorMutation::TargetIdentity,
        ),
        (
            "target revision agreement",
            "Budget.TargetRev",
            3,
            SuccessorMutation::TargetRevision,
        ),
        (
            "disposition target kind",
            "Budget.DispKind",
            3,
            SuccessorMutation::DispositionTargetKind,
        ),
        (
            "disposition target id",
            "Budget.DispId",
            3,
            SuccessorMutation::DispositionTargetId,
        ),
        (
            "envelope target kind",
            "Budget.EnvKind",
            3,
            SuccessorMutation::EnvelopeTargetKind,
        ),
        (
            "envelope target id",
            "Budget.EnvId",
            3,
            SuccessorMutation::EnvelopeTargetId,
        ),
        (
            "envelope target revision",
            "Budget.EnvRev",
            3,
            SuccessorMutation::EnvelopeTargetRevision,
        ),
        (
            "cache completeness",
            "Budget.Cache",
            3,
            SuccessorMutation::CacheCompleteness,
        ),
        (
            "predecessor chain",
            "Budget.Pred",
            3,
            SuccessorMutation::Predecessor,
        ),
        (
            "head digest chain",
            "Budget.Head",
            3,
            SuccessorMutation::HeadDigest,
        ),
    ] {
        assert!(
            publish_successor(&admin, revision, fence, mutation)
                .await
                .is_err(),
            "{label} publication must fail closed"
        );
    }
    assert_eq!(
        publish_successor(&admin, "Budget.Rev_3", 3, SuccessorMutation::None).await,
        Ok("PUBLISHED".to_string())
    );
    install_max_fence_head(&admin).await;
    assert!(
        publish_successor(&admin, "Budget.Wrap", 0, SuccessorMutation::None)
            .await
            .is_err(),
        "u64::MAX must not wrap to fence zero"
    );
}

async fn install_max_fence_head(client: &Client) {
    client
        .batch_execute(&format!(
            "INSERT INTO object_store_retention.object_dispatch_budget_configurations \
             SELECT (jsonb_populate_record(\
               NULL::object_store_retention.object_dispatch_budget_configurations,\
               to_jsonb(c) || jsonb_build_object(\
                 'allocation_revision', 'Budget.Max',\
                 'allocation_fence', 18446744073709551615::numeric,\
                 'disposition_id', '{new_id}'\
               )\
             )).* FROM object_store_retention.object_dispatch_budget_configurations c \
             WHERE c.provider_boundary_id = '{BOUNDARY}' AND c.allocation_fence = 3;\
             INSERT INTO object_store_retention.object_dispatch_budget_dimensions \
             SELECT (jsonb_populate_record(\
               NULL::object_store_retention.object_dispatch_budget_dimensions,\
               to_jsonb(d) || jsonb_build_object(\
                 'allocation_revision', 'Budget.Max',\
                 'allocation_fence', 18446744073709551615::numeric\
               )\
             )).* FROM object_store_retention.object_dispatch_budget_dimensions d \
             WHERE d.provider_boundary_id = '{BOUNDARY}' AND d.allocation_fence = 3;\
             INSERT INTO object_store_retention.object_dispatch_budget_caps \
             SELECT (jsonb_populate_record(\
               NULL::object_store_retention.object_dispatch_budget_caps,\
               to_jsonb(c) || jsonb_build_object(\
                 'allocation_revision', 'Budget.Max',\
                 'allocation_fence', 18446744073709551615::numeric\
               )\
             )).* FROM object_store_retention.object_dispatch_budget_caps c \
             WHERE c.provider_boundary_id = '{BOUNDARY}' AND c.allocation_fence = 3;\
             UPDATE object_store_retention.object_dispatch_current_budget_configuration \
             SET allocation_revision = 'Budget.Max', allocation_fence = 18446744073709551615 \
             WHERE provider_boundary_id = '{BOUNDARY}';",
            new_id = Uuid::now_v7(),
        ))
        .await
        .expect("install unreachable max-fence fixture");
}

#[derive(Clone, Copy)]
enum SuccessorMutation {
    None,
    TargetIdentity,
    TargetRevision,
    DispositionTargetKind,
    DispositionTargetId,
    EnvelopeTargetKind,
    EnvelopeTargetId,
    EnvelopeTargetRevision,
    CacheCompleteness,
    Predecessor,
    HeadDigest,
}

async fn publish_successor(
    client: &Client,
    revision: &str,
    fence: u64,
    mutation: SuccessorMutation,
) -> Result<String, String> {
    let target_id = if matches!(mutation, SuccessorMutation::TargetIdentity) {
        "different-target"
    } else {
        "target"
    };
    let disposition_target_revision = if matches!(mutation, SuccessorMutation::TargetRevision) {
        "c.target_revision + 2"
    } else {
        "c.target_revision + 1"
    };
    let disposition_target_kind = if matches!(mutation, SuccessorMutation::DispositionTargetKind) {
        "2::smallint"
    } else {
        "c.target_kind"
    };
    let disposition_target_id = if matches!(mutation, SuccessorMutation::DispositionTargetId) {
        "'different-disposition-target'"
    } else {
        "c.target_id"
    };
    let envelope_target_kind = if matches!(mutation, SuccessorMutation::EnvelopeTargetKind) {
        "2::smallint"
    } else {
        "c.target_kind"
    };
    let envelope_target_id = if matches!(mutation, SuccessorMutation::EnvelopeTargetId) {
        "'different-envelope-target'"
    } else {
        "c.target_id"
    };
    let envelope_target_revision = if matches!(mutation, SuccessorMutation::EnvelopeTargetRevision)
    {
        "c.target_revision + 2"
    } else {
        "c.target_revision + 1"
    };
    let dimensions = if matches!(mutation, SuccessorMutation::CacheCompleteness) {
        "jsonb_set(c.dimensions, '{0,cacheEffect}', '1'::jsonb)"
    } else {
        "c.dimensions"
    };
    let predecessor = if matches!(mutation, SuccessorMutation::Predecessor) {
        "NULL::uuid"
    } else {
        "c.disposition_id"
    };
    let head_digest = if matches!(mutation, SuccessorMutation::HeadDigest) {
        "decode(repeat('99',32),'hex')"
    } else {
        "c.envelope_record_digest"
    };
    let sql = format!(
        "SELECT (object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
          'object-store-dispatch-budget-limiter-v1', c.provider_boundary_id, '{revision}',\
          {fence}::bigint::object_store_retention.uint64, c.hard_expires_at_unix_ms,\
          c.core_schema_revision, c.disposition_schema_revision, c.envelope_schema_revision,\
          c.target_kind, '{target_id}', c.target_revision + 1,\
          {disposition_target_kind}, {disposition_target_id}, {disposition_target_revision},\
          {envelope_target_kind}, {envelope_target_id}, {envelope_target_revision},\
          c.cell_id, c.cell_id, c.provider_boundary_id,\
          c.provider_boundary_id, c.provider_allocation_set_revision,\
          c.provider_allocation_set_revision, c.provider_allocation_set_revision,\
          c.provider_allocation_set_fence, c.provider_allocation_set_fence,\
          c.provider_allocation_set_fence, c.core_record_digest, '{new_id}'::uuid,\
          decode(repeat('55',32),'hex'), c.core_record_digest, c.disposition_revision + 1,\
          {predecessor}, c.disposition_record_digest, c.envelope_revision, {head_digest},\
          decode(repeat('66',32),'hex'), c.core_record_digest, decode(repeat('55',32),'hex'),\
          c.final_budget_vector_digest, c.envelope_revision + 1, c.disposition,\
          c.cache_implementation_package_path, c.cache_implementation_revision,\
          c.cache_proof_digest, c.cache_effect_vector_digest, c.final_budget_vector_digest,\
          {dimensions}, c.cap_budgets)).result_code \
         FROM object_store_retention.object_dispatch_current_budget_configuration current_config \
         JOIN object_store_retention.object_dispatch_budget_configurations c \
           USING (provider_boundary_id, allocation_revision, allocation_fence) \
         WHERE current_config.provider_boundary_id = '{BOUNDARY}'",
        new_id = Uuid::now_v7(),
    );
    client
        .batch_execute(
            "GRANT SELECT ON object_store_retention.object_dispatch_current_budget_configuration, \
             object_store_retention.object_dispatch_budget_configurations \
             TO object_dispatch_retention_maintenance",
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    client
        .batch_execute(
            "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; \
             BEGIN ISOLATION LEVEL SERIALIZABLE",
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
    match client.query_one(&sql, &[]).await {
        Ok(row) => {
            let result = row.get(0);
            client
                .batch_execute(
                    "COMMIT; RESET SESSION AUTHORIZATION; \
                     REVOKE SELECT ON \
                       object_store_retention.object_dispatch_current_budget_configuration, \
                       object_store_retention.object_dispatch_budget_configurations \
                     FROM object_dispatch_retention_maintenance",
                )
                .await
                .map_err(|error| format!("{error:?}"))?;
            Ok(result)
        }
        Err(error) => {
            let _ = client
                .batch_execute(
                    "ROLLBACK; RESET SESSION AUTHORIZATION; \
                     REVOKE SELECT ON \
                       object_store_retention.object_dispatch_current_budget_configuration, \
                       object_store_retention.object_dispatch_budget_configurations \
                     FROM object_dispatch_retention_maintenance",
                )
                .await;
            Err(format!("{error:?}; SQL: {sql}"))
        }
    }
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_expired_exact_publication_replays_but_charge_fails_closed() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    let database_now: i64 = admin
        .query_one("SELECT object_store_retention.clock_unix_ms_v1()", &[])
        .await
        .expect("read database clock")
        .get(0);
    let expiry = database_now + 100;
    seed_configuration_with_expiry(&admin, expiry).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    seed_configuration_with_expiry(&admin, expiry).await;
    assert_eq!(
        charge(
            &url,
            1,
            1,
            Uuid::now_v7(),
            Uuid::now_v7(),
            future_deadline(),
        )
        .await,
        "CONFIGURATION_UNRESOLVED"
    );
    assert_eq!(grant_count(&admin).await, 0);
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_missing_malformed_and_stage3_inconsistent_configs_fail_closed() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;

    let cases = [
        (
            "missing current pin",
            format!(
                "DELETE FROM object_store_retention.object_dispatch_current_budget_configuration WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "INSERT INTO object_store_retention.object_dispatch_current_budget_configuration VALUES ('{BOUNDARY}', '{REVISION}', {FENCE})"
            ),
        ),
        (
            "malformed stored cap JSON",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET cap_budgets = '{{}}'::jsonb WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET cap_budgets = '{}'::jsonb WHERE provider_boundary_id = '{BOUNDARY}'",
                cap_json()
            ),
        ),
        (
            "class-2 schema revision mismatch",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET core_schema_revision = 'wrong' WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET core_schema_revision = 'object-store-frozen-capacity-budget-core-v1' WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
        ),
        (
            "class-3 digest-chain mismatch",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET envelope_core_digest = decode(repeat('99',32),'hex') WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET envelope_core_digest = core_record_digest WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
        ),
        (
            "class-3 headroom identity mismatch",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_dimensions SET pre_cache_headroom = pre_cache_headroom + 1 WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_dimensions SET pre_cache_headroom = effective_bound - measured_load - target_demand - failure_reserve WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
        ),
        (
            "stored target projection mismatch",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET disposition_target_id = 'different-target' WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET disposition_target_id = target_id WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
        ),
        (
            "stored history projection mismatch",
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET expected_prior_head_revision = 1 WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
            format!(
                "UPDATE object_store_retention.object_dispatch_budget_configurations SET expected_prior_head_revision = 0 WHERE provider_boundary_id = '{BOUNDARY}'"
            ),
        ),
    ];

    for (label, corrupt, restore) in cases {
        admin
            .batch_execute(&corrupt)
            .await
            .unwrap_or_else(|error| panic!("install {label}: {error}"));
        assert_eq!(
            charge(
                &url,
                1,
                1,
                Uuid::now_v7(),
                Uuid::now_v7(),
                future_deadline(),
            )
            .await,
            "CONFIGURATION_UNRESOLVED",
            "case: {label}"
        );
        assert_eq!(grant_count(&admin).await, 0, "case: {label}");
        admin
            .batch_execute(&restore)
            .await
            .unwrap_or_else(|error| panic!("restore {label}: {error}"));
    }
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cd5_charge_before_send_conformance_and_authority_unavailable() {
    let url = env::var("LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL")
        .expect("runner must set LORE_TEST_PROVIDER_CHARGE_ATOMICITY_PG_URL");
    let admin = connect(&url).await;
    install(&admin).await;
    seed_configuration(&admin).await;

    let LiveDatabase {
        client: authority_client,
        _connection: authority_connection,
    } = connect(&url).await;
    authority_client
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_runtime")
        .await
        .expect("assume runtime fixture identity");
    let authority = PostgresProviderChargeAuthority::new(
        authority_client,
        PostgresProviderChargeConfig {
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(5),
        },
    )
    .expect("construct real PostgreSQL charge authority");
    let transport_calls = Arc::new(AtomicU32::new(0));
    let client = GovernedProviderClient::new(
        live_boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        authority,
        CountingTransport(transport_calls.clone()),
    );

    set_available(&admin, 1, 0).await;
    let refused = live_request(Uuid::now_v7(), Uuid::now_v7());
    let mut refused_ledger = ProviderAttemptLedger::new(BOUNDARY, &refused.logical_request_id)
        .expect("construct refused ledger");
    assert_eq!(
        client.execute(&mut refused_ledger, &refused).await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::BudgetExhausted
        ))
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 0);
    assert_eq!(refused_ledger.committed_grant_count(), 0);

    set_available(&admin, 1, 1).await;
    set_available(&admin, 2, 1).await;
    let granted = live_request(Uuid::now_v7(), Uuid::now_v7());
    let mut granted_ledger = ProviderAttemptLedger::new(BOUNDARY, &granted.logical_request_id)
        .expect("construct granted ledger");
    assert_eq!(
        client.execute(&mut granted_ledger, &granted).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(granted_ledger.committed_grant_count(), 1);
    assert_eq!(granted_ledger.attempt_count(), 1);
    assert_eq!(
        client.execute(&mut granted_ledger, &granted).await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::AttemptAlreadyCharged
        ))
    );
    assert_eq!(granted_ledger.committed_grant_count(), 1);
    assert_eq!(granted_ledger.attempt_count(), 1);

    let mut duplicate_ledger = ProviderAttemptLedger::new(BOUNDARY, &granted.logical_request_id)
        .expect("construct duplicate-attempt ledger");
    assert_eq!(
        client.execute(&mut duplicate_ledger, &granted).await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::AttemptAlreadyCharged
        ))
    );
    assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(duplicate_ledger.committed_grant_count(), 0);
    assert_eq!(duplicate_ledger.attempt_count(), 0);
    drop(authority_connection);

    let LiveDatabase {
        client: dead_client,
        _connection: dead_connection,
    } = connect(&url).await;
    dead_client
        .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_runtime")
        .await
        .expect("assume runtime fixture identity");
    let backend_pid: i32 = dead_client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("read authority backend pid")
        .get(0);
    admin
        .execute("SELECT pg_terminate_backend($1)", &[&backend_pid])
        .await
        .expect("terminate authority backend");
    let dead_authority = PostgresProviderChargeAuthority::new(
        dead_client,
        PostgresProviderChargeConfig {
            statement_timeout: Duration::from_secs(1),
            lock_timeout: Duration::from_secs(1),
        },
    )
    .expect("construct terminated authority");
    let dead_calls = Arc::new(AtomicU32::new(0));
    let dead_governed = GovernedProviderClient::new(
        live_boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        dead_authority,
        CountingTransport(dead_calls.clone()),
    );
    let unavailable = live_request(Uuid::now_v7(), Uuid::now_v7());
    let mut unavailable_ledger =
        ProviderAttemptLedger::new(BOUNDARY, &unavailable.logical_request_id)
            .expect("construct unavailable ledger");
    assert_eq!(
        dead_governed
            .execute(&mut unavailable_ledger, &unavailable)
            .await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::AuthorityUnavailable
        ))
    );
    assert_eq!(dead_calls.load(Ordering::SeqCst), 0);
    assert_eq!(unavailable_ledger.committed_grant_count(), 0);
    drop(dead_connection);
}

struct CountingTransport(Arc<AtomicU32>);

impl ProviderTransport for CountingTransport {
    fn issue(
        &self,
        _attempt: &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
        })
    }
}

fn live_boundary() -> CellProviderBoundary {
    CellProviderBoundary::new(BOUNDARY, "fixture-bucket", "test-1", "objects.test.invalid")
        .expect("construct live provider boundary")
}

fn live_request(logical_request_id: Uuid, attempt_id: Uuid) -> ProviderAttemptRequest {
    ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Drain,
        attempt_class: ProviderAttemptClass::Readiness,
        target: live_boundary().target().clone(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: future_deadline(),
        budget_pin: BudgetPin {
            revision: REVISION.to_string(),
            fence: FENCE,
        },
        put_body: None,
        put_part: None,
    }
}

struct LiveDatabase {
    client: Client,
    _connection: AbortOnDropHandle<()>,
}

impl Deref for LiveDatabase {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for LiveDatabase {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

async fn connect(url: &str) -> LiveDatabase {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let handle =
        AbortOnDropHandle::new(lore_base::lore_spawn!("provider-charge-live", async move {
            let _ = connection.await;
        }));
    LiveDatabase {
        client,
        _connection: handle,
    }
}

async fn install(client: &Client) {
    client
        .batch_execute(
            "DO $$ BEGIN \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance NOLOGIN; END IF; \
             IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator NOLOGIN; END IF; \
             END $$;",
        )
        .await
        .expect("create fixture roles");
    for migration in [
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0007,
        MIGRATION_0008,
        MIGRATION_0009,
        MIGRATION_0010,
        MIGRATION_0011,
        MIGRATION_0012,
        MIGRATION_0013,
        MIGRATION_0014,
        MIGRATION_0015,
        MIGRATION_0016,
        MIGRATION_0017,
        MIGRATION_0018,
        MIGRATION_0019,
        MIGRATION_0020,
        MIGRATION_0021,
        MIGRATION_0022,
    ] {
        client
            .batch_execute(migration)
            .await
            .expect("install migration");
    }
}

async fn seed_configuration(client: &Client) {
    seed_configuration_with_expiry(client, i64::MAX).await;
}

async fn seed_configuration_with_expiry(client: &Client, hard_expiry: i64) {
    let sql = first_publication_sql(hard_expiry, FENCE);
    client
        .batch_execute(&sql)
        .await
        .expect("publish resolved configuration");
}

fn first_publication_sql(hard_expiry: i64, allocation_fence: u64) -> String {
    let caps = cap_json();
    format!(
        "SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;\
         BEGIN ISOLATION LEVEL SERIALIZABLE;\
         SELECT object_store_retention.object_store_dispatch_publish_budget_configuration_v1(\
           'object-store-dispatch-budget-limiter-v1', '{BOUNDARY}', '{REVISION}',\
           {allocation_fence}::bigint::object_store_retention.uint64,\
           {hard_expiry}, 'object-store-frozen-capacity-budget-core-v1',\
           'object-store-exact-target-cache-disposition-v1',\
           'object-store-budget-frozen-envelope-v1', 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 1::smallint, 'target',\
           1::bigint::object_store_retention.uint64, 'cell-test', 'cell-test', '{BOUNDARY}',\
           '{BOUNDARY}', 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, 1::bigint::object_store_retention.uint64,\
           1::bigint::object_store_retention.uint64, decode(repeat('11',32),'hex'),\
           '018f3e12-a456-7abc-8def-000000000001'::uuid, decode(repeat('22',32),'hex'),\
           decode(repeat('11',32),'hex'), 1::bigint::object_store_retention.uint64,\
           NULL::uuid, NULL::bytea, 0::bigint::object_store_retention.uint64, NULL::bytea,\
           decode(repeat('33',32),'hex'), decode(repeat('11',32),'hex'),\
           decode(repeat('22',32),'hex'), decode(repeat('44',32),'hex'),\
           1::bigint::object_store_retention.uint64, 1::smallint,\
           NULL::text, NULL::text, NULL::bytea, NULL::bytea, decode(repeat('44',32),'hex'),\
           '[{{\"dimensionId\":\"all\",\"effectiveBound\":10,\"measuredLoad\":1,\"targetDemand\":1,\"failureReserve\":1,\"preCacheHeadroom\":7,\"finalBudget\":7}}]'::jsonb,\
           '{caps}'::jsonb);\
         COMMIT; RESET SESSION AUTHORIZATION;"
    )
}

fn cap_json() -> String {
    (1..=7)
        .map(|class| {
            let capacity = if class == 1 { 3 } else if class == 7 { 1 } else { 2 };
            format!(
                "{{\"capClass\":{class},\"capacityUnits\":{capacity},\"refillUnits\":{capacity},\"refillIntervalMs\":{INTERVAL_MS}}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",")
        .pipe(|entries| format!("[{entries}]"))
}

async fn competing_charges(url: &str, traffic_class: i16, attempt_class: i16) -> (String, String) {
    let first = charge(
        url,
        traffic_class,
        attempt_class,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    );
    let second = charge(
        url,
        traffic_class,
        attempt_class,
        Uuid::now_v7(),
        Uuid::now_v7(),
        future_deadline(),
    );
    tokio::join!(first, second)
}

async fn charge(
    url: &str,
    traffic_class: i16,
    attempt_class: i16,
    logical_request_id: Uuid,
    attempt_id: Uuid,
    deadline: i64,
) -> String {
    charge_with_pin(
        url,
        traffic_class,
        attempt_class,
        logical_request_id,
        attempt_id,
        deadline,
        REVISION,
        FENCE,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn charge_with_pin(
    url: &str,
    traffic_class: i16,
    attempt_class: i16,
    logical_request_id: Uuid,
    attempt_id: Uuid,
    deadline: i64,
    revision: &str,
    fence: u64,
) -> String {
    let sql = charge_sql(
        traffic_class,
        attempt_class,
        logical_request_id,
        attempt_id,
        deadline,
        revision,
        fence,
    );
    for retry in 0..3 {
        let mut client = connect(url).await;
        client
            .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_runtime")
            .await
            .expect("assume runtime fixture identity");
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .expect("start charge transaction");
        match transaction.query_one(&sql, &[]).await {
            Ok(row) => {
                let result: String = row.get(0);
                transaction
                    .commit()
                    .await
                    .expect("commit decisive charge result");
                return result;
            }
            Err(error)
                if retry < 2 && error.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => {}
            Err(error) => panic!("execute charge: {error:?}"),
        }
    }
    unreachable!("bounded retry loop always returns or panics")
}

#[allow(clippy::too_many_arguments)]
fn charge_sql(
    traffic_class: i16,
    attempt_class: i16,
    logical_request_id: Uuid,
    attempt_id: Uuid,
    deadline: i64,
    revision: &str,
    fence: u64,
) -> String {
    let caps = if matches!(attempt_class, 9 | 10) {
        "ARRAY[1,2,7]::smallint[]"
    } else {
        "ARRAY[1,2]::smallint[]"
    };
    format!(
        "SELECT (object_store_retention.object_store_dispatch_charge_provider_attempt_v1(\
         'object-store-dispatch-budget-limiter-v1', '{BOUNDARY}', {traffic_class}::smallint,\
         {attempt_class}::smallint, 1::bigint::object_store_retention.uint64, '{revision}',\
         {fence}::bigint::object_store_retention.uint64, '{logical_request_id}'::uuid,\
         '{attempt_id}'::uuid, 1, {deadline}::bigint, {caps})).result_code"
    )
}

async fn set_available(client: &Client, cap_class: i16, units: u64) {
    client
        .batch_execute(&format!(
            "UPDATE object_store_retention.object_dispatch_budget_bucket_state SET \
             available_scaled = {units} * {INTERVAL_MS}, \
             updated_at_unix_ms = object_store_retention.clock_unix_ms_v1(), \
             state_revision = state_revision + 1 \
             WHERE provider_boundary_id = '{BOUNDARY}' AND cap_class = {cap_class};"
        ))
        .await
        .expect("set bucket availability");
}

async fn bucket_state(client: &Client, cap_class: i16) -> (String, i64) {
    let row = client
        .query_one(
            "SELECT available_scaled::text, state_revision::bigint FROM \
             object_store_retention.object_dispatch_budget_bucket_state \
             WHERE provider_boundary_id = $1 AND cap_class = $2",
            &[&BOUNDARY, &cap_class],
        )
        .await
        .expect("read bucket state");
    (row.get(0), row.get(1))
}

async fn bucket_available_at(
    client: &Client,
    revision: &str,
    fence: u64,
    cap_class: i16,
) -> String {
    client
        .query_one(
            "SELECT available_scaled::text FROM \
             object_store_retention.object_dispatch_budget_bucket_state \
             WHERE provider_boundary_id = $1 AND allocation_revision = $2 \
               AND allocation_fence = $3::bigint::object_store_retention.uint64 \
               AND cap_class = $4",
            &[
                &BOUNDARY,
                &revision,
                &i64::try_from(fence).expect("fixture fence fits i64"),
                &cap_class,
            ],
        )
        .await
        .expect("read exact rotated bucket state")
        .get(0)
}

async fn reset_grants(client: &Client) {
    client
        .batch_execute("TRUNCATE object_store_retention.object_dispatch_provider_charge_grants")
        .await
        .expect("reset grants between independent cases");
}

async fn grant_count(client: &Client) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .expect("count grants")
        .get(0)
}

async fn grant_record(client: &Client, logical_request_id: Uuid, attempt_id: Uuid) -> (Uuid, i64) {
    let row = client
        .query_one(
            "SELECT grant_id, grant_committed_at_unix_ms FROM \
             object_store_retention.object_dispatch_provider_charge_grants \
             WHERE provider_boundary_id = $1 AND logical_request_id = $2 AND attempt_id = $3",
            &[&BOUNDARY, &logical_request_id, &attempt_id],
        )
        .await
        .expect("read durable grant identity");
    (row.get(0), row.get(1))
}

fn sorted<'a>(first: &'a str, second: &'a str) -> [&'a str; 2] {
    if first <= second {
        [first, second]
    } else {
        [second, first]
    }
}

fn future_deadline() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis();
    i64::try_from(now).expect("current Unix milliseconds must fit i64") + 60_000
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

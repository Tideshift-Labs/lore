// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Direct mTLS client for the independent object-dispatch continuity database.
//!
//! The connector deliberately has no plaintext, opportunistic TLS, native-root, password-only, or
//! insecure-verifier mode. PostgreSQL verifies the client identity and maps it to one boundary role;
//! rustls verifies the server DNS name against the explicitly provisioned continuity root CA.

use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::sync::Mutex;
use tokio_postgres::IsolationLevel;
use tokio_postgres::Row;
use tokio_postgres::config::Host;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::PgLsn;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

const API_REVISION: &str = "object-store-authority-continuity-v1";
const SCHEMA_REVISION: &str = "object-store-authority-continuity-schema-v1";
const CONTINUITY_CONTRACT_REVISION: &str = "object-store-authority-continuity-contract-v1";
const MUTATION_ISOLATION_LEVEL: IsolationLevel = IsolationLevel::Serializable;
const REQUIRED_MUTATION_RETRY_ATTEMPTS: u8 = 3;
const FIRST_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(25);
const SECOND_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_ARCHIVE_PROOF_BYTES: usize = 1_048_576;
const MAX_RETIREMENT_PROOF_BYTES: usize = 1_048_576;

enum MutationAttemptOutcome<T> {
    Committed(T),
    RetryAfter(Duration),
    Reconcile(T),
    Exhausted,
    Fail,
}

macro_rules! mutation_step_or_finish {
    ($label:lifetime, $client_self:expr, $attempt:ident, $future:expr) => {{
        match $future.await {
            Ok(value) => value,
            Err(error) => {
                if let Some(delay) = $client_self.mutation_retry_delay(&error, $attempt) {
                    break $label MutationAttemptOutcome::RetryAfter(delay);
                }
                if postgres_error_is_known_aborted_mutation(&error) {
                    break $label MutationAttemptOutcome::Exhausted;
                }
                break $label MutationAttemptOutcome::Fail;
            }
        }
    }};
}

macro_rules! run_serializable_mutation {
    ($client_self:expr, $sql:expr, $params:expr, $decode_and_validate:expr, $reconcile:expr) => {{
        let mut attempt = 1;
        loop {
            let outcome = 'attempt: {
                let mut session = $client_self.session.lock().await;
                let client = &mut session.client;
                let transaction = mutation_step_or_finish!(
                    'attempt,
                    $client_self,
                    attempt,
                    client
                        .build_transaction()
                        .isolation_level(MUTATION_ISOLATION_LEVEL)
                        .start()
                );
                mutation_step_or_finish!(
                    'attempt,
                    $client_self,
                    attempt,
                    $client_self.apply_mutation_timeouts(&transaction)
                );
                let row = mutation_step_or_finish!(
                    'attempt,
                    $client_self,
                    attempt,
                    transaction.query_one($sql, $params)
                );
                let result = ($decode_and_validate)(&row)?;
                match transaction.commit().await {
                    Ok(()) => MutationAttemptOutcome::Committed(result),
                    Err(error) => match commit_failure_action(
                        error.is_closed(),
                        error
                            .as_db_error()
                            .map(|database_error| database_error.code().code()),
                        attempt,
                        $client_self.max_retry_attempts,
                    ) {
                        CommitFailureAction::RetryAfter(delay) => {
                            MutationAttemptOutcome::RetryAfter(delay)
                        }
                        CommitFailureAction::Reconcile => {
                            MutationAttemptOutcome::Reconcile(result)
                        }
                        CommitFailureAction::Exhausted => MutationAttemptOutcome::Exhausted,
                        CommitFailureAction::Fail => MutationAttemptOutcome::Fail,
                    },
                }
            };
            match outcome {
                MutationAttemptOutcome::Committed(result) => break Ok(result),
                MutationAttemptOutcome::RetryAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
                MutationAttemptOutcome::Reconcile(result) => {
                    if $client_self.reconnect().await.is_err() {
                        break Err(ContinuityError::AmbiguousCommit);
                    }
                    match ($reconcile)(&result).await {
                        CommitReconciliation::Adopt(adopted) => break Ok(adopted),
                        CommitReconciliation::Retry => {
                            let Some(delay) =
                                bounded_retry_delay(attempt, $client_self.max_retry_attempts)
                            else {
                                break Err(ContinuityError::AmbiguousCommit);
                            };
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                        }
                        CommitReconciliation::Unresolved => {
                            break Err(ContinuityError::AmbiguousCommit);
                        }
                    }
                }
                MutationAttemptOutcome::Exhausted => {
                    break Err(ContinuityError::RetryExhausted);
                }
                MutationAttemptOutcome::Fail => {
                    break Err(ContinuityError::Postgres { transient: false });
                }
            }
        }
    }};
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitFailureAction {
    RetryAfter(Duration),
    Reconcile,
    Exhausted,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CommitReconciliation<T> {
    Adopt(T),
    Retry,
    Unresolved,
}

fn same_procedure_row(
    authoritative: &ContinuityProcedureResult,
    precommit: &ContinuityProcedureResult,
) -> bool {
    authoritative.state == precommit.state
        && authoritative.ownership_state == precommit.ownership_state
        && authoritative.authority_epoch == precommit.authority_epoch
        && authoritative.continuity_seq == precommit.continuity_seq
        && authoritative.continuity_token_id == precommit.continuity_token_id
        && authoritative.row_blake3 == precommit.row_blake3
        && authoritative.external_committed_at_unix_ms == precommit.external_committed_at_unix_ms
}

fn reconcile_begin_readback(
    precommit: &ContinuityProcedureResult,
    readback: Option<ContinuityTokenLookup>,
) -> CommitReconciliation<ContinuityProcedureResult> {
    match readback {
        Some(ContinuityTokenLookup::Found(authoritative))
            if same_procedure_row(&authoritative, precommit) =>
        {
            CommitReconciliation::Adopt(precommit.clone())
        }
        Some(ContinuityTokenLookup::NotFound { .. }) => CommitReconciliation::Retry,
        Some(ContinuityTokenLookup::Found(_)) | None => CommitReconciliation::Unresolved,
    }
}

fn reconcile_token_transition_readback(
    identity: &ContinuityIntentIdentity,
    expected_prior_row_blake3: &[u8; 32],
    precommit: &ContinuityProcedureResult,
    readback: Option<ContinuityTokenLookup>,
) -> CommitReconciliation<ContinuityProcedureResult> {
    match readback {
        Some(ContinuityTokenLookup::Found(authoritative))
            if same_procedure_row(&authoritative, precommit) =>
        {
            CommitReconciliation::Adopt(precommit.clone())
        }
        Some(ContinuityTokenLookup::Found(authoritative))
            if authoritative.authority_epoch == identity.authority_epoch
                && authoritative.continuity_seq == identity.continuity_seq
                && authoritative.continuity_token_id == identity.continuity_token_id
                && authoritative.row_blake3 == *expected_prior_row_blake3 =>
        {
            CommitReconciliation::Retry
        }
        Some(ContinuityTokenLookup::Found(_))
        | Some(ContinuityTokenLookup::NotFound { .. })
        | None => CommitReconciliation::Unresolved,
    }
}

fn reconcile_snapshot_readback(
    request: &RecordSnapshotRequest,
    latest_snapshot: Option<Option<ReconciliationSnapshot>>,
) -> CommitReconciliation<RecordSnapshotResult> {
    match latest_snapshot {
        Some(Some(snapshot))
            if snapshot.snapshot_id == request.snapshot_id
                && snapshot.through_continuity_seq == request.through_continuity_seq
                && snapshot.manifest_blake3 == request.manifest_blake3 =>
        {
            CommitReconciliation::Retry
        }
        Some(None) => CommitReconciliation::Retry,
        Some(Some(_)) | None => CommitReconciliation::Unresolved,
    }
}

fn reconcile_epoch_allocation_readback(
    request: &AllocateEpochRequest,
    readback: Option<ContinuityEpochState>,
) -> CommitReconciliation<ContinuityEpochState> {
    match readback {
        Some(state) if state.authority_epoch == request.expected_current_epoch => {
            CommitReconciliation::Retry
        }
        Some(_) | None => CommitReconciliation::Unresolved,
    }
}

fn reconcile_archive_readback(
    request: &ArchivePruneRequest,
    readback: Option<ContinuityTokenLookup>,
) -> CommitReconciliation<ArchivePruneResult> {
    match readback {
        Some(ContinuityTokenLookup::Found(authoritative))
            if authoritative.authority_epoch == request.authority_epoch
                && authoritative.continuity_seq == request.continuity_seq
                && authoritative.continuity_token_id == request.continuity_token_id
                && authoritative.row_blake3 == request.expected_row_blake3 =>
        {
            CommitReconciliation::Retry
        }
        Some(ContinuityTokenLookup::Found(_))
        | Some(ContinuityTokenLookup::NotFound { .. })
        | None => CommitReconciliation::Unresolved,
    }
}

fn reconcile_retirement_readback(
    request: &RetireEpochRequest,
    precommit: &RetiredEpochSummary,
    retired_summary: Option<RetiredEpochSummary>,
    active_interval: Option<PrunedInterval>,
) -> CommitReconciliation<RetiredEpochSummary> {
    if let Some(summary) = retired_summary {
        return if summary == *precommit
            && validate_retired_epoch_summary_for_retirement(&summary, request).is_ok()
        {
            CommitReconciliation::Adopt(precommit.clone())
        } else {
            CommitReconciliation::Unresolved
        };
    }
    match active_interval {
        Some(interval)
            if interval.start_sequence == 1
                && interval.interval_blake3 == request.expected_interval_checkpoint_blake3 =>
        {
            CommitReconciliation::Retry
        }
        Some(_) | None => CommitReconciliation::Unresolved,
    }
}

macro_rules! run_bounded_read {
    ($client_self:expr, $query_method:ident, $sql:expr, $params:expr, $decode_and_validate:expr) => {{
        let mut session = $client_self.session.lock().await;
        let transaction = session
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(ContinuityError::postgres)?;
        $client_self
            .apply_mutation_timeouts(&transaction)
            .await
            .map_err(ContinuityError::postgres)?;
        let row = transaction
            .$query_method($sql, $params)
            .await
            .map_err(ContinuityError::postgres)?;
        let result = ($decode_and_validate)(row)?;
        transaction
            .commit()
            .await
            .map_err(ContinuityError::postgres)?;
        Ok(result)
    }};
}
const BEGIN_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2::text::object_store_continuity.uint64, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64, $14::text::object_store_continuity.uint64, \
      $15::text::object_store_continuity.uint64, $16\
    )";
const GET_BY_TOKEN_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_get_by_token_v1($1, $2, $3)";
const MARK_BOUND_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_bound_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13\
    )";
const MARK_COMPLETED_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_completed_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const MARK_NO_LOCAL_EFFECT_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_no_local_effect_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16\
    )";
const QUARANTINE_SQL: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_quarantine_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const MARK_AMBIGUOUS_DISPATCH_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15\
    )";
const PREPARE_ADJUDICATION_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_prepare_adjudication_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16\
    )";
const COMPLETE_ADJUDICATION_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_complete_adjudication_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
      $16, $17, $18, $19\
    )";
const RECORD_SNAPSHOT_SQL: &str = "SELECT accepted_snapshot_id, \
    accepted_through_continuity_seq::text, accepted_manifest_blake3, \
    accepted_coverage_blake3, recorded_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_record_snapshot_v1(\
      $1, $2, $3, $4::text::object_store_continuity.uint64, \
      $5::text::object_store_continuity.uint64, $6, $7, \
      $8::text::object_store_continuity.uint64, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64\
    )";
const RELEASE_SHADOW_OWNERSHIP_SQL: &str = "SELECT result_code, state, ownership_state, \
    authority_epoch::text, continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_release_shadow_ownership_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
      $15, $16, $17\
    )";
const READ_RECONCILIATION_STATE_SQL: &str = "SELECT current_authority_epoch::text, \
    continuity_seq_high_water::text, owned_rows::text, owned_bytes::text, \
    owned_concurrency::text, latest_snapshot_id, latest_snapshot_through_continuity_seq::text, \
    latest_snapshot_manifest_blake3 FROM \
    object_store_continuity.object_store_continuity_read_reconciliation_state_v1(\
      $1, $2, $3::text::object_store_continuity.uint64\
    )";
const READ_EPOCH_SQL: &str = "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_read_epoch_v1($1, $2)";
const ALLOCATE_EPOCH_SQL: &str = "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_allocate_epoch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )";
const READ_SHADOW_RELEASE_RECEIPT_SQL: &str = "SELECT receipt_provider_boundary_id, \
    receipt_authority_epoch::text, receipt_continuity_seq::text, receipt_continuity_token_id, \
    release_id, receipt_blake3, released_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )";
const ARCHIVE_PRUNE_SQL: &str = "SELECT accepted_start_sequence::text, \
    accepted_end_sequence::text, accepted_row_count::text, prune_commit_sequence::text, \
    accepted_interval_blake3 FROM \
    object_store_continuity.object_store_continuity_archive_prune_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9\
    )";
const READ_PRUNED_INTERVAL_SQL: &str = "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, end_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, canonical_row_bytes_sum::text, \
    canonical_row_bytes_min::text, canonical_row_bytes_max::text, quota_rows_sum::text, \
    quota_rows_min::text, quota_rows_max::text, quota_bytes_sum::text, quota_bytes_min::text, \
    quota_bytes_max::text, quota_concurrency_sum::text, quota_concurrency_min::text, \
    quota_concurrency_max::text, created_at_min_unix_ms, created_at_max_unix_ms, \
    closed_at_min_unix_ms, closed_at_max_unix_ms, prune_commit_sequence_min::text, \
    prune_commit_sequence_max::text, pruned_at_min_unix_ms, pruned_at_max_unix_ms, \
    canonical_interval_bytes, interval_blake3 FROM \
    object_store_continuity.object_store_continuity_read_pruned_interval_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8\
    )";
const RETIRE_EPOCH_SQL: &str = "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, final_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, interval_checkpoint_blake3, created_at_min_unix_ms, \
    created_at_max_unix_ms, closed_at_min_unix_ms, closed_at_max_unix_ms, \
    pruned_at_min_unix_ms, pruned_at_max_unix_ms, prune_commit_sequence_max::text, \
    covering_snapshot_id, covering_snapshot_through_sequence::text, \
    covering_snapshot_authority_lsn, covering_snapshot_manifest_blake3, \
    retirement_proof_blake3, canonical_summary_bytes, summary_blake3, retired_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_retire_epoch_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, $4, $5, $6, $7, $8, $9\
    )";
const READ_RETIRED_EPOCH_SQL: &str = "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, final_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, interval_checkpoint_blake3, created_at_min_unix_ms, \
    created_at_max_unix_ms, closed_at_min_unix_ms, closed_at_max_unix_ms, \
    pruned_at_min_unix_ms, pruned_at_max_unix_ms, prune_commit_sequence_max::text, \
    covering_snapshot_id, covering_snapshot_through_sequence::text, \
    covering_snapshot_authority_lsn, covering_snapshot_manifest_blake3, \
    retirement_proof_blake3, canonical_summary_bytes, summary_blake3, retired_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_retired_epoch_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, $4, $5, $6, $7\
    )";

/// Connection material for one continuity boundary identity.
///
/// The custom [`Debug`] implementation never prints the URL or PEM material because each can carry
/// credentials. Callers should obtain the PEM values from the deployment secret provider and keep
/// them in memory only.
#[derive(Clone)]
pub struct ContinuityTlsConfig {
    pub postgres_url: String,
    pub root_ca_pem: String,
    pub client_certificate_chain_pem: String,
    pub private_key_pem: String,
    pub connect_timeout: Duration,
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
    pub max_retry_attempts: u8,
}

impl fmt::Debug for ContinuityTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuityTlsConfig")
            .field("postgres_url", &"<redacted>")
            .field("root_ca_pem", &"<redacted>")
            .field("client_certificate_chain_pem", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("max_retry_attempts", &self.max_retry_attempts)
            .finish()
    }
}

impl ContinuityTlsConfig {
    /// Validate the fail-closed connection contract without opening a socket.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        self.connection_material().map(|_| ())
    }

    fn connection_material(
        &self,
    ) -> Result<(tokio_postgres::Config, MakeRustlsConnect), ContinuityError> {
        if self.connect_timeout.is_zero() {
            return Err(ContinuityError::InvalidConfiguration(
                "connect timeout must be positive",
            ));
        }
        if self.statement_timeout.as_millis() == 0
            || !self
                .statement_timeout
                .subsec_nanos()
                .is_multiple_of(1_000_000)
            || u64::try_from(self.statement_timeout.as_millis()).is_err()
        {
            return Err(ContinuityError::InvalidConfiguration(
                "statement timeout must be a positive whole-millisecond value",
            ));
        }
        if self.lock_timeout.as_millis() == 0
            || !self.lock_timeout.subsec_nanos().is_multiple_of(1_000_000)
            || u64::try_from(self.lock_timeout.as_millis()).is_err()
        {
            return Err(ContinuityError::InvalidConfiguration(
                "lock timeout must be a positive whole-millisecond value",
            ));
        }
        if self.max_retry_attempts != REQUIRED_MUTATION_RETRY_ATTEMPTS {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity mutation retry attempts must equal three",
            ));
        }
        let postgres = self
            .postgres_url
            .parse::<tokio_postgres::Config>()
            .map_err(|_| ContinuityError::InvalidConfiguration("invalid PostgreSQL URL"))?;
        if postgres.get_ssl_mode() != SslMode::Require {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL requires sslmode=require",
            ));
        }
        let [Host::Tcp(host)] = postgres.get_hosts() else {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL requires exactly one TCP DNS host",
            ));
        };
        if host.parse::<IpAddr>().is_ok() || !is_dns_name(host) {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL host must be a DNS name",
            ));
        }
        if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity PostgreSQL URL requires user and database",
            ));
        }

        let mut roots = RootCertStore::empty();
        let mut root_reader = Cursor::new(self.root_ca_pem.as_bytes());
        let mut root_count = 0usize;
        for certificate in rustls_pemfile::certs(&mut root_reader) {
            let certificate = certificate
                .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid root CA PEM"))?;
            roots
                .add(certificate)
                .map_err(|_| ContinuityError::InvalidTlsMaterial("unusable root CA certificate"))?;
            root_count = root_count.saturating_add(1);
        }
        if root_count == 0 {
            return Err(ContinuityError::InvalidTlsMaterial(
                "root CA bundle is empty",
            ));
        }

        let mut certificate_reader = Cursor::new(self.client_certificate_chain_pem.as_bytes());
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid client certificate PEM"))?;
        if certificates.is_empty() {
            return Err(ContinuityError::InvalidTlsMaterial(
                "client certificate chain is empty",
            ));
        }
        let mut key_reader = Cursor::new(self.private_key_pem.as_bytes());
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|_| ContinuityError::InvalidTlsMaterial("invalid client private key PEM"))?
            .ok_or(ContinuityError::InvalidTlsMaterial(
                "client private key is empty",
            ))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ContinuityError::InvalidTlsMaterial("unsupported TLS protocol set"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .map_err(|_| {
                ContinuityError::InvalidTlsMaterial("client certificate and key do not match")
            })?;
        Ok((postgres, MakeRustlsConnect::new(tls)))
    }
}

/// Closed failure surface for the continuity client. Messages intentionally omit dynamic
/// connection strings, PEM bodies, SQL parameter values, and server diagnostics.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContinuityError {
    #[error("invalid continuity connection configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid continuity TLS material: {0}")]
    InvalidTlsMaterial(&'static str),
    #[error("continuity database connection timed out")]
    ConnectTimeout,
    #[error("continuity database operation failed")]
    Postgres { transient: bool },
    #[error("continuity mutation retry budget exhausted")]
    RetryExhausted,
    #[error("continuity mutation commit outcome is ambiguous")]
    AmbiguousCommit,
    #[error("invalid continuity procedure result: {0}")]
    InvalidResponse(&'static str),
}

impl ContinuityError {
    fn postgres(error: tokio_postgres::Error) -> Self {
        Self::Postgres {
            transient: postgres_error_is_transient(&error),
        }
    }

    /// Whether retrying against the same deployment revision can be safe after backoff.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::ConnectTimeout => true,
            Self::Postgres { transient } => *transient,
            Self::InvalidConfiguration(_)
            | Self::InvalidTlsMaterial(_)
            | Self::RetryExhausted
            | Self::AmbiguousCommit
            | Self::InvalidResponse(_) => false,
        }
    }
}

/// Immutable input to the gapless continuity-intent allocation procedure.
pub struct BeginIntentRequest {
    pub provider_boundary_id: String,
    pub expected_authority_epoch: u64,
    pub continuity_token_id: Uuid,
    pub intent_kind: ContinuityIntentKind,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub operation_quota_class: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub selected_fingerprint: [u8; 32],
    pub continuity_policy_revision: String,
    pub quota_bytes: u64,
    pub quota_rows: u64,
    pub quota_concurrency: u64,
    pub retention_deadline_unix_ms: i64,
}

/// Exact identity that every runtime transition re-presents to prevent cross-request adoption.
pub struct ContinuityIntentIdentity {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub intent_kind: ContinuityIntentKind,
    pub selected_fingerprint: [u8; 32],
}

/// Local durable binding transition from external INTENT to BOUND.
pub struct MarkBoundRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
}

/// Terminal transition after the exact local result is durable.
pub struct MarkCompletedRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
}

/// Decisive no-local-effect transition with its exact quota-release basis.
pub struct MarkNoLocalEffectRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
    pub release_id: Uuid,
    pub release_basis_id: String,
    pub release_basis_blake3: [u8; 32],
}

/// Exact stored state and binding evidence accepted by a quarantine transition.
pub enum QuarantinePriorState {
    Intent,
    Bound { local_binding_blake3: [u8; 32] },
}

impl QuarantinePriorState {
    fn as_sql(&self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::Bound { .. } => "BOUND",
        }
    }

    fn local_binding_blake3(&self) -> Option<&[u8]> {
        match self {
            Self::Intent => None,
            Self::Bound {
                local_binding_blake3,
            } => Some(local_binding_blake3),
        }
    }
}

/// Reconciler transition that preserves ownership while making ambiguity explicit.
pub struct QuarantineRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub prior_state: QuarantinePriorState,
    pub terminal_evidence_blake3: [u8; 32],
}

/// Reconciler transition from BOUND to explicit possible-provider-dispatch ambiguity.
pub struct MarkAmbiguousDispatchRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub local_binding_blake3: [u8; 32],
    pub terminal_evidence_blake3: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityAdjudicationKind {
    NoLocalEffect,
    NoDispatch,
}

impl ContinuityAdjudicationKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "NO_LOCAL_EFFECT",
            Self::NoDispatch => "NO_DISPATCH",
        }
    }

    fn prepared_prior_state_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "QUARANTINED",
            Self::NoDispatch => "AMBIGUOUS_DISPATCH",
        }
    }

    fn final_state_sql(self) -> &'static str {
        match self {
            Self::NoLocalEffect => "ADJUDICATED_NO_LOCAL_EFFECT",
            Self::NoDispatch => "ADJUDICATED_NO_DISPATCH",
        }
    }
}

/// First half of authenticated two-step adjudication. Ownership remains reserved.
pub struct PrepareAdjudicationRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub adjudication_kind: ContinuityAdjudicationKind,
    pub local_binding_blake3: Option<[u8; 32]>,
    pub terminal_evidence_blake3: [u8; 32],
}

/// Final adjudication evidence and exact release basis.
pub struct CompleteAdjudicationRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub adjudication_kind: ContinuityAdjudicationKind,
    pub local_binding_blake3: Option<[u8; 32]>,
    pub terminal_evidence_blake3: [u8; 32],
    pub release_id: Uuid,
    pub release_basis_id: String,
    pub release_basis_blake3: [u8; 32],
}

/// Exact local durability evidence accepted into one monotonic continuity snapshot.
pub struct RecordSnapshotRequest {
    pub snapshot_id: Uuid,
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub through_continuity_seq: u64,
    pub authority_lsn: u64,
    pub manifest_blake3: [u8; 32],
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub local_binding_blake3: [u8; 32],
    pub local_state_blake3: [u8; 32],
    pub local_quota_ownership_blake3: [u8; 32],
    pub local_counter_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSnapshotResult {
    pub accepted_snapshot_id: Uuid,
    pub accepted_through_continuity_seq: u64,
    pub accepted_manifest_blake3: [u8; 32],
    pub accepted_coverage_blake3: [u8; 32],
    pub recorded_at_unix_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoveredReleaseState {
    Bound,
    Completed,
}

impl CoveredReleaseState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Bound => "BOUND",
            Self::Completed => "COMPLETED",
        }
    }

    fn as_state(self) -> ContinuityState {
        match self {
            Self::Bound => ContinuityState::Bound,
            Self::Completed => ContinuityState::Completed,
        }
    }
}

/// Release request bound to an exact accepted snapshot coverage receipt.
pub struct ReleaseShadowOwnershipRequest {
    pub identity: ContinuityIntentIdentity,
    pub expected_prior_row_blake3: [u8; 32],
    pub expected_state: CoveredReleaseState,
    pub snapshot_id: Uuid,
    pub expected_manifest_blake3: [u8; 32],
    pub expected_coverage_blake3: [u8; 32],
    pub release_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationSnapshot {
    pub snapshot_id: Uuid,
    pub through_continuity_seq: u64,
    pub manifest_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationState {
    pub current_authority_epoch: u64,
    pub continuity_seq_high_water: u64,
    pub owned_rows: u64,
    pub owned_bytes: u64,
    pub owned_concurrency: u64,
    pub latest_snapshot: Option<ReconciliationSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityEpochState {
    pub authority_epoch: u64,
    pub continuity_seq_high_water: u64,
}

/// Compare-and-swap allocation of a strictly newer drained boundary epoch.
pub struct AllocateEpochRequest {
    pub provider_boundary_id: String,
    pub expected_current_epoch: u64,
    pub next_epoch: u64,
    pub epoch_namespace_blake3: [u8; 32],
}

/// Exact released-token identity used for least-privilege receipt readback.
pub struct ReadShadowReleaseReceiptRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowReleaseReceipt {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub release_id: Uuid,
    pub receipt_blake3: [u8; 32],
    pub released_at_unix_ms: i64,
}

/// Exact terminal detail and local-dependency proof accepted for bounded archive/prune.
pub struct ArchivePruneRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub expected_continuity_policy_revision: String,
    pub expected_epoch_namespace_blake3: [u8; 32],
    pub expected_row_blake3: [u8; 32],
    pub expected_release_receipt_blake3: [u8; 32],
    pub archive_proof_bytes: Vec<u8>,
    pub archive_proof_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivePruneResult {
    pub accepted_start_sequence: u64,
    pub accepted_end_sequence: u64,
    pub accepted_row_count: u64,
    pub prune_commit_sequence: u64,
    pub accepted_interval_blake3: [u8; 32],
}

/// Authenticated namespace and sequence used to adopt one containing pruned interval.
pub struct ReadPrunedIntervalRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub expected_continuity_policy_revision: String,
    pub expected_epoch_namespace_blake3: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunedInterval {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub row_count: u64,
    pub api_revision: String,
    pub schema_revision: String,
    pub continuity_contract_revision: String,
    pub continuity_policy_revision: String,
    pub completed_count: u64,
    pub no_local_effect_count: u64,
    pub adjudicated_no_local_effect_count: u64,
    pub adjudicated_no_dispatch_count: u64,
    pub canonical_row_bytes_sum: u64,
    pub canonical_row_bytes_min: u64,
    pub canonical_row_bytes_max: u64,
    pub quota_rows_sum: u64,
    pub quota_rows_min: u64,
    pub quota_rows_max: u64,
    pub quota_bytes_sum: u64,
    pub quota_bytes_min: u64,
    pub quota_bytes_max: u64,
    pub quota_concurrency_sum: u64,
    pub quota_concurrency_min: u64,
    pub quota_concurrency_max: u64,
    pub created_at_min_unix_ms: i64,
    pub created_at_max_unix_ms: i64,
    pub closed_at_min_unix_ms: i64,
    pub closed_at_max_unix_ms: i64,
    pub prune_commit_sequence_min: u64,
    pub prune_commit_sequence_max: u64,
    pub pruned_at_min_unix_ms: i64,
    pub pruned_at_max_unix_ms: i64,
    pub canonical_interval_bytes: Vec<u8>,
    pub interval_blake3: [u8; 32],
}

/// Exact old-epoch checkpoint and proof accepted for one bounded retirement.
pub struct RetireEpochRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub expected_continuity_policy_revision: String,
    pub expected_epoch_namespace_blake3: [u8; 32],
    pub expected_interval_checkpoint_blake3: [u8; 32],
    pub covering_snapshot_id: Uuid,
    pub expected_snapshot_manifest_blake3: [u8; 32],
    pub retirement_proof_bytes: Vec<u8>,
    pub retirement_proof_blake3: [u8; 32],
}

/// Authenticated namespace used to adopt one retired epoch summary.
pub struct ReadRetiredEpochRequest {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub expected_continuity_policy_revision: String,
    pub expected_epoch_namespace_blake3: [u8; 32],
}

/// Canonical namespace checkpoint for one completely pruned retired epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredEpochSummary {
    pub provider_boundary_id: String,
    pub authority_epoch: u64,
    pub start_sequence: u64,
    pub final_sequence: u64,
    pub row_count: u64,
    pub api_revision: String,
    pub schema_revision: String,
    pub continuity_contract_revision: String,
    pub continuity_policy_revision: String,
    pub completed_count: u64,
    pub no_local_effect_count: u64,
    pub adjudicated_no_local_effect_count: u64,
    pub adjudicated_no_dispatch_count: u64,
    pub interval_checkpoint_blake3: [u8; 32],
    pub created_at_min_unix_ms: i64,
    pub created_at_max_unix_ms: i64,
    pub closed_at_min_unix_ms: i64,
    pub closed_at_max_unix_ms: i64,
    pub pruned_at_min_unix_ms: i64,
    pub pruned_at_max_unix_ms: i64,
    pub prune_commit_sequence_max: u64,
    pub covering_snapshot_id: Uuid,
    pub covering_snapshot_through_sequence: u64,
    pub covering_snapshot_authority_lsn: u64,
    pub covering_snapshot_manifest_blake3: [u8; 32],
    pub retirement_proof_blake3: [u8; 32],
    pub canonical_summary_bytes: Vec<u8>,
    pub summary_blake3: [u8; 32],
    pub retired_at_unix_ms: i64,
}

/// Server-derived result projection shared by continuity mutation and read procedures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityProcedureResult {
    pub result_code: ContinuityResultCode,
    pub state: ContinuityState,
    pub ownership_state: ContinuityOwnershipState,
    pub authority_epoch: u64,
    pub continuity_seq: u64,
    pub continuity_token_id: Uuid,
    pub row_blake3: [u8; 32],
    pub external_committed_at_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuityTokenLookup {
    Found(ContinuityProcedureResult),
    NotFound {
        continuity_token_id: Uuid,
        observed_at_unix_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityResultCode {
    Created,
    Found,
    Replay,
    Updated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityState {
    Intent,
    Bound,
    Completed,
    NoLocalEffect,
    Quarantined,
    AmbiguousDispatch,
    AdjudicationPrepared,
    AdjudicatedNoLocalEffect,
    AdjudicatedNoDispatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityOwnershipState {
    ShadowReserved,
    OwnershipReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinuityIntentKind {
    UuidAdmission,
    DispatchCas,
}

impl ContinuityIntentKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::UuidAdmission => "UUID_ADMISSION",
            Self::DispatchCas => "DISPATCH_CAS",
        }
    }
}

/// One direct connection to the independent continuity authority.
pub struct ContinuityClient {
    config: ContinuityTlsConfig,
    session: Mutex<ContinuitySession>,
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
    max_retry_attempts: u8,
}

struct ContinuitySession {
    client: tokio_postgres::Client,
    _connection_task: AbortOnDropHandle<()>,
}

impl ContinuityClient {
    /// Connect with mandatory server-name verification and client-certificate authentication.
    pub async fn connect(config: &ContinuityTlsConfig) -> Result<Self, ContinuityError> {
        let session = Self::connect_session(config).await?;
        Ok(Self {
            config: config.clone(),
            session: Mutex::new(session),
            statement_timeout_ms: u64::try_from(config.statement_timeout.as_millis()).map_err(
                |_| ContinuityError::InvalidConfiguration("statement timeout is too large"),
            )?,
            lock_timeout_ms: u64::try_from(config.lock_timeout.as_millis())
                .map_err(|_| ContinuityError::InvalidConfiguration("lock timeout is too large"))?,
            max_retry_attempts: config.max_retry_attempts,
        })
    }

    async fn connect_session(
        config: &ContinuityTlsConfig,
    ) -> Result<ContinuitySession, ContinuityError> {
        let (postgres, tls) = config.connection_material()?;
        let connected = tokio::time::timeout(config.connect_timeout, postgres.connect(tls))
            .await
            .map_err(|_| ContinuityError::ConnectTimeout)?
            .map_err(ContinuityError::postgres)?;
        let (client, connection) = connected;
        let connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
            "object-store-continuity-postgres",
            async move {
                if connection.await.is_err() {
                    tracing::error!("object-store continuity PostgreSQL connection ended");
                }
            }
        ));
        Ok(ContinuitySession {
            client,
            _connection_task: connection_task,
        })
    }

    async fn reconnect(&self) -> Result<(), ContinuityError> {
        let replacement = Self::connect_session(&self.config).await?;
        let mut session = self.session.lock().await;
        *session = replacement;
        Ok(())
    }

    async fn apply_mutation_timeouts(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
    ) -> Result<(), tokio_postgres::Error> {
        let statement = mutation_timeout_sql(self.statement_timeout_ms, self.lock_timeout_ms);
        transaction.batch_execute(&statement).await
    }

    fn mutation_retry_delay(&self, error: &tokio_postgres::Error, attempt: u8) -> Option<Duration> {
        mutation_retry_delay_for_shape(
            error
                .as_db_error()
                .map(|database_error| database_error.code().code()),
            attempt,
            self.max_retry_attempts,
        )
    }

    async fn reconcile_begin_commit(
        &self,
        request: &BeginIntentRequest,
        precommit: &ContinuityProcedureResult,
    ) -> CommitReconciliation<ContinuityProcedureResult> {
        let readback = self
            .get_by_token(&request.provider_boundary_id, request.continuity_token_id)
            .await
            .ok();
        reconcile_begin_readback(precommit, readback)
    }

    async fn reconcile_token_transition_commit(
        &self,
        identity: &ContinuityIntentIdentity,
        expected_prior_row_blake3: &[u8; 32],
        precommit: &ContinuityProcedureResult,
    ) -> CommitReconciliation<ContinuityProcedureResult> {
        let readback = self
            .get_by_token(&identity.provider_boundary_id, identity.continuity_token_id)
            .await
            .ok();
        reconcile_token_transition_readback(
            identity,
            expected_prior_row_blake3,
            precommit,
            readback,
        )
    }

    async fn reconcile_snapshot_commit(
        &self,
        request: &RecordSnapshotRequest,
        _precommit: &RecordSnapshotResult,
    ) -> CommitReconciliation<RecordSnapshotResult> {
        let latest_snapshot = match self
            .read_reconciliation_state(&request.provider_boundary_id, request.authority_epoch)
            .await
        {
            Ok(Some(state)) => Some(state.latest_snapshot),
            Ok(None) | Err(_) => None,
        };
        reconcile_snapshot_readback(request, latest_snapshot)
    }

    async fn reconcile_epoch_allocation_commit(
        &self,
        request: &AllocateEpochRequest,
        _precommit: &ContinuityEpochState,
    ) -> CommitReconciliation<ContinuityEpochState> {
        let readback = self
            .read_epoch(&request.provider_boundary_id)
            .await
            .ok()
            .flatten();
        reconcile_epoch_allocation_readback(request, readback)
    }

    async fn reconcile_archive_commit(
        &self,
        request: &ArchivePruneRequest,
        _precommit: &ArchivePruneResult,
    ) -> CommitReconciliation<ArchivePruneResult> {
        let readback = self
            .get_by_token(&request.provider_boundary_id, request.continuity_token_id)
            .await
            .ok();
        reconcile_archive_readback(request, readback)
    }

    async fn reconcile_retirement_commit(
        &self,
        request: &RetireEpochRequest,
        precommit: &RetiredEpochSummary,
    ) -> CommitReconciliation<RetiredEpochSummary> {
        let read_request = ReadRetiredEpochRequest {
            provider_boundary_id: request.provider_boundary_id.clone(),
            authority_epoch: request.authority_epoch,
            expected_continuity_policy_revision: request
                .expected_continuity_policy_revision
                .clone(),
            expected_epoch_namespace_blake3: request.expected_epoch_namespace_blake3,
        };
        if let Ok(summary) = self.read_retired_epoch(&read_request).await {
            return reconcile_retirement_readback(request, precommit, Some(summary), None);
        }
        let interval_request = ReadPrunedIntervalRequest {
            provider_boundary_id: request.provider_boundary_id.clone(),
            authority_epoch: request.authority_epoch,
            continuity_seq: 1,
            expected_continuity_policy_revision: request
                .expected_continuity_policy_revision
                .clone(),
            expected_epoch_namespace_blake3: request.expected_epoch_namespace_blake3,
        };
        let interval = self.read_pruned_interval(&interval_request).await.ok();
        reconcile_retirement_readback(request, precommit, None, interval)
    }

    /// Allocate or replay an exact intent in a serializable read-write transaction.
    pub async fn begin(
        &self,
        request: &BeginIntentRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        if request.expected_authority_epoch == 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "expected authority epoch must be positive",
            ));
        }
        if request.provider_boundary_id.is_empty()
            || request.authenticated_cell_id.is_empty()
            || request.authenticated_tenant_id.is_empty()
            || request.operation_quota_class.is_empty()
            || request.continuity_policy_revision.is_empty()
        {
            return Err(ContinuityError::InvalidConfiguration(
                "continuity begin text must be nonempty",
            ));
        }
        if request.retention_deadline_unix_ms < 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "retention deadline must be nonnegative",
            ));
        }
        let expected_authority_epoch = request.expected_authority_epoch.to_string();
        let quota_bytes = request.quota_bytes.to_string();
        let quota_rows = request.quota_rows.to_string();
        let quota_concurrency = request.quota_concurrency.to_string();
        run_serializable_mutation!(
            self,
            BEGIN_SQL,
            &[
                &API_REVISION,
                &expected_authority_epoch,
                &request.continuity_token_id,
                &request.provider_boundary_id,
                &request.intent_kind.as_sql(),
                &request.authenticated_cell_id,
                &request.authenticated_tenant_id,
                &request.logical_request_id,
                &request.attempt_id,
                &&request.selected_fingerprint[..],
                &request.continuity_policy_revision,
                &request.operation_quota_class,
                &quota_rows,
                &quota_bytes,
                &quota_concurrency,
                &request.retention_deadline_unix_ms,
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_begin_result(&result, request)?;
                Ok(result)
            },
            |precommit| self.reconcile_begin_commit(request, precommit)
        )
    }

    /// Read an exact token through the boundary-authorized SECURITY DEFINER surface.
    pub async fn get_by_token(
        &self,
        provider_boundary_id: &str,
        continuity_token_id: Uuid,
    ) -> Result<ContinuityTokenLookup, ContinuityError> {
        run_bounded_read!(
            self,
            query_one,
            GET_BY_TOKEN_SQL,
            &[&API_REVISION, &provider_boundary_id, &continuity_token_id],
            |row: Row| {
                let result = parse_token_lookup(&row)?;
                if let ContinuityTokenLookup::Found(found) = &result {
                    validate_lookup_result(found)?;
                }
                let returned_token = match &result {
                    ContinuityTokenLookup::Found(found) => found.continuity_token_id,
                    ContinuityTokenLookup::NotFound {
                        continuity_token_id,
                        ..
                    } => *continuity_token_id,
                };
                if returned_token != continuity_token_id {
                    return Err(ContinuityError::InvalidResponse(
                        "token lookup returned a different token",
                    ));
                }
                Ok(result)
            }
        )
    }

    /// Bind an external intent to its exact durable local request state.
    pub async fn mark_bound(
        &self,
        request: &MarkBoundRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            MARK_BOUND_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &&request.local_binding_blake3[..],
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::Bound,
                    ContinuityOwnershipState::ShadowReserved,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Record exact terminal evidence while retaining shadow ownership for snapshot coverage.
    pub async fn mark_completed(
        &self,
        request: &MarkCompletedRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            MARK_COMPLETED_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &&request.local_binding_blake3[..],
                &&request.terminal_evidence_blake3[..],
                &"BOUND",
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::Completed,
                    ContinuityOwnershipState::ShadowReserved,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Close an intent that provably produced no local effect and release its shadow ownership.
    pub async fn mark_no_local_effect(
        &self,
        request: &MarkNoLocalEffectRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_release_basis_id(&request.release_basis_id)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            MARK_NO_LOCAL_EFFECT_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &&request.terminal_evidence_blake3[..],
                &request.release_id,
                &request.release_basis_id,
                &&request.release_basis_blake3[..],
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::NoLocalEffect,
                    ContinuityOwnershipState::OwnershipReleased,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Preserve shadow ownership while recording an exact INTENT or BOUND quarantine.
    pub async fn quarantine(
        &self,
        request: &QuarantineRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request.prior_state.local_binding_blake3();
        run_serializable_mutation!(
            self,
            QUARANTINE_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &request.prior_state.as_sql(),
                &local_binding,
                &&request.terminal_evidence_blake3[..],
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::Quarantined,
                    ContinuityOwnershipState::ShadowReserved,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Preserve shadow ownership while recording a BOUND dispatch as externally ambiguous.
    pub async fn mark_ambiguous_dispatch(
        &self,
        request: &MarkAmbiguousDispatchRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            MARK_AMBIGUOUS_DISPATCH_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &&request.local_binding_blake3[..],
                &&request.terminal_evidence_blake3[..],
                &"BOUND",
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::AmbiguousDispatch,
                    ContinuityOwnershipState::ShadowReserved,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Prepare a typed adjudication while retaining shadow ownership.
    pub async fn prepare_adjudication(
        &self,
        request: &PrepareAdjudicationRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_adjudication_binding(
            request.adjudication_kind,
            request.local_binding_blake3.as_ref(),
        )?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request
            .local_binding_blake3
            .as_ref()
            .map(|digest| &digest[..]);
        run_serializable_mutation!(
            self,
            PREPARE_ADJUDICATION_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &request.adjudication_kind.prepared_prior_state_sql(),
                &local_binding,
                &&request.terminal_evidence_blake3[..],
                &request.adjudication_kind.as_sql(),
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    ContinuityState::AdjudicationPrepared,
                    ContinuityOwnershipState::ShadowReserved,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Complete a prepared adjudication and release its exact shadow ownership once.
    pub async fn complete_adjudication(
        &self,
        request: &CompleteAdjudicationRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        validate_adjudication_binding(
            request.adjudication_kind,
            request.local_binding_blake3.as_ref(),
        )?;
        validate_release_basis_id(&request.release_basis_id)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        let local_binding = request
            .local_binding_blake3
            .as_ref()
            .map(|digest| &digest[..]);
        let expected_state = match request.adjudication_kind {
            ContinuityAdjudicationKind::NoLocalEffect => ContinuityState::AdjudicatedNoLocalEffect,
            ContinuityAdjudicationKind::NoDispatch => ContinuityState::AdjudicatedNoDispatch,
        };
        run_serializable_mutation!(
            self,
            COMPLETE_ADJUDICATION_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &local_binding,
                &&request.terminal_evidence_blake3[..],
                &request.adjudication_kind.as_sql(),
                &request.adjudication_kind.final_state_sql(),
                &request.release_id,
                &request.release_basis_id,
                &&request.release_basis_blake3[..],
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    expected_state,
                    ContinuityOwnershipState::OwnershipReleased,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Record exact local durability coverage without installing or deriving local evidence.
    pub async fn record_snapshot(
        &self,
        request: &RecordSnapshotRequest,
    ) -> Result<RecordSnapshotResult, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.authority_epoch == 0
            || request.continuity_seq == 0
            || request.through_continuity_seq < request.continuity_seq
        {
            return Err(ContinuityError::InvalidConfiguration(
                "snapshot identity and coverage must be valid",
            ));
        }
        let epoch = request.authority_epoch.to_string();
        let through_sequence = request.through_continuity_seq.to_string();
        let sequence = request.continuity_seq.to_string();
        let counter_revision = request.local_counter_revision.to_string();
        let authority_lsn = PgLsn::from(request.authority_lsn);
        run_serializable_mutation!(
            self,
            RECORD_SNAPSHOT_SQL,
            &[
                &API_REVISION,
                &request.snapshot_id,
                &request.provider_boundary_id,
                &epoch,
                &through_sequence,
                &authority_lsn,
                &&request.manifest_blake3[..],
                &sequence,
                &request.continuity_token_id,
                &&request.local_binding_blake3[..],
                &&request.local_state_blake3[..],
                &&request.local_quota_ownership_blake3[..],
                &counter_revision,
            ],
            |row: &Row| {
                let result = parse_snapshot_result(row)?;
                if result.accepted_snapshot_id != request.snapshot_id
                    || result.accepted_through_continuity_seq != request.through_continuity_seq
                    || result.accepted_manifest_blake3 != request.manifest_blake3
                {
                    return Err(ContinuityError::InvalidResponse(
                        "snapshot result identity is inconsistent",
                    ));
                }
                Ok(result)
            },
            |precommit| self.reconcile_snapshot_commit(request, precommit)
        )
    }

    /// Release BOUND or COMPLETED ownership only from exact accepted snapshot coverage.
    pub async fn release_shadow_ownership(
        &self,
        request: &ReleaseShadowOwnershipRequest,
    ) -> Result<ContinuityProcedureResult, ContinuityError> {
        validate_identity(&request.identity)?;
        let epoch = request.identity.authority_epoch.to_string();
        let sequence = request.identity.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            RELEASE_SHADOW_OWNERSHIP_SQL,
            &[
                &API_REVISION,
                &request.identity.provider_boundary_id,
                &epoch,
                &sequence,
                &request.identity.continuity_token_id,
                &request.identity.authenticated_cell_id,
                &request.identity.authenticated_tenant_id,
                &request.identity.logical_request_id,
                &request.identity.attempt_id,
                &request.identity.intent_kind.as_sql(),
                &&request.identity.selected_fingerprint[..],
                &&request.expected_prior_row_blake3[..],
                &request.expected_state.as_sql(),
                &request.snapshot_id,
                &&request.expected_manifest_blake3[..],
                &&request.expected_coverage_blake3[..],
                &request.release_id,
            ],
            |row: &Row| {
                let result = parse_procedure_result(row)?;
                validate_transition_result(
                    &result,
                    &request.identity,
                    request.expected_state.as_state(),
                    ContinuityOwnershipState::OwnershipReleased,
                )?;
                Ok(result)
            },
            |precommit| {
                self.reconcile_token_transition_commit(
                    &request.identity,
                    &request.expected_prior_row_blake3,
                    precommit,
                )
            }
        )
    }

    /// Read one boundary's exact current reconciliation counters and latest snapshot.
    pub async fn read_reconciliation_state(
        &self,
        provider_boundary_id: &str,
        authority_epoch: u64,
    ) -> Result<Option<ReconciliationState>, ContinuityError> {
        if provider_boundary_id.is_empty() || authority_epoch == 0 {
            return Err(ContinuityError::InvalidConfiguration(
                "reconciliation identity must be valid",
            ));
        }
        let epoch = authority_epoch.to_string();
        run_bounded_read!(
            self,
            query_opt,
            READ_RECONCILIATION_STATE_SQL,
            &[&API_REVISION, &provider_boundary_id, &epoch],
            |row: Option<Row>| {
                row.map(|row| {
                    let state = parse_reconciliation_state(&row)?;
                    if state.current_authority_epoch != authority_epoch {
                        return Err(ContinuityError::InvalidResponse(
                            "reconciliation epoch is inconsistent",
                        ));
                    }
                    Ok(state)
                })
                .transpose()
            }
        )
    }

    /// Read the current epoch and its gapless continuity sequence high-water.
    pub async fn read_epoch(
        &self,
        provider_boundary_id: &str,
    ) -> Result<Option<ContinuityEpochState>, ContinuityError> {
        if provider_boundary_id.is_empty() {
            return Err(ContinuityError::InvalidConfiguration(
                "provider boundary ID must be nonempty",
            ));
        }
        run_bounded_read!(
            self,
            query_opt,
            READ_EPOCH_SQL,
            &[&API_REVISION, &provider_boundary_id],
            |row: Option<Row>| row.map(|row| parse_epoch_state(&row)).transpose()
        )
    }

    /// Allocate a strictly newer epoch only after the authority proves the current epoch drained.
    pub async fn allocate_epoch(
        &self,
        request: &AllocateEpochRequest,
    ) -> Result<ContinuityEpochState, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.expected_current_epoch == 0
            || request.next_epoch <= request.expected_current_epoch
        {
            return Err(ContinuityError::InvalidConfiguration(
                "epoch allocation identity and ordering must be valid",
            ));
        }
        let expected_current_epoch = request.expected_current_epoch.to_string();
        let next_epoch = request.next_epoch.to_string();
        run_serializable_mutation!(
            self,
            ALLOCATE_EPOCH_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &expected_current_epoch,
                &next_epoch,
                &&request.epoch_namespace_blake3[..],
            ],
            |row: &Row| {
                let result = parse_epoch_state(row)?;
                if result.authority_epoch != request.next_epoch
                    || result.continuity_seq_high_water != 0
                {
                    return Err(ContinuityError::InvalidResponse(
                        "allocated epoch result is inconsistent",
                    ));
                }
                Ok(result)
            },
            |precommit| self.reconcile_epoch_allocation_commit(request, precommit)
        )
    }

    /// Read one exact canonical shadow-release receipt without granting table access.
    pub async fn read_shadow_release_receipt(
        &self,
        request: &ReadShadowReleaseReceiptRequest,
    ) -> Result<Option<ShadowReleaseReceipt>, ContinuityError> {
        if request.provider_boundary_id.is_empty()
            || request.authority_epoch == 0
            || request.continuity_seq == 0
        {
            return Err(ContinuityError::InvalidConfiguration(
                "shadow release receipt identity must be valid",
            ));
        }
        let epoch = request.authority_epoch.to_string();
        let sequence = request.continuity_seq.to_string();
        run_bounded_read!(
            self,
            query_opt,
            READ_SHADOW_RELEASE_RECEIPT_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &epoch,
                &sequence,
                &request.continuity_token_id,
            ],
            |row: Option<Row>| {
                row.map(|row| {
                    let receipt = parse_shadow_release_receipt(&row)?;
                    if receipt.provider_boundary_id != request.provider_boundary_id
                        || receipt.authority_epoch != request.authority_epoch
                        || receipt.continuity_seq != request.continuity_seq
                        || receipt.continuity_token_id != request.continuity_token_id
                    {
                        return Err(ContinuityError::InvalidResponse(
                            "shadow release receipt identity is inconsistent",
                        ));
                    }
                    Ok(receipt)
                })
                .transpose()
            }
        )
    }

    /// Replace one exact eligible terminal detail row with its bounded authenticated interval.
    pub async fn archive_prune(
        &self,
        request: &ArchivePruneRequest,
    ) -> Result<ArchivePruneResult, ContinuityError> {
        validate_archive_prune_request(request)?;
        let epoch = request.authority_epoch.to_string();
        let sequence = request.continuity_seq.to_string();
        run_serializable_mutation!(
            self,
            ARCHIVE_PRUNE_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &epoch,
                &sequence,
                &request.continuity_token_id,
                &&request.expected_row_blake3[..],
                &&request.expected_release_receipt_blake3[..],
                &&request.archive_proof_bytes[..],
                &&request.archive_proof_blake3[..],
            ],
            |row: &Row| {
                let result = parse_archive_prune_result(row)?;
                validate_archive_prune_result_for_sequence(&result, request.continuity_seq)?;
                Ok(result)
            },
            |precommit| self.reconcile_archive_commit(request, precommit)
        )
    }

    /// Read and validate the authenticated pruned interval containing one exact sequence.
    pub async fn read_pruned_interval(
        &self,
        request: &ReadPrunedIntervalRequest,
    ) -> Result<PrunedInterval, ContinuityError> {
        validate_read_pruned_interval_request(request)?;
        let epoch = request.authority_epoch.to_string();
        let sequence = request.continuity_seq.to_string();
        run_bounded_read!(
            self,
            query_one,
            READ_PRUNED_INTERVAL_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &epoch,
                &sequence,
                &SCHEMA_REVISION,
                &CONTINUITY_CONTRACT_REVISION,
                &request.expected_continuity_policy_revision,
                &&request.expected_epoch_namespace_blake3[..],
            ],
            |row: Row| {
                let interval = parse_pruned_interval(&row)?;
                validate_pruned_interval(&interval, request)?;
                Ok(interval)
            }
        )
    }

    /// Replace one fully covered old-epoch interval with its canonical retired summary.
    pub async fn retire_epoch(
        &self,
        request: &RetireEpochRequest,
    ) -> Result<RetiredEpochSummary, ContinuityError> {
        validate_retire_epoch_request(request)?;
        let epoch = request.authority_epoch.to_string();
        run_serializable_mutation!(
            self,
            RETIRE_EPOCH_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &epoch,
                &&request.expected_epoch_namespace_blake3[..],
                &&request.expected_interval_checkpoint_blake3[..],
                &request.covering_snapshot_id,
                &&request.expected_snapshot_manifest_blake3[..],
                &&request.retirement_proof_bytes[..],
                &&request.retirement_proof_blake3[..],
            ],
            |row: &Row| {
                let summary = parse_retired_epoch_summary(row)?;
                validate_retired_epoch_summary_for_retirement(&summary, request)?;
                Ok(summary)
            },
            |precommit| self.reconcile_retirement_commit(request, precommit)
        )
    }

    /// Read and validate one authenticated retired namespace checkpoint.
    pub async fn read_retired_epoch(
        &self,
        request: &ReadRetiredEpochRequest,
    ) -> Result<RetiredEpochSummary, ContinuityError> {
        validate_read_retired_epoch_request(request)?;
        let epoch = request.authority_epoch.to_string();
        run_bounded_read!(
            self,
            query_one,
            READ_RETIRED_EPOCH_SQL,
            &[
                &API_REVISION,
                &request.provider_boundary_id,
                &epoch,
                &SCHEMA_REVISION,
                &CONTINUITY_CONTRACT_REVISION,
                &request.expected_continuity_policy_revision,
                &&request.expected_epoch_namespace_blake3[..],
            ],
            |row: Row| {
                let summary = parse_retired_epoch_summary(&row)?;
                validate_retired_epoch_summary_namespace(
                    &summary,
                    &request.provider_boundary_id,
                    request.authority_epoch,
                    &request.expected_continuity_policy_revision,
                )?;
                Ok(summary)
            }
        )
    }
}

fn validate_begin_result(
    result: &ContinuityProcedureResult,
    request: &BeginIntentRequest,
) -> Result<(), ContinuityError> {
    match result.result_code {
        ContinuityResultCode::Created
            if result.state == ContinuityState::Intent
                && result.ownership_state == ContinuityOwnershipState::ShadowReserved => {}
        ContinuityResultCode::Replay if valid_state_ownership_pair(result) => {}
        ContinuityResultCode::Created | ContinuityResultCode::Replay => {
            return Err(ContinuityError::InvalidResponse(
                "begin result state is inconsistent",
            ));
        }
        ContinuityResultCode::Found | ContinuityResultCode::Updated => {
            return Err(ContinuityError::InvalidResponse(
                "begin result code is unsupported",
            ));
        }
    }
    if result.authority_epoch != request.expected_authority_epoch
        || result.continuity_token_id != request.continuity_token_id
    {
        return Err(ContinuityError::InvalidResponse(
            "begin result identity is inconsistent",
        ));
    }
    Ok(())
}

fn valid_state_ownership_pair(result: &ContinuityProcedureResult) -> bool {
    match result.state {
        ContinuityState::Intent
        | ContinuityState::Quarantined
        | ContinuityState::AmbiguousDispatch
        | ContinuityState::AdjudicationPrepared => {
            result.ownership_state == ContinuityOwnershipState::ShadowReserved
        }
        ContinuityState::NoLocalEffect
        | ContinuityState::AdjudicatedNoLocalEffect
        | ContinuityState::AdjudicatedNoDispatch => {
            result.ownership_state == ContinuityOwnershipState::OwnershipReleased
        }
        ContinuityState::Bound | ContinuityState::Completed => true,
    }
}

fn validate_lookup_result(result: &ContinuityProcedureResult) -> Result<(), ContinuityError> {
    if result.result_code != ContinuityResultCode::Found {
        return Err(ContinuityError::InvalidResponse(
            "token lookup result code is unsupported",
        ));
    }
    Ok(())
}

fn validate_transition_result(
    result: &ContinuityProcedureResult,
    identity: &ContinuityIntentIdentity,
    expected_state: ContinuityState,
    expected_ownership: ContinuityOwnershipState,
) -> Result<(), ContinuityError> {
    if !matches!(
        result.result_code,
        ContinuityResultCode::Updated | ContinuityResultCode::Replay
    ) {
        return Err(ContinuityError::InvalidResponse(
            "transition result code is unsupported",
        ));
    }
    if result.state != expected_state || result.ownership_state != expected_ownership {
        return Err(ContinuityError::InvalidResponse(
            "transition result state is inconsistent",
        ));
    }
    if result.authority_epoch != identity.authority_epoch
        || result.continuity_seq != identity.continuity_seq
        || result.continuity_token_id != identity.continuity_token_id
    {
        return Err(ContinuityError::InvalidResponse(
            "transition result identity is inconsistent",
        ));
    }
    Ok(())
}

fn validate_adjudication_binding(
    kind: ContinuityAdjudicationKind,
    local_binding_blake3: Option<&[u8; 32]>,
) -> Result<(), ContinuityError> {
    match (kind, local_binding_blake3) {
        (ContinuityAdjudicationKind::NoLocalEffect, None)
        | (ContinuityAdjudicationKind::NoDispatch, Some(_)) => Ok(()),
        (ContinuityAdjudicationKind::NoLocalEffect, Some(_)) => {
            Err(ContinuityError::InvalidConfiguration(
                "no-local-effect adjudication forbids a local binding",
            ))
        }
        (ContinuityAdjudicationKind::NoDispatch, None) => {
            Err(ContinuityError::InvalidConfiguration(
                "no-dispatch adjudication requires a local binding",
            ))
        }
    }
}

fn validate_release_basis_id(release_basis_id: &str) -> Result<(), ContinuityError> {
    if release_basis_id.is_empty() {
        return Err(ContinuityError::InvalidConfiguration(
            "release basis ID must be nonempty",
        ));
    }
    Ok(())
}

fn validate_identity(identity: &ContinuityIntentIdentity) -> Result<(), ContinuityError> {
    if identity.authority_epoch == 0 || identity.continuity_seq == 0 {
        return Err(ContinuityError::InvalidConfiguration(
            "authority epoch and continuity sequence must be positive",
        ));
    }
    if identity.provider_boundary_id.is_empty()
        || identity.authenticated_cell_id.is_empty()
        || identity.authenticated_tenant_id.is_empty()
    {
        return Err(ContinuityError::InvalidConfiguration(
            "continuity intent identity text must be nonempty",
        ));
    }
    Ok(())
}

fn parse_snapshot_result(row: &Row) -> Result<RecordSnapshotResult, ContinuityError> {
    let recorded_at_unix_ms = row
        .try_get::<_, i64>(4)
        .map_err(|_| ContinuityError::InvalidResponse("snapshot time is not bigint"))?;
    if recorded_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "snapshot time must be nonnegative",
        ));
    }
    Ok(RecordSnapshotResult {
        accepted_snapshot_id: row
            .try_get(0)
            .map_err(|_| ContinuityError::InvalidResponse("snapshot ID is not UUID"))?,
        accepted_through_continuity_seq: parse_u64_text(row, 1)?,
        accepted_manifest_blake3: parse_digest(
            row.try_get(2)
                .map_err(|_| ContinuityError::InvalidResponse("manifest digest is not bytea"))?,
        )?,
        accepted_coverage_blake3: parse_digest(
            row.try_get(3)
                .map_err(|_| ContinuityError::InvalidResponse("coverage digest is not bytea"))?,
        )?,
        recorded_at_unix_ms,
    })
}

fn parse_reconciliation_state(row: &Row) -> Result<ReconciliationState, ContinuityError> {
    let current_authority_epoch = parse_u64_text(row, 0)?;
    if current_authority_epoch == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch must be positive",
        ));
    }
    let snapshot_id = row
        .try_get::<_, Option<Uuid>>(5)
        .map_err(|_| ContinuityError::InvalidResponse("latest snapshot ID is not nullable UUID"))?;
    let snapshot_sequence = row.try_get::<_, Option<String>>(6).map_err(|_| {
        ContinuityError::InvalidResponse("latest snapshot sequence is not nullable text")
    })?;
    let snapshot_digest = row.try_get::<_, Option<Vec<u8>>>(7).map_err(|_| {
        ContinuityError::InvalidResponse("latest snapshot digest is not nullable bytea")
    })?;
    let latest_snapshot = match (snapshot_id, snapshot_sequence, snapshot_digest) {
        (None, None, None) => None,
        (Some(snapshot_id), Some(sequence), Some(digest)) => {
            let through_continuity_seq = parse_u64_text_value(&sequence)?;
            if through_continuity_seq == 0 {
                return Err(ContinuityError::InvalidResponse(
                    "latest snapshot sequence must be positive",
                ));
            }
            Some(ReconciliationSnapshot {
                snapshot_id,
                through_continuity_seq,
                manifest_blake3: parse_digest(digest)?,
            })
        }
        _ => {
            return Err(ContinuityError::InvalidResponse(
                "latest snapshot evidence is partially null",
            ));
        }
    };
    Ok(ReconciliationState {
        current_authority_epoch,
        continuity_seq_high_water: parse_u64_text(row, 1)?,
        owned_rows: parse_u64_text(row, 2)?,
        owned_bytes: parse_u64_text(row, 3)?,
        owned_concurrency: parse_u64_text(row, 4)?,
        latest_snapshot,
    })
}

fn parse_epoch_state(row: &Row) -> Result<ContinuityEpochState, ContinuityError> {
    let authority_epoch = parse_u64_text(row, 0)?;
    if authority_epoch == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch must be positive",
        ));
    }
    Ok(ContinuityEpochState {
        authority_epoch,
        continuity_seq_high_water: parse_u64_text(row, 1)?,
    })
}

fn parse_shadow_release_receipt(row: &Row) -> Result<ShadowReleaseReceipt, ContinuityError> {
    let released_at_unix_ms = row
        .try_get::<_, i64>(6)
        .map_err(|_| ContinuityError::InvalidResponse("release receipt time is invalid"))?;
    if released_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "release receipt time must be nonnegative",
        ));
    }
    Ok(ShadowReleaseReceipt {
        provider_boundary_id: row
            .try_get(0)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt boundary is invalid"))?,
        authority_epoch: parse_u64_text(row, 1)?,
        continuity_seq: parse_u64_text(row, 2)?,
        continuity_token_id: row
            .try_get(3)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt token is invalid"))?,
        release_id: row
            .try_get(4)
            .map_err(|_| ContinuityError::InvalidResponse("release receipt ID is invalid"))?,
        receipt_blake3: parse_digest(
            row.try_get(5).map_err(|_| {
                ContinuityError::InvalidResponse("release receipt digest is invalid")
            })?,
        )?,
        released_at_unix_ms,
    })
}

fn parse_archive_prune_result(row: &Row) -> Result<ArchivePruneResult, ContinuityError> {
    let result = ArchivePruneResult {
        accepted_start_sequence: parse_u64_text(row, 0)?,
        accepted_end_sequence: parse_u64_text(row, 1)?,
        accepted_row_count: parse_u64_text(row, 2)?,
        prune_commit_sequence: parse_u64_text(row, 3)?,
        accepted_interval_blake3: parse_digest(row.try_get(4).map_err(|_| {
            ContinuityError::InvalidResponse("archive interval digest is invalid")
        })?)?,
    };
    validate_archive_prune_result(&result)?;
    Ok(result)
}

fn parse_pruned_interval(row: &Row) -> Result<PrunedInterval, ContinuityError> {
    let interval = PrunedInterval {
        provider_boundary_id: required_text(row, 0, "pruned interval boundary is invalid")?,
        authority_epoch: parse_u64_text(row, 1)?,
        start_sequence: parse_u64_text(row, 2)?,
        end_sequence: parse_u64_text(row, 3)?,
        row_count: parse_u64_text(row, 4)?,
        api_revision: required_text(row, 5, "pruned interval API revision is invalid")?,
        schema_revision: required_text(row, 6, "pruned interval schema revision is invalid")?,
        continuity_contract_revision: required_text(
            row,
            7,
            "pruned interval contract revision is invalid",
        )?,
        continuity_policy_revision: required_text(
            row,
            8,
            "pruned interval policy revision is invalid",
        )?,
        completed_count: parse_u64_text(row, 9)?,
        no_local_effect_count: parse_u64_text(row, 10)?,
        adjudicated_no_local_effect_count: parse_u64_text(row, 11)?,
        adjudicated_no_dispatch_count: parse_u64_text(row, 12)?,
        canonical_row_bytes_sum: parse_u64_text(row, 13)?,
        canonical_row_bytes_min: parse_u64_text(row, 14)?,
        canonical_row_bytes_max: parse_u64_text(row, 15)?,
        quota_rows_sum: parse_u64_text(row, 16)?,
        quota_rows_min: parse_u64_text(row, 17)?,
        quota_rows_max: parse_u64_text(row, 18)?,
        quota_bytes_sum: parse_u64_text(row, 19)?,
        quota_bytes_min: parse_u64_text(row, 20)?,
        quota_bytes_max: parse_u64_text(row, 21)?,
        quota_concurrency_sum: parse_u64_text(row, 22)?,
        quota_concurrency_min: parse_u64_text(row, 23)?,
        quota_concurrency_max: parse_u64_text(row, 24)?,
        created_at_min_unix_ms: parse_i64(row, 25, "pruned interval created minimum is invalid")?,
        created_at_max_unix_ms: parse_i64(row, 26, "pruned interval created maximum is invalid")?,
        closed_at_min_unix_ms: parse_i64(row, 27, "pruned interval closed minimum is invalid")?,
        closed_at_max_unix_ms: parse_i64(row, 28, "pruned interval closed maximum is invalid")?,
        prune_commit_sequence_min: parse_u64_text(row, 29)?,
        prune_commit_sequence_max: parse_u64_text(row, 30)?,
        pruned_at_min_unix_ms: parse_i64(row, 31, "pruned interval pruned minimum is invalid")?,
        pruned_at_max_unix_ms: parse_i64(row, 32, "pruned interval pruned maximum is invalid")?,
        canonical_interval_bytes: row.try_get(33).map_err(|_| {
            ContinuityError::InvalidResponse("pruned interval canonical bytes are invalid")
        })?,
        interval_blake3: parse_digest(
            row.try_get(34).map_err(|_| {
                ContinuityError::InvalidResponse("pruned interval digest is invalid")
            })?,
        )?,
    };
    validate_pruned_interval_shape(&interval)?;
    Ok(interval)
}

fn parse_retired_epoch_summary(row: &Row) -> Result<RetiredEpochSummary, ContinuityError> {
    let covering_snapshot_authority_lsn = row
        .try_get::<_, PgLsn>(23)
        .map_err(|_| ContinuityError::InvalidResponse("retired epoch snapshot LSN is invalid"))?;
    let summary = RetiredEpochSummary {
        provider_boundary_id: required_text(row, 0, "retired epoch boundary is invalid")?,
        authority_epoch: parse_u64_text(row, 1)?,
        start_sequence: parse_u64_text(row, 2)?,
        final_sequence: parse_u64_text(row, 3)?,
        row_count: parse_u64_text(row, 4)?,
        api_revision: required_text(row, 5, "retired epoch API revision is invalid")?,
        schema_revision: required_text(row, 6, "retired epoch schema revision is invalid")?,
        continuity_contract_revision: required_text(
            row,
            7,
            "retired epoch contract revision is invalid",
        )?,
        continuity_policy_revision: required_text(
            row,
            8,
            "retired epoch policy revision is invalid",
        )?,
        completed_count: parse_u64_text(row, 9)?,
        no_local_effect_count: parse_u64_text(row, 10)?,
        adjudicated_no_local_effect_count: parse_u64_text(row, 11)?,
        adjudicated_no_dispatch_count: parse_u64_text(row, 12)?,
        interval_checkpoint_blake3: parse_digest(row.try_get(13).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch interval digest is invalid")
        })?)?,
        created_at_min_unix_ms: parse_i64(row, 14, "retired epoch created minimum is invalid")?,
        created_at_max_unix_ms: parse_i64(row, 15, "retired epoch created maximum is invalid")?,
        closed_at_min_unix_ms: parse_i64(row, 16, "retired epoch closed minimum is invalid")?,
        closed_at_max_unix_ms: parse_i64(row, 17, "retired epoch closed maximum is invalid")?,
        pruned_at_min_unix_ms: parse_i64(row, 18, "retired epoch pruned minimum is invalid")?,
        pruned_at_max_unix_ms: parse_i64(row, 19, "retired epoch pruned maximum is invalid")?,
        prune_commit_sequence_max: parse_u64_text(row, 20)?,
        covering_snapshot_id: row.try_get(21).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch snapshot ID is invalid")
        })?,
        covering_snapshot_through_sequence: parse_u64_text(row, 22)?,
        covering_snapshot_authority_lsn: covering_snapshot_authority_lsn.into(),
        covering_snapshot_manifest_blake3: parse_digest(row.try_get(24).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch snapshot manifest is invalid")
        })?)?,
        retirement_proof_blake3: parse_digest(row.try_get(25).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch proof digest is invalid")
        })?)?,
        canonical_summary_bytes: row.try_get(26).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch canonical bytes are invalid")
        })?,
        summary_blake3: parse_digest(row.try_get(27).map_err(|_| {
            ContinuityError::InvalidResponse("retired epoch summary digest is invalid")
        })?)?,
        retired_at_unix_ms: parse_i64(row, 28, "retired epoch time is invalid")?,
    };
    validate_retired_epoch_summary_shape(&summary)?;
    Ok(summary)
}

fn validate_archive_prune_request(request: &ArchivePruneRequest) -> Result<(), ContinuityError> {
    if request.provider_boundary_id.is_empty()
        || request.expected_continuity_policy_revision.is_empty()
        || request.authority_epoch == 0
        || request.continuity_seq == 0
        || request.archive_proof_bytes.is_empty()
        || request.archive_proof_bytes.len() > MAX_ARCHIVE_PROOF_BYTES
    {
        return Err(ContinuityError::InvalidConfiguration(
            "archive identity and proof must be valid",
        ));
    }
    Ok(())
}

fn validate_archive_prune_result(result: &ArchivePruneResult) -> Result<(), ContinuityError> {
    let expected_row_count = result
        .accepted_end_sequence
        .checked_sub(result.accepted_start_sequence)
        .and_then(|width| width.checked_add(1));
    if result.accepted_start_sequence == 0
        || result.accepted_end_sequence == 0
        || result.accepted_row_count == 0
        || result.prune_commit_sequence == 0
        || expected_row_count != Some(result.accepted_row_count)
    {
        return Err(ContinuityError::InvalidResponse(
            "archive interval result is inconsistent",
        ));
    }
    Ok(())
}

fn validate_archive_prune_result_for_sequence(
    result: &ArchivePruneResult,
    requested_sequence: u64,
) -> Result<(), ContinuityError> {
    if requested_sequence < result.accepted_start_sequence
        || requested_sequence > result.accepted_end_sequence
    {
        return Err(ContinuityError::InvalidResponse(
            "archive result does not cover the requested sequence",
        ));
    }
    Ok(())
}

fn validate_read_pruned_interval_request(
    request: &ReadPrunedIntervalRequest,
) -> Result<(), ContinuityError> {
    if request.provider_boundary_id.is_empty()
        || request.authority_epoch == 0
        || request.continuity_seq == 0
        || request.expected_continuity_policy_revision.is_empty()
    {
        return Err(ContinuityError::InvalidConfiguration(
            "pruned interval read identity and policy must be valid",
        ));
    }
    Ok(())
}

fn validate_pruned_interval(
    interval: &PrunedInterval,
    request: &ReadPrunedIntervalRequest,
) -> Result<(), ContinuityError> {
    if interval.provider_boundary_id != request.provider_boundary_id
        || interval.authority_epoch != request.authority_epoch
        || request.continuity_seq < interval.start_sequence
        || request.continuity_seq > interval.end_sequence
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval identity is inconsistent",
        ));
    }
    if interval.api_revision != API_REVISION
        || interval.schema_revision != SCHEMA_REVISION
        || interval.continuity_contract_revision != CONTINUITY_CONTRACT_REVISION
        || interval.continuity_policy_revision != request.expected_continuity_policy_revision
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval revision is inconsistent",
        ));
    }
    Ok(())
}

fn validate_pruned_interval_shape(interval: &PrunedInterval) -> Result<(), ContinuityError> {
    let expected_row_count = interval
        .end_sequence
        .checked_sub(interval.start_sequence)
        .and_then(|width| width.checked_add(1));
    if interval.start_sequence == 0
        || interval.end_sequence == 0
        || interval.row_count == 0
        || expected_row_count != Some(interval.row_count)
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval range is inconsistent",
        ));
    }

    let terminal_count = [
        interval.completed_count,
        interval.no_local_effect_count,
        interval.adjudicated_no_local_effect_count,
        interval.adjudicated_no_dispatch_count,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add);
    if terminal_count != Some(interval.row_count) {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval terminal counts are inconsistent",
        ));
    }

    if interval.canonical_row_bytes_min > interval.canonical_row_bytes_max
        || interval.quota_rows_min > interval.quota_rows_max
        || interval.quota_bytes_min > interval.quota_bytes_max
        || interval.quota_concurrency_min > interval.quota_concurrency_max
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval aggregate bounds are inconsistent",
        ));
    }

    if interval.created_at_min_unix_ms < 0
        || interval.created_at_min_unix_ms > interval.created_at_max_unix_ms
        || interval.closed_at_min_unix_ms < 0
        || interval.closed_at_min_unix_ms > interval.closed_at_max_unix_ms
        || interval.pruned_at_min_unix_ms < 0
        || interval.pruned_at_min_unix_ms > interval.pruned_at_max_unix_ms
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval time bounds are inconsistent",
        ));
    }

    if interval.prune_commit_sequence_min == 0
        || interval.prune_commit_sequence_min > interval.prune_commit_sequence_max
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval prune sequence bounds are inconsistent",
        ));
    }

    if interval.canonical_interval_bytes.len() <= interval.interval_blake3.len()
        || !interval
            .canonical_interval_bytes
            .ends_with(&interval.interval_blake3)
    {
        return Err(ContinuityError::InvalidResponse(
            "pruned interval canonical evidence is inconsistent",
        ));
    }
    Ok(())
}

fn validate_retire_epoch_request(request: &RetireEpochRequest) -> Result<(), ContinuityError> {
    if request.provider_boundary_id.is_empty()
        || request.authority_epoch == 0
        || request.expected_continuity_policy_revision.is_empty()
        || request.retirement_proof_bytes.is_empty()
        || request.retirement_proof_bytes.len() > MAX_RETIREMENT_PROOF_BYTES
    {
        return Err(ContinuityError::InvalidConfiguration(
            "epoch retirement identity and proof must be valid",
        ));
    }
    Ok(())
}

fn validate_read_retired_epoch_request(
    request: &ReadRetiredEpochRequest,
) -> Result<(), ContinuityError> {
    if request.provider_boundary_id.is_empty()
        || request.authority_epoch == 0
        || request.expected_continuity_policy_revision.is_empty()
    {
        return Err(ContinuityError::InvalidConfiguration(
            "retired epoch read identity and policy must be valid",
        ));
    }
    Ok(())
}

fn validate_retired_epoch_summary_namespace(
    summary: &RetiredEpochSummary,
    provider_boundary_id: &str,
    authority_epoch: u64,
    expected_continuity_policy_revision: &str,
) -> Result<(), ContinuityError> {
    if summary.provider_boundary_id != provider_boundary_id
        || summary.authority_epoch != authority_epoch
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch identity is inconsistent",
        ));
    }
    if summary.api_revision != API_REVISION
        || summary.schema_revision != SCHEMA_REVISION
        || summary.continuity_contract_revision != CONTINUITY_CONTRACT_REVISION
        || summary.continuity_policy_revision != expected_continuity_policy_revision
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch revision is inconsistent",
        ));
    }
    Ok(())
}

fn validate_retired_epoch_summary_for_retirement(
    summary: &RetiredEpochSummary,
    request: &RetireEpochRequest,
) -> Result<(), ContinuityError> {
    validate_retired_epoch_summary_namespace(
        summary,
        &request.provider_boundary_id,
        request.authority_epoch,
        &request.expected_continuity_policy_revision,
    )?;
    if summary.interval_checkpoint_blake3 != request.expected_interval_checkpoint_blake3
        || summary.covering_snapshot_id != request.covering_snapshot_id
        || summary.covering_snapshot_manifest_blake3 != request.expected_snapshot_manifest_blake3
        || summary.retirement_proof_blake3 != request.retirement_proof_blake3
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch checkpoint evidence is inconsistent",
        ));
    }
    Ok(())
}

fn validate_retired_epoch_summary_shape(
    summary: &RetiredEpochSummary,
) -> Result<(), ContinuityError> {
    let expected_row_count = summary
        .final_sequence
        .checked_sub(summary.start_sequence)
        .and_then(|width| width.checked_add(1));
    if summary.authority_epoch == 0
        || summary.start_sequence != 1
        || summary.final_sequence == 0
        || summary.row_count == 0
        || expected_row_count != Some(summary.row_count)
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch range is inconsistent",
        ));
    }

    let terminal_count = [
        summary.completed_count,
        summary.no_local_effect_count,
        summary.adjudicated_no_local_effect_count,
        summary.adjudicated_no_dispatch_count,
    ]
    .into_iter()
    .try_fold(0_u64, u64::checked_add);
    if terminal_count != Some(summary.row_count) {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch terminal counts are inconsistent",
        ));
    }

    if summary.created_at_min_unix_ms < 0
        || summary.created_at_min_unix_ms > summary.created_at_max_unix_ms
        || summary.closed_at_min_unix_ms < 0
        || summary.closed_at_min_unix_ms > summary.closed_at_max_unix_ms
        || summary.pruned_at_min_unix_ms < 0
        || summary.pruned_at_min_unix_ms > summary.pruned_at_max_unix_ms
        || summary.retired_at_unix_ms < summary.pruned_at_max_unix_ms
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch time bounds are inconsistent",
        ));
    }

    if summary.prune_commit_sequence_max == 0
        || summary.covering_snapshot_through_sequence < summary.final_sequence
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch checkpoint bounds are inconsistent",
        ));
    }

    if summary.canonical_summary_bytes.len() <= summary.summary_blake3.len()
        || !summary
            .canonical_summary_bytes
            .ends_with(&summary.summary_blake3)
    {
        return Err(ContinuityError::InvalidResponse(
            "retired epoch canonical evidence is inconsistent",
        ));
    }
    Ok(())
}

fn parse_procedure_result(row: &Row) -> Result<ContinuityProcedureResult, ContinuityError> {
    let authority_epoch = parse_u64_text(row, 3)?;
    let continuity_seq = parse_u64_text(row, 4)?;
    if authority_epoch == 0 || continuity_seq == 0 {
        return Err(ContinuityError::InvalidResponse(
            "authority epoch and continuity sequence must be positive",
        ));
    }
    let digest = row
        .try_get::<_, Vec<u8>>(6)
        .map_err(|_| ContinuityError::InvalidResponse("row digest is not bytea"))?;
    let row_blake3 = parse_digest(digest)?;
    let committed_at = row
        .try_get::<_, i64>(7)
        .map_err(|_| ContinuityError::InvalidResponse("commit time is not bigint"))?;
    if committed_at < 0 {
        return Err(ContinuityError::InvalidResponse(
            "commit time must be nonnegative",
        ));
    }
    Ok(ContinuityProcedureResult {
        result_code: parse_result_code(&required_text(row, 0, "result code is missing")?)?,
        state: parse_state(&required_text(row, 1, "state is missing")?)?,
        ownership_state: parse_ownership_state(&required_text(
            row,
            2,
            "ownership state is missing",
        )?)?,
        authority_epoch,
        continuity_seq,
        continuity_token_id: row
            .try_get(5)
            .map_err(|_| ContinuityError::InvalidResponse("continuity token is not UUID"))?,
        row_blake3,
        external_committed_at_unix_ms: committed_at,
    })
}

fn parse_token_lookup(row: &Row) -> Result<ContinuityTokenLookup, ContinuityError> {
    let result_code = required_text(row, 0, "result code is missing")?;
    if result_code != "NOT_FOUND" {
        return parse_procedure_result(row).map(ContinuityTokenLookup::Found);
    }
    let state = row
        .try_get::<_, Option<String>>(1)
        .map_err(|_| ContinuityError::InvalidResponse("not-found state is not nullable text"))?;
    let ownership = row.try_get::<_, Option<String>>(2).map_err(|_| {
        ContinuityError::InvalidResponse("not-found ownership is not nullable text")
    })?;
    let authority_epoch = row.try_get::<_, Option<String>>(3).map_err(|_| {
        ContinuityError::InvalidResponse("not-found authority epoch is not nullable text")
    })?;
    let continuity_seq = row.try_get::<_, Option<String>>(4).map_err(|_| {
        ContinuityError::InvalidResponse("not-found continuity sequence is not nullable text")
    })?;
    let row_blake3 = row.try_get::<_, Option<Vec<u8>>>(6).map_err(|_| {
        ContinuityError::InvalidResponse("not-found row digest is not nullable bytea")
    })?;
    let observed_at_unix_ms = row
        .try_get::<_, i64>(7)
        .map_err(|_| ContinuityError::InvalidResponse("not-found time is not bigint"))?;
    validate_not_found_shape(
        state.as_deref(),
        ownership.as_deref(),
        authority_epoch.as_deref(),
        continuity_seq.as_deref(),
        row_blake3.as_deref(),
        observed_at_unix_ms,
    )?;
    Ok(ContinuityTokenLookup::NotFound {
        continuity_token_id: row
            .try_get(5)
            .map_err(|_| ContinuityError::InvalidResponse("continuity token is not UUID"))?,
        observed_at_unix_ms,
    })
}

fn validate_not_found_shape(
    state: Option<&str>,
    ownership: Option<&str>,
    authority_epoch: Option<&str>,
    continuity_seq: Option<&str>,
    row_blake3: Option<&[u8]>,
    observed_at_unix_ms: i64,
) -> Result<(), ContinuityError> {
    if state.is_some()
        || ownership.is_some()
        || authority_epoch.is_some()
        || continuity_seq.is_some()
        || row_blake3.is_some()
    {
        return Err(ContinuityError::InvalidResponse(
            "not-found result carries stored-row evidence",
        ));
    }
    if observed_at_unix_ms < 0 {
        return Err(ContinuityError::InvalidResponse(
            "not-found time must be nonnegative",
        ));
    }
    Ok(())
}

fn required_text(
    row: &Row,
    index: usize,
    message: &'static str,
) -> Result<String, ContinuityError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ContinuityError::InvalidResponse(message))?;
    if value.is_empty() {
        return Err(ContinuityError::InvalidResponse(message));
    }
    Ok(value)
}

fn parse_result_code(value: &str) -> Result<ContinuityResultCode, ContinuityError> {
    match value {
        "CREATED" => Ok(ContinuityResultCode::Created),
        "FOUND" => Ok(ContinuityResultCode::Found),
        "REPLAY" => Ok(ContinuityResultCode::Replay),
        "UPDATED" => Ok(ContinuityResultCode::Updated),
        _ => Err(ContinuityError::InvalidResponse(
            "result code is unsupported",
        )),
    }
}

fn parse_state(value: &str) -> Result<ContinuityState, ContinuityError> {
    match value {
        "INTENT" => Ok(ContinuityState::Intent),
        "BOUND" => Ok(ContinuityState::Bound),
        "COMPLETED" => Ok(ContinuityState::Completed),
        "NO_LOCAL_EFFECT" => Ok(ContinuityState::NoLocalEffect),
        "QUARANTINED" => Ok(ContinuityState::Quarantined),
        "AMBIGUOUS_DISPATCH" => Ok(ContinuityState::AmbiguousDispatch),
        "ADJUDICATION_PREPARED" => Ok(ContinuityState::AdjudicationPrepared),
        "ADJUDICATED_NO_LOCAL_EFFECT" => Ok(ContinuityState::AdjudicatedNoLocalEffect),
        "ADJUDICATED_NO_DISPATCH" => Ok(ContinuityState::AdjudicatedNoDispatch),
        _ => Err(ContinuityError::InvalidResponse("state is unsupported")),
    }
}

fn parse_ownership_state(value: &str) -> Result<ContinuityOwnershipState, ContinuityError> {
    match value {
        "SHADOW_RESERVED" => Ok(ContinuityOwnershipState::ShadowReserved),
        "OWNERSHIP_RELEASED" => Ok(ContinuityOwnershipState::OwnershipReleased),
        _ => Err(ContinuityError::InvalidResponse(
            "ownership state is unsupported",
        )),
    }
}

fn parse_u64_text(row: &Row, index: usize) -> Result<u64, ContinuityError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| ContinuityError::InvalidResponse("uint64 field is not text"))?;
    parse_u64_text_value(&value)
}

fn parse_u64_text_value(value: &str) -> Result<u64, ContinuityError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ContinuityError::InvalidResponse("uint64 field is out of range"))?;
    if value != parsed.to_string() {
        return Err(ContinuityError::InvalidResponse(
            "uint64 field is not canonical decimal text",
        ));
    }
    Ok(parsed)
}

fn parse_i64(row: &Row, index: usize, message: &'static str) -> Result<i64, ContinuityError> {
    row.try_get(index)
        .map_err(|_| ContinuityError::InvalidResponse(message))
}

fn parse_digest(value: Vec<u8>) -> Result<[u8; 32], ContinuityError> {
    value
        .try_into()
        .map_err(|_| ContinuityError::InvalidResponse("row digest is not 32 bytes"))
}

fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn postgres_error_is_transient(error: &tokio_postgres::Error) -> bool {
    postgres_error_shape_is_transient(
        error.is_closed(),
        error
            .as_db_error()
            .map(|database_error| database_error.code().code()),
    )
}

fn postgres_error_is_known_aborted_mutation(error: &tokio_postgres::Error) -> bool {
    postgres_error_shape_is_known_aborted_mutation(
        error
            .as_db_error()
            .map(|database_error| database_error.code().code()),
    )
}

fn postgres_error_shape_is_known_aborted_mutation(sqlstate: Option<&str>) -> bool {
    matches!(sqlstate, Some("40001" | "40P01"))
}

fn mutation_retry_delay_for_shape(
    sqlstate: Option<&str>,
    attempt: u8,
    max_retry_attempts: u8,
) -> Option<Duration> {
    if attempt >= max_retry_attempts || !postgres_error_shape_is_known_aborted_mutation(sqlstate) {
        return None;
    }
    bounded_retry_delay(attempt, max_retry_attempts)
}

fn bounded_retry_delay(attempt: u8, max_retry_attempts: u8) -> Option<Duration> {
    if attempt >= max_retry_attempts {
        return None;
    }
    match attempt {
        1 => Some(FIRST_MUTATION_RETRY_DELAY),
        2 => Some(SECOND_MUTATION_RETRY_DELAY),
        _ => None,
    }
}

fn commit_failure_action(
    is_closed: bool,
    sqlstate: Option<&str>,
    attempt: u8,
    max_retry_attempts: u8,
) -> CommitFailureAction {
    if postgres_error_shape_is_known_aborted_mutation(sqlstate) {
        return mutation_retry_delay_for_shape(sqlstate, attempt, max_retry_attempts).map_or(
            CommitFailureAction::Exhausted,
            CommitFailureAction::RetryAfter,
        );
    }
    if is_closed || sqlstate.is_some_and(|code| code.starts_with("08")) {
        return CommitFailureAction::Reconcile;
    }
    CommitFailureAction::Fail
}

fn mutation_timeout_sql(statement_timeout_ms: u64, lock_timeout_ms: u64) -> String {
    format!(
        "SET LOCAL statement_timeout = '{statement_timeout_ms}ms'; \
         SET LOCAL lock_timeout = '{lock_timeout_ms}ms';"
    )
}

fn postgres_error_shape_is_transient(is_closed: bool, sqlstate: Option<&str>) -> bool {
    if is_closed {
        return true;
    }
    let Some(code) = sqlstate else {
        return false;
    };
    code.starts_with("08")
        || code.starts_with("40")
        || code.starts_with("53")
        || code == "57P01"
        || code == "57P03"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> ContinuityIntentIdentity {
        ContinuityIntentIdentity {
            provider_boundary_id: "boundary-a".to_string(),
            authority_epoch: 7,
            continuity_seq: 11,
            continuity_token_id: Uuid::from_u128(13),
            authenticated_cell_id: "cell-a".to_string(),
            authenticated_tenant_id: "tenant-a".to_string(),
            logical_request_id: Uuid::from_u128(17),
            attempt_id: Uuid::from_u128(19),
            intent_kind: ContinuityIntentKind::DispatchCas,
            selected_fingerprint: [0x21; 32],
        }
    }

    fn sample_result(identity: &ContinuityIntentIdentity) -> ContinuityProcedureResult {
        ContinuityProcedureResult {
            result_code: ContinuityResultCode::Updated,
            state: ContinuityState::Quarantined,
            ownership_state: ContinuityOwnershipState::ShadowReserved,
            authority_epoch: identity.authority_epoch,
            continuity_seq: identity.continuity_seq,
            continuity_token_id: identity.continuity_token_id,
            row_blake3: [0x51; 32],
            external_committed_at_unix_ms: 23,
        }
    }

    fn sample_archive_prune_request() -> ArchivePruneRequest {
        ArchivePruneRequest {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            continuity_seq: 11,
            continuity_token_id: Uuid::from_u128(23),
            expected_continuity_policy_revision: "policy-v1".to_string(),
            expected_epoch_namespace_blake3: [0x29; 32],
            expected_row_blake3: [0x31; 32],
            expected_release_receipt_blake3: [0x41; 32],
            archive_proof_bytes: vec![0x51],
            archive_proof_blake3: [0x61; 32],
        }
    }

    fn sample_archive_prune_result() -> ArchivePruneResult {
        ArchivePruneResult {
            accepted_start_sequence: 10,
            accepted_end_sequence: 12,
            accepted_row_count: 3,
            prune_commit_sequence: 5,
            accepted_interval_blake3: [0x71; 32],
        }
    }

    fn sample_read_pruned_interval_request() -> ReadPrunedIntervalRequest {
        ReadPrunedIntervalRequest {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            continuity_seq: 11,
            expected_continuity_policy_revision: "policy-live-test".to_string(),
            expected_epoch_namespace_blake3: [0x81; 32],
        }
    }

    fn sample_pruned_interval() -> PrunedInterval {
        let interval_blake3 = [0x91; 32];
        let mut canonical_interval_bytes = vec![0xA1; 64];
        canonical_interval_bytes.extend_from_slice(&interval_blake3);
        PrunedInterval {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            start_sequence: 10,
            end_sequence: 12,
            row_count: 3,
            api_revision: API_REVISION.to_string(),
            schema_revision: SCHEMA_REVISION.to_string(),
            continuity_contract_revision: CONTINUITY_CONTRACT_REVISION.to_string(),
            continuity_policy_revision: "policy-live-test".to_string(),
            completed_count: 1,
            no_local_effect_count: 1,
            adjudicated_no_local_effect_count: 0,
            adjudicated_no_dispatch_count: 1,
            canonical_row_bytes_sum: 300,
            canonical_row_bytes_min: 90,
            canonical_row_bytes_max: 110,
            quota_rows_sum: 6,
            quota_rows_min: 1,
            quota_rows_max: 3,
            quota_bytes_sum: 60,
            quota_bytes_min: 10,
            quota_bytes_max: 30,
            quota_concurrency_sum: 3,
            quota_concurrency_min: 1,
            quota_concurrency_max: 1,
            created_at_min_unix_ms: 1,
            created_at_max_unix_ms: 3,
            closed_at_min_unix_ms: 4,
            closed_at_max_unix_ms: 6,
            prune_commit_sequence_min: 2,
            prune_commit_sequence_max: 4,
            pruned_at_min_unix_ms: 7,
            pruned_at_max_unix_ms: 9,
            canonical_interval_bytes,
            interval_blake3,
        }
    }

    fn sample_retire_epoch_request() -> RetireEpochRequest {
        RetireEpochRequest {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            expected_continuity_policy_revision: "policy-live-test".to_string(),
            expected_epoch_namespace_blake3: [0x81; 32],
            expected_interval_checkpoint_blake3: [0x91; 32],
            covering_snapshot_id: Uuid::parse_str("018f0000-0000-7000-8000-000000000001")
                .expect("sample snapshot ID must be UUIDv7"),
            expected_snapshot_manifest_blake3: [0xA1; 32],
            retirement_proof_bytes: vec![0xB1],
            retirement_proof_blake3: [0xC1; 32],
        }
    }

    fn sample_read_retired_epoch_request() -> ReadRetiredEpochRequest {
        ReadRetiredEpochRequest {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            expected_continuity_policy_revision: "policy-live-test".to_string(),
            expected_epoch_namespace_blake3: [0x81; 32],
        }
    }

    fn sample_retired_epoch_summary() -> RetiredEpochSummary {
        let summary_blake3 = [0xD1; 32];
        let mut canonical_summary_bytes = vec![0xE1; 64];
        canonical_summary_bytes.extend_from_slice(&summary_blake3);
        RetiredEpochSummary {
            provider_boundary_id: "boundary-live-test".to_string(),
            authority_epoch: 7,
            start_sequence: 1,
            final_sequence: 3,
            row_count: 3,
            api_revision: API_REVISION.to_string(),
            schema_revision: SCHEMA_REVISION.to_string(),
            continuity_contract_revision: CONTINUITY_CONTRACT_REVISION.to_string(),
            continuity_policy_revision: "policy-live-test".to_string(),
            completed_count: 1,
            no_local_effect_count: 1,
            adjudicated_no_local_effect_count: 0,
            adjudicated_no_dispatch_count: 1,
            interval_checkpoint_blake3: [0x91; 32],
            created_at_min_unix_ms: 1,
            created_at_max_unix_ms: 3,
            closed_at_min_unix_ms: 4,
            closed_at_max_unix_ms: 6,
            pruned_at_min_unix_ms: 7,
            pruned_at_max_unix_ms: 9,
            prune_commit_sequence_max: 4,
            covering_snapshot_id: Uuid::parse_str("018f0000-0000-7000-8000-000000000001")
                .expect("sample snapshot ID must be UUIDv7"),
            covering_snapshot_through_sequence: 3,
            covering_snapshot_authority_lsn: 17,
            covering_snapshot_manifest_blake3: [0xA1; 32],
            retirement_proof_blake3: [0xC1; 32],
            canonical_summary_bytes,
            summary_blake3,
            retired_at_unix_ms: 10,
        }
    }

    fn assert_adopted<T>(outcome: CommitReconciliation<T>, expected: &T)
    where
        T: std::fmt::Debug + PartialEq,
    {
        match outcome {
            CommitReconciliation::Adopt(adopted) => assert_eq!(&adopted, expected),
            CommitReconciliation::Retry | CommitReconciliation::Unresolved => {
                panic!("expected exact authoritative adoption")
            }
        }
    }

    fn assert_retry<T>(outcome: CommitReconciliation<T>) {
        assert!(matches!(outcome, CommitReconciliation::Retry));
    }

    fn assert_unresolved<T>(outcome: CommitReconciliation<T>) {
        assert!(matches!(outcome, CommitReconciliation::Unresolved));
    }

    fn normalized_embedded_migration() -> String {
        std::str::from_utf8(crate::schema::CONTINUITY_MIGRATION_V1)
            .expect("embedded migration must remain UTF-8 SQL")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn client_procedure_signatures_match_the_embedded_migration() {
        let migration = normalized_embedded_migration();
        for signature in [
            "CREATE FUNCTION object_store_continuity.object_store_continuity_get_by_token_v1( \
             api_revision text, provider_boundary_id text, continuity_token_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_begin_v1( \
             api_revision text, expected_current_epoch object_store_continuity.uint64, \
             continuity_token_id uuid, provider_boundary_id text, intent_kind text, \
             authenticated_cell_id text, authenticated_tenant_id text, logical_request_id uuid, \
             attempt_id uuid, selected_fingerprint bytea, expected_policy_revision text, \
             operation_quota_class text, requested_rows object_store_continuity.uint64, \
             requested_bytes object_store_continuity.uint64, requested_concurrency \
             object_store_continuity.uint64, retention_deadline_unix_ms bigint )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_bound_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_completed_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, expected_prior_state text DEFAULT 'BOUND' )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_no_local_effect_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, terminal_evidence_blake3 bytea, release_id uuid, \
             release_basis_id text, release_basis_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_quarantine_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_mark_ambiguous_dispatch_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, expected_prior_state text DEFAULT 'BOUND' )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_prepare_adjudication_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_prior_state text, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, adjudication_kind text )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_complete_adjudication_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, local_binding_blake3 bytea, \
             terminal_evidence_blake3 bytea, adjudication_kind text, final_state text, \
             release_id uuid, release_basis_id text, release_basis_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_record_snapshot_v1( \
             api_revision text, snapshot_id uuid, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, through_continuity_seq object_store_continuity.uint64, \
             authority_lsn pg_lsn, manifest_blake3 bytea, continuity_seq \
             object_store_continuity.uint64, continuity_token_id uuid, local_binding_blake3 bytea, \
             local_state_blake3 bytea, local_quota_ownership_blake3 bytea, \
             local_counter_revision object_store_continuity.uint64 )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_release_shadow_ownership_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, authenticated_cell_id text, authenticated_tenant_id text, \
             logical_request_id uuid, attempt_id uuid, intent_kind text, selected_fingerprint bytea, \
             expected_prior_row_blake3 bytea, expected_state text, snapshot_id uuid, \
             expected_manifest_blake3 bytea, expected_coverage_blake3 bytea, release_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_reconciliation_state_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64 )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_epoch_v1( \
             api_revision text, provider_boundary_id text )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_allocate_epoch_v1( \
             api_revision text, provider_boundary_id text, expected_current_epoch \
             object_store_continuity.uint64, next_epoch object_store_continuity.uint64, \
             epoch_namespace_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1( \
             api_revision text, requested_provider_boundary_id text, requested_authority_epoch \
             object_store_continuity.uint64, requested_continuity_seq \
             object_store_continuity.uint64, requested_continuity_token_id uuid )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_archive_prune_v1( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, \
             continuity_token_id uuid, expected_row_blake3 bytea, \
             expected_release_receipt_blake3 bytea, archive_proof_bytes bytea, \
             archive_proof_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_retire_epoch_v2( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, expected_epoch_namespace_blake3 bytea, \
             expected_interval_checkpoint_blake3 bytea, covering_snapshot_id uuid, \
             expected_snapshot_manifest_blake3 bytea, retirement_proof_bytes bytea, \
             retirement_proof_blake3 bytea )",
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_retired_epoch_v2( \
             api_revision text, provider_boundary_id text, authority_epoch \
             object_store_continuity.uint64, expected_schema_revision text, \
             expected_continuity_contract_revision text, \
             expected_continuity_policy_revision text, expected_epoch_namespace_blake3 bytea )",
        ] {
            assert!(
                migration.contains(signature),
                "embedded migration is missing client procedure signature: {signature}"
            );
        }
    }

    #[test]
    fn begin_query_calls_only_the_versioned_procedure_with_numeric_u64_parameters() {
        assert_eq!(
            BEGIN_SQL,
            "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, external_committed_at_unix_ms \
    FROM object_store_continuity.object_store_continuity_begin_v1(\
      $1, $2::text::object_store_continuity.uint64, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
      $13::text::object_store_continuity.uint64, $14::text::object_store_continuity.uint64, \
      $15::text::object_store_continuity.uint64, $16\
    )"
        );
        assert_eq!(
            BEGIN_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            4
        );
        assert!(!BEGIN_SQL.contains("::bigint"));
    }

    #[test]
    fn token_read_query_calls_only_the_versioned_boundary_authorized_procedure() {
        assert_eq!(
            GET_BY_TOKEN_SQL,
            "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_get_by_token_v1($1, $2, $3)"
        );
    }

    #[test]
    fn transition_queries_call_only_versioned_procedures_with_numeric_u64_identity() {
        for (query, procedure, last_parameter) in [
            (
                MARK_BOUND_SQL,
                "object_store_continuity_mark_bound_v1",
                "$13",
            ),
            (
                MARK_COMPLETED_SQL,
                "object_store_continuity_mark_completed_v1",
                "$15",
            ),
            (
                MARK_NO_LOCAL_EFFECT_SQL,
                "object_store_continuity_mark_no_local_effect_v1",
                "$16",
            ),
        ] {
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                2,
                "query: {query}"
            );
            assert!(query.contains(last_parameter), "query: {query}");
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
    }

    #[test]
    fn reconciler_queries_match_the_frozen_procedure_arity_and_numeric_identity() {
        const RESULT_PROJECTION: &str = "SELECT result_code, state, ownership_state, authority_epoch::text, \
    continuity_seq::text, continuity_token_id, row_blake3, \
    external_committed_at_unix_ms FROM";
        for (query, procedure, parameter_count) in [
            (QUARANTINE_SQL, "object_store_continuity_quarantine_v1", 15),
            (
                MARK_AMBIGUOUS_DISPATCH_SQL,
                "object_store_continuity_mark_ambiguous_dispatch_v1",
                15,
            ),
            (
                PREPARE_ADJUDICATION_SQL,
                "object_store_continuity_prepare_adjudication_v1",
                16,
            ),
            (
                COMPLETE_ADJUDICATION_SQL,
                "object_store_continuity_complete_adjudication_v1",
                19,
            ),
        ] {
            assert!(
                query.starts_with(RESULT_PROJECTION),
                "query does not present the complete procedure-result projection: {query}"
            );
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                2,
                "query: {query}"
            );
            assert!(
                query.contains(&format!("${parameter_count}")),
                "query does not present all {parameter_count} parameters: {query}"
            );
            assert!(!query.contains(&format!("${}", parameter_count + 1)));
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
    }

    #[test]
    fn snapshot_release_and_read_queries_pin_arity_and_uint64_transfer() {
        for (query, procedure, parameter_count, uint64_casts) in [
            (
                RECORD_SNAPSHOT_SQL,
                "object_store_continuity_record_snapshot_v1",
                13,
                4,
            ),
            (
                RELEASE_SHADOW_OWNERSHIP_SQL,
                "object_store_continuity_release_shadow_ownership_v1",
                17,
                2,
            ),
            (
                READ_RECONCILIATION_STATE_SQL,
                "object_store_continuity_read_reconciliation_state_v1",
                3,
                1,
            ),
            (
                READ_EPOCH_SQL,
                "object_store_continuity_read_epoch_v1",
                2,
                0,
            ),
            (
                ALLOCATE_EPOCH_SQL,
                "object_store_continuity_allocate_epoch_v1",
                5,
                2,
            ),
            (
                READ_SHADOW_RELEASE_RECEIPT_SQL,
                "object_store_continuity_read_shadow_release_receipt_v1",
                5,
                2,
            ),
        ] {
            assert!(
                query.contains(&format!("object_store_continuity.{procedure}(")),
                "query did not call {procedure}: {query}"
            );
            assert_eq!(
                query
                    .matches("::text::object_store_continuity.uint64")
                    .count(),
                uint64_casts,
                "query: {query}"
            );
            assert!(
                query.contains(&format!("${parameter_count}")),
                "query: {query}"
            );
            assert!(!query.contains(&format!("${}", parameter_count + 1)));
            assert!(!query.contains("::bigint"), "query: {query}");
            assert_eq!(query.matches("SELECT").count(), 1, "query: {query}");
        }
        assert_eq!(CoveredReleaseState::Bound.as_sql(), "BOUND");
        assert_eq!(CoveredReleaseState::Completed.as_sql(), "COMPLETED");
    }

    #[test]
    fn epoch_allocation_query_and_migration_pin_drained_cas_reset_semantics() {
        assert_eq!(
            ALLOCATE_EPOCH_SQL,
            "SELECT authority_epoch::text, continuity_seq_high_water::text FROM \
    object_store_continuity.object_store_continuity_allocate_epoch_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )"
        );
        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_serializable_write_v1(); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF next_epoch <= expected_current_epoch OR octet_length(epoch_namespace_blake3) <> 32 THEN RAISE EXCEPTION 'INVALID_NEXT_EPOCH' USING ERRCODE = '22023'; END IF;",
            "AND intent.state NOT IN ('COMPLETED', 'NO_LOCAL_EFFECT', 'ADJUDICATED_NO_LOCAL_EFFECT', 'ADJUDICATED_NO_DISPATCH')",
            "RAISE EXCEPTION 'EPOCH_CAS_OR_DRAIN_FAILED' USING ERRCODE = '40001';",
            "current_authority_epoch = next_epoch, continuity_seq_high_water = 0, epoch_namespace_blake3 = object_store_continuity_allocate_epoch_v1.epoch_namespace_blake3",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded epoch allocation lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn release_receipt_read_pins_exact_projection_canonical_validation_and_reconciler_auth() {
        assert_eq!(
            READ_SHADOW_RELEASE_RECEIPT_SQL,
            "SELECT receipt_provider_boundary_id, \
    receipt_authority_epoch::text, receipt_continuity_seq::text, receipt_continuity_token_id, \
    release_id, receipt_blake3, released_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5\
    )"
        );
        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_reconciler_v1();",
            "WHERE receipt.provider_boundary_id = requested_provider_boundary_id AND receipt.authority_epoch = requested_authority_epoch AND receipt.continuity_seq = requested_continuity_seq AND receipt.continuity_token_id = requested_continuity_token_id; IF NOT FOUND THEN RETURN; END IF;",
            "PERFORM object_store_continuity.assert_blake3_v1(release_preimage, stored.receipt_blake3);",
            "IF stored.canonical_receipt_bytes IS DISTINCT FROM release_preimage || stored.receipt_blake3 THEN RAISE EXCEPTION 'SHADOW_RELEASE_RECEIPT_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000'; END IF;",
            "object_store_continuity.object_store_continuity_read_shadow_release_receipt_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded release-receipt read lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn archive_prune_query_and_migration_pin_bounded_reconciler_contract() {
        assert_eq!(
            ARCHIVE_PRUNE_SQL,
            "SELECT accepted_start_sequence::text, \
    accepted_end_sequence::text, accepted_row_count::text, prune_commit_sequence::text, \
    accepted_interval_blake3 FROM \
    object_store_continuity.object_store_continuity_archive_prune_v1(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8, $9\
    )"
        );
        assert_eq!(
            ARCHIVE_PRUNE_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            2
        );
        assert!(!ARCHIVE_PRUNE_SQL.contains("$10"));
        assert!(!ARCHIVE_PRUNE_SQL.contains("::bigint"));

        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_serializable_write_v1(); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF octet_length(expected_row_blake3) <> 32 OR octet_length(expected_release_receipt_blake3) <> 32 THEN RAISE EXCEPTION 'ARCHIVE_EXPECTED_DIGEST_INVALID' USING ERRCODE = '22023'; END IF;",
            "PERFORM object_store_continuity.assert_archive_eligibility_v1( archive_proof_bytes, archive_proof_blake3, stored, release_value.receipt_blake3 );",
            "accepted_start_sequence := merged.start_sequence; accepted_end_sequence := merged.end_sequence; accepted_row_count := merged.row_count; accepted_interval_blake3 := merged.interval_blake3; RETURN NEXT;",
            "object_store_continuity.object_store_continuity_archive_prune_v1(text, text, object_store_continuity.uint64, object_store_continuity.uint64, uuid, bytea, bytea, bytea, bytea)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded archive/prune contract lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn archive_prune_request_accepts_nonempty_identity_and_bounded_proof() {
        let mut request = sample_archive_prune_request();
        request.archive_proof_bytes = vec![0x51; MAX_ARCHIVE_PROOF_BYTES];

        validate_archive_prune_request(&request)
            .expect("an exact maximum-sized archive proof must remain admissible");
    }

    #[test]
    fn archive_prune_request_rejects_missing_identity_and_unbounded_proof() {
        let mut invalid_requests = Vec::new();
        let mut empty_boundary = sample_archive_prune_request();
        empty_boundary.provider_boundary_id.clear();
        invalid_requests.push(empty_boundary);
        let mut zero_epoch = sample_archive_prune_request();
        zero_epoch.authority_epoch = 0;
        invalid_requests.push(zero_epoch);
        let mut zero_sequence = sample_archive_prune_request();
        zero_sequence.continuity_seq = 0;
        invalid_requests.push(zero_sequence);
        let mut empty_proof = sample_archive_prune_request();
        empty_proof.archive_proof_bytes.clear();
        invalid_requests.push(empty_proof);
        let mut oversized_proof = sample_archive_prune_request();
        oversized_proof.archive_proof_bytes = vec![0x51; MAX_ARCHIVE_PROOF_BYTES + 1];
        invalid_requests.push(oversized_proof);

        for request in invalid_requests {
            assert!(matches!(
                validate_archive_prune_request(&request),
                Err(ContinuityError::InvalidConfiguration(
                    "archive identity and proof must be valid"
                ))
            ));
        }
    }

    #[test]
    fn archive_prune_result_accepts_exact_nonzero_interval_and_digest() {
        let result = sample_archive_prune_result();

        validate_archive_prune_result(&result)
            .expect("a contiguous nonzero archive interval must validate");
        assert_eq!(result.accepted_interval_blake3, [0x71; 32]);
    }

    #[test]
    fn archive_prune_result_rejects_zero_reversed_and_count_mismatch_shapes() {
        let mut invalid_results = Vec::new();
        let mut zero_start = sample_archive_prune_result();
        zero_start.accepted_start_sequence = 0;
        invalid_results.push(zero_start);
        let mut reversed = sample_archive_prune_result();
        reversed.accepted_start_sequence = 13;
        invalid_results.push(reversed);
        let mut count_mismatch = sample_archive_prune_result();
        count_mismatch.accepted_row_count = 2;
        invalid_results.push(count_mismatch);
        let mut zero_commit = sample_archive_prune_result();
        zero_commit.prune_commit_sequence = 0;
        invalid_results.push(zero_commit);

        for result in invalid_results {
            assert!(matches!(
                validate_archive_prune_result(&result),
                Err(ContinuityError::InvalidResponse(
                    "archive interval result is inconsistent"
                ))
            ));
        }
    }

    #[test]
    fn archive_prune_result_must_cover_the_requested_sequence() {
        let result = sample_archive_prune_result();
        validate_archive_prune_result_for_sequence(&result, 11)
            .expect("the requested sequence is covered by the accepted interval");
        for outside in [9, 13] {
            assert!(matches!(
                validate_archive_prune_result_for_sequence(&result, outside),
                Err(ContinuityError::InvalidResponse(
                    "archive result does not cover the requested sequence"
                ))
            ));
        }
    }

    #[test]
    fn pruned_interval_read_query_and_migration_pin_authenticated_closed_contract() {
        assert_eq!(
            READ_PRUNED_INTERVAL_SQL,
            "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, end_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, canonical_row_bytes_sum::text, \
    canonical_row_bytes_min::text, canonical_row_bytes_max::text, quota_rows_sum::text, \
    quota_rows_min::text, quota_rows_max::text, quota_bytes_sum::text, quota_bytes_min::text, \
    quota_bytes_max::text, quota_concurrency_sum::text, quota_concurrency_min::text, \
    quota_concurrency_max::text, created_at_min_unix_ms, created_at_max_unix_ms, \
    closed_at_min_unix_ms, closed_at_max_unix_ms, prune_commit_sequence_min::text, \
    prune_commit_sequence_max::text, pruned_at_min_unix_ms, pruned_at_max_unix_ms, \
    canonical_interval_bytes, interval_blake3 FROM \
    object_store_continuity.object_store_continuity_read_pruned_interval_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, \
      $4::text::object_store_continuity.uint64, $5, $6, $7, $8\
    )"
        );
        assert_eq!(
            READ_PRUNED_INTERVAL_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            2
        );
        assert!(READ_PRUNED_INTERVAL_SQL.contains("$8"));
        assert!(!READ_PRUNED_INTERVAL_SQL.contains("$9"));
        assert!(!READ_PRUNED_INTERVAL_SQL.contains("::bigint"));

        let migration = normalized_embedded_migration();
        for invariant in [
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_pruned_interval_v2( api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64, continuity_seq object_store_continuity.uint64, expected_schema_revision text, expected_continuity_contract_revision text, expected_continuity_policy_revision text, expected_epoch_namespace_blake3 bytea )",
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_reconciler_v1();",
            "OR epoch_value.schema_revision IS DISTINCT FROM expected_schema_revision OR epoch_value.continuity_contract_revision IS DISTINCT FROM expected_continuity_contract_revision OR epoch_value.continuity_policy_revision IS DISTINCT FROM expected_continuity_policy_revision OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM expected_epoch_namespace_blake3 THEN RAISE EXCEPTION 'PRUNED_INTERVAL_NAMESPACE_MISMATCH' USING ERRCODE = '22023';",
            "AND existing.start_sequence <= object_store_continuity_read_pruned_interval_v2.continuity_seq AND existing.end_sequence >= object_store_continuity_read_pruned_interval_v2.continuity_seq;",
            "IF NOT FOUND THEN RAISE EXCEPTION 'PRUNED_INTERVAL_NOT_FOUND' USING ERRCODE = '02000'; END IF;",
            "PERFORM object_store_continuity.assert_blake3_v1( object_store_continuity.pruned_range_preimage_v2(stored_range), stored_range.interval_blake3 );",
            "IF stored_range.canonical_interval_bytes IS DISTINCT FROM object_store_continuity.pruned_range_preimage_v2(stored_range) || stored_range.interval_blake3 THEN RAISE EXCEPTION 'PRUNED_INTERVAL_CANONICAL_BYTES_MISMATCH' USING ERRCODE = '22000'; END IF;",
            "object_store_continuity.object_store_continuity_read_pruned_interval_v2(text, text, object_store_continuity.uint64, object_store_continuity.uint64, text, text, text, bytea)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded pruned-interval read lost invariant: {invariant}"
            );
        }
        assert!(
            !migration.contains("GRANT SELECT ON"),
            "continuity roles must not receive direct table reads"
        );
    }

    #[test]
    fn pruned_interval_read_request_requires_exact_nonempty_identity_and_policy() {
        validate_read_pruned_interval_request(&sample_read_pruned_interval_request())
            .expect("an exact namespace request must validate");

        let mut invalid_requests = Vec::new();
        let mut empty_boundary = sample_read_pruned_interval_request();
        empty_boundary.provider_boundary_id.clear();
        invalid_requests.push(empty_boundary);
        let mut zero_epoch = sample_read_pruned_interval_request();
        zero_epoch.authority_epoch = 0;
        invalid_requests.push(zero_epoch);
        let mut zero_sequence = sample_read_pruned_interval_request();
        zero_sequence.continuity_seq = 0;
        invalid_requests.push(zero_sequence);
        let mut empty_policy = sample_read_pruned_interval_request();
        empty_policy.expected_continuity_policy_revision.clear();
        invalid_requests.push(empty_policy);

        for request in invalid_requests {
            assert!(matches!(
                validate_read_pruned_interval_request(&request),
                Err(ContinuityError::InvalidConfiguration(
                    "pruned interval read identity and policy must be valid"
                ))
            ));
        }
    }

    #[test]
    fn pruned_interval_accepts_closed_range_aggregates_and_canonical_digest() {
        let request = sample_read_pruned_interval_request();
        let interval = sample_pruned_interval();

        validate_pruned_interval_shape(&interval)
            .expect("a closed, bounded aggregate interval must validate");
        validate_pruned_interval(&interval, &request)
            .expect("the exact containing namespace interval must validate");
        assert_eq!(interval.interval_blake3, [0x91; 32]);
        assert!(
            interval
                .canonical_interval_bytes
                .ends_with(&interval.interval_blake3)
        );
    }

    #[test]
    fn pruned_interval_rejects_each_closed_shape_invariant() {
        let mut invalid_intervals = Vec::new();
        let mut zero_start = sample_pruned_interval();
        zero_start.start_sequence = 0;
        invalid_intervals.push(zero_start);
        let mut count_mismatch = sample_pruned_interval();
        count_mismatch.row_count = 2;
        invalid_intervals.push(count_mismatch);
        let mut terminal_overflow = sample_pruned_interval();
        terminal_overflow.completed_count = u64::MAX;
        invalid_intervals.push(terminal_overflow);
        let mut terminal_mismatch = sample_pruned_interval();
        terminal_mismatch.completed_count = 0;
        invalid_intervals.push(terminal_mismatch);
        let mut aggregate_bounds = sample_pruned_interval();
        aggregate_bounds.quota_bytes_min = 31;
        invalid_intervals.push(aggregate_bounds);
        let mut negative_time = sample_pruned_interval();
        negative_time.created_at_min_unix_ms = -1;
        invalid_intervals.push(negative_time);
        let mut reversed_time = sample_pruned_interval();
        reversed_time.closed_at_min_unix_ms = 7;
        invalid_intervals.push(reversed_time);
        let mut zero_prune_sequence = sample_pruned_interval();
        zero_prune_sequence.prune_commit_sequence_min = 0;
        invalid_intervals.push(zero_prune_sequence);
        let mut reversed_prune_sequence = sample_pruned_interval();
        reversed_prune_sequence.prune_commit_sequence_min = 5;
        invalid_intervals.push(reversed_prune_sequence);
        let mut missing_canonical_preimage = sample_pruned_interval();
        missing_canonical_preimage.canonical_interval_bytes = vec![0x91; 32];
        invalid_intervals.push(missing_canonical_preimage);
        let mut wrong_canonical_digest = sample_pruned_interval();
        wrong_canonical_digest.canonical_interval_bytes.pop();
        wrong_canonical_digest.canonical_interval_bytes.push(0x92);
        invalid_intervals.push(wrong_canonical_digest);

        for interval in invalid_intervals {
            assert!(
                validate_pruned_interval_shape(&interval).is_err(),
                "invalid pruned interval shape must fail closed: {interval:?}"
            );
        }
    }

    #[test]
    fn pruned_interval_rejects_identity_containment_and_revision_mismatch() {
        let request = sample_read_pruned_interval_request();
        let mut invalid_intervals = Vec::new();
        let mut wrong_boundary = sample_pruned_interval();
        wrong_boundary.provider_boundary_id = "boundary-other".to_string();
        invalid_intervals.push(wrong_boundary);
        let mut wrong_epoch = sample_pruned_interval();
        wrong_epoch.authority_epoch += 1;
        invalid_intervals.push(wrong_epoch);
        let mut misses_sequence = sample_pruned_interval();
        misses_sequence.start_sequence = 12;
        misses_sequence.end_sequence = 14;
        invalid_intervals.push(misses_sequence);
        let mut wrong_api = sample_pruned_interval();
        wrong_api.api_revision.push_str("-other");
        invalid_intervals.push(wrong_api);
        let mut wrong_schema = sample_pruned_interval();
        wrong_schema.schema_revision.push_str("-other");
        invalid_intervals.push(wrong_schema);
        let mut wrong_contract = sample_pruned_interval();
        wrong_contract
            .continuity_contract_revision
            .push_str("-other");
        invalid_intervals.push(wrong_contract);
        let mut wrong_policy = sample_pruned_interval();
        wrong_policy.continuity_policy_revision.push_str("-other");
        invalid_intervals.push(wrong_policy);

        for interval in invalid_intervals {
            assert!(
                validate_pruned_interval(&interval, &request).is_err(),
                "mismatched pruned interval must fail closed: {interval:?}"
            );
        }
    }

    #[test]
    fn epoch_retirement_query_and_migration_pin_serializable_replay_contract() {
        assert_eq!(
            RETIRE_EPOCH_SQL,
            "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, final_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, interval_checkpoint_blake3, created_at_min_unix_ms, \
    created_at_max_unix_ms, closed_at_min_unix_ms, closed_at_max_unix_ms, \
    pruned_at_min_unix_ms, pruned_at_max_unix_ms, prune_commit_sequence_max::text, \
    covering_snapshot_id, covering_snapshot_through_sequence::text, \
    covering_snapshot_authority_lsn, covering_snapshot_manifest_blake3, \
    retirement_proof_blake3, canonical_summary_bytes, summary_blake3, retired_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_retire_epoch_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, $4, $5, $6, $7, $8, $9\
    )"
        );
        assert_eq!(
            RETIRE_EPOCH_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            1
        );
        assert!(RETIRE_EPOCH_SQL.contains("$9"));
        assert!(!RETIRE_EPOCH_SQL.contains("$10"));
        assert!(!RETIRE_EPOCH_SQL.contains("::bigint"));

        let migration = normalized_embedded_migration();
        for invariant in [
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_serializable_write_v1(); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF octet_length(expected_epoch_namespace_blake3) <> 32 OR octet_length(expected_interval_checkpoint_blake3) <> 32 OR octet_length(expected_snapshot_manifest_blake3) <> 32 OR octet_length(retirement_proof_blake3) <> 32 THEN RAISE EXCEPTION 'EPOCH_RETIREMENT_EXPECTED_DIGEST_INVALID' USING ERRCODE = '22023'; END IF;",
            "IF FOUND THEN IF NOT epoch_value.retired OR summary_value.interval_checkpoint_blake3 IS DISTINCT FROM expected_interval_checkpoint_blake3 OR summary_value.covering_snapshot_id IS DISTINCT FROM covering_snapshot_id OR summary_value.covering_snapshot_manifest_blake3 IS DISTINCT FROM expected_snapshot_manifest_blake3 OR summary_value.retirement_proof_blake3 IS DISTINCT FROM retirement_proof_blake3 THEN RAISE EXCEPTION 'EPOCH_RETIREMENT_REPLAY_MISMATCH' USING ERRCODE = '23505';",
            "IF epoch_value.retired OR boundary.current_authority_epoch = authority_epoch OR epoch_value.continuity_seq_high_water = 0 THEN RAISE EXCEPTION 'EPOCH_RETIREMENT_NOT_OLD_ACTIVE_NAMESPACE' USING ERRCODE = '22023'; END IF;",
            "IF EXISTS ( SELECT 1 FROM object_store_continuity.intents AS intent WHERE intent.provider_boundary_id = object_store_continuity_retire_epoch_v2.provider_boundary_id AND intent.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch ) THEN RAISE EXCEPTION 'EPOCH_RETIREMENT_LIVE_DETAIL_REMAINS' USING ERRCODE = '55000'; END IF;",
            "IF interval_count <> 1 OR active_range.start_sequence <> 1 OR active_range.end_sequence IS DISTINCT FROM epoch_value.continuity_seq_high_water THEN RAISE EXCEPTION 'EPOCH_RETIREMENT_INTERVAL_COVERAGE_INCOMPLETE' USING ERRCODE = '55000'; END IF;",
            "AND snapshot.authority_epoch = object_store_continuity_retire_epoch_v2.authority_epoch AND snapshot.through_continuity_seq >= epoch_value.continuity_seq_high_water;",
            "PERFORM object_store_continuity.assert_epoch_retirement_eligibility_v2( retirement_proof_bytes, retirement_proof_blake3, provider_boundary_id, authority_epoch, epoch_value.continuity_seq_high_water, active_range.interval_blake3, snapshot_value.snapshot_id, snapshot_value.manifest_blake3, epoch_value.prune_commit_sequence_high_water );",
            "INSERT INTO object_store_continuity.retired_epoch_summaries SELECT (summary_value).*; DELETE FROM object_store_continuity.pruned_ranges AS existing",
            "UPDATE object_store_continuity.epoch_counters SET retired = true",
            "object_store_continuity.object_store_continuity_retire_epoch_v2(text, text, object_store_continuity.uint64, bytea, bytea, uuid, bytea, bytea, bytea)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded epoch retirement lost invariant: {invariant}"
            );
        }
    }

    #[test]
    fn retired_epoch_read_query_and_migration_pin_authenticated_closed_contract() {
        assert_eq!(
            READ_RETIRED_EPOCH_SQL,
            "SELECT provider_boundary_id, authority_epoch::text, \
    start_sequence::text, final_sequence::text, row_count::text, api_revision, schema_revision, \
    continuity_contract_revision, continuity_policy_revision, completed_count::text, \
    no_local_effect_count::text, adjudicated_no_local_effect_count::text, \
    adjudicated_no_dispatch_count::text, interval_checkpoint_blake3, created_at_min_unix_ms, \
    created_at_max_unix_ms, closed_at_min_unix_ms, closed_at_max_unix_ms, \
    pruned_at_min_unix_ms, pruned_at_max_unix_ms, prune_commit_sequence_max::text, \
    covering_snapshot_id, covering_snapshot_through_sequence::text, \
    covering_snapshot_authority_lsn, covering_snapshot_manifest_blake3, \
    retirement_proof_blake3, canonical_summary_bytes, summary_blake3, retired_at_unix_ms FROM \
    object_store_continuity.object_store_continuity_read_retired_epoch_v2(\
      $1, $2, $3::text::object_store_continuity.uint64, $4, $5, $6, $7\
    )"
        );
        assert_eq!(
            READ_RETIRED_EPOCH_SQL
                .matches("::text::object_store_continuity.uint64")
                .count(),
            1
        );
        assert!(READ_RETIRED_EPOCH_SQL.contains("$7"));
        assert!(!READ_RETIRED_EPOCH_SQL.contains("$8"));
        assert!(!READ_RETIRED_EPOCH_SQL.contains("::bigint"));

        let migration = normalized_embedded_migration();
        for invariant in [
            "CREATE FUNCTION object_store_continuity.object_store_continuity_read_retired_epoch_v2( api_revision text, provider_boundary_id text, authority_epoch object_store_continuity.uint64, expected_schema_revision text, expected_continuity_contract_revision text, expected_continuity_policy_revision text, expected_epoch_namespace_blake3 bytea )",
            "RETURNS SETOF object_store_continuity.retired_epoch_summaries LANGUAGE plpgsql STABLE SECURITY DEFINER",
            "PERFORM object_store_continuity.assert_api_revision_v1(api_revision); PERFORM object_store_continuity.assert_reconciler_v1();",
            "IF NOT FOUND OR NOT epoch_value.retired OR epoch_value.api_revision IS DISTINCT FROM api_revision OR epoch_value.schema_revision IS DISTINCT FROM expected_schema_revision OR epoch_value.continuity_contract_revision IS DISTINCT FROM expected_continuity_contract_revision OR epoch_value.continuity_policy_revision IS DISTINCT FROM expected_continuity_policy_revision OR epoch_value.epoch_namespace_blake3 IS DISTINCT FROM expected_epoch_namespace_blake3 THEN RAISE EXCEPTION 'RETIRED_EPOCH_NAMESPACE_MISMATCH' USING ERRCODE = '22023'; END IF;",
            "IF NOT FOUND THEN RAISE EXCEPTION 'RETIRED_EPOCH_SUMMARY_NOT_FOUND' USING ERRCODE = '02000'; END IF;",
            "PERFORM object_store_continuity.assert_retired_epoch_summary_v2( summary_value, epoch_value, snapshot_value ); RETURN NEXT summary_value;",
            "object_store_continuity.object_store_continuity_read_retired_epoch_v2(text, text, object_store_continuity.uint64, text, text, text, bytea)",
            "TO object_dispatch_continuity_reconciler;",
        ] {
            assert!(
                migration.contains(invariant),
                "embedded retired epoch read lost invariant: {invariant}"
            );
        }
        assert!(
            !migration.contains("GRANT SELECT ON"),
            "continuity roles must not receive direct table reads"
        );
    }

    #[test]
    fn epoch_retirement_request_accepts_bounded_proof_and_rejects_invalid_identity() {
        let mut maximum = sample_retire_epoch_request();
        maximum.retirement_proof_bytes = vec![0xB1; MAX_RETIREMENT_PROOF_BYTES];
        validate_retire_epoch_request(&maximum)
            .expect("an exact maximum-sized retirement proof must remain admissible");

        let mut invalid_requests = Vec::new();
        let mut empty_boundary = sample_retire_epoch_request();
        empty_boundary.provider_boundary_id.clear();
        invalid_requests.push(empty_boundary);
        let mut zero_epoch = sample_retire_epoch_request();
        zero_epoch.authority_epoch = 0;
        invalid_requests.push(zero_epoch);
        let mut empty_policy = sample_retire_epoch_request();
        empty_policy.expected_continuity_policy_revision.clear();
        invalid_requests.push(empty_policy);
        let mut empty_proof = sample_retire_epoch_request();
        empty_proof.retirement_proof_bytes.clear();
        invalid_requests.push(empty_proof);
        let mut oversized_proof = sample_retire_epoch_request();
        oversized_proof.retirement_proof_bytes = vec![0xB1; MAX_RETIREMENT_PROOF_BYTES + 1];
        invalid_requests.push(oversized_proof);

        for request in invalid_requests {
            assert!(matches!(
                validate_retire_epoch_request(&request),
                Err(ContinuityError::InvalidConfiguration(
                    "epoch retirement identity and proof must be valid"
                ))
            ));
        }
    }

    #[test]
    fn retired_epoch_read_request_requires_nonempty_identity_and_policy() {
        validate_read_retired_epoch_request(&sample_read_retired_epoch_request())
            .expect("an exact retired namespace request must validate");

        let mut invalid_requests = Vec::new();
        let mut empty_boundary = sample_read_retired_epoch_request();
        empty_boundary.provider_boundary_id.clear();
        invalid_requests.push(empty_boundary);
        let mut zero_epoch = sample_read_retired_epoch_request();
        zero_epoch.authority_epoch = 0;
        invalid_requests.push(zero_epoch);
        let mut empty_policy = sample_read_retired_epoch_request();
        empty_policy.expected_continuity_policy_revision.clear();
        invalid_requests.push(empty_policy);

        for request in invalid_requests {
            assert!(matches!(
                validate_read_retired_epoch_request(&request),
                Err(ContinuityError::InvalidConfiguration(
                    "retired epoch read identity and policy must be valid"
                ))
            ));
        }
    }

    #[test]
    fn retired_epoch_summary_accepts_closed_checkpoint_and_retirement_evidence() {
        let request = sample_retire_epoch_request();
        let summary = sample_retired_epoch_summary();

        validate_retired_epoch_summary_shape(&summary)
            .expect("a closed retired epoch summary must validate");
        validate_retired_epoch_summary_for_retirement(&summary, &request)
            .expect("the exact retirement checkpoint evidence must validate");
        validate_retired_epoch_summary_namespace(
            &summary,
            &request.provider_boundary_id,
            request.authority_epoch,
            &request.expected_continuity_policy_revision,
        )
        .expect("the exact retired namespace must validate for readback");
        assert!(
            summary
                .canonical_summary_bytes
                .ends_with(&summary.summary_blake3)
        );
    }

    #[test]
    fn retired_epoch_summary_rejects_each_closed_shape_invariant() {
        let mut invalid_summaries = Vec::new();
        let mut zero_epoch = sample_retired_epoch_summary();
        zero_epoch.authority_epoch = 0;
        invalid_summaries.push(zero_epoch);
        let mut wrong_start = sample_retired_epoch_summary();
        wrong_start.start_sequence = 2;
        invalid_summaries.push(wrong_start);
        let mut count_mismatch = sample_retired_epoch_summary();
        count_mismatch.row_count = 2;
        invalid_summaries.push(count_mismatch);
        let mut terminal_overflow = sample_retired_epoch_summary();
        terminal_overflow.completed_count = u64::MAX;
        invalid_summaries.push(terminal_overflow);
        let mut terminal_mismatch = sample_retired_epoch_summary();
        terminal_mismatch.completed_count = 0;
        invalid_summaries.push(terminal_mismatch);
        let mut negative_time = sample_retired_epoch_summary();
        negative_time.created_at_min_unix_ms = -1;
        invalid_summaries.push(negative_time);
        let mut reversed_time = sample_retired_epoch_summary();
        reversed_time.closed_at_min_unix_ms = 7;
        invalid_summaries.push(reversed_time);
        let mut retired_before_pruned = sample_retired_epoch_summary();
        retired_before_pruned.retired_at_unix_ms = 8;
        invalid_summaries.push(retired_before_pruned);
        let mut zero_prune_sequence = sample_retired_epoch_summary();
        zero_prune_sequence.prune_commit_sequence_max = 0;
        invalid_summaries.push(zero_prune_sequence);
        let mut insufficient_snapshot = sample_retired_epoch_summary();
        insufficient_snapshot.covering_snapshot_through_sequence = 2;
        invalid_summaries.push(insufficient_snapshot);
        let mut missing_canonical_preimage = sample_retired_epoch_summary();
        missing_canonical_preimage.canonical_summary_bytes = vec![0xD1; 32];
        invalid_summaries.push(missing_canonical_preimage);
        let mut wrong_canonical_digest = sample_retired_epoch_summary();
        wrong_canonical_digest.canonical_summary_bytes.pop();
        wrong_canonical_digest.canonical_summary_bytes.push(0xD2);
        invalid_summaries.push(wrong_canonical_digest);

        for summary in invalid_summaries {
            assert!(
                validate_retired_epoch_summary_shape(&summary).is_err(),
                "invalid retired epoch summary must fail closed: {summary:?}"
            );
        }
    }

    #[test]
    fn retired_epoch_summary_rejects_namespace_and_checkpoint_mismatch() {
        let request = sample_retire_epoch_request();
        let mut namespace_mismatches = Vec::new();
        let mut wrong_boundary = sample_retired_epoch_summary();
        wrong_boundary.provider_boundary_id = "boundary-other".to_string();
        namespace_mismatches.push(wrong_boundary);
        let mut wrong_epoch = sample_retired_epoch_summary();
        wrong_epoch.authority_epoch += 1;
        namespace_mismatches.push(wrong_epoch);
        let mut wrong_api = sample_retired_epoch_summary();
        wrong_api.api_revision.push_str("-other");
        namespace_mismatches.push(wrong_api);
        let mut wrong_schema = sample_retired_epoch_summary();
        wrong_schema.schema_revision.push_str("-other");
        namespace_mismatches.push(wrong_schema);
        let mut wrong_contract = sample_retired_epoch_summary();
        wrong_contract
            .continuity_contract_revision
            .push_str("-other");
        namespace_mismatches.push(wrong_contract);
        let mut wrong_policy = sample_retired_epoch_summary();
        wrong_policy.continuity_policy_revision.push_str("-other");
        namespace_mismatches.push(wrong_policy);

        for summary in namespace_mismatches {
            assert!(
                validate_retired_epoch_summary_namespace(
                    &summary,
                    &request.provider_boundary_id,
                    request.authority_epoch,
                    &request.expected_continuity_policy_revision,
                )
                .is_err(),
                "mismatched retired namespace must fail closed: {summary:?}"
            );
        }

        let mut checkpoint_mismatches = Vec::new();
        let mut wrong_interval = sample_retired_epoch_summary();
        wrong_interval.interval_checkpoint_blake3 = [0x01; 32];
        checkpoint_mismatches.push(wrong_interval);
        let mut wrong_snapshot = sample_retired_epoch_summary();
        wrong_snapshot.covering_snapshot_id = Uuid::now_v7();
        checkpoint_mismatches.push(wrong_snapshot);
        let mut wrong_manifest = sample_retired_epoch_summary();
        wrong_manifest.covering_snapshot_manifest_blake3 = [0x02; 32];
        checkpoint_mismatches.push(wrong_manifest);
        let mut wrong_proof = sample_retired_epoch_summary();
        wrong_proof.retirement_proof_blake3 = [0x03; 32];
        checkpoint_mismatches.push(wrong_proof);

        for summary in checkpoint_mismatches {
            assert!(
                validate_retired_epoch_summary_for_retirement(&summary, &request).is_err(),
                "mismatched retirement checkpoint must fail closed: {summary:?}"
            );
        }
    }

    #[test]
    fn reconciler_state_algebra_is_closed_and_pairs_adjudication_kind_with_final_state() {
        assert_eq!(QuarantinePriorState::Intent.as_sql(), "INTENT");
        assert_eq!(
            QuarantinePriorState::Bound {
                local_binding_blake3: [0x11; 32],
            }
            .as_sql(),
            "BOUND"
        );
        for (kind, prior_state, final_state) in [
            (
                ContinuityAdjudicationKind::NoLocalEffect,
                "QUARANTINED",
                "ADJUDICATED_NO_LOCAL_EFFECT",
            ),
            (
                ContinuityAdjudicationKind::NoDispatch,
                "AMBIGUOUS_DISPATCH",
                "ADJUDICATED_NO_DISPATCH",
            ),
        ] {
            assert_eq!(kind.prepared_prior_state_sql(), prior_state);
            assert_eq!(kind.final_state_sql(), final_state);
        }
    }

    #[test]
    fn quarantine_prior_state_preserves_only_bound_local_binding_evidence() {
        assert_eq!(QuarantinePriorState::Intent.local_binding_blake3(), None);
        let digest = [0xa5; 32];
        assert_eq!(
            QuarantinePriorState::Bound {
                local_binding_blake3: digest,
            }
            .local_binding_blake3(),
            Some(digest.as_slice())
        );
    }

    #[test]
    fn quarantine_request_requires_exact_terminal_evidence() {
        let request = QuarantineRequest {
            identity: sample_identity(),
            expected_prior_row_blake3: [0x31; 32],
            prior_state: QuarantinePriorState::Intent,
            terminal_evidence_blake3: [0x41; 32],
        };
        assert_eq!(request.terminal_evidence_blake3, [0x41; 32]);
        assert!(QUARANTINE_SQL.contains("$15"));
    }

    #[test]
    fn adjudication_kind_requires_its_exact_local_binding_shape() {
        let digest = [0x3c; 32];
        assert!(
            validate_adjudication_binding(ContinuityAdjudicationKind::NoLocalEffect, None).is_ok()
        );
        assert!(
            validate_adjudication_binding(ContinuityAdjudicationKind::NoDispatch, Some(&digest))
                .is_ok()
        );
        for (kind, binding) in [
            (ContinuityAdjudicationKind::NoLocalEffect, Some(&digest)),
            (ContinuityAdjudicationKind::NoDispatch, None),
        ] {
            assert!(matches!(
                validate_adjudication_binding(kind, binding),
                Err(ContinuityError::InvalidConfiguration(_))
            ));
        }
    }

    #[test]
    fn release_basis_validation_rejects_empty_ids_before_database_access() {
        assert!(validate_release_basis_id("release-basis:v1").is_ok());
        assert!(matches!(
            validate_release_basis_id(""),
            Err(ContinuityError::InvalidConfiguration(
                "release basis ID must be nonempty"
            ))
        ));
    }

    #[test]
    fn transition_result_validation_accepts_only_exact_identity_state_and_ownership() {
        let identity = sample_identity();
        let exact = sample_result(&identity);
        validate_transition_result(
            &exact,
            &identity,
            ContinuityState::Quarantined,
            ContinuityOwnershipState::ShadowReserved,
        )
        .expect("the exact transition result must validate");

        let mut replay = exact.clone();
        replay.result_code = ContinuityResultCode::Replay;
        validate_transition_result(
            &replay,
            &identity,
            ContinuityState::Quarantined,
            ContinuityOwnershipState::ShadowReserved,
        )
        .expect("an exact replay must validate");

        let mut wrong_identity = exact.clone();
        wrong_identity.continuity_seq += 1;
        let mut wrong_code = exact.clone();
        wrong_code.result_code = ContinuityResultCode::Found;
        let mut wrong_state = exact.clone();
        wrong_state.state = ContinuityState::AmbiguousDispatch;
        let mut wrong_ownership = exact;
        wrong_ownership.ownership_state = ContinuityOwnershipState::OwnershipReleased;
        for result in [wrong_identity, wrong_code, wrong_state, wrong_ownership] {
            assert!(matches!(
                validate_transition_result(
                    &result,
                    &identity,
                    ContinuityState::Quarantined,
                    ContinuityOwnershipState::ShadowReserved,
                ),
                Err(ContinuityError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn begin_result_validation_accepts_current_row_replay_and_rejects_invalid_shapes() {
        let identity = sample_identity();
        let request = BeginIntentRequest {
            provider_boundary_id: identity.provider_boundary_id.clone(),
            expected_authority_epoch: identity.authority_epoch,
            continuity_token_id: identity.continuity_token_id,
            intent_kind: identity.intent_kind,
            authenticated_cell_id: identity.authenticated_cell_id.clone(),
            authenticated_tenant_id: identity.authenticated_tenant_id.clone(),
            operation_quota_class: "test".to_string(),
            logical_request_id: identity.logical_request_id,
            attempt_id: identity.attempt_id,
            selected_fingerprint: identity.selected_fingerprint,
            continuity_policy_revision: "policy-v1".to_string(),
            quota_bytes: 1,
            quota_rows: 1,
            quota_concurrency: 1,
            retention_deadline_unix_ms: 1,
        };
        let mut exact = sample_result(&identity);
        exact.result_code = ContinuityResultCode::Created;
        exact.state = ContinuityState::Intent;
        validate_begin_result(&exact, &request).expect("the exact begin result must validate");

        for (state, ownership_state) in [
            (
                ContinuityState::Intent,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Bound,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Bound,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::Completed,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::Completed,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::NoLocalEffect,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::Quarantined,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AmbiguousDispatch,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AdjudicationPrepared,
                ContinuityOwnershipState::ShadowReserved,
            ),
            (
                ContinuityState::AdjudicatedNoLocalEffect,
                ContinuityOwnershipState::OwnershipReleased,
            ),
            (
                ContinuityState::AdjudicatedNoDispatch,
                ContinuityOwnershipState::OwnershipReleased,
            ),
        ] {
            let mut replay = exact.clone();
            replay.result_code = ContinuityResultCode::Replay;
            replay.state = state;
            replay.ownership_state = ownership_state;
            validate_begin_result(&replay, &request)
                .expect("begin replay must accept every closed stored-row state");
        }

        let mut wrong_identity = exact.clone();
        wrong_identity.continuity_token_id = Uuid::from_u128(29);
        let mut wrong_code = exact.clone();
        wrong_code.result_code = ContinuityResultCode::Updated;
        let mut wrong_state = exact.clone();
        wrong_state.state = ContinuityState::Bound;
        let mut wrong_ownership = exact.clone();
        wrong_ownership.ownership_state = ContinuityOwnershipState::OwnershipReleased;
        let mut wrong_replay_ownership = exact;
        wrong_replay_ownership.result_code = ContinuityResultCode::Replay;
        wrong_replay_ownership.state = ContinuityState::AdjudicatedNoDispatch;
        for result in [
            wrong_identity,
            wrong_code,
            wrong_state,
            wrong_ownership,
            wrong_replay_ownership,
        ] {
            assert!(matches!(
                validate_begin_result(&result, &request),
                Err(ContinuityError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn token_lookup_result_validation_accepts_only_found() {
        let identity = sample_identity();
        let mut found = sample_result(&identity);
        found.result_code = ContinuityResultCode::Found;
        validate_lookup_result(&found).expect("FOUND must validate for token lookup");
        for result_code in [
            ContinuityResultCode::Created,
            ContinuityResultCode::Replay,
            ContinuityResultCode::Updated,
        ] {
            let mut invalid = found.clone();
            invalid.result_code = result_code;
            assert!(matches!(
                validate_lookup_result(&invalid),
                Err(ContinuityError::InvalidResponse(
                    "token lookup result code is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn every_mutation_uses_the_serializable_isolation_contract() {
        assert!(matches!(
            MUTATION_ISOLATION_LEVEL,
            IsolationLevel::Serializable
        ));
    }

    #[test]
    fn mutation_and_read_inventories_use_their_shared_bounded_executors() {
        let production_source = include_str!("continuity.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("continuity source must contain its test module boundary");
        let transaction_count = production_source.matches(".build_transaction()").count();
        let timeout_count = production_source
            .matches("apply_mutation_timeouts(&transaction)")
            .count();
        let mutation_count = production_source
            .matches("run_serializable_mutation!(")
            .count();
        let bounded_read_count = production_source.matches("run_bounded_read!(").count();
        let read_only_transaction_count = production_source.matches(".read_only(true)").count();
        let reconciliation_callback_count = production_source.matches("self.reconcile_").count();

        assert_eq!(mutation_count, 13, "mutation inventory changed");
        assert_eq!(reconciliation_callback_count, mutation_count);
        assert_eq!(bounded_read_count, 6, "read inventory changed");
        assert_eq!(transaction_count, 2, "shared database executors split");
        assert_eq!(read_only_transaction_count, 1);
        assert_eq!(timeout_count, transaction_count);
    }

    #[test]
    fn bounded_read_executor_has_no_retry_or_backoff_path() {
        let production_source = include_str!("continuity.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("continuity source must contain its test module boundary");
        let bounded_read_source = production_source
            .split("macro_rules! run_bounded_read")
            .nth(1)
            .and_then(|source| source.split("const BEGIN_SQL").next())
            .expect("bounded read executor must precede the SQL inventory");

        assert!(bounded_read_source.contains(".read_only(true)"));
        assert!(bounded_read_source.contains("apply_mutation_timeouts(&transaction)"));
        for forbidden in [
            "tokio::time::sleep",
            "continue",
            "mutation_retry",
            "CommitFailureAction",
        ] {
            assert!(
                !bounded_read_source.contains(forbidden),
                "bounded read executor gained retry behavior {forbidden}"
            );
        }
    }

    #[test]
    fn mutation_backoff_and_reconnect_run_after_the_attempt_scope_releases_session() {
        let production_source = include_str!("continuity.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("continuity source must contain its test module boundary");
        let mutation_executor = production_source
            .split("macro_rules! run_serializable_mutation")
            .nth(1)
            .and_then(|source| source.split("enum CommitFailureAction").next())
            .expect("serializable mutation executor must be present");
        let attempt_scope = mutation_executor
            .split("let outcome = 'attempt: {")
            .nth(1)
            .and_then(|source| source.split("match outcome").next())
            .expect("mutation attempt must have a lexical resource scope");
        assert!(attempt_scope.contains("session.lock().await"));
        assert!(attempt_scope.contains("transaction.commit().await"));
        assert!(!attempt_scope.contains("tokio::time::sleep"));
        assert!(!attempt_scope.contains("reconnect().await"));

        let after_attempt = mutation_executor
            .split("match outcome")
            .nth(1)
            .expect("mutation outcomes must run after the lexical attempt scope");
        assert!(after_attempt.contains("tokio::time::sleep"));
        assert!(after_attempt.contains("reconnect().await"));
        assert!(after_attempt.contains("($reconcile)(&result).await"));
    }

    #[test]
    fn u64_max_has_an_exact_lossless_numeric_text_representation() {
        assert_eq!(u64::MAX.to_string(), "18446744073709551615");
        assert_eq!(
            parse_u64_text_value("18446744073709551615")
                .expect("u64 max must survive the NUMERIC text projection"),
            u64::MAX
        );
    }

    #[test]
    fn uint64_result_parser_rejects_negative_overflow_and_noncanonical_numbers() {
        for value in ["-1", "18446744073709551616", " 1", "1 ", "1.0", ""] {
            let error = parse_u64_text_value(value)
                .expect_err("an invalid uint64 text projection must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("uint64 field is out of range")
                ),
                "unexpected error for {value:?}: {error}"
            );
        }
        for value in ["+1", "01"] {
            let error = parse_u64_text_value(value)
                .expect_err("a noncanonical uint64 text projection must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("uint64 field is not canonical decimal text")
                ),
                "unexpected error for {value:?}: {error}"
            );
        }
    }

    #[test]
    fn digest_parser_accepts_exactly_32_bytes() {
        assert_eq!(
            parse_digest(vec![0x5a; 32]).expect("a 32-byte BLAKE3 digest must parse"),
            [0x5a; 32]
        );
        for digest in [vec![0x5a; 31], vec![0x5a; 33]] {
            let error = parse_digest(digest).expect_err("a non-32-byte digest must fail closed");
            assert!(
                matches!(
                    error,
                    ContinuityError::InvalidResponse("row digest is not 32 bytes")
                ),
                "unexpected digest error: {error}"
            );
        }
    }

    #[test]
    fn result_code_parser_accepts_only_the_frozen_allowlist() {
        for (text, expected) in [
            ("CREATED", ContinuityResultCode::Created),
            ("FOUND", ContinuityResultCode::Found),
            ("REPLAY", ContinuityResultCode::Replay),
            ("UPDATED", ContinuityResultCode::Updated),
        ] {
            assert_eq!(
                parse_result_code(text).expect("allowlisted result code must parse"),
                expected
            );
        }
        for text in ["", "created", "DELETED", " CREATED"] {
            assert!(matches!(
                parse_result_code(text),
                Err(ContinuityError::InvalidResponse(
                    "result code is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn state_parser_accepts_only_the_frozen_allowlist() {
        for (text, expected) in [
            ("INTENT", ContinuityState::Intent),
            ("BOUND", ContinuityState::Bound),
            ("COMPLETED", ContinuityState::Completed),
            ("NO_LOCAL_EFFECT", ContinuityState::NoLocalEffect),
            ("QUARANTINED", ContinuityState::Quarantined),
            ("AMBIGUOUS_DISPATCH", ContinuityState::AmbiguousDispatch),
            (
                "ADJUDICATION_PREPARED",
                ContinuityState::AdjudicationPrepared,
            ),
            (
                "ADJUDICATED_NO_LOCAL_EFFECT",
                ContinuityState::AdjudicatedNoLocalEffect,
            ),
            (
                "ADJUDICATED_NO_DISPATCH",
                ContinuityState::AdjudicatedNoDispatch,
            ),
        ] {
            assert_eq!(
                parse_state(text).expect("allowlisted continuity state must parse"),
                expected
            );
        }
        for text in ["", "intent", "RELEASED", " INTENT"] {
            assert!(matches!(
                parse_state(text),
                Err(ContinuityError::InvalidResponse("state is unsupported"))
            ));
        }
    }

    #[test]
    fn ownership_parser_accepts_only_the_frozen_allowlist() {
        assert_eq!(
            parse_ownership_state("SHADOW_RESERVED").expect("shadow ownership state must parse"),
            ContinuityOwnershipState::ShadowReserved
        );
        assert_eq!(
            parse_ownership_state("OWNERSHIP_RELEASED")
                .expect("released ownership state must parse"),
            ContinuityOwnershipState::OwnershipReleased
        );
        for text in ["", "shadow_reserved", "OWNED", " SHADOW_RESERVED"] {
            assert!(matches!(
                parse_ownership_state(text),
                Err(ContinuityError::InvalidResponse(
                    "ownership state is unsupported"
                ))
            ));
        }
    }

    #[test]
    fn not_found_shape_accepts_only_null_stored_evidence_and_nonnegative_time() {
        validate_not_found_shape(None, None, None, None, None, 0)
            .expect("the migration's exact nullable absence shape must parse");
        validate_not_found_shape(None, None, None, None, None, i64::MAX)
            .expect("a nonnegative observation time must parse");

        let digest = [0x5a; 32];
        for result in [
            validate_not_found_shape(Some("INTENT"), None, None, None, None, 0),
            validate_not_found_shape(None, Some("SHADOW_RESERVED"), None, None, None, 0),
            validate_not_found_shape(None, None, Some("1"), None, None, 0),
            validate_not_found_shape(None, None, None, Some("1"), None, 0),
            validate_not_found_shape(None, None, None, None, Some(&digest), 0),
        ] {
            assert!(matches!(
                result,
                Err(ContinuityError::InvalidResponse(
                    "not-found result carries stored-row evidence"
                ))
            ));
        }

        assert!(matches!(
            validate_not_found_shape(None, None, None, None, None, -1),
            Err(ContinuityError::InvalidResponse(
                "not-found time must be nonnegative"
            ))
        ));
    }

    #[test]
    fn dns_validator_rejects_paths_addresses_and_invalid_labels() {
        for invalid in [
            "",
            "/var/run/postgresql",
            r"C:\postgres\socket",
            "::1",
            ".continuity.internal",
            "continuity.internal.",
            "continuity..internal",
            "-continuity.internal",
            "continuity-.internal",
            "continuity_internal",
            "contínuïty.internal",
        ] {
            assert!(
                !is_dns_name(invalid),
                "accepted invalid DNS name {invalid:?}"
            );
        }
        assert!(is_dns_name("continuity-1.internal"));
    }

    #[test]
    fn mutation_timeout_query_sets_both_server_enforced_local_bounds() {
        assert_eq!(
            mutation_timeout_sql(2_000, 750),
            "SET LOCAL statement_timeout = '2000ms'; SET LOCAL lock_timeout = '750ms';"
        );
        assert_eq!(
            mutation_timeout_sql(u64::MAX, 1),
            format!(
                "SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout = '1ms';",
                u64::MAX
            )
        );
    }

    #[test]
    fn mutation_retry_schedule_is_exactly_three_attempts_with_frozen_delays() {
        for sqlstate in ["40001", "40P01"] {
            assert_eq!(
                mutation_retry_delay_for_shape(Some(sqlstate), 1, 3),
                Some(Duration::from_millis(25))
            );
            assert_eq!(
                mutation_retry_delay_for_shape(Some(sqlstate), 2, 3),
                Some(Duration::from_millis(100))
            );
            assert_eq!(mutation_retry_delay_for_shape(Some(sqlstate), 3, 3), None);
            assert_eq!(mutation_retry_delay_for_shape(Some(sqlstate), 4, 3), None);
        }
    }

    #[test]
    fn mutation_retry_rejects_transport_capacity_restart_and_unknown_failures() {
        for sqlstate in [
            None,
            Some("08000"),
            Some("08006"),
            Some("40003"),
            Some("53000"),
            Some("53100"),
            Some("57P01"),
            Some("57P03"),
            Some("XXXXX"),
        ] {
            assert_eq!(
                mutation_retry_delay_for_shape(sqlstate, 1, 3),
                None,
                "mutation retry accepted unresolved failure {sqlstate:?}"
            );
        }
    }

    #[test]
    fn begin_reconciliation_adopts_only_the_exact_precommit_row_and_never_found() {
        let identity = sample_identity();
        let mut precommit = sample_result(&identity);
        precommit.result_code = ContinuityResultCode::Created;
        let mut authoritative = precommit.clone();
        authoritative.result_code = ContinuityResultCode::Found;

        assert_adopted(
            reconcile_begin_readback(
                &precommit,
                Some(ContinuityTokenLookup::Found(authoritative.clone())),
            ),
            &precommit,
        );

        let mut mismatches = Vec::new();
        let mut mismatch = authoritative.clone();
        mismatch.state = ContinuityState::Completed;
        mismatches.push(mismatch);
        let mut mismatch = authoritative.clone();
        mismatch.ownership_state = ContinuityOwnershipState::OwnershipReleased;
        mismatches.push(mismatch);
        let mut mismatch = authoritative.clone();
        mismatch.authority_epoch += 1;
        mismatches.push(mismatch);
        let mut mismatch = authoritative.clone();
        mismatch.continuity_seq += 1;
        mismatches.push(mismatch);
        let mut mismatch = authoritative.clone();
        mismatch.continuity_token_id = Uuid::from_u128(0xDEAD);
        mismatches.push(mismatch);
        let mut mismatch = authoritative.clone();
        mismatch.row_blake3 = [0x52; 32];
        mismatches.push(mismatch);
        let mut mismatch = authoritative;
        mismatch.external_committed_at_unix_ms += 1;
        mismatches.push(mismatch);

        for mismatch in mismatches {
            assert_unresolved(reconcile_begin_readback(
                &precommit,
                Some(ContinuityTokenLookup::Found(mismatch)),
            ));
        }
        assert_retry(reconcile_begin_readback(
            &precommit,
            Some(ContinuityTokenLookup::NotFound {
                continuity_token_id: precommit.continuity_token_id,
                observed_at_unix_ms: 1,
            }),
        ));
        assert_unresolved(reconcile_begin_readback(&precommit, None));
    }

    #[test]
    fn token_transition_reconciliation_distinguishes_exact_result_prior_and_mismatch() {
        let identity = sample_identity();
        let precommit = sample_result(&identity);
        let expected_prior_row_blake3 = [0x31; 32];
        let mut authoritative = precommit.clone();
        authoritative.result_code = ContinuityResultCode::Found;

        assert_adopted(
            reconcile_token_transition_readback(
                &identity,
                &expected_prior_row_blake3,
                &precommit,
                Some(ContinuityTokenLookup::Found(authoritative.clone())),
            ),
            &precommit,
        );

        let mut prior = authoritative.clone();
        prior.state = ContinuityState::Bound;
        prior.row_blake3 = expected_prior_row_blake3;
        assert_retry(reconcile_token_transition_readback(
            &identity,
            &expected_prior_row_blake3,
            &precommit,
            Some(ContinuityTokenLookup::Found(prior)),
        ));

        for mismatch in [
            {
                let mut value = authoritative.clone();
                value.row_blake3 = [0x52; 32];
                value
            },
            {
                let mut value = authoritative.clone();
                value.external_committed_at_unix_ms += 1;
                value
            },
            {
                let mut value = authoritative;
                value.continuity_token_id = Uuid::from_u128(0xBEEF);
                value
            },
        ] {
            assert_unresolved(reconcile_token_transition_readback(
                &identity,
                &expected_prior_row_blake3,
                &precommit,
                Some(ContinuityTokenLookup::Found(mismatch)),
            ));
        }
        assert_unresolved(reconcile_token_transition_readback(
            &identity,
            &expected_prior_row_blake3,
            &precommit,
            Some(ContinuityTokenLookup::NotFound {
                continuity_token_id: identity.continuity_token_id,
                observed_at_unix_ms: 1,
            }),
        ));
        assert_unresolved(reconcile_token_transition_readback(
            &identity,
            &expected_prior_row_blake3,
            &precommit,
            None,
        ));
    }

    #[test]
    fn incomplete_snapshot_epoch_and_archive_reads_never_fabricate_adoption() {
        let snapshot_request = RecordSnapshotRequest {
            snapshot_id: Uuid::from_u128(0x101),
            provider_boundary_id: "boundary-a".to_string(),
            authority_epoch: 7,
            through_continuity_seq: 11,
            authority_lsn: 13,
            manifest_blake3: [0x21; 32],
            continuity_seq: 11,
            continuity_token_id: Uuid::from_u128(0x102),
            local_binding_blake3: [0x31; 32],
            local_state_blake3: [0x41; 32],
            local_quota_ownership_blake3: [0x51; 32],
            local_counter_revision: 17,
        };
        let exact_snapshot = ReconciliationSnapshot {
            snapshot_id: snapshot_request.snapshot_id,
            through_continuity_seq: snapshot_request.through_continuity_seq,
            manifest_blake3: snapshot_request.manifest_blake3,
        };
        assert_retry(reconcile_snapshot_readback(
            &snapshot_request,
            Some(Some(exact_snapshot.clone())),
        ));
        assert_retry(reconcile_snapshot_readback(&snapshot_request, Some(None)));
        let mut mismatched_snapshot = exact_snapshot;
        mismatched_snapshot.manifest_blake3 = [0x22; 32];
        assert_unresolved(reconcile_snapshot_readback(
            &snapshot_request,
            Some(Some(mismatched_snapshot)),
        ));
        assert_unresolved(reconcile_snapshot_readback(&snapshot_request, None));

        let epoch_request = AllocateEpochRequest {
            provider_boundary_id: "boundary-a".to_string(),
            expected_current_epoch: 7,
            next_epoch: 8,
            epoch_namespace_blake3: [0x61; 32],
        };
        assert_retry(reconcile_epoch_allocation_readback(
            &epoch_request,
            Some(ContinuityEpochState {
                authority_epoch: 7,
                continuity_seq_high_water: 0,
            }),
        ));
        assert_unresolved(reconcile_epoch_allocation_readback(
            &epoch_request,
            Some(ContinuityEpochState {
                authority_epoch: 8,
                continuity_seq_high_water: 0,
            }),
        ));
        assert_unresolved(reconcile_epoch_allocation_readback(&epoch_request, None));

        let archive_request = sample_archive_prune_request();
        let prior = ContinuityProcedureResult {
            result_code: ContinuityResultCode::Found,
            state: ContinuityState::NoLocalEffect,
            ownership_state: ContinuityOwnershipState::OwnershipReleased,
            authority_epoch: archive_request.authority_epoch,
            continuity_seq: archive_request.continuity_seq,
            continuity_token_id: archive_request.continuity_token_id,
            row_blake3: archive_request.expected_row_blake3,
            external_committed_at_unix_ms: 1,
        };
        assert_retry(reconcile_archive_readback(
            &archive_request,
            Some(ContinuityTokenLookup::Found(prior.clone())),
        ));
        let mut mismatched_prior = prior;
        mismatched_prior.row_blake3 = [0x32; 32];
        assert_unresolved(reconcile_archive_readback(
            &archive_request,
            Some(ContinuityTokenLookup::Found(mismatched_prior)),
        ));
        assert_unresolved(reconcile_archive_readback(
            &archive_request,
            Some(ContinuityTokenLookup::NotFound {
                continuity_token_id: archive_request.continuity_token_id,
                observed_at_unix_ms: 1,
            }),
        ));
        assert_unresolved(reconcile_archive_readback(&archive_request, None));
    }

    #[test]
    fn retirement_reconciliation_adopts_only_exact_validated_precommit_summary() {
        let request = sample_retire_epoch_request();
        let precommit = sample_retired_epoch_summary();

        assert_adopted(
            reconcile_retirement_readback(&request, &precommit, Some(precommit.clone()), None),
            &precommit,
        );
        let mut mismatched_summary = precommit.clone();
        mismatched_summary.retirement_proof_blake3 = [0xC2; 32];
        assert_unresolved(reconcile_retirement_readback(
            &request,
            &precommit,
            Some(mismatched_summary),
            None,
        ));
        let mut mismatched_request = sample_retire_epoch_request();
        mismatched_request.expected_snapshot_manifest_blake3 = [0xA2; 32];
        assert_unresolved(reconcile_retirement_readback(
            &mismatched_request,
            &precommit,
            Some(precommit.clone()),
            None,
        ));

        let mut active_interval = sample_pruned_interval();
        active_interval.start_sequence = 1;
        active_interval.interval_blake3 = request.expected_interval_checkpoint_blake3;
        assert_retry(reconcile_retirement_readback(
            &request,
            &precommit,
            None,
            Some(active_interval.clone()),
        ));
        active_interval.interval_blake3 = [0x92; 32];
        assert_unresolved(reconcile_retirement_readback(
            &request,
            &precommit,
            None,
            Some(active_interval),
        ));
        assert_unresolved(reconcile_retirement_readback(
            &request, &precommit, None, None,
        ));
    }

    #[test]
    fn commit_failure_requires_reconciliation_only_for_transport_ambiguity() {
        assert_eq!(
            commit_failure_action(true, None, 1, 3),
            CommitFailureAction::Reconcile
        );
        for sqlstate in ["08000", "08006"] {
            assert_eq!(
                commit_failure_action(false, Some(sqlstate), 1, 3),
                CommitFailureAction::Reconcile
            );
        }
        for sqlstate in ["53000", "53100", "57P01", "57P03", "XXXXX"] {
            assert_eq!(
                commit_failure_action(false, Some(sqlstate), 1, 3),
                CommitFailureAction::Fail,
                "commit classified broad transient SQLSTATE {sqlstate} as replay authority"
            );
        }
    }

    #[test]
    fn commit_known_abort_retry_exhausts_after_the_third_attempt() {
        for sqlstate in ["40001", "40P01"] {
            assert_eq!(
                commit_failure_action(false, Some(sqlstate), 1, 3),
                CommitFailureAction::RetryAfter(Duration::from_millis(25))
            );
            assert_eq!(
                commit_failure_action(false, Some(sqlstate), 2, 3),
                CommitFailureAction::RetryAfter(Duration::from_millis(100))
            );
            assert_eq!(
                commit_failure_action(false, Some(sqlstate), 3, 3),
                CommitFailureAction::Exhausted
            );
        }
    }

    #[test]
    fn postgres_transience_is_a_closed_transport_and_sqlstate_set() {
        assert!(postgres_error_shape_is_transient(true, None));
        for sqlstate in ["08006", "40001", "40P01", "53000", "57P01", "57P03"] {
            assert!(
                postgres_error_shape_is_transient(false, Some(sqlstate)),
                "expected SQLSTATE {sqlstate} to be transient"
            );
        }
        for sqlstate in ["22003", "23505", "28000", "42601", "57P02", "XXXXX"] {
            assert!(
                !postgres_error_shape_is_transient(false, Some(sqlstate)),
                "expected SQLSTATE {sqlstate} to be permanent"
            );
        }
        assert!(!postgres_error_shape_is_transient(false, None));
    }

    #[test]
    fn client_level_errors_are_transient_only_when_the_contract_says_so() {
        assert_eq!(
            ContinuityError::AmbiguousCommit,
            ContinuityError::AmbiguousCommit
        );
        assert_ne!(
            ContinuityError::AmbiguousCommit,
            ContinuityError::RetryExhausted
        );
        assert!(ContinuityError::ConnectTimeout.is_transient());
        assert!(ContinuityError::Postgres { transient: true }.is_transient());
        assert!(!ContinuityError::Postgres { transient: false }.is_transient());
        assert!(
            !ContinuityError::InvalidConfiguration("test configuration failure").is_transient()
        );
        assert!(!ContinuityError::InvalidTlsMaterial("test TLS failure").is_transient());
        assert!(!ContinuityError::RetryExhausted.is_transient());
        assert!(!ContinuityError::AmbiguousCommit.is_transient());
        assert!(!ContinuityError::InvalidResponse("test response failure").is_transient());
    }

    #[test]
    fn postgres_error_rendering_and_source_chain_never_expose_driver_diagnostics() {
        let error = ContinuityError::Postgres { transient: true };
        assert_eq!(format!("{error}"), "continuity database operation failed");
        assert_eq!(format!("{error:?}"), "Postgres { transient: true }");
        assert!(std::error::Error::source(&error).is_none());

        assert_eq!(
            ContinuityError::RetryExhausted.to_string(),
            "continuity mutation retry budget exhausted"
        );
        assert_eq!(
            ContinuityError::AmbiguousCommit.to_string(),
            "continuity mutation commit outcome is ambiguous"
        );
    }
}

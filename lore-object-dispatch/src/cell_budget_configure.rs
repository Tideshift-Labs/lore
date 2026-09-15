// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Bounded local-development budget publication through the existing maintenance procedure.
//! These records attest an operator-selected local policy, not measured provider capacity or
//! deployment approval. Successors preserve depletion through the authority's publication API.

use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::dispatch_client::DispatchDatabaseIdentity;
use crate::dispatch_pool::DispatchConnectionBudget;
use crate::dispatch_pool::DispatchPoolConfig;
use crate::dispatch_pool::DispatchPoolRole;
use crate::dispatch_pool::DispatchRuntimePool;
use crate::dispatch_pool::DispatchTlsMode;

pub const LOCAL_BUDGET_REVISION: &str = "local-cell-budget-policy-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalBudgetConfiguration {
    pub schema_revision: String,
    pub provenance: String,
    pub cell_id: String,
    pub provider_boundary_id: String,
    pub provider_endpoint: String,
    pub provider_bucket: String,
    pub evidence_reference: String,
    pub system_identifier: String,
    pub database_oid: u32,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub issued_at_unix_ms: i64,
    pub hard_expires_at_unix_ms: i64,
    pub shared_units: u64,
    pub class_units: u64,
    pub list_units: u64,
    pub refill_interval_ms: u64,
    pub predecessor: Option<BudgetPredecessor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BudgetPredecessor {
    pub allocation_fence: u64,
    pub disposition_id: String,
    pub disposition_digest: String,
    pub envelope_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BudgetReceipt {
    pub result: String,
    /// Observation at this command's database clock, not a readiness or renewal grant.
    pub expired: bool,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub hard_expires_at_unix_ms: i64,
    pub disposition_id: String,
    pub disposition_digest: String,
    pub envelope_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetAction {
    Publish,
    Verify,
    /// Recover the exact current receipt, including after expiry. Never commits or grants readiness.
    Reconcile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetConfigureError {
    #[error("local budget configuration is invalid")]
    InvalidConfiguration,
    #[error("local budget database connection or identity was refused")]
    ConnectionRefused,
    #[error("local budget authority refused the configuration")]
    AuthorityRefused,
    #[error("local budget is not the exact currently published configuration")]
    NotPublished,
    #[error("local budget publication outcome is unknown; reconcile the exact configuration")]
    OutcomeUnknown,
}

impl LocalBudgetConfiguration {
    pub fn from_json(bytes: &[u8]) -> Result<Self, BudgetConfigureError> {
        if bytes.len() > 16_384 {
            return Err(BudgetConfigureError::InvalidConfiguration);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), BudgetConfigureError> {
        let valid_token = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && value.as_bytes()[0].is_ascii_alphanumeric()
        };
        let horizon = self
            .hard_expires_at_unix_ms
            .checked_sub(self.issued_at_unix_ms);
        let local_endpoint = self
            .provider_endpoint
            .strip_prefix("http://")
            .and_then(|endpoint| endpoint.strip_suffix('/').or(Some(endpoint)))
            .is_some_and(|endpoint| {
                ["minio", "localhost", "127.0.0.1", "[::1]"]
                    .into_iter()
                    .any(|host| {
                        endpoint == host
                            || endpoint.strip_prefix(host).is_some_and(|suffix| {
                                suffix.strip_prefix(':').is_some_and(|port| {
                                    port.parse::<u16>().is_ok_and(|port| port > 0)
                                })
                            })
                    })
            });
        if self.schema_revision != LOCAL_BUDGET_REVISION
            || self.provenance != "operator-selected-local-development-limit-v1"
            || ![
                &self.cell_id,
                &self.provider_boundary_id,
                &self.provider_bucket,
                &self.allocation_revision,
            ]
            .into_iter()
            .all(|s| valid_token(s))
            || !local_endpoint
            || self.provider_endpoint.len() > 256
            || self.provider_endpoint.contains(['@', '?', '#', '\n', '\r'])
            || self.evidence_reference.is_empty()
            || self.evidence_reference.len() > 512
            || self.issued_at_unix_ms < 0
            || !horizon.is_some_and(|h| (60_000..=86_400_000).contains(&h))
            || self.allocation_fence == 0
            || self.allocation_fence > i64::MAX as u64
            || !(1..=1_000_000).contains(&self.shared_units)
            || self.class_units == 0
            || self.class_units >= self.shared_units
            || self.list_units == 0
            || self.list_units >= self.class_units
            || !(100..=60_000).contains(&self.refill_interval_ms)
        {
            return Err(BudgetConfigureError::InvalidConfiguration);
        }
        self.database_identity()?;
        match &self.predecessor {
            None if self.allocation_fence == 1 => {}
            Some(prior) if prior.allocation_fence.checked_add(1) == Some(self.allocation_fence) => {
                Uuid::parse_str(&prior.disposition_id)
                    .map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
                digest_bytes(&prior.disposition_digest)?;
                digest_bytes(&prior.envelope_digest)?;
            }
            _ => return Err(BudgetConfigureError::InvalidConfiguration),
        }
        Ok(())
    }

    fn database_identity(&self) -> Result<DispatchDatabaseIdentity, BudgetConfigureError> {
        let system = self
            .system_identifier
            .parse()
            .map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
        DispatchDatabaseIdentity::new(system, self.database_oid)
            .map_err(|_| BudgetConfigureError::InvalidConfiguration)
    }
}

fn digest_bytes(value: &str) -> Result<Vec<u8>, BudgetConfigureError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BudgetConfigureError::InvalidConfiguration);
    }
    (0..32)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .map_err(|_| BudgetConfigureError::InvalidConfiguration)
        })
        .collect()
}

fn digest(label: &str, bytes: &[u8]) -> blake3::Hash {
    let mut hash = blake3::Hasher::new_derive_key(label);
    hash.update(bytes);
    hash.finalize()
}

/// Verify and reconcile use the same exact-identity oracle as publish, but always roll back.
/// A first publication or successor returning PUBLISHED is refused without persisting it.
/// Only reconcile accepts expiry, to recover a lost receipt for an explicit successor.
/// Every action requires a pinned root CA before opening a database connection.
pub async fn configure_budget(
    config: &LocalBudgetConfiguration,
    url: &str,
    tls: DispatchTlsMode,
    action: BudgetAction,
) -> Result<BudgetReceipt, BudgetConfigureError> {
    if !matches!(&tls, DispatchTlsMode::PinnedRootCa(pem) if !pem.trim().is_empty()) {
        return Err(BudgetConfigureError::ConnectionRefused);
    }
    tokio::time::timeout(
        Duration::from_secs(30),
        configure_budget_inner(config, url, tls, action),
    )
    .await
    .map_err(|_| match action {
        BudgetAction::Publish => BudgetConfigureError::OutcomeUnknown,
        BudgetAction::Verify | BudgetAction::Reconcile => BudgetConfigureError::AuthorityRefused,
    })?
}

async fn configure_budget_inner(
    config: &LocalBudgetConfiguration,
    url: &str,
    tls: DispatchTlsMode,
    action: BudgetAction,
) -> Result<BudgetReceipt, BudgetConfigureError> {
    config.validate()?;
    let pool = DispatchRuntimePool::new(DispatchPoolConfig {
        postgres_url: url.to_owned(),
        role: DispatchPoolRole::Maintenance,
        expected_database_identity: config.database_identity()?,
        pool_max: 1,
        connect_timeout: Duration::from_secs(10),
        acquire_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(10),
        lock_timeout: Duration::from_secs(2),
        tls,
        budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0)
            .map_err(|_| BudgetConfigureError::InvalidConfiguration)?,
    })
    .map_err(|_| BudgetConfigureError::ConnectionRefused)?;
    let mut lease = pool
        .acquire()
        .await
        .map_err(|_| BudgetConfigureError::ConnectionRefused)?;
    let transaction = lease
        .client()
        .map_err(|_| BudgetConfigureError::ConnectionRefused)?
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
    transaction
        .batch_execute(&pool.bounded_execution_preamble())
        .await
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
    let now: i64 = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .await
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?
        .try_get(0)
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
    let expired = now >= config.hard_expires_at_unix_ms;
    if now < config.issued_at_unix_ms || (expired && action != BudgetAction::Reconcile) {
        return Err(BudgetConfigureError::InvalidConfiguration);
    }
    let canonical =
        serde_json::to_vec(config).map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
    let core = digest("Commit0 local development budget core v1", &canonical);
    let disposition = digest(
        "Commit0 local development no-cache disposition v1",
        core.as_bytes(),
    );
    let envelope = digest(
        "Commit0 local development budget envelope v1",
        disposition.as_bytes(),
    );
    let mut uuid_bytes = [0; 16];
    uuid_bytes.copy_from_slice(&disposition.as_bytes()[..16]);
    let disposition_id = Uuid::from_bytes(uuid_bytes);
    let dimensions = serde_json::json!([{
        "dimensionId":"local-policy-requests", "effectiveBound":config.shared_units,
        "measuredLoad":0, "targetDemand":0, "failureReserve":0,
        "preCacheHeadroom":config.shared_units, "finalBudget":config.shared_units
    }])
    .to_string();
    let caps = (1..=7)
        .map(|class| {
            let units = match class {
                1 => config.shared_units,
                7 => config.list_units,
                _ => config.class_units,
            };
            serde_json::json!({"capClass":class,"capacityUnits":units,"refillUnits":units,
            "refillIntervalMs":config.refill_interval_ms})
        })
        .collect::<Vec<_>>();
    let caps =
        serde_json::to_string(&caps).map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
    let vector = digest(
        "Commit0 local development budget vector v1",
        dimensions.as_bytes(),
    );
    let prior_id = config
        .predecessor
        .as_ref()
        .map(|p| Uuid::parse_str(&p.disposition_id))
        .transpose()
        .map_err(|_| BudgetConfigureError::InvalidConfiguration)?;
    let prior_disposition = config
        .predecessor
        .as_ref()
        .map(|p| digest_bytes(&p.disposition_digest))
        .transpose()?;
    let prior_envelope = config
        .predecessor
        .as_ref()
        .map(|p| digest_bytes(&p.envelope_digest))
        .transpose()?;
    let prior_revision = config
        .predecessor
        .as_ref()
        .map_or(0, |p| p.allocation_fence)
        .to_string();
    let revision = config.allocation_fence.to_string();
    let row = transaction
        .query_one(
            PUBLISH_SQL,
            &[
                &config.provider_boundary_id,
                &config.allocation_revision,
                &revision,
                &config.hard_expires_at_unix_ms,
                &config.cell_id,
                &core.as_bytes().as_slice(),
                &disposition_id,
                &disposition.as_bytes().as_slice(),
                &prior_id,
                &prior_disposition,
                &prior_revision,
                &prior_envelope,
                &envelope.as_bytes().as_slice(),
                &vector.as_bytes().as_slice(),
                &dimensions,
                &caps,
            ],
        )
        .await
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
    let code: String = row
        .try_get("result_code")
        .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
    if action != BudgetAction::Publish {
        transaction
            .rollback()
            .await
            .map_err(|_| BudgetConfigureError::AuthorityRefused)?;
        if code != "REPLAY" {
            return Err(BudgetConfigureError::NotPublished);
        }
    } else {
        if code != "REPLAY" && code != "PUBLISHED" {
            return Err(BudgetConfigureError::AuthorityRefused);
        }
        transaction
            .commit()
            .await
            .map_err(|_| BudgetConfigureError::OutcomeUnknown)?;
    }
    Ok(BudgetReceipt {
        result: match action {
            BudgetAction::Verify => "VERIFIED".into(),
            BudgetAction::Reconcile => "RECONCILED".into(),
            BudgetAction::Publish => code,
        },
        expired,
        allocation_revision: config.allocation_revision.clone(),
        allocation_fence: config.allocation_fence,
        hard_expires_at_unix_ms: config.hard_expires_at_unix_ms,
        disposition_id: disposition_id.to_string(),
        disposition_digest: disposition.to_hex().to_string(),
        envelope_digest: envelope.to_hex().to_string(),
    })
}

const PUBLISH_SQL: &str = "SELECT r.result_code FROM
object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
'object-store-dispatch-budget-limiter-v1', $1, $2, $3::text::object_store_retention.uint64, $4,
'object-store-frozen-capacity-budget-core-v1', 'object-store-exact-target-cache-disposition-v1',
'object-store-budget-frozen-envelope-v1', 1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64,
1::smallint, $5, $3::text::object_store_retention.uint64, $5, $5, $1, $1,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
$6, $7, $8, $6, $3::text::object_store_retention.uint64,
$9, $10, $11::text::object_store_retention.uint64, $12,
$13, $6, $8, $14, $3::text::object_store_retention.uint64, 1::smallint,
NULL::text, NULL::text, NULL::bytea, NULL::bytea, $14, $15::text::jsonb, $16::text::jsonb) AS r";

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Bounded budget publication through the existing maintenance procedure, for the two provenance
//! types in [`crate::budget_provenance`]. A local record attests an operator-selected local
//! policy. A documented-provider record attests KV's 2026-08-31 adoption of the documented
//! DO Spaces per-bucket limit for one bound endpoint. Neither is measured provider capacity or
//! deployment approval. Successors preserve depletion through the authority's publication API.

use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_PROVENANCE;
use crate::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_REVISION;
use crate::budget_provenance::DOCUMENTED_PROVIDER_ENDPOINT;
use crate::budget_provenance::DOCUMENTED_PROVIDER_ENDPOINT_HOST;
use crate::budget_provenance::DOCUMENTED_PROVIDER_MAX_OPERATIONS_PER_SECOND;
use crate::budget_provenance::DOCUMENTED_PROVIDER_MAX_WINDOW_MS;
use crate::budget_provenance::DOCUMENTED_PROVIDER_REGION;
use crate::budget_provenance::DOCUMENTED_PROVIDER_REVISION_PREFIX;
use crate::budget_provenance::DOCUMENTED_PROVIDER_RULING_REFERENCE;
use crate::budget_provenance::LOCAL_BUDGET_PROVENANCE;
use crate::budget_provenance::LOCAL_MAX_WINDOW_MS;
use crate::budget_provenance::documented_provider_revision;
use crate::budget_provenance::is_local_endpoint;
use crate::dispatch_client::DispatchDatabaseIdentity;
use crate::dispatch_pool::DispatchConnectionBudget;
use crate::dispatch_pool::DispatchPoolConfig;
use crate::dispatch_pool::DispatchPoolRole;
use crate::dispatch_pool::DispatchRuntimePool;
use crate::dispatch_pool::DispatchTlsMode;

pub const LEGACY_LOCAL_BUDGET_REVISION: &str = "local-cell-budget-policy-v1";
pub const LOCAL_BUDGET_REVISION: &str = "local-cell-budget-policy-v2";

#[cfg(test)]
#[path = "cell_budget_configure_tests.rs"]
mod tests;

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
    /// Documented-provider records only. Absent, and so omitted from the canonical bytes, on a
    /// local record, which keeps every retained local digest unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_region: Option<String>,
    /// Documented-provider records only: the ruling this record binds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruling_reference: Option<String>,
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
    /// The record's provenance type, so a receipt never reads as another type's evidence. A
    /// receipt retained from before this field existed is local: no other type was publishable.
    #[serde(default = "local_receipt_provenance")]
    pub provenance: String,
    /// Observation at this command's database clock, not a readiness or renewal grant.
    pub expired: bool,
    pub allocation_revision: String,
    pub allocation_fence: u64,
    pub hard_expires_at_unix_ms: i64,
    pub disposition_id: String,
    pub disposition_digest: String,
    pub envelope_digest: String,
}

/// The values a budget must agree with, read from the cell's rendered loreserver configuration
/// layers. `None` means no layer sets that key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellConfigBinding {
    /// `plugins.postgres.immutable_store.object_store.bucket`
    pub bucket: Option<String>,
    /// `plugins.postgres.immutable_store.object_store.endpoint_url`
    pub endpoint_url: Option<String>,
    /// `plugins.postgres.immutable_store.fragment_provider.provider_boundary_id`
    pub provider_boundary_id: Option<String>,
    /// `plugins.postgres.immutable_store.fragment_provider.endpoint_host`
    pub endpoint_host: Option<String>,
}

impl CellConfigBinding {
    /// Read the binding from loreserver configuration layers in load order. A later layer
    /// overrides a key an earlier one set, as the server's layered loading does. A layer that is
    /// not TOML, or a bound key that is not a string, is refused. Environment overrides are not
    /// seen here, so the operator passes the layers that set these keys.
    pub fn from_toml_layers<S: AsRef<str>>(layers: &[S]) -> Result<Self, BudgetConfigureError> {
        const STORE: [&str; 3] = ["plugins", "postgres", "immutable_store"];
        let mut binding = Self::default();
        for layer in layers {
            let table: toml::Table = toml::from_str(layer.as_ref())
                .map_err(|_err| BudgetConfigureError::CellBindingMismatch)?;
            for (section, key, slot) in [
                ("object_store", "bucket", &mut binding.bucket),
                ("object_store", "endpoint_url", &mut binding.endpoint_url),
                (
                    "fragment_provider",
                    "provider_boundary_id",
                    &mut binding.provider_boundary_id,
                ),
                (
                    "fragment_provider",
                    "endpoint_host",
                    &mut binding.endpoint_host,
                ),
            ] {
                let mut value = Some(&table);
                for name in STORE.iter().chain([&section]) {
                    value = value
                        .and_then(|table| table.get(*name))
                        .and_then(toml::Value::as_table);
                }
                match value.and_then(|table| table.get(key)) {
                    None => {}
                    Some(toml::Value::String(text)) => *slot = Some(text.clone()),
                    Some(_) => return Err(BudgetConfigureError::CellBindingMismatch),
                }
            }
        }
        Ok(binding)
    }
}

struct BudgetDomains {
    core: &'static str,
    disposition: &'static str,
    envelope: &'static str,
    vector: &'static str,
    dimension: &'static str,
}

fn local_receipt_provenance() -> String {
    LOCAL_BUDGET_PROVENANCE.to_owned()
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
    #[error("budget configuration does not match the cell configuration, or none was supplied")]
    CellBindingMismatch,
}

impl LocalBudgetConfiguration {
    pub fn from_json(bytes: &[u8]) -> Result<Self, BudgetConfigureError> {
        if bytes.len() > 16_384 {
            return Err(BudgetConfigureError::InvalidConfiguration);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
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
        // Each provenance type closes its own schema, endpoint, window and binding fields. A record
        // matching neither arm completely is refused; nothing falls through to the other type.
        let provenance_bound = if self.is_documented_provider() {
            self.schema_revision == DOCUMENTED_PROVIDER_BUDGET_REVISION
                && self.provider_region.as_deref() == Some(DOCUMENTED_PROVIDER_REGION)
                && self.ruling_reference.as_deref() == Some(DOCUMENTED_PROVIDER_RULING_REFERENCE)
                && self.provider_endpoint == DOCUMENTED_PROVIDER_ENDPOINT
                && horizon.is_some_and(|h| (60_000..=DOCUMENTED_PROVIDER_MAX_WINDOW_MS).contains(&h))
                && self.allocation_revision
                    == documented_provider_revision(
                        self.allocation_fence,
                        self.hard_expires_at_unix_ms,
                    )
                // The sustained rate is shared units per refill interval. A refill interval of at
                // most one second keeps the bucket at most 800, so one second sees at most a full
                // bucket plus one refill.
                && self.refill_interval_ms <= 1000
                && self.shared_units.checked_mul(1000).is_some_and(|scaled| {
                    self.refill_interval_ms
                        .checked_mul(DOCUMENTED_PROVIDER_MAX_OPERATIONS_PER_SECOND)
                        .is_some_and(|ceiling| scaled <= ceiling)
                })
        } else {
            self.provenance == LOCAL_BUDGET_PROVENANCE
                && [LEGACY_LOCAL_BUDGET_REVISION, LOCAL_BUDGET_REVISION]
                    .contains(&self.schema_revision.as_str())
                && self.provider_region.is_none()
                && self.ruling_reference.is_none()
                && is_local_endpoint(&self.provider_endpoint)
                && horizon.is_some_and(|h| (60_000..=LOCAL_MAX_WINDOW_MS).contains(&h))
                && !self
                    .allocation_revision
                    .starts_with(DOCUMENTED_PROVIDER_REVISION_PREFIX)
        };
        if !provenance_bound
            || ![
                &self.cell_id,
                &self.provider_boundary_id,
                &self.provider_bucket,
                &self.allocation_revision,
            ]
            .into_iter()
            .all(|s| valid_token(s))
            || self.provider_endpoint.len() > 256
            || self.provider_endpoint.contains(['@', '?', '#', '\n', '\r'])
            || self.evidence_reference.is_empty()
            || self.evidence_reference.len() > 512
            || self.issued_at_unix_ms < 0
            || (self.schema_revision != LEGACY_LOCAL_BUDGET_REVISION
                && self.issued_at_unix_ms > 0xffff_ffff_ffff)
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
                    .map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
                digest_bytes(&prior.disposition_digest)?;
                digest_bytes(&prior.envelope_digest)?;
            }
            _ => return Err(BudgetConfigureError::InvalidConfiguration),
        }
        Ok(())
    }

    pub fn is_documented_provider(&self) -> bool {
        self.provenance == DOCUMENTED_PROVIDER_BUDGET_PROVENANCE
    }

    /// Compare this record with the cell's own configuration. The bucket and endpoint URL must be
    /// set there and equal; a boundary id or endpoint host the layers set must equal too.
    pub fn check_cell_binding(&self, cell: &CellConfigBinding) -> Result<(), BudgetConfigureError> {
        let host_bound = !self.is_documented_provider()
            || cell
                .endpoint_host
                .as_deref()
                .is_none_or(|host| host == DOCUMENTED_PROVIDER_ENDPOINT_HOST);
        if cell.bucket.as_deref() != Some(self.provider_bucket.as_str())
            || cell.endpoint_url.as_deref() != Some(self.provider_endpoint.as_str())
            || cell
                .provider_boundary_id
                .as_deref()
                .is_some_and(|boundary| boundary != self.provider_boundary_id)
            || !host_bound
        {
            return Err(BudgetConfigureError::CellBindingMismatch);
        }
        Ok(())
    }

    /// Digest domains and the limiter dimension. The documented type has its own, so its digests
    /// can never equal a local record's, and a reader of the stored dimension sees which it is.
    fn domains(&self) -> BudgetDomains {
        if self.is_documented_provider() {
            BudgetDomains {
                core: "Commit0 documented provider budget core v1",
                disposition: "Commit0 documented provider no-cache disposition v1",
                envelope: "Commit0 documented provider budget envelope v1",
                vector: "Commit0 documented provider budget vector v1",
                dimension: "documented-provider-operations",
            }
        } else {
            BudgetDomains {
                core: "Commit0 local development budget core v1",
                disposition: "Commit0 local development no-cache disposition v1",
                envelope: "Commit0 local development budget envelope v1",
                vector: "Commit0 local development budget vector v1",
                dimension: "local-policy-requests",
            }
        }
    }

    fn database_identity(&self) -> Result<DispatchDatabaseIdentity, BudgetConfigureError> {
        let system = self
            .system_identifier
            .parse()
            .map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
        DispatchDatabaseIdentity::new(system, self.database_oid)
            .map_err(|_err| BudgetConfigureError::InvalidConfiguration)
    }
}

fn digest_bytes(value: &str) -> Result<Vec<u8>, BudgetConfigureError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BudgetConfigureError::InvalidConfiguration);
    }
    (0..32)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .map_err(|_err| BudgetConfigureError::InvalidConfiguration)
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
///
/// This entry point has no cell configuration, so it refuses a documented-provider record. Use
/// [`configure_budget_for_cell`] for that type.
pub async fn configure_budget(
    config: &LocalBudgetConfiguration,
    url: &str,
    tls: DispatchTlsMode,
    action: BudgetAction,
) -> Result<BudgetReceipt, BudgetConfigureError> {
    configure_budget_checked(config, None, url, tls, action).await
}

/// [`configure_budget`], first checking the record against the cell's own configuration. Required
/// for a documented-provider record; also accepted for a local one.
pub async fn configure_budget_for_cell(
    config: &LocalBudgetConfiguration,
    cell: &CellConfigBinding,
    url: &str,
    tls: DispatchTlsMode,
    action: BudgetAction,
) -> Result<BudgetReceipt, BudgetConfigureError> {
    configure_budget_checked(config, Some(cell), url, tls, action).await
}

async fn configure_budget_checked(
    config: &LocalBudgetConfiguration,
    cell: Option<&CellConfigBinding>,
    url: &str,
    tls: DispatchTlsMode,
    action: BudgetAction,
) -> Result<BudgetReceipt, BudgetConfigureError> {
    if !matches!(&tls, DispatchTlsMode::PinnedRootCa(pem) if !pem.trim().is_empty()) {
        return Err(BudgetConfigureError::ConnectionRefused);
    }
    // Before any connection: a documented-provider record binds the cell's own bucket and
    // endpoint, so it is never published without them.
    match cell {
        Some(cell) => config.check_cell_binding(cell)?,
        None if config.is_documented_provider() => {
            return Err(BudgetConfigureError::CellBindingMismatch);
        }
        None => {}
    }
    tokio::time::timeout(
        Duration::from_secs(30),
        configure_budget_inner(config, url, tls, action),
    )
    .await
    .map_err(|_err| match action {
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
            .map_err(|_err| BudgetConfigureError::InvalidConfiguration)?,
    })
    .map_err(|_err| BudgetConfigureError::ConnectionRefused)?;
    let mut lease = pool
        .acquire()
        .await
        .map_err(|_err| BudgetConfigureError::ConnectionRefused)?;
    let transaction = lease
        .client()
        .map_err(|_err| BudgetConfigureError::ConnectionRefused)?
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .await
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
    transaction
        .batch_execute(&pool.bounded_execution_preamble())
        .await
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
    let now: i64 = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .await
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?
        .try_get(0)
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
    let expired = now >= config.hard_expires_at_unix_ms;
    if now < config.issued_at_unix_ms || (expired && action != BudgetAction::Reconcile) {
        return Err(BudgetConfigureError::InvalidConfiguration);
    }
    let canonical =
        serde_json::to_vec(config).map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
    let domains = config.domains();
    let core = digest(domains.core, &canonical);
    let disposition = digest(domains.disposition, core.as_bytes());
    let envelope = digest(domains.envelope, disposition.as_bytes());
    let disposition_id = local_disposition_id(config, &disposition);
    let dimensions = serde_json::json!([{
        "dimensionId":domains.dimension, "effectiveBound":config.shared_units,
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
        serde_json::to_string(&caps).map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
    let vector = digest(domains.vector, dimensions.as_bytes());
    let prior_id = config
        .predecessor
        .as_ref()
        .map(|p| Uuid::parse_str(&p.disposition_id))
        .transpose()
        .map_err(|_err| BudgetConfigureError::InvalidConfiguration)?;
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
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
    let code: String = row
        .try_get("result_code")
        .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
    if action != BudgetAction::Publish {
        transaction
            .rollback()
            .await
            .map_err(|_err| BudgetConfigureError::AuthorityRefused)?;
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
            .map_err(|_err| BudgetConfigureError::OutcomeUnknown)?;
    }
    Ok(BudgetReceipt {
        result: match action {
            BudgetAction::Verify => "VERIFIED".into(),
            BudgetAction::Reconcile => "RECONCILED".into(),
            BudgetAction::Publish => code,
        },
        provenance: config.provenance.clone(),
        expired,
        allocation_revision: config.allocation_revision.clone(),
        allocation_fence: config.allocation_fence,
        hard_expires_at_unix_ms: config.hard_expires_at_unix_ms,
        disposition_id: disposition_id.to_string(),
        disposition_digest: disposition.to_hex().to_string(),
        envelope_digest: envelope.to_hex().to_string(),
    })
}

// Keep v1 byte-identical for retained configuration replay. A v2 successor can name that
// exact opaque predecessor through the local projection API, then serve as a UUIDv7
// predecessor for the canonical capacity publisher. Neither path rewrites prior records.
fn local_disposition_id(config: &LocalBudgetConfiguration, disposition: &blake3::Hash) -> Uuid {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&disposition.as_bytes()[..16]);
    if config.schema_revision != LEGACY_LOCAL_BUDGET_REVISION {
        bytes[..6].copy_from_slice(&config.issued_at_unix_ms.to_be_bytes()[2..]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
    }
    Uuid::from_bytes(bytes)
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

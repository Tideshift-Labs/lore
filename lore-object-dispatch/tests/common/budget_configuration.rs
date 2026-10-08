// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_PROVENANCE;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_REVISION;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_ENDPOINT;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_REGION;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_RULING_REFERENCE;
use lore_object_dispatch::budget_provenance::documented_provider_revision;
use lore_object_dispatch::cell_budget_configure::LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;

pub fn config(system: u64, database: u32, now: i64) -> LocalBudgetConfiguration {
    LocalBudgetConfiguration {
        schema_revision: LOCAL_BUDGET_REVISION.into(),
        provenance: "operator-selected-local-development-limit-v1".into(),
        cell_id: "test-cell".into(),
        provider_boundary_id: "test-cell-provider".into(),
        provider_endpoint: "http://minio:9000".into(),
        provider_bucket: "test-fragments".into(),
        evidence_reference: "owned TLS operator test fixture".into(),
        provider_region: None,
        ruling_reference: None,
        system_identifier: system.to_string(),
        database_oid: database,
        allocation_revision: "budget-v1".into(),
        allocation_fence: 1,
        issued_at_unix_ms: now,
        hard_expires_at_unix_ms: now + 120_000,
        shared_units: 100,
        class_units: 80,
        list_units: 20,
        refill_interval_ms: 60_000,
        predecessor: None,
    }
}

/// A valid documented-provider record at the sfo3 endpoint: 800 operations per second exactly
/// (shared 800 per 1000 ms), a two minute window, and the allocation revision derived from its
/// fence and hard expiry.
#[allow(dead_code)]
pub fn documented_config(system: u64, database: u32, now: i64) -> LocalBudgetConfiguration {
    let hard_expires_at_unix_ms = now + 120_000;
    LocalBudgetConfiguration {
        schema_revision: DOCUMENTED_PROVIDER_BUDGET_REVISION.into(),
        provenance: DOCUMENTED_PROVIDER_BUDGET_PROVENANCE.into(),
        cell_id: "test-cell".into(),
        provider_boundary_id: "test-cell-provider".into(),
        provider_endpoint: DOCUMENTED_PROVIDER_ENDPOINT.into(),
        provider_bucket: "test-fragments".into(),
        evidence_reference: "owner decision 2026-08-31 documented provider limit".into(),
        provider_region: Some(DOCUMENTED_PROVIDER_REGION.into()),
        ruling_reference: Some(DOCUMENTED_PROVIDER_RULING_REFERENCE.into()),
        system_identifier: system.to_string(),
        database_oid: database,
        allocation_revision: documented_provider_revision(1, hard_expires_at_unix_ms),
        allocation_fence: 1,
        issued_at_unix_ms: now,
        hard_expires_at_unix_ms,
        shared_units: 800,
        class_units: 640,
        list_units: 160,
        refill_interval_ms: 1000,
        predecessor: None,
    }
}

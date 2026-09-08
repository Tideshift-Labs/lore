// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
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

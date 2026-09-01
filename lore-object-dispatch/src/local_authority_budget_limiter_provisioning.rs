// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark shared cell-local budget-limiter provisioning and charge artifact.

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0022_object_store_dispatch_budget_limiter_provisioning.sql");

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x71, 0x08, 0xe6, 0xce, 0x39, 0xe2, 0xde, 0xdb, 0xc1, 0x51, 0xc9, 0x71, 0xab, 0x95, 0xfb, 0x7d,
    0x2e, 0x9d, 0x17, 0x0b, 0x13, 0x48, 0x86, 0xb0, 0xa3, 0x85, 0xaa, 0x68, 0xcc, 0xc0, 0x7b, 0xea,
];

#[must_use]
pub fn validate_embedded_local_authority_budget_limiter_provisioning_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_BLAKE3_V1
}

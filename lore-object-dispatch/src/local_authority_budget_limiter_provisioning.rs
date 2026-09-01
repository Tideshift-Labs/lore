// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark shared cell-local budget-limiter provisioning and charge artifact.

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0022_object_store_dispatch_budget_limiter_provisioning.sql");

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x7d, 0x47, 0x1d, 0x45, 0x24, 0xde, 0xc9, 0x7f, 0x01, 0x08, 0xb5, 0x7d, 0x58, 0x6f, 0x99, 0x67,
    0x6e, 0x48, 0x72, 0x18, 0x60, 0xbb, 0x78, 0xb1, 0x71, 0x0b, 0x6d, 0x6a, 0x7e, 0x97, 0x9c, 0x34,
];

#[must_use]
pub fn validate_embedded_local_authority_budget_limiter_provisioning_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_BUDGET_LIMITER_PROVISIONING_MIGRATION_BLAKE3_V1
}

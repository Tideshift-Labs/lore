// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark shared cell-local budget-limiter schema.

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0021_object_store_dispatch_budget_limiter_schema.sql");

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x63, 0x22, 0x50, 0x48, 0x76, 0x52, 0xee, 0x25, 0x50, 0x5a, 0xe9, 0x79, 0xc6, 0xa8, 0xea, 0xc9,
    0xe6, 0x2a, 0xd9, 0x6b, 0x2a, 0xee, 0xa5, 0x18, 0x64, 0xb3, 0x20, 0xbc, 0x50, 0x95, 0x3d, 0x07,
];

#[must_use]
pub fn validate_embedded_local_authority_budget_limiter_schema_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark shared cell-local budget-limiter schema.

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0021_object_store_dispatch_budget_limiter_schema.sql");

pub const LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x33, 0x87, 0xf7, 0x10, 0x79, 0xd8, 0x15, 0x52, 0xe9, 0x72, 0x26, 0x14, 0x4e, 0x3f, 0x85, 0x26,
    0x70, 0x6f, 0x19, 0x7d, 0x6e, 0xed, 0xb2, 0x3a, 0xf9, 0xaf, 0x5a, 0x41, 0xac, 0x43, 0xfb, 0x31,
];

#[must_use]
pub fn validate_embedded_local_authority_budget_limiter_schema_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_BUDGET_LIMITER_SCHEMA_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded local retention-authority schema artifact.
//!
//! Runtime code does not install this migration. Provisioning must install and attest the exact
//! bytes before any request admission, compaction, or prune path can become ready.

/// Frozen local retention schema contract revision declared by the migration.
pub const RETENTION_SCHEMA_REVISION_V1: &str = "object-store-retention-authority-schema-v1";

/// Canonical schema bytes. The first slice intentionally makes the transactional migration itself
/// the sole schema artifact so a second handwritten DDL representation cannot drift.
pub const RETENTION_SCHEMA_V1: &[u8] =
    include_bytes!("../migrations/0002_object_store_retention_authority.sql");

/// Exact PostgreSQL migration bytes, embedded for image/provisioning parity only.
pub const RETENTION_MIGRATION_V1: &[u8] = RETENTION_SCHEMA_V1;

/// BLAKE3-256 of [`RETENTION_MIGRATION_V1`].
pub const RETENTION_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xf8, 0x6d, 0x1a, 0x57, 0x4c, 0xab, 0x93, 0x46, 0xef, 0x39, 0x84, 0x3f, 0xed, 0x6f, 0xfb, 0x84,
    0x9c, 0xaf, 0xe5, 0x96, 0x78, 0x81, 0xa4, 0x5d, 0x0c, 0x6d, 0x89, 0x02, 0x87, 0x80, 0xf6, 0xdd,
];

/// Fail closed if a packaging or merge operation changes the embedded migration bytes.
pub fn validate_embedded_retention_migration_v1() -> bool {
    blake3::hash(RETENTION_MIGRATION_V1).as_bytes() == &RETENTION_MIGRATION_BLAKE3_V1
}

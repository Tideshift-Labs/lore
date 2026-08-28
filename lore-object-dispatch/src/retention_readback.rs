// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded local retention-authority maintenance readback artifact.
//!
//! Runtime code does not install or call this migration. It exists for exact provisioning parity
//! and a future maintenance client that feeds one coherent snapshot to the pure retention planners.

/// Frozen retention readback API revision.
pub const RETENTION_READBACK_API_REVISION_V1: &str = "object-store-retention-readback-v1";

/// Exact PostgreSQL readback migration bytes, embedded for image/provisioning parity only.
pub const RETENTION_READBACK_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0004_object_store_retention_readback.sql");

/// BLAKE3-256 of [`RETENTION_READBACK_MIGRATION_V1`].
pub const RETENTION_READBACK_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x0e, 0x96, 0xda, 0x46, 0x6d, 0x8d, 0x7d, 0x63, 0x9a, 0x51, 0x0e, 0xe1, 0xa8, 0x82, 0xa7, 0x97,
    0x65, 0xd3, 0x62, 0x44, 0xc2, 0x6e, 0x94, 0x19, 0x48, 0xe1, 0x89, 0xf9, 0x4d, 0xf0, 0xed, 0x05,
];

/// Fail closed if a packaging or merge operation changes the embedded migration bytes.
pub fn validate_embedded_retention_readback_migration_v1() -> bool {
    blake3::hash(RETENTION_READBACK_MIGRATION_V1).as_bytes()
        == &RETENTION_READBACK_MIGRATION_BLAKE3_V1
}

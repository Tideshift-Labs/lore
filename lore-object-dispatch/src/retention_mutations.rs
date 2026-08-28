// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded local retention-authority mutation artifact.
//!
//! Runtime code does not install or call this migration. A future maintenance client must validate
//! the pure planner projection before invoking these serializable compare-and-swap procedures.

/// Frozen retention mutation API revision.
pub const RETENTION_MUTATIONS_API_REVISION_V1: &str = "object-store-retention-mutations-v1";

/// Exact PostgreSQL mutation migration bytes, embedded for image/provisioning parity only.
pub const RETENTION_MUTATIONS_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0005_object_store_retention_mutations.sql");

/// BLAKE3-256 of [`RETENTION_MUTATIONS_MIGRATION_V1`].
pub const RETENTION_MUTATIONS_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xe3, 0x72, 0xc5, 0x4b, 0x96, 0x5c, 0x37, 0x1d, 0xda, 0x71, 0x77, 0xf7, 0xa1, 0x33, 0x1b, 0xbb,
    0x8c, 0x85, 0xeb, 0xe6, 0x6d, 0x41, 0xe9, 0xea, 0xcd, 0xef, 0x33, 0x62, 0x56, 0xb8, 0x1e, 0x46,
];

/// Fail closed if a packaging or merge operation changes the embedded migration bytes.
pub fn validate_embedded_retention_mutations_migration_v1() -> bool {
    blake3::hash(RETENTION_MUTATIONS_MIGRATION_V1).as_bytes()
        == &RETENTION_MUTATIONS_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded local retention-authority provisioning procedure artifact.
//!
//! Runtime code does not install or call this migration. Provisioning owns exact installation and
//! readback before any request admission, compaction, or prune path can become ready.

/// Frozen provisioning procedure API revision.
pub const RETENTION_PROVISIONING_API_REVISION_V1: &str = "object-store-retention-provisioning-v1";

/// Exact PostgreSQL provisioning migration bytes, embedded for image/provisioning parity only.
pub const RETENTION_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0003_object_store_retention_provisioning.sql");

/// BLAKE3-256 of [`RETENTION_PROVISIONING_MIGRATION_V1`].
pub const RETENTION_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x64, 0x7e, 0xe3, 0x20, 0xd6, 0xa6, 0x15, 0xf9, 0xa3, 0xd9, 0x1d, 0x29, 0x19, 0xdd, 0x47, 0x89,
    0xff, 0xe4, 0x07, 0x3d, 0x9f, 0x9e, 0xa2, 0xb9, 0x75, 0x17, 0xd4, 0xaf, 0xe9, 0x74, 0xa1, 0x84,
];

/// Fail closed if a packaging or merge operation changes the embedded migration bytes.
pub fn validate_embedded_retention_provisioning_migration_v1() -> bool {
    blake3::hash(RETENTION_PROVISIONING_MIGRATION_V1).as_bytes()
        == &RETENTION_PROVISIONING_MIGRATION_BLAKE3_V1
}

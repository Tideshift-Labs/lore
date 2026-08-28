// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark migration for replay-safe, append-only compact-prune receipts.

use blake3::Hash;

pub const RETENTION_PRUNE_RECEIPTS_API_REVISION_V2: &str =
    "object-store-retention-prune-receipts-v2";
pub const RETENTION_PRUNE_RECEIPTS_MIGRATION_V2: &[u8] =
    include_bytes!("../migrations/0006_object_store_retention_prune_receipts_v2.sql");
pub const RETENTION_PRUNE_RECEIPTS_MIGRATION_BLAKE3_V2: [u8; 32] = [
    150, 135, 235, 246, 220, 195, 119, 24, 73, 177, 246, 144, 235, 139, 230, 91, 1, 5, 38, 71, 74,
    149, 203, 218, 171, 196, 170, 230, 241, 109, 33, 138,
];

pub fn validate_embedded_retention_prune_receipts_migration_v2() -> bool {
    Hash::from_bytes(RETENTION_PRUNE_RECEIPTS_MIGRATION_BLAKE3_V2)
        == blake3::hash(RETENTION_PRUNE_RECEIPTS_MIGRATION_V2)
}

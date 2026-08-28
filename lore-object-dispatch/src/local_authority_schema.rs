// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark local dispatch-authority table-edge artifact.
//!
//! This migration extends the already provisioned retention namespace. Runtime code does not
//! install it, and the artifact contains no mutation procedure or provider-dispatch authority.

/// Frozen local dispatch-authority schema contract revision.
pub const LOCAL_AUTHORITY_SCHEMA_REVISION_V1: &str = "object-store-dispatch-authority-schema-v1";

/// Exact PostgreSQL migration bytes, embedded for later provisioning/image parity only.
pub const LOCAL_AUTHORITY_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0007_object_store_dispatch_authority_core.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xd7, 0x62, 0xb8, 0x41, 0xbd, 0x31, 0xa3, 0x79, 0x08, 0xa6, 0xff, 0x95, 0xc2, 0x29, 0x2d, 0x5a,
    0xbf, 0xca, 0x23, 0x4f, 0xa9, 0xb7, 0xd3, 0xc0, 0xc6, 0x39, 0xec, 0x63, 0xdc, 0xf3, 0xa7, 0xff,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_MIGRATION_V1).as_bytes() == &LOCAL_AUTHORITY_MIGRATION_BLAKE3_V1
}

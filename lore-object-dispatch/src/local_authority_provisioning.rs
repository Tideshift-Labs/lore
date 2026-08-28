// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark local dispatch-authority provisioning and readback artifact.
//!
//! Runtime code does not install or call this migration. External provisioning owns exact
//! installation and readback before any dispatch-authority mutation can become ready.

/// Frozen local dispatch-authority provisioning API revision.
pub const LOCAL_AUTHORITY_PROVISIONING_API_REVISION_V1: &str =
    "object-store-dispatch-authority-provisioning-v1";

/// Exact PostgreSQL provisioning migration bytes, embedded for image/provisioning parity only.
pub const LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0008_object_store_dispatch_authority_provisioning.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x90, 0x90, 0x0a, 0x39, 0x2e, 0x8d, 0x6c, 0xa0, 0xb5, 0x9c, 0x12, 0xaa, 0x73, 0x5e, 0x6a, 0xcf,
    0x8d, 0xa3, 0x64, 0x31, 0x90, 0x25, 0xb8, 0xfa, 0xe4, 0xca, 0xfe, 0x88, 0xa5, 0x1e, 0xd1, 0x4d,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_provisioning_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PROVISIONING_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PROVISIONING_MIGRATION_BLAKE3_V1
}

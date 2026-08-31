// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark dispatcher-identity provisioning and readback artifact.
//!
//! The migration installs and attests migration 0018's schema edge, and carries the cell's first
//! growth-tolerant in-database readback: it asserts the objects it names rather than manifesting
//! the whole schema, and is the one authority procedure the dispatch runtime role may call. It
//! settles CD-1's handed-down caveat N2 -- see the artifact's own header for the reasoning, and
//! [`crate::cell_schema_install`] for the whole-schema manifest that stays out of band.
//!
//! Runtime code neither installs nor calls this artifact.

/// Exact PostgreSQL dispatcher-identity provisioning migration bytes, embedded for parity.
pub const LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql");

/// The provisioning API revision the migration's entry points require.
pub const LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_API_REVISION_V1: &str =
    "object-store-dispatch-dispatcher-identity-provisioning-v1";

/// BLAKE3-256 of [`LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xc7, 0xd7, 0x87, 0x10, 0xd1, 0x25, 0x2b, 0x22, 0xa0, 0xa7, 0xa9, 0xfe, 0x72, 0x2e, 0x91, 0xf9,
    0xfd, 0x79, 0xe0, 0x67, 0x69, 0x87, 0xd9, 0x61, 0xd0, 0xcc, 0xb7, 0x7b, 0x04, 0x17, 0xe7, 0x8f,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
#[must_use]
pub fn validate_embedded_local_authority_dispatcher_identity_provisioning_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_DISPATCHER_IDENTITY_PROVISIONING_MIGRATION_BLAKE3_V1
}

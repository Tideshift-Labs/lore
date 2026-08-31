// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark per-participant dispatcher-identity schema artifact.
//!
//! The migration replaces migration 0007's two single-active-dispatcher constraints -- the
//! one-ACTIVE-per-boundary partial unique index and the `(provider_boundary_id, lease_generation)`
//! primary key -- so each participant owns its own lease chain (CR-033 D8). Runtime code neither
//! installs nor calls this artifact.

/// Exact PostgreSQL dispatcher-identity schema migration bytes, embedded for provisioning parity.
pub const LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xa7, 0xd5, 0x4d, 0x94, 0xd0, 0xfa, 0x50, 0x35, 0x87, 0x2e, 0xb9, 0xb3, 0x42, 0x6c, 0xbb, 0xe6,
    0x47, 0x1b, 0xcf, 0x9a, 0xe3, 0x4e, 0xd4, 0x18, 0x77, 0x54, 0x2f, 0x05, 0x0e, 0x1a, 0xaa, 0xd9,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
#[must_use]
pub fn validate_embedded_local_authority_dispatcher_identity_schema_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_BLAKE3_V1
}

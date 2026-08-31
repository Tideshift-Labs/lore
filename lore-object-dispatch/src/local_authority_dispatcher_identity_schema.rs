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
    0x39, 0x0a, 0x12, 0x75, 0x92, 0x7f, 0xc9, 0x27, 0x37, 0x46, 0xa8, 0x18, 0x0a, 0xab, 0x42, 0xab,
    0x7c, 0x44, 0x6b, 0xe6, 0x28, 0x3a, 0x82, 0xf1, 0x26, 0x30, 0x26, 0xfb, 0xee, 0x0f, 0x75, 0x5b,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
#[must_use]
pub fn validate_embedded_local_authority_dispatcher_identity_schema_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_DISPATCHER_IDENTITY_SCHEMA_MIGRATION_BLAKE3_V1
}

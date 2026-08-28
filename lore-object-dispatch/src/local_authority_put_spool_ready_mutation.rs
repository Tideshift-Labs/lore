// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark atomic PUT SPOOL_READY database mutation artifact.
//!
//! Runtime code does not install or call this migration. The database procedure records a
//! caller assertion that the complete body is already durable at the supplied handle. It cannot
//! write, fsync, rename, inspect, or otherwise prove the filesystem state itself.

/// Exact PostgreSQL PUT SPOOL_READY mutation migration bytes.
pub const LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x1b, 0xf1, 0x02, 0xfc, 0xe2, 0xe8, 0x6f, 0x48, 0xee, 0xd6, 0x29, 0x5e, 0x13, 0x49, 0x79, 0x55,
    0x64, 0xc4, 0xaa, 0xe4, 0x8a, 0xa5, 0xac, 0x5d, 0x5a, 0xf5, 0xab, 0x52, 0x33, 0xb0, 0x46, 0x2c,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_spool_ready_mutation_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_SPOOL_READY_MUTATION_MIGRATION_BLAKE3_V1
}

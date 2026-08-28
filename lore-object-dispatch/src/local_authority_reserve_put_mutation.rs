// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark atomic ReservePut authority mutation artifact.
//!
//! Runtime code does not install or call this migration yet. The SQL procedure owns database-clock
//! admission, three-scope quota reservation, canonical evidence, and the initial spool row.

/// Exact PostgreSQL ReservePut mutation migration bytes.
pub const LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xeb, 0x5d, 0x41, 0x3b, 0x9d, 0x5d, 0xd5, 0xd4, 0x58, 0x02, 0xb3, 0xac, 0xac, 0xa1, 0x93, 0xcc,
    0x6b, 0x5a, 0xc7, 0x83, 0xe3, 0x8a, 0x4c, 0x00, 0x00, 0x2a, 0x9f, 0x9a, 0xbf, 0x77, 0xed, 0x7a,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_reserve_put_mutation_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_RESERVE_PUT_MUTATION_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark pre-Submit PUT-reservation schema artifact.
//!
//! The migration adds distinct reservation identity, admission, and current-ACK evidence to the
//! unbound PUT spool row. Runtime code neither installs nor calls this artifact.

/// Exact PostgreSQL PUT-reservation schema migration bytes, embedded for provisioning parity only.
pub const LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x56, 0xb6, 0xb8, 0x91, 0xf6, 0xfa, 0x44, 0x87, 0x54, 0x94, 0xa9, 0xd6, 0x44, 0xb1, 0xa8, 0xad,
    0x66, 0xf1, 0xf8, 0x7b, 0xe5, 0xf8, 0x86, 0xef, 0xeb, 0x32, 0x4d, 0xa0, 0x5c, 0xb2, 0xae, 0x67,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_reservation_schema_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_RESERVATION_SCHEMA_MIGRATION_BLAKE3_V1
}

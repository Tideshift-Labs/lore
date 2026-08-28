// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark PUT-reservation provisioning and readback artifact.
//!
//! Runtime code neither installs nor calls this migration. Provisioning must apply and attest its
//! exact bytes after the frozen core authority, codec, and PUT-reservation schema artifacts.

/// Exact PostgreSQL PUT-reservation provisioning migration bytes.
pub const LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xaf, 0xe6, 0x3d, 0xb9, 0x6b, 0xf2, 0x86, 0xd1, 0xf0, 0x4e, 0x60, 0x15, 0xea, 0xf7, 0x97, 0xe0,
    0x20, 0xb2, 0xfc, 0xbb, 0x2b, 0x13, 0x01, 0x22, 0x24, 0xc6, 0x6e, 0xf4, 0x62, 0xd4, 0x72, 0x48,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_reservation_provisioning_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_RESERVATION_PROVISIONING_MIGRATION_BLAKE3_V1
}

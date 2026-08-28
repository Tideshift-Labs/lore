// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark canonical PUT-reservation lifecycle-record codec artifact.
//!
//! Runtime code neither installs nor calls this migration. A later authoritative mutation uses the
//! owner-only SQL codec where database-generated admission time and expiry are available.

/// Exact PostgreSQL PUT-reservation lifecycle-record codec migration bytes.
pub const LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xb3, 0x71, 0x16, 0xd9, 0xd8, 0x7e, 0x49, 0xad, 0x5c, 0x00, 0x51, 0x51, 0x4e, 0x72, 0x1a, 0x80,
    0xd0, 0xc3, 0x9f, 0x1c, 0x9d, 0xca, 0xa5, 0x1c, 0x19, 0xf7, 0xa7, 0x76, 0x18, 0xee, 0x65, 0x14,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_reservation_record_codec_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_RESERVATION_RECORD_CODEC_MIGRATION_BLAKE3_V1
}

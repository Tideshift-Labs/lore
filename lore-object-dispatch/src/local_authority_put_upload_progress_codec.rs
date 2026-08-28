// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark in-flight PUT-upload progress codec artifact.
//!
//! Runtime code does not install or call this migration. The SQL codec keeps the durable
//! reservation record and exact ReservePut replay valid after a non-final body prefix is fsynced.

/// Exact PostgreSQL PUT-upload progress codec migration bytes.
pub const LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xf5, 0x36, 0x1a, 0xa6, 0x6c, 0x3e, 0x1b, 0xdc, 0xed, 0x68, 0x30, 0x40, 0xe3, 0xa4, 0x05, 0x55,
    0x7a, 0x8d, 0x2d, 0x07, 0xf8, 0x5a, 0x18, 0x2e, 0x8e, 0x33, 0x86, 0x7e, 0x20, 0x86, 0x31, 0xa0,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_upload_progress_codec_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_CODEC_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark canonical PUT SPOOL_READY row codec artifact.
//!
//! Runtime code does not install or call this migration. The SQL codec authenticates the
//! database row and its state-2 ReservePut replay after a later filesystem coordinator has
//! supplied durable-handle, body-digest, and ready-clock assertions. It cannot prove them.

/// Exact PostgreSQL PUT SPOOL_READY codec migration bytes.
pub const LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x18, 0x0f, 0xed, 0x6b, 0x34, 0xdb, 0x41, 0x3c, 0x76, 0x1e, 0x7d, 0xcd, 0x1e, 0x52, 0x50, 0x11,
    0x9a, 0xca, 0x5c, 0x50, 0x11, 0x69, 0x77, 0xe8, 0xde, 0x54, 0xca, 0x13, 0x14, 0x08, 0xcf, 0x8c,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_spool_ready_codec_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_SPOOL_READY_CODEC_MIGRATION_BLAKE3_V1
}

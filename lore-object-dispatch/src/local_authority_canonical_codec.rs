// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark local dispatch-authority canonical codec artifact.
//!
//! The SQL codec constructs database-clock-bearing ReservePut evidence through a separately
//! reviewed `public.blake3(bytea)` provider. Runtime code neither installs nor calls this artifact.

/// Exact PostgreSQL canonical-codec migration bytes, embedded for provisioning parity only.
pub const LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xb0, 0x80, 0x3e, 0xac, 0xad, 0x02, 0x85, 0x66, 0xe9, 0xfd, 0x55, 0x59, 0xf8, 0xf8, 0x06, 0x9c,
    0x44, 0xad, 0x29, 0x0d, 0x56, 0x31, 0xa8, 0xce, 0xf1, 0xa4, 0xf7, 0xc9, 0x66, 0x9e, 0xa1, 0x2a,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_canonical_codec_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_CANONICAL_CODEC_MIGRATION_BLAKE3_V1
}

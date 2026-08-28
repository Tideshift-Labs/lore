// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark atomic non-final PUT-upload progress mutation artifact.
//!
//! Runtime code does not install or call this migration. The database procedure records only a
//! prefix that a later filesystem coordinator has already written and fsynced; it cannot prove the
//! filesystem observation itself.

/// Exact PostgreSQL PUT-upload progress mutation migration bytes.
pub const LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql");

/// BLAKE3-256 of [`LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xf9, 0xbb, 0x0d, 0x0e, 0xd3, 0x66, 0x89, 0xb6, 0xc1, 0x5b, 0x96, 0x86, 0x10, 0x8a, 0xdc, 0x90,
    0x5c, 0xd8, 0xfe, 0x98, 0x39, 0x15, 0x6e, 0x05, 0x1f, 0xc4, 0x43, 0xb0, 0x99, 0x41, 0x07, 0x8c,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
pub fn validate_embedded_local_authority_put_upload_progress_mutation_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_PUT_UPLOAD_PROGRESS_MUTATION_MIGRATION_BLAKE3_V1
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded source-dark dispatcher registration migration.
//!
//! Migration 0020 closes INV-EM's database-ownership gaps. Maintenance pre-enrolls each durable
//! participant identity with a BLAKE3 commitment to its restart-stable key. The runtime-only
//! serializable mutation authenticates that key, owns monotonic dispatcher generations, and mints
//! the canonical dispatcher record. It also strengthens 0019's growth-tolerant object assertion
//! with the exact attempts foreign-key carrier and narrows its readback to the runtime consumer.
//!
//! Runtime code neither installs nor calls this artifact. The future typed CD-3 client must call
//! the installed procedures and persist the enrolled participant key across process restarts.

/// Exact PostgreSQL dispatcher-registration migration bytes, embedded for provisioning parity.
pub const LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0020_object_store_dispatch_dispatcher_registration.sql");

/// The runtime registration API revision installed by migration 0020.
pub const LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_API_REVISION_V1: &str =
    "object-store-dispatch-dispatcher-registration-v1";

/// BLAKE3-256 of [`LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1`].
pub const LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0xae, 0xde, 0x41, 0x35, 0xd0, 0x81, 0xa9, 0xad, 0xbe, 0xc5, 0x1c, 0xd4, 0x11, 0x41, 0xfa, 0xea,
    0x81, 0xeb, 0x3b, 0x25, 0x86, 0x0a, 0xb9, 0xd1, 0x96, 0x80, 0x73, 0xa2, 0x30, 0xaa, 0x78, 0xe9,
];

/// Fail closed if packaging or merge changes the embedded migration bytes.
#[must_use]
pub fn validate_embedded_local_authority_dispatcher_registration_migration_v1() -> bool {
    blake3::hash(LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_V1).as_bytes()
        == &LOCAL_AUTHORITY_DISPATCHER_REGISTRATION_MIGRATION_BLAKE3_V1
}

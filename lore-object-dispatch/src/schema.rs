// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Embedded independent-continuity schema artifact.
//!
//! The migration is the exact transactional composition generated from WP-121's canonical
//! `schema.sql` and `procedures.sql`. Runtime code does not auto-install it. Provisioning must
//! install and read back the separately attested bytes before this crate can become ready.

/// Frozen schema contract revision declared by the migration.
pub const CONTINUITY_SCHEMA_REVISION_V1: &str = "object-store-authority-continuity-schema-v1";

/// Exact generated PostgreSQL migration bytes. They are embedded for image/provisioning parity,
/// not executed during loreserver startup.
pub const CONTINUITY_MIGRATION_V1: &[u8] =
    include_bytes!("../migrations/0001_object_store_authority_continuity.sql");

/// BLAKE3-256 of [`CONTINUITY_MIGRATION_V1`].
pub const CONTINUITY_MIGRATION_BLAKE3_V1: [u8; 32] = [
    0x15, 0x30, 0xe5, 0x11, 0x56, 0x8b, 0x42, 0xb9, 0x36, 0x8b, 0x12, 0x96, 0xeb, 0x6c, 0xdb, 0xae,
    0xec, 0xbc, 0x7f, 0x56, 0xa7, 0x83, 0x8a, 0xc2, 0x53, 0xbc, 0xbe, 0xb9, 0x54, 0x34, 0xe6, 0xdd,
];

/// Fail closed if a packaging or merge operation changes the embedded migration bytes.
pub fn validate_embedded_continuity_migration_v1() -> bool {
    blake3::hash(CONTINUITY_MIGRATION_V1).as_bytes() == &CONTINUITY_MIGRATION_BLAKE3_V1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migration_matches_its_frozen_blake3() {
        assert!(validate_embedded_continuity_migration_v1());
        assert_eq!(CONTINUITY_MIGRATION_V1.len(), 193_646);
        assert_eq!(
            blake3::hash(CONTINUITY_MIGRATION_V1).to_hex().as_str(),
            "1530e511568b42b9368b1296eb6cdbaeecbc7f56a7838ac253bcbeb95434e6dd"
        );
    }

    #[test]
    fn embedded_migration_is_transactional_and_declares_the_frozen_revision() {
        let migration = std::str::from_utf8(CONTINUITY_MIGRATION_V1)
            .expect("embedded migration must remain UTF-8 SQL");
        assert!(migration.starts_with("-- SPDX-License-Identifier: Apache-2.0\n"));
        assert!(migration.contains("\nBEGIN;\nSET LOCAL ROLE object_dispatch_continuity_owner;\n"));
        assert!(migration.ends_with("\nCOMMIT;\n"));
        assert_eq!(migration.matches("\nBEGIN;\n").count(), 1);
        assert_eq!(migration.matches("\nCOMMIT;\n").count(), 1);
        assert_eq!(
            migration
                .matches("SET LOCAL ROLE object_dispatch_continuity_owner;")
                .count(),
            1
        );
    }

    #[test]
    fn embedded_migration_freezes_the_schema_revision_in_every_authority_shape() {
        let migration = std::str::from_utf8(CONTINUITY_MIGRATION_V1)
            .expect("embedded migration must remain UTF-8 SQL");
        assert_eq!(migration.matches(CONTINUITY_SCHEMA_REVISION_V1).count(), 8);
        assert_eq!(
            migration
                .matches(&format!(
                    "schema_revision text NOT NULL CHECK (schema_revision = \
                     '{CONTINUITY_SCHEMA_REVISION_V1}')"
                ))
                .count(),
            3
        );
    }
}

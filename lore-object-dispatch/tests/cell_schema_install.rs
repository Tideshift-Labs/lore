// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Static, offline contract tests for CD-1's out-of-band cell-authority schema
//! installer/attester (`lore_object_dispatch::cell_schema_install`).
//!
//! No PostgreSQL, no Docker, no `#[ignore]`. This file only reads the frozen migration SQL
//! from disk (independently of the module's own `include_str!` copies) and the module's own
//! public constants, and cross-checks them against each other. The live proof that installing
//! this schema into a real PostgreSQL 16 catalog behaves as attested belongs to the main
//! session's live tier (see CR-033 D5 and the WP-114 CD-1 work package), not this file.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use lore_object_dispatch::cell_schema_install::CELL_AUTHORITY_SCHEMA;
use lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SECTIONS;
use lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SQL;
use lore_object_dispatch::cell_schema_install::CELL_DEFERRED_MIGRATIONS;
use lore_object_dispatch::cell_schema_install::CELL_DEFERRED_PROCEDURES;
use lore_object_dispatch::cell_schema_install::CELL_INERT_RETENTION_TABLES;
use lore_object_dispatch::cell_schema_install::CELL_INSTALL_SET;
use lore_object_dispatch::cell_schema_install::CELL_MIGRATOR_ROLE;
use lore_object_dispatch::cell_schema_install::CELL_OWNER_ROLE;
use lore_object_dispatch::cell_schema_install::CELL_REPLACED_FUNCTIONS;
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_INSTALL_API_REVISION_V1;
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_LAYERS;
use lore_object_dispatch::cell_schema_install::CELL_SERVICE_ROLES;
use lore_object_dispatch::cell_schema_install::CellInstallStep;
use lore_object_dispatch::cell_schema_install::CellSchemaError;
use lore_object_dispatch::cell_schema_install::CellSchemaLayerId;
use lore_object_dispatch::cell_schema_install::cell_install_plan;
use lore_object_dispatch::cell_schema_install::validate_cell_install_set_digests;

// ---------------------------------------------------------------------------------------------
// Ground truth read directly from `migrations/` at test time, independent of the module's own
// embedded copies. See the crate's existing `local_authority_put_reservation_provisioning.rs`
// for the same house style (static assertions over frozen SQL text, an entrypoint inventory
// guard, and a source-dark check).
// ---------------------------------------------------------------------------------------------

const CELL_INSTALLED_MIGRATION_NUMBERS: [u16; 16] =
    [2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

fn migrations_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn migration_file_name_on_disk(number: u16) -> String {
    let prefix = format!("{number:04}_");
    let mut matches: Vec<String> = std::fs::read_dir(migrations_dir())
        .expect("read migrations directory")
        .map(|entry| {
            entry
                .expect("read migration entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with(&prefix) && name.ends_with(".sql"))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one migration file for {number:04}_*.sql, found {matches:?}"
    );
    matches.remove(0)
}

fn all_migration_numbers_on_disk() -> BTreeSet<u16> {
    std::fs::read_dir(migrations_dir())
        .expect("read migrations directory")
        .map(|entry| {
            entry
                .expect("read migration entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".sql"))
        .map(|name| {
            name.get(..4)
                .and_then(|prefix| prefix.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("migration file with non-numeric prefix: {name}"))
        })
        .collect()
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

/// Every byte offset in `haystack` at which `needle` starts. Overlapping matches are not a
/// concern for the fixed function-name needles this file searches for.
fn find_all(haystack: &str, needle: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut cursor = 0;
    while let Some(offset) = haystack
        .get(cursor..)
        .and_then(|remainder| remainder.find(needle))
    {
        let position = cursor + offset;
        positions.push(position);
        cursor = position + needle.len();
    }
    positions
}

/// Uppercased, punctuation-delimited tokens (underscores kept as part of a token), so a
/// reserved-word scan can require an exact token match instead of a raw substring match that
/// would false-positive on identifiers like `created_at_unix_ms`.
fn sql_tokens(sql: &str) -> Vec<String> {
    sql.split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_uppercase)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1. Install set is exactly CR-033 D5's.
// ---------------------------------------------------------------------------------------------

#[test]
fn install_set_is_exactly_cr_033_d5s() {
    let numbers: Vec<u16> = CELL_INSTALL_SET
        .iter()
        .map(|migration| migration.number)
        .collect();
    assert_eq!(numbers, CELL_INSTALLED_MIGRATION_NUMBERS);

    assert_eq!(CELL_DEFERRED_MIGRATIONS, [4, 5, 6]);
    for number in CELL_INSTALLED_MIGRATION_NUMBERS {
        assert!(
            !CELL_DEFERRED_MIGRATIONS.contains(&number),
            "installed migration {number} must not also be listed as deferred"
        );
    }

    // Migration 0001 no longer exists on disk and must not be referenced by the module's own
    // source (the module must not, for instance, special-case a stale "0001 through ..." range).
    assert!(!all_migration_numbers_on_disk().contains(&1));
    let module_source = include_str!("../src/cell_schema_install.rs");
    assert!(!module_source.contains("0001_"));

    // Every migration file on disk is classified as installed or deferred. A future 0018 must
    // fail this assertion rather than being silently excluded from either list.
    let on_disk = all_migration_numbers_on_disk();
    let mut classified: BTreeSet<u16> = CELL_INSTALLED_MIGRATION_NUMBERS.into_iter().collect();
    classified.extend(CELL_DEFERRED_MIGRATIONS);
    assert_eq!(
        on_disk, classified,
        "every migrations/*.sql file must be classified as installed or deferred"
    );
}

// ---------------------------------------------------------------------------------------------
// 2. Embedded bytes are the frozen bytes.
// ---------------------------------------------------------------------------------------------

#[test]
fn embedded_bytes_are_the_frozen_bytes() {
    assert!(validate_cell_install_set_digests());

    for migration in &CELL_INSTALL_SET {
        let hash = blake3::hash(migration.sql.as_bytes());
        assert_eq!(
            migration.blake3,
            *hash.as_bytes(),
            "embedded blake3 mismatch for migration {}",
            migration.file_name
        );

        let disk_name = migration_file_name_on_disk(migration.number);
        assert_eq!(
            migration.file_name, disk_name,
            "file_name mismatch for migration {}",
            migration.number
        );

        let disk_contents = std::fs::read_to_string(migrations_dir().join(&disk_name))
            .unwrap_or_else(|error| panic!("read {disk_name}: {error}"));
        assert_eq!(
            migration.sql, disk_contents,
            "embedded sql does not equal the on-disk contents of {disk_name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Plan ordering.
// ---------------------------------------------------------------------------------------------

#[test]
fn plan_interleaves_layer_installs_immediately_after_their_ddl_step() {
    let plan = cell_install_plan();
    assert_eq!(plan.len(), 20);

    let ddl_indices: Vec<usize> = plan
        .iter()
        .filter_map(|step| match step {
            CellInstallStep::Migration(index) => Some(*index),
            CellInstallStep::InstallLayer(_) => None,
        })
        .collect();
    assert_eq!(
        ddl_indices,
        (0..CELL_INSTALL_SET.len()).collect::<Vec<_>>(),
        "DDL steps must appear in ascending CELL_INSTALL_SET order"
    );

    let mut layer_positions = Vec::with_capacity(CELL_SCHEMA_LAYERS.len());
    for (layer_index, layer) in CELL_SCHEMA_LAYERS.iter().enumerate() {
        let install_position = plan
            .iter()
            .position(|step| *step == CellInstallStep::InstallLayer(layer_index))
            .unwrap_or_else(|| panic!("layer {layer_index} ({:?}) missing from plan", layer.id));
        let ddl_migration_index = CELL_INSTALL_SET
            .iter()
            .position(|migration| migration.number == layer.installed_after_migration)
            .unwrap_or_else(|| {
                panic!(
                    "layer {layer_index}'s installed_after_migration {} is not in CELL_INSTALL_SET",
                    layer.installed_after_migration
                )
            });
        assert!(
            install_position > 0,
            "layer {layer_index} cannot be the first plan step"
        );
        assert_eq!(
            plan[install_position - 1],
            CellInstallStep::Migration(ddl_migration_index),
            "layer {layer_index} must immediately follow the DDL step for migration {}",
            layer.installed_after_migration
        );
        layer_positions.push(install_position);
    }

    assert!(
        layer_positions.windows(2).all(|pair| pair[0] < pair[1]),
        "layers must appear in plan order Retention, Authority, PutReservation"
    );
    assert_eq!(CELL_SCHEMA_LAYERS[0].id, CellSchemaLayerId::Retention);
    assert_eq!(CELL_SCHEMA_LAYERS[1].id, CellSchemaLayerId::Authority);
    assert_eq!(CELL_SCHEMA_LAYERS[2].id, CellSchemaLayerId::PutReservation);
}

// ---------------------------------------------------------------------------------------------
// 4. Layer contract matches the frozen SQL.
// ---------------------------------------------------------------------------------------------

#[test]
fn layer_contract_matches_the_frozen_sql() {
    struct Expected {
        id: CellSchemaLayerId,
        api_revision: &'static str,
        schema_revision: &'static str,
        install_function: &'static str,
        read_state_function: &'static str,
        read_state_retired_after: Option<u16>,
        installed_after_migration: u16,
        migration_blake3_hex: &'static str,
    }

    let expected = [
        Expected {
            id: CellSchemaLayerId::Retention,
            api_revision: "object-store-retention-provisioning-v1",
            schema_revision: "object-store-retention-authority-schema-v1",
            install_function: "object_store_retention_install_v1",
            read_state_function: "object_store_retention_read_state_v1",
            read_state_retired_after: None,
            installed_after_migration: 3,
            migration_blake3_hex: "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd",
        },
        Expected {
            id: CellSchemaLayerId::Authority,
            api_revision: "object-store-dispatch-authority-provisioning-v1",
            schema_revision: "object-store-dispatch-authority-schema-v1",
            install_function: "object_store_dispatch_authority_install_v1",
            read_state_function: "object_store_dispatch_authority_read_state_v1",
            read_state_retired_after: Some(11),
            installed_after_migration: 8,
            migration_blake3_hex: "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff",
        },
        Expected {
            id: CellSchemaLayerId::PutReservation,
            api_revision: "object-store-dispatch-put-reservation-provisioning-v1",
            schema_revision: "object-store-dispatch-put-reservation-schema-v1",
            install_function: "object_store_dispatch_put_reservation_install_v1",
            read_state_function: "object_store_dispatch_put_reservation_read_state_v1",
            read_state_retired_after: Some(12),
            installed_after_migration: 11,
            migration_blake3_hex: "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67",
        },
        Expected {
            id: CellSchemaLayerId::DispatcherIdentity,
            api_revision: "object-store-dispatch-dispatcher-identity-provisioning-v1",
            schema_revision: "object-store-dispatch-dispatcher-identity-schema-v1",
            install_function: "object_store_dispatch_dispatcher_identity_install_v1",
            read_state_function: "object_store_dispatch_dispatcher_identity_read_state_v1",
            // 0020 keeps the readback body but narrows EXECUTE to the runtime role. The out-of-band
            // migrator therefore attests this layer from the identity tuple and live catalog.
            read_state_retired_after: Some(20),
            installed_after_migration: 19,
            migration_blake3_hex: "a7d54d94d0fa5035872eb9b3426cbbe6471bcf9ae34ed41877542f050e1aaad9",
        },
    ];

    assert_eq!(CELL_SCHEMA_LAYERS.len(), expected.len());
    for (layer, want) in CELL_SCHEMA_LAYERS.iter().zip(expected.iter()) {
        assert_eq!(layer.id, want.id);
        assert_eq!(layer.api_revision, want.api_revision);
        assert_eq!(layer.schema_revision, want.schema_revision);
        assert_eq!(layer.install_function, want.install_function);
        assert_eq!(layer.read_state_function, want.read_state_function);
        assert_eq!(
            layer.read_state_retired_after,
            want.read_state_retired_after
        );
        assert_eq!(
            layer.installed_after_migration,
            want.installed_after_migration
        );
        assert_eq!(layer.migration_blake3_hex, want.migration_blake3_hex);
        assert!(
            layer
                .identity_columns
                .iter()
                .all(|column| !column.is_empty()),
            "layer {:?} has an empty identity column name",
            layer.id
        );

        let migration = CELL_INSTALL_SET
            .iter()
            .find(|migration| migration.number == layer.installed_after_migration)
            .unwrap_or_else(|| {
                panic!(
                    "no CELL_INSTALL_SET entry for migration {}",
                    layer.installed_after_migration
                )
            });
        let sql = migration.sql;

        assert!(
            sql.contains(&format!(
                "CREATE FUNCTION object_store_retention.{}(",
                layer.install_function
            )),
            "migration {} does not CREATE FUNCTION {}",
            migration.number,
            layer.install_function
        );
        assert!(
            sql.contains(&format!(
                "CREATE FUNCTION object_store_retention.{}(",
                layer.read_state_function
            )),
            "migration {} does not CREATE FUNCTION {}",
            migration.number,
            layer.read_state_function
        );
        assert!(
            sql.contains(layer.migration_blake3_hex),
            "migration {} does not contain its own pinned digest {}",
            migration.number,
            layer.migration_blake3_hex
        );
        assert!(
            sql.contains(layer.schema_revision),
            "migration {} does not contain schema revision {}",
            migration.number,
            layer.schema_revision
        );
        assert!(
            sql.contains(layer.api_revision),
            "migration {} does not contain api revision {}",
            migration.number,
            layer.api_revision
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 5. Retirement claims are grounded in the SQL.
// ---------------------------------------------------------------------------------------------

#[test]
fn retirement_claims_are_grounded_in_the_sql() {
    let migration_0011 = CELL_INSTALL_SET
        .iter()
        .find(|migration| migration.number == 11)
        .expect("migration 0011 in CELL_INSTALL_SET");
    let sql_0011 = migration_0011.sql;

    // Authority's install/read_state entrypoints are explicitly revoked from the migrator (and,
    // for read_state, also maintenance) in 0011 -- grounds `read_state_retired_after: Some(11)`.
    assert!(sql_0011.contains(
        "REVOKE EXECUTE ON FUNCTION\n  object_store_retention.object_store_dispatch_authority_install_v1(\n    text, text, bytea, object_store_retention.uint64\n  )\nFROM object_dispatch_retention_migrator;"
    ));
    assert!(sql_0011.contains(
        "REVOKE EXECUTE ON FUNCTION\n  object_store_retention.object_store_dispatch_authority_read_state_v1(text)\nFROM object_dispatch_retention_migrator, object_dispatch_retention_maintenance;"
    ));

    // PutReservation's `Some(12)`: 0011's own catalog manifest scans `functions=`/`function_acls=`
    // over the whole `object_store_retention` schema with no `proname IN (...)` name filter, so
    // its readback cannot distinguish "the chain up to 0011" from "the chain up to 0011 plus
    // whatever 0012 adds" until 0012 actually adds a new function.
    assert!(sql_0011.contains("'functions=' || COALESCE(("));
    assert!(
        !sql_0011.contains("AND procedure.proname IN ("),
        "0011's catalog manifest must not filter functions by name"
    );
    assert!(sql_0011.contains(
        "        FROM pg_catalog.pg_proc AS procedure\n        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace\n       WHERE namespace.nspname = 'object_store_retention'\n    ), '[]'),\n    'function_acls='"
    ));

    let migration_0012 = CELL_INSTALL_SET
        .iter()
        .find(|migration| migration.number == 12)
        .expect("migration 0012 in CELL_INSTALL_SET");
    assert!(
        migration_0012
            .sql
            .contains("CREATE FUNCTION object_store_retention."),
        "0012 must add at least one new function to the schema 0011's readback would then see"
    );

    let migration_0020 = CELL_INSTALL_SET
        .iter()
        .find(|migration| migration.number == 20)
        .expect("migration 0020 in CELL_INSTALL_SET");
    assert!(migration_0020.sql.contains(
        "REVOKE ALL ON FUNCTION\n  object_store_retention.object_store_dispatch_dispatcher_identity_read_state_v1(text)\nFROM object_dispatch_retention_migrator, object_dispatch_retention_maintenance;"
    ));

    // NOTE: the live consequence -- that 0011's readback therefore cannot attest a
    // fully-installed chain once 0012+ has landed -- is proved by the main session's live tier,
    // not by this offline test.
}

// ---------------------------------------------------------------------------------------------
// 6. Replacement inventory is complete.
// ---------------------------------------------------------------------------------------------

#[test]
fn replacement_inventory_is_complete() {
    assert_eq!(CELL_REPLACED_FUNCTIONS.len(), 5);

    let scan_migrations: Vec<_> = CELL_INSTALL_SET
        .iter()
        .filter(|migration| (12..=20).contains(&migration.number))
        .collect();

    let needle = "CREATE OR REPLACE FUNCTION object_store_retention.";
    let total_occurrences: usize = scan_migrations
        .iter()
        .map(|migration| find_all(migration.sql, needle).len())
        .sum();
    assert_eq!(
        total_occurrences,
        CELL_REPLACED_FUNCTIONS.len(),
        "every CREATE OR REPLACE FUNCTION in 0012-0020 must have exactly one CELL_REPLACED_FUNCTIONS entry"
    );

    for replaced in &CELL_REPLACED_FUNCTIONS {
        assert!(
            replaced.introduced_by < replaced.replaced_by,
            "{} must be introduced before it is replaced",
            replaced.name
        );

        let introducing_migration = CELL_INSTALL_SET
            .iter()
            .find(|migration| migration.number == replaced.introduced_by)
            .unwrap_or_else(|| {
                panic!(
                    "introduced_by {} not in CELL_INSTALL_SET",
                    replaced.introduced_by
                )
            });
        assert!(
            introducing_migration.sql.contains(&format!(
                "CREATE FUNCTION object_store_retention.{}(",
                replaced.name
            )),
            "migration {} does not CREATE FUNCTION {}",
            replaced.introduced_by,
            replaced.name
        );

        let replacing_migration = CELL_INSTALL_SET
            .iter()
            .find(|migration| migration.number == replaced.replaced_by)
            .unwrap_or_else(|| {
                panic!(
                    "replaced_by {} not in CELL_INSTALL_SET",
                    replaced.replaced_by
                )
            });
        assert!(
            replacing_migration.sql.contains(&format!(
                "CREATE OR REPLACE FUNCTION object_store_retention.{}(",
                replaced.name
            )),
            "migration {} does not CREATE OR REPLACE FUNCTION {}",
            replaced.replaced_by,
            replaced.name
        );

        let expected_identity_arguments = match replaced.name {
            "local_put_reservation_record_v1" => {
                "text, text, text, text, text, uuid, uuid, uuid, uuid, \
                 object_store_retention.uint64, bytea, text, bytea, object_store_retention.uint64, \
                 bytea, bytea, text, object_store_retention.uint64, bigint, bigint, bigint, bigint, \
                 bigint, object_store_retention.uint64, object_store_retention.uint64, \
                 object_store_retention.uint64, object_store_retention.uint64, \
                 object_store_retention.uint64, bytea, bytea, object_store_retention.uint64, \
                 integer, integer, integer"
            }
            "project_dispatch_reserved_put_v1" => {
                "object_store_retention.object_dispatch_spool_objects, text"
            }
            "assert_dispatch_dispatcher_identity_reader_v1"
            | "assert_dispatch_dispatcher_identity_objects_v1" => "",
            other => panic!("unexpected CELL_REPLACED_FUNCTIONS name in test fixture: {other}"),
        };
        assert_eq!(replaced.argument_types, expected_identity_arguments);

        let revoke_needle = format!("object_store_retention.{}(", replaced.name);
        let revoke_statement = replacing_migration
            .sql
            .split(';')
            .find(|statement| {
                statement.contains("REVOKE ALL ON FUNCTION") && statement.contains(&revoke_needle)
            })
            .unwrap_or_else(|| {
                panic!(
                    "migration {} missing REVOKE ALL for replaced function {}",
                    replaced.replaced_by, replaced.name
                )
            });
        if replaced.replaced_by == 20 {
            assert!(
                revoke_statement.contains("FROM PUBLIC"),
                "REVOKE ALL ON FUNCTION {} in migration {} must remove inherited PUBLIC execute",
                replaced.name,
                replaced.replaced_by
            );
        } else {
            for role in CELL_SERVICE_ROLES {
                assert!(
                    revoke_statement.contains(role),
                    "REVOKE ALL ON FUNCTION {} in migration {} does not name role {role}",
                    replaced.name,
                    replaced.replaced_by
                );
            }
        }
    }

    // Vice versa: every CREATE OR REPLACE FUNCTION found by scanning corresponds to exactly one
    // pinned entry, keyed by (name, replacing migration) since a name can recur (as
    // project_dispatch_reserved_put_v1 does, replaced once in 0014 and again in 0016).
    for migration in &scan_migrations {
        for position in find_all(migration.sql, needle) {
            let name_start = position + needle.len();
            let name_end = migration.sql[name_start..]
                .find('(')
                .map(|offset| name_start + offset)
                .expect("CREATE OR REPLACE FUNCTION must be followed by a parameter list");
            let name = &migration.sql[name_start..name_end];
            assert!(
                CELL_REPLACED_FUNCTIONS
                    .iter()
                    .any(|replaced| replaced.name == name
                        && replaced.replaced_by == migration.number),
                "unpinned CREATE OR REPLACE FUNCTION {name} found in migration {}",
                migration.number
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 7. Inert-state inventory.
// ---------------------------------------------------------------------------------------------

#[test]
fn inert_state_inventory_is_exact() {
    assert_eq!(
        CELL_INERT_RETENTION_TABLES,
        [
            "object_dispatch_full_record_ownership",
            "object_dispatch_record_storage_counters",
            "object_dispatch_compact_receipts",
            "object_dispatch_compact_prune_watermark",
        ]
    );
    assert!(!CELL_INERT_RETENTION_TABLES.contains(&"object_dispatch_retention_schema_state"));

    assert_eq!(CELL_DEFERRED_PROCEDURES.len(), 6);
    let deferred_procedures: BTreeSet<&str> = CELL_DEFERRED_PROCEDURES.into_iter().collect();
    assert_eq!(
        deferred_procedures.len(),
        6,
        "CELL_DEFERRED_PROCEDURES must not contain duplicate names"
    );

    let deferred_migrations = [
        include_str!("../migrations/0004_object_store_retention_readback.sql"),
        include_str!("../migrations/0005_object_store_retention_mutations.sql"),
        include_str!("../migrations/0006_object_store_retention_prune_receipts_v2.sql"),
    ];

    for procedure in &deferred_procedures {
        let appears_in_a_deferred_migration = deferred_migrations.iter().any(|sql| {
            sql.contains(&format!(
                "CREATE FUNCTION object_store_retention.{procedure}("
            ))
        });
        assert!(
            appears_in_a_deferred_migration,
            "deferred procedure {procedure} not found as a CREATE FUNCTION in 0004-0006"
        );

        for migration in &CELL_INSTALL_SET {
            assert!(
                !migration.sql.contains(*procedure),
                "deferred procedure {procedure} unexpectedly appears in installed migration {}",
                migration.number
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 8. Manifest SQL hygiene.
// ---------------------------------------------------------------------------------------------

/// Every ACL aggregate must order by values that are stable across clusters.
///
/// A role OID is assigned in creation order, so `ORDER BY entry.grantee` produces a different row
/// order on a cluster whose roles were created in a different sequence. That does not make the
/// pinned digest wrong, it makes it flaky, which is worse: the failure appears only on the cell you
/// did not test on. The disposable-container live tier cannot catch this, because its role creation
/// order is fixed, so the check has to be a source-level one.
///
/// This test exists because a review found five aggregates still ordering by OID after a commit
/// that claimed to have fixed exactly that.
#[test]
fn every_acl_aggregate_orders_by_rendered_name_never_by_oid() {
    let sql = CELL_CATALOG_MANIFEST_SQL;

    // `aclexplode` yields (grantor, grantee, privilege_type, is_grantable). Every aggregate over it
    // must render and sort by grantor and grantee, and must break ties on is_grantable, or two
    // items differing only in those collide on every sort key and come back unordered.
    let acl_aggregates = sql.matches("pg_catalog.aclexplode(").count();
    assert!(
        acl_aggregates >= 6,
        "expected at least six aclexplode aggregates, found {acl_aggregates}"
    );
    assert_eq!(
        sql.matches("pg_catalog.pg_get_userbyid(entry.grantor)")
            .count(),
        acl_aggregates * 2,
        "each aclexplode aggregate must render the grantor AND sort by it"
    );

    // No ORDER BY key may be a raw OID column.
    for raw_oid_key in [
        "ORDER BY entry.grantee",
        "ORDER BY role_oid",
        "ORDER BY default_acl.defaclrole,",
        "entry.grantee, entry.privilege_type)",
    ] {
        assert!(
            !sql.contains(raw_oid_key),
            "manifest SQL sorts by a raw OID: {raw_oid_key}"
        );
    }

    // Every ACL aggregate ends its sort on is_grantable, the last discriminating column.
    assert_eq!(
        sql.matches("entry.privilege_type, entry.is_grantable)")
            .count(),
        acl_aggregates,
        "each ACL aggregate must break its final tie on is_grantable"
    );
}

#[test]
fn catalog_manifest_sql_is_a_single_hygienic_read_only_statement() {
    assert_eq!(CELL_CATALOG_MANIFEST_SECTIONS.len(), 12);

    // The four catalogs a privilege change can hide in when only relation and function ACLs are
    // manifested. `pg_default_acl` is the one migration 0002 actually writes, so its absence was a
    // live widening path, not a hypothetical one.
    for required_catalog in ["pg_default_acl", "pg_trigger", "pg_policy", "pg_rewrite"] {
        assert!(
            CELL_CATALOG_MANIFEST_SQL.contains(required_catalog),
            "the manifest must read {required_catalog}"
        );
    }

    let sql = CELL_CATALOG_MANIFEST_SQL.trim();
    assert!(
        sql.to_ascii_uppercase().starts_with("SELECT"),
        "manifest SQL must start with SELECT"
    );

    let semicolon_count = sql.matches(';').count();
    assert!(
        semicolon_count <= 1,
        "manifest SQL must be a single statement"
    );
    if semicolon_count == 1 {
        assert!(
            sql.ends_with(';'),
            "the manifest SQL's one semicolon must be trailing, not mid-statement"
        );
    }

    let forbidden_keywords = [
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE", "TRUNCATE",
    ];
    let tokens = sql_tokens(sql);
    for keyword in forbidden_keywords {
        assert!(
            !tokens.iter().any(|token| token == keyword),
            "manifest SQL contains forbidden DDL/DML keyword {keyword}"
        );
    }

    for section in CELL_CATALOG_MANIFEST_SECTIONS {
        assert!(
            sql.contains(section),
            "manifest SQL missing section {section}"
        );
    }

    assert!(sql.contains("pg_catalog.pg_proc"));
    for required in ["prosecdef", "proconfig", "proacl", "pg_get_functiondef"] {
        assert!(
            sql.contains(required),
            "manifest SQL missing pg_proc detail {required}"
        );
    }
    assert!(sql.contains("pg_catalog.pg_class"));
    for required in ["relacl", "relrowsecurity", "relforcerowsecurity"] {
        assert!(
            sql.contains(required),
            "manifest SQL missing pg_class detail {required}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 9. Redaction discipline.
// ---------------------------------------------------------------------------------------------

fn assert_is_a_redacted_error<T: std::error::Error + std::fmt::Debug>() {}

/// Every variant, constructed with the most sensitive-looking payload each one accepts.
///
/// Exhaustive by construction: the `match` below is over `CellSchemaError` with no wildcard arm, so
/// adding a variant to the enum stops compiling this file until it is listed here.
fn every_error_variant() -> Vec<CellSchemaError> {
    let variants = vec![
        CellSchemaError::Precondition("session_user is not migrator"),
        CellSchemaError::Postgres,
        CellSchemaError::InvalidResponse("scalar column"),
        CellSchemaError::PartialLayerIdentity(CellSchemaLayerId::PutReservation),
        CellSchemaError::LayerIdentityDrift(CellSchemaLayerId::Authority),
        CellSchemaError::CatalogDrift("function_acls"),
        CellSchemaError::ResidualServicePrivilege,
        CellSchemaError::InertStateMismatch("inert tables"),
        CellSchemaError::RetiredEntrypointReachable("authority"),
        CellSchemaError::RetiredEntrypointUnexpectedFailure("put_reservation"),
        CellSchemaError::RefusedUnattestedSchema("catalog drift"),
        CellSchemaError::UnexpectedInstallResult,
    ];
    // The match below forces a new *arm*, which a `=> {}` satisfies without adding the variant to
    // the vec these tests actually sweep. Pinning the length is what makes adding a variant fail
    // here rather than pass unswept.
    assert_eq!(
        variants.len(),
        12,
        "a new CellSchemaError variant must be added to this vec, not only to the match below"
    );
    for variant in &variants {
        // No wildcard: this is the compile-time exhaustiveness check.
        match variant {
            CellSchemaError::Precondition(_)
            | CellSchemaError::Postgres
            | CellSchemaError::InvalidResponse(_)
            | CellSchemaError::PartialLayerIdentity(_)
            | CellSchemaError::LayerIdentityDrift(_)
            | CellSchemaError::CatalogDrift(_)
            | CellSchemaError::ResidualServicePrivilege
            | CellSchemaError::InertStateMismatch(_)
            | CellSchemaError::RetiredEntrypointReachable(_)
            | CellSchemaError::RetiredEntrypointUnexpectedFailure(_)
            | CellSchemaError::RefusedUnattestedSchema(_)
            | CellSchemaError::UnexpectedInstallResult => {}
        }
    }
    variants
}

#[test]
fn cell_schema_error_is_a_standard_redacted_error_type() {
    // A normal `thiserror`-derived error (Display + Debug + std::error::Error), so it composes with
    // `?` the way every other error enum in this crate does (see `retention_client.rs`).
    assert_is_a_redacted_error::<CellSchemaError>();

    for variant in every_error_variant() {
        for rendered in [format!("{variant}"), format!("{variant:?}")] {
            for leak in [
                "postgres://",
                "postgresql://",
                "password",
                "PRIVATE KEY",
                "sslmode",
                "@localhost",
                "@127.0.0.1",
            ] {
                assert!(
                    !rendered.contains(leak),
                    "{variant:?} rendered a redacted token: {leak}"
                );
            }
            // A connection string always carries a scheme separator. Nothing in a rendered error
            // may look like a host or URL at all.
            assert!(
                !rendered.contains("://"),
                "{variant:?} rendered something URL-shaped"
            );
        }
        // `source()` is the other surface a driver error escapes through; there must be none.
        assert!(
            std::error::Error::source(&variant).is_none(),
            "{variant:?} exposes a source error, which can carry driver diagnostics"
        );
        // The reason label carried into `RefusedUnattestedSchema` must itself be fixed text.
        assert!(!variant.reason().is_empty());
        assert!(!variant.reason().contains("://"));
    }
}

#[test]
fn installer_source_has_no_unwrap_or_expect_outside_test_cfg() {
    for (label, source) in [
        (
            "cell_schema_install.rs",
            include_str!("../src/cell_schema_install.rs"),
        ),
        (
            "src/bin/cell-schema-install.rs",
            include_str!("../src/bin/cell-schema-install.rs"),
        ),
    ] {
        // House convention (see every other module in this crate) puts the `#[cfg(test)] mod
        // tests` block at the end of the file; scan only the text before it.
        let production_source = source
            .find("#[cfg(test)]")
            .map_or(source, |offset| &source[..offset]);
        for forbidden in ["unwrap(", "expect("] {
            assert!(
                !production_source.contains(forbidden),
                "{label} contains {forbidden} outside #[cfg(test)]"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 10. Source-dark and no-service guard.
// ---------------------------------------------------------------------------------------------

#[test]
fn no_service_shell_and_runtime_source_never_calls_the_install_procedures() {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let module_path = src_root.join("cell_schema_install.rs");
    let bin_path = src_root.join("bin").join("cell-schema-install.rs");
    assert!(
        bin_path.is_file(),
        "expected the operator CLI at {}",
        bin_path.display()
    );

    let mut sources = Vec::new();
    collect_rust_sources(&src_root, &mut sources);
    assert!(sources.contains(&module_path));
    assert!(sources.contains(&bin_path));

    let install_procedure_names = [
        "object_store_retention_install_v1",
        "object_store_retention_read_state_v1",
        "object_store_dispatch_authority_install_v1",
        "object_store_dispatch_authority_read_state_v1",
        "object_store_dispatch_put_reservation_install_v1",
        "object_store_dispatch_put_reservation_read_state_v1",
    ];

    for path in &sources {
        if path == &module_path || path == &bin_path {
            continue;
        }
        let source = std::fs::read_to_string(path).expect("read production Rust source");
        assert!(
            !source.contains("cell_schema_install::"),
            "{} references cell_schema_install::, but runtime source must never install this artifact",
            path.display()
        );
        for entrypoint in install_procedure_names {
            assert!(
                !source.contains(entrypoint),
                "{} calls install-procedure entrypoint {entrypoint}",
                path.display()
            );
        }
    }

    let bin_source = std::fs::read_to_string(&bin_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", bin_path.display()));
    for forbidden in ["TcpListener", "bind(", "serve", "tonic", "axum", "loop {"] {
        assert!(
            !bin_source.contains(forbidden),
            "the operator CLI must not be a long-running service (found {forbidden})"
        );
    }
    assert!(
        bin_source.contains("fn main"),
        "the operator CLI must have a fn main"
    );
}

// ---------------------------------------------------------------------------------------------
// Top-level constants.
// ---------------------------------------------------------------------------------------------

#[test]
fn top_level_constants_match_the_frozen_role_and_schema_names() {
    assert_eq!(
        CELL_SCHEMA_INSTALL_API_REVISION_V1,
        "object-store-cell-schema-install-v1"
    );
    assert_eq!(CELL_AUTHORITY_SCHEMA, "object_store_retention");
    assert_eq!(CELL_OWNER_ROLE, "object_dispatch_retention_owner");
    assert_eq!(CELL_MIGRATOR_ROLE, "object_dispatch_retention_migrator");
    assert_eq!(
        CELL_SERVICE_ROLES,
        [
            "object_dispatch_retention_runtime",
            "object_dispatch_retention_maintenance",
            "object_dispatch_retention_migrator",
        ]
    );
}

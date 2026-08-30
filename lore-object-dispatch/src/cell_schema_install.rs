// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Out-of-band cell authority schema installer and attester (WP-114 CD-1).
//!
//! This module is the production install path for CR-033 D5's cell install set: migrations 0002,
//! 0003, then 0007 through 0017. Retention migrations 0004 through 0006 are deferred and are never
//! installed; migration 0001 does not exist.
//!
//! Six properties this module owns, and nothing else in the crate does:
//!
//! 1. **Migrator-role install, out of band.** Every public entry point here refuses unless the
//!    connection's `session_user` is `object_dispatch_retention_migrator`: install, attestation, the
//!    manifest measurement, and the revoke pass alike. `session_user` rather than `current_user`,
//!    because `SET ROLE` cannot forge it. Runtime never installs a migration; no other module in
//!    this crate references this one, and the crate is not linked into loreserver.
//! 2. **Namespace separation.** Everything lives in the `object_store_retention` schema under the
//!    four `object_dispatch_retention_*` roles. This bootstrap never installs `lore-postgres`'s
//!    schema and never assumes `lore-postgres`'s `ensure_schema` advisory-lock bootstrap has run.
//! 3. **All-absent-or-all-valid identity tuples.** Each added schema layer is attested as one
//!    tuple, not per object. A partial tuple is refused, never repaired.
//! 4. **One transaction discipline, stated rather than assumed.** [`attest_cell_schema`] is safe
//!    to call from inside a caller's open transaction and is savepoint-guarded where it must be.
//!    [`install_cell_schema`] is not, and refuses rather than corrupting the caller: it cannot be,
//!    because every frozen artifact carries its own `BEGIN`/`COMMIT` and every layer install
//!    procedure requires `SERIALIZABLE`.
//! 5. **Live catalog readback.** An installed-migration digest does not attest the live PostgreSQL
//!    catalog, so attestation digests a canonical twelve-section manifest over the schema:
//!    relations, columns, constraints, indexes, types, function definitions with their security
//!    attributes (`prosecdef`, `proconfig`), function ACLs, relation and column ACLs (`relacl`,
//!    `attacl`, row-security flags), **default privileges** (`pg_default_acl`), triggers, and rules
//!    and policies. Default privileges earn their section by measurement, not by theory: an
//!    installed cell holds zero `pg_default_acl` rows, so any entry is drift by definition, and an
//!    `ALTER DEFAULT PRIVILEGES ... GRANT EXECUTE ON FUNCTIONS TO <service role>` would otherwise
//!    make every future owner-created function service-executable while every section digest stayed
//!    identical. After any function replacement, prior service-role privileges are explicitly
//!    revoked and then attested as absent.
//! 6. **Inert state.** Four of the five tables 0002 creates are present but unwritable while 0004
//!    through 0006 are uninstalled. That is the expected state and is asserted, not "fixed".
//!
//! What this module is **not**: it is not a service, a dispatcher, a daemon, or an RPC surface. The
//! separate-process service shell was deleted under CR-033 D6/P2 and does not return here. The
//! companion `cell-schema-install` binary is a one-shot operator command that opens one connection,
//! performs one install or one attestation, and exits.
//!
//! ## Readback coverage this module closes, and what it does not
//!
//! WP-114 CD-1's caveat N2 names two readback gaps. This module closes the first: it is the live
//! caller of 0003's `object_store_retention_read_state_v1`, which previously had none.
//!
//! It does not add a `read_state` procedure for 0012 through 0017; new procedures are migrations,
//! and migrations after 0017 belong to CD-3. Instead it attests those layers from the live catalog
//! directly. That matters more than it first appears: 0011's
//! `assert_dispatch_put_reservation_catalog_v1` manifests **every** function in the schema with no
//! name filter, and 0012 through 0017 add functions. So on a fully installed cell the 0011 readback
//! does not merely fail to cover the later layers, it fails closed with
//! `DISPATCH_AUTHORITY_CATALOG_MISMATCH`. `attest_cell_schema` confirms exactly that, records it as
//! an expected retirement rather than an error, and carries the later layers itself.

use std::fmt::Write as _;

use tokio_postgres::Client;
use tokio_postgres::Row;

/// Frozen API revision of this out-of-band installer/attester.
pub const CELL_SCHEMA_INSTALL_API_REVISION_V1: &str = "object-store-cell-schema-install-v1";

/// The one schema namespace the cell authority owns.
pub const CELL_AUTHORITY_SCHEMA: &str = "object_store_retention";

/// Owns every object in [`CELL_AUTHORITY_SCHEMA`].
pub const CELL_OWNER_ROLE: &str = "object_dispatch_retention_owner";

/// The only role permitted to install or attest. Runtime never installs.
pub const CELL_MIGRATOR_ROLE: &str = "object_dispatch_retention_migrator";

/// Runtime, maintenance, migrator, in that order.
pub const CELL_SERVICE_ROLES: [&str; 3] = [
    "object_dispatch_retention_runtime",
    "object_dispatch_retention_maintenance",
    "object_dispatch_retention_migrator",
];

/// One frozen migration artifact of the cell install set.
#[derive(Clone, Copy, Debug)]
pub struct CellMigration {
    /// Numeric slot, e.g. `7` for `0007_*.sql`.
    pub number: u16,
    /// Exact file name under `migrations/`.
    pub file_name: &'static str,
    /// Exact embedded bytes of the frozen artifact.
    pub sql: &'static str,
    /// BLAKE3-256 of [`CellMigration::sql`].
    pub blake3: [u8; 32],
}

macro_rules! cell_migration {
    ($number:expr, $file_name:literal, $digest:literal) => {
        CellMigration {
            number: $number,
            file_name: $file_name,
            sql: include_str!(concat!("../migrations/", $file_name)),
            blake3: hex32($digest),
        }
    };
}

/// CR-033 D5's cell install set, in install order.
pub const CELL_INSTALL_SET: [CellMigration; 13] = [
    cell_migration!(
        2,
        "0002_object_store_retention_authority.sql",
        "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd"
    ),
    cell_migration!(
        3,
        "0003_object_store_retention_provisioning.sql",
        "647ee320d6a615f9a3d91d2919dd4789ffe4073d9f9ea2b97517d4afe974a184"
    ),
    cell_migration!(
        7,
        "0007_object_store_dispatch_authority_core.sql",
        "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff"
    ),
    cell_migration!(
        8,
        "0008_object_store_dispatch_authority_provisioning.sql",
        "90900a392e8d6ca0b59c12aa735e6acf8da364319025b8fae4cafe88a51ed14d"
    ),
    cell_migration!(
        9,
        "0009_object_store_dispatch_authority_canonical_codec.sql",
        "b0803eacad028566e9fd5559f8f8069c44ad290d5631a8cef1a4f7c9669ea12a"
    ),
    cell_migration!(
        10,
        "0010_object_store_dispatch_put_reservation_schema.sql",
        "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67"
    ),
    cell_migration!(
        11,
        "0011_object_store_dispatch_put_reservation_provisioning.sql",
        "afe63db96bf286d1f04e6015eaf797e020b2fcbb2b13012224c66ef462d47248"
    ),
    cell_migration!(
        12,
        "0012_object_store_dispatch_put_reservation_record_codec.sql",
        "b37116d9d87e49ad5c0051514e721a80d0c39f1c9dcaa51c19f7a77618ee6514"
    ),
    cell_migration!(
        13,
        "0013_object_store_dispatch_reserve_put_mutation.sql",
        "eb5d413b9d5dd5d45802b3acaca193cc6b5ac783e38a4c00002a9f9abf77ed7a"
    ),
    cell_migration!(
        14,
        "0014_object_store_dispatch_put_upload_progress_codec.sql",
        "f5361aa66c3e1bdced683040e3a405557a8d2d07f85a182e8e33867e208631a0"
    ),
    cell_migration!(
        15,
        "0015_object_store_dispatch_put_upload_progress_mutation.sql",
        "f9bb0d0ed36689b6c15b9686108adc905cd8fe9839156e051fc443b09941078c"
    ),
    cell_migration!(
        16,
        "0016_object_store_dispatch_put_spool_ready_codec.sql",
        "180fed6b34db413c761e7dcd1e5250119aca5c50116977e8de54ca131408cf8c"
    ),
    cell_migration!(
        17,
        "0017_object_store_dispatch_put_spool_ready_mutation.sql",
        "1bf102fce2e86f48eed6295e1349795564c4aae48aa5ac5d5af5ab5233b0462c"
    ),
];

/// Retention migrations retained, compiled, and deliberately not installed (CR-033 D5).
pub const CELL_DEFERRED_MIGRATIONS: [u16; 3] = [4, 5, 6];

/// Fail closed if packaging or merge changed any embedded artifact's bytes.
///
/// Checks two things that can drift apart independently: every install-set artifact against its own
/// pinned digest, and every layer contract's digest against the artifact that layer names.
#[must_use]
pub fn validate_cell_install_set_digests() -> bool {
    for migration in CELL_INSTALL_SET {
        if blake3::hash(migration.sql.as_bytes()).as_bytes() != &migration.blake3 {
            return false;
        }
    }
    for layer in CELL_SCHEMA_LAYERS {
        let Some(migration) = cell_migration_for(layer.contract_migration) else {
            return false;
        };
        let mut expected = [0u8; 32];
        if hex_to_bytes(layer.migration_blake3_hex, &mut expected).is_err() {
            return false;
        }
        if migration.blake3 != expected {
            return false;
        }
    }
    true
}

/// Look up an install-set artifact by migration number.
#[must_use]
pub fn cell_migration_for(number: u16) -> Option<CellMigration> {
    let mut index = 0;
    while index < CELL_INSTALL_SET.len() {
        if CELL_INSTALL_SET[index].number == number {
            return Some(CELL_INSTALL_SET[index]);
        }
        index += 1;
    }
    None
}

/// The three schema layers that carry an identity tuple in the singleton schema-state row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellSchemaLayerId {
    /// Migrations 0002 and 0003.
    Retention,
    /// Migrations 0007 and 0008.
    Authority,
    /// Migrations 0009, 0010 and 0011.
    PutReservation,
}

impl CellSchemaLayerId {
    /// Stable, non-sensitive label for reports and diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Retention => "retention",
            Self::Authority => "authority",
            Self::PutReservation => "put_reservation",
        }
    }
}

/// One schema layer's install/attest contract, as frozen by its own migration.
#[derive(Clone, Copy, Debug)]
pub struct CellSchemaLayer {
    /// Which layer this is.
    pub id: CellSchemaLayerId,
    /// The provisioning API revision its procedures require.
    pub api_revision: &'static str,
    /// The schema revision its identity tuple pins.
    pub schema_revision: &'static str,
    /// Lowercase hex BLAKE3-256 of the artifact the layer's install procedure demands.
    pub migration_blake3_hex: &'static str,
    /// Migration number whose bytes [`CellSchemaLayer::migration_blake3_hex`] digests.
    pub contract_migration: u16,
    /// Bare name of the layer's install procedure.
    pub install_function: &'static str,
    /// Bare name of the layer's authoritative readback procedure.
    pub read_state_function: &'static str,
    /// `Some(n)` when installing migration `n` retires this readback for a fully installed cell.
    pub read_state_retired_after: Option<u16>,
    /// The exact SQLSTATE the retired readback must raise, when it is retired.
    ///
    /// The two layers retire for different reasons and must fail differently: `42501` when the
    /// EXECUTE privilege was revoked, `55000` when the entrypoint survives but its own catalog
    /// manifest no longer matches. Accepting either code for either layer would let one failure
    /// mode silently stand in for the other.
    pub read_state_retired_sqlstate: Option<&'static str>,
    /// `Some(n)` when installing migration `n` also makes this layer's install procedure unusable.
    ///
    /// Today this matches `read_state_retired_after` for both dispatch layers, but the two are
    /// independent facts: 0011 revokes the 0008 install entrypoint outright, while the
    /// put-reservation install entrypoint keeps its grant and instead fails through the catalog
    /// assert its own projection runs. A future layer could retire one and not the other.
    pub install_retired_after: Option<u16>,
    /// The four schema-state columns that form this layer's all-absent-or-all-valid tuple.
    pub identity_columns: [&'static str; 4],
    /// The DDL migration after which this layer's install procedure must run.
    pub installed_after_migration: u16,
}

/// The layer contracts, in install order.
pub const CELL_SCHEMA_LAYERS: [CellSchemaLayer; 3] = [
    CellSchemaLayer {
        id: CellSchemaLayerId::Retention,
        api_revision: "object-store-retention-provisioning-v1",
        schema_revision: "object-store-retention-authority-schema-v1",
        migration_blake3_hex: "f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd",
        contract_migration: 2,
        install_function: "object_store_retention_install_v1",
        read_state_function: "object_store_retention_read_state_v1",
        read_state_retired_after: None,
        read_state_retired_sqlstate: None,
        install_retired_after: None,
        identity_columns: [
            "schema_revision",
            "migration_blake3",
            "install_revision",
            "installed_at_unix_ms",
        ],
        installed_after_migration: 3,
    },
    CellSchemaLayer {
        id: CellSchemaLayerId::Authority,
        api_revision: "object-store-dispatch-authority-provisioning-v1",
        schema_revision: "object-store-dispatch-authority-schema-v1",
        migration_blake3_hex: "d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff",
        contract_migration: 7,
        install_function: "object_store_dispatch_authority_install_v1",
        read_state_function: "object_store_dispatch_authority_read_state_v1",
        // 0011 revokes EXECUTE on both 0008 entrypoints from every role that held them.
        read_state_retired_after: Some(11),
        read_state_retired_sqlstate: Some("42501"),
        install_retired_after: Some(11),
        identity_columns: [
            "local_authority_schema_revision",
            "local_authority_migration_blake3",
            "local_authority_install_revision",
            "local_authority_installed_at_unix_ms",
        ],
        installed_after_migration: 8,
    },
    CellSchemaLayer {
        id: CellSchemaLayerId::PutReservation,
        api_revision: "object-store-dispatch-put-reservation-provisioning-v1",
        schema_revision: "object-store-dispatch-put-reservation-schema-v1",
        migration_blake3_hex: "56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67",
        contract_migration: 10,
        install_function: "object_store_dispatch_put_reservation_install_v1",
        read_state_function: "object_store_dispatch_put_reservation_read_state_v1",
        // 0011's catalog manifest covers every function in the schema with no name filter, and
        // 0012 adds one. The readback therefore fails closed once 0012 lands.
        read_state_retired_after: Some(12),
        // The entrypoint keeps its grant; its projection runs 0011's catalog assert, which 0012
        // invalidates. Same for the install procedure, which projects through the same assert.
        read_state_retired_sqlstate: Some("55000"),
        install_retired_after: Some(12),
        identity_columns: [
            "put_reservation_schema_revision",
            "put_reservation_migration_blake3",
            "put_reservation_install_revision",
            "put_reservation_installed_at_unix_ms",
        ],
        installed_after_migration: 11,
    },
];

/// A function the install set replaces after first creating it.
///
/// `CREATE OR REPLACE FUNCTION` is not an ACL reset: privileges granted to the prior definition
/// survive it. Every entry here is revoked from all three service roles after its replacing
/// migration, and then attested as unreachable.
#[derive(Clone, Copy, Debug)]
pub struct ReplacedFunction {
    /// Bare function name.
    pub name: &'static str,
    /// The argument-TYPE list, as a `REVOKE ALL ON FUNCTION name(...)` statement spells it.
    ///
    /// Deliberately not `pg_get_function_identity_arguments` output, which also carries parameter
    /// names. This is the form the revoke statement needs, and resolution against the live catalog
    /// goes through `regprocedure`, which parses exactly this form. Naming it after the catalog
    /// function it is not cost one failed live run.
    pub argument_types: &'static str,
    /// Migration that first created it.
    pub introduced_by: u16,
    /// Migration that replaced its body.
    pub replaced_by: u16,
}

const PUT_RESERVATION_RECORD_V1_ARGUMENTS: &str = "text, text, text, text, text, uuid, uuid, uuid, \
     uuid, object_store_retention.uint64, bytea, text, bytea, object_store_retention.uint64, \
     bytea, bytea, text, object_store_retention.uint64, bigint, bigint, bigint, bigint, bigint, \
     object_store_retention.uint64, object_store_retention.uint64, object_store_retention.uint64, \
     object_store_retention.uint64, object_store_retention.uint64, bytea, bytea, \
     object_store_retention.uint64, integer, integer, integer";

const RESERVED_PUT_PROJECTION_ARGUMENTS: &str =
    "object_store_retention.object_dispatch_spool_objects, text";

/// Every `CREATE OR REPLACE FUNCTION` in the install set whose target already existed.
pub const CELL_REPLACED_FUNCTIONS: [ReplacedFunction; 3] = [
    ReplacedFunction {
        name: "local_put_reservation_record_v1",
        argument_types: PUT_RESERVATION_RECORD_V1_ARGUMENTS,
        introduced_by: 12,
        replaced_by: 14,
    },
    ReplacedFunction {
        name: "project_dispatch_reserved_put_v1",
        argument_types: RESERVED_PUT_PROJECTION_ARGUMENTS,
        introduced_by: 13,
        replaced_by: 14,
    },
    // Replaced twice: 0014 rewrites the projection for the v2 record, 0016 again for the
    // spool-ready record. `introduced_by` stays 0013, the migration whose plain CREATE FUNCTION
    // first defined this signature.
    ReplacedFunction {
        name: "project_dispatch_reserved_put_v1",
        argument_types: RESERVED_PUT_PROJECTION_ARGUMENTS,
        introduced_by: 13,
        replaced_by: 16,
    },
];

/// The four tables 0002 creates that no installed procedure can write while 0004-0006 are absent.
///
/// The fifth table 0002 creates, `object_dispatch_retention_schema_state`, is written by 0003's
/// install procedure and is deliberately not listed here.
pub const CELL_INERT_RETENTION_TABLES: [&str; 4] = [
    "object_dispatch_full_record_ownership",
    "object_dispatch_record_storage_counters",
    "object_dispatch_compact_receipts",
    "object_dispatch_compact_prune_watermark",
];

/// The 0004-0006 procedures that must never be installed in a cell.
pub const CELL_DEFERRED_PROCEDURES: [&str; 6] = [
    "object_store_retention_apply_prune_v1",
    "object_store_retention_apply_prune_v2",
    "object_store_retention_apply_transfer_v1",
    "object_store_retention_read_prune_v1",
    "object_store_retention_read_prune_v2",
    "object_store_retention_read_transfer_v1",
];

/// One ordered step of the install plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellInstallStep {
    /// Apply `CELL_INSTALL_SET[index]`'s frozen DDL.
    Migration(usize),
    /// Call `CELL_SCHEMA_LAYERS[index]`'s install procedure.
    InstallLayer(usize),
}

/// The exact ordered install plan: thirteen DDL steps with the three layer installs interleaved.
///
/// Ordering is load-bearing. 0011 retires 0008's install entrypoint, so the authority layer must be
/// installed while migration 0011 has not yet been applied.
#[must_use]
pub fn cell_install_plan() -> Vec<CellInstallStep> {
    let mut plan = Vec::with_capacity(CELL_INSTALL_SET.len() + CELL_SCHEMA_LAYERS.len());
    for (index, migration) in CELL_INSTALL_SET.iter().enumerate() {
        plan.push(CellInstallStep::Migration(index));
        for (layer_index, layer) in CELL_SCHEMA_LAYERS.iter().enumerate() {
            if layer.installed_after_migration == migration.number {
                plan.push(CellInstallStep::InstallLayer(layer_index));
            }
        }
    }
    plan
}

/// Ordered section names of the live catalog manifest.
pub const CELL_CATALOG_MANIFEST_SECTIONS: [&str; 12] = [
    "schema",
    "relations",
    "columns",
    "constraints",
    "indexes",
    "types",
    "functions",
    "function_acls",
    "relation_acls",
    "default_acls",
    "triggers",
    "rules_and_policies",
];

/// One read-only statement producing the nine manifest sections, in
/// [`CELL_CATALOG_MANIFEST_SECTIONS`] order.
///
/// Every aggregate is explicitly ordered so the manifest is deterministic. Every ACL is read
/// through `COALESCE(acl, acldefault(...))` so that materializing a previously implicit ACL, which
/// a no-op `REVOKE` does, cannot by itself look like drift. Role identities are rendered by name,
/// never by OID.
pub const CELL_CATALOG_MANIFEST_SQL: &str = "SELECT
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      space.nspname,
      pg_catalog.pg_get_userbyid(space.nspowner),
      (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
         CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
              ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
         entry.privilege_type, entry.is_grantable
       ) ORDER BY entry.grantee, entry.privilege_type)
         FROM pg_catalog.aclexplode(
           COALESCE(space.nspacl, pg_catalog.acldefault('n', space.nspowner))
         ) AS entry)
    ) ORDER BY space.nspname)::text
      FROM pg_catalog.pg_namespace AS space
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS schema,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, relation.relkind,
      pg_catalog.pg_get_userbyid(relation.relowner),
      relation.relpersistence, relation.relreplident,
      relation.relrowsecurity, relation.relforcerowsecurity
    ) ORDER BY relation.relname)::text
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS relations,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, attribute.attnum, attribute.attname,
      pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
      attribute.attnotnull, attribute.attidentity, attribute.attgenerated,
      CASE WHEN attribute.attcollation = 0 THEN NULL
           ELSE pg_catalog.format('%I.%I', collation_space.nspname, collation_state.collname)
      END,
      pg_catalog.pg_get_expr(attribute_default.adbin, attribute_default.adrelid, false)
    ) ORDER BY relation.relname, attribute.attnum)::text
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
      JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
      LEFT JOIN pg_catalog.pg_attrdef AS attribute_default
        ON attribute_default.adrelid = relation.oid
       AND attribute_default.adnum = attribute.attnum
      LEFT JOIN pg_catalog.pg_collation AS collation_state
        ON collation_state.oid = attribute.attcollation
      LEFT JOIN pg_catalog.pg_namespace AS collation_space
        ON collation_space.oid = collation_state.collnamespace
     WHERE space.nspname = 'object_store_retention'
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped
  ), '[]') AS columns,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      constraint_state.conname, constraint_state.contype,
      COALESCE(relation.relname, type_state.typname),
      pg_catalog.pg_get_constraintdef(constraint_state.oid, false),
      constraint_state.convalidated, constraint_state.condeferrable
    ) ORDER BY COALESCE(relation.relname, type_state.typname), constraint_state.conname)::text
      FROM pg_catalog.pg_constraint AS constraint_state
      JOIN pg_catalog.pg_namespace AS space ON space.oid = constraint_state.connamespace
      LEFT JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_state.conrelid
      LEFT JOIN pg_catalog.pg_type AS type_state ON type_state.oid = constraint_state.contypid
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS constraints,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      index_relation.relname, pg_catalog.pg_get_indexdef(index_state.indexrelid),
      index_state.indisunique, index_state.indisprimary, index_state.indisvalid,
      index_state.indisready, index_state.indislive, index_state.indcheckxmin
    ) ORDER BY index_relation.relname)::text
      FROM pg_catalog.pg_index AS index_state
      JOIN pg_catalog.pg_class AS index_relation ON index_relation.oid = index_state.indexrelid
      JOIN pg_catalog.pg_namespace AS space ON space.oid = index_relation.relnamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS indexes,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      type_state.typname, type_state.typtype, type_state.typcategory,
      type_state.typisdefined, type_state.typdelim, type_state.typnotnull,
      type_state.typdefault, pg_catalog.pg_get_userbyid(type_state.typowner),
      (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
         CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
              ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
         entry.privilege_type, entry.is_grantable
       ) ORDER BY entry.grantee, entry.privilege_type)
         FROM pg_catalog.aclexplode(
           COALESCE(type_state.typacl, pg_catalog.acldefault('T', type_state.typowner))
         ) AS entry)
    ) ORDER BY type_state.typname)::text
      FROM pg_catalog.pg_type AS type_state
      JOIN pg_catalog.pg_namespace AS space ON space.oid = type_state.typnamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS types,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      procedure.proname,
      pg_catalog.pg_get_function_identity_arguments(procedure.oid),
      pg_catalog.pg_get_function_result(procedure.oid),
      procedure.prokind, procedure.provolatile, procedure.prosecdef,
      procedure.proleakproof, procedure.proisstrict, procedure.proparallel,
      procedure.proconfig, pg_catalog.pg_get_userbyid(procedure.proowner),
      pg_catalog.pg_get_functiondef(procedure.oid)
    ) ORDER BY procedure.proname,
               pg_catalog.pg_get_function_identity_arguments(procedure.oid))::text
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_namespace AS space ON space.oid = procedure.pronamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS functions,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      procedure.proname,
      pg_catalog.pg_get_function_identity_arguments(procedure.oid),
      CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
           ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
      entry.privilege_type, entry.is_grantable
    ) ORDER BY procedure.proname,
               pg_catalog.pg_get_function_identity_arguments(procedure.oid),
               entry.grantee, entry.privilege_type)::text
      FROM pg_catalog.pg_proc AS procedure
      JOIN pg_catalog.pg_namespace AS space ON space.oid = procedure.pronamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
      ) AS entry
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS function_acls,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname,
      CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
           ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
      entry.privilege_type, entry.is_grantable
    ) ORDER BY relation.relname, entry.grantee, entry.privilege_type)::text
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
      ) AS entry
     WHERE space.nspname = 'object_store_retention'
  ), '[]') || '|' || COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, attribute.attname,
      CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
           ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
      entry.privilege_type, entry.is_grantable
    ) ORDER BY relation.relname, attribute.attname,
               entry.grantee, entry.privilege_type)::text
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
      JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
      CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS entry
     WHERE space.nspname = 'object_store_retention'
       AND attribute.attnum > 0
       AND NOT attribute.attisdropped
       AND attribute.attacl IS NOT NULL
  ), '[]') AS relation_acls,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      pg_catalog.pg_get_userbyid(default_acl.defaclrole),
      COALESCE(space.nspname, ''),
      default_acl.defaclobjtype,
      CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
           ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
      entry.privilege_type, entry.is_grantable
    ) ORDER BY pg_catalog.pg_get_userbyid(default_acl.defaclrole),
               COALESCE(space.nspname, ''),
               default_acl.defaclobjtype,
               CASE WHEN entry.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(entry.grantee) END,
               entry.privilege_type)::text
      FROM pg_catalog.pg_default_acl AS default_acl
      -- LEFT JOIN, and schema-less entries are in scope. defaclnamespace is 0 for a
      -- default-privilege statement written without an IN SCHEMA clause, and no namespace has oid
      -- 0, so an inner join silently drops exactly the statement this section exists to catch: a
      -- schema-less default EXECUTE privilege for a service role reaches functions created in
      -- object_store_retention just the same, and would otherwise attest clean.
      LEFT JOIN pg_catalog.pg_namespace AS space ON space.oid = default_acl.defaclnamespace
      CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) AS entry
     WHERE default_acl.defaclnamespace = 0
        OR space.nspname = 'object_store_retention'
  ), '[]') AS default_acls,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, trigger_state.tgname, trigger_state.tgenabled,
      pg_catalog.pg_get_triggerdef(trigger_state.oid)
    ) ORDER BY relation.relname, trigger_state.tgname)::text
      FROM pg_catalog.pg_trigger AS trigger_state
      JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_state.tgrelid
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
     WHERE space.nspname = 'object_store_retention'
       AND NOT trigger_state.tgisinternal
  ), '[]') AS triggers,
  COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, rule_state.rulename,
      pg_catalog.pg_get_ruledef(rule_state.oid)
    ) ORDER BY relation.relname, rule_state.rulename)::text
      FROM pg_catalog.pg_rewrite AS rule_state
      JOIN pg_catalog.pg_class AS relation ON relation.oid = rule_state.ev_class
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') || '|' || COALESCE((
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
      relation.relname, policy.polname, policy.polcmd, policy.polpermissive,
      pg_catalog.pg_get_expr(policy.polqual, policy.polrelid, false),
      pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid, false),
      -- By rendered name, not OID: OIDs are creation-order dependent across clusters, and
      -- pg_get_userbyid(0) renders an unknown-OID placeholder rather than the PUBLIC pseudo-role
      -- that polroles uses 0 to mean.
      (SELECT pg_catalog.jsonb_agg(name ORDER BY name)
         FROM (SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC'
                           ELSE pg_catalog.pg_get_userbyid(role_oid) END AS name
                 FROM pg_catalog.unnest(policy.polroles) AS role_oid) AS policy_role)
    ) ORDER BY relation.relname, policy.polname)::text
      FROM pg_catalog.pg_policy AS policy
      JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
      JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
     WHERE space.nspname = 'object_store_retention'
  ), '[]') AS rules_and_policies";

/// Pinned per-section BLAKE3-256 digests of the fully installed cell catalog, PostgreSQL 16.
///
/// Sections are in [`CELL_CATALOG_MANIFEST_SECTIONS`] order. Measured, not derived: see
/// `tests/run-cell-schema-install-live.ps1`.
pub const CELL_CATALOG_SECTION_BLAKE3_V1: [[u8; 32]; 12] = [
    hex32("ad659e388e49dc7666f006ca9f7b598f59f133ff8e9c4d61a90f6d01cbd265a7"),
    hex32("bacb6cf9f7b75490162883a1d628341aebb9d77bbbf48e2cee84e5f21ef6c8cf"),
    hex32("e926ee2b4c879aa706209b29c9a2e9e0a5e664cdce60c5b7f0b6757d0915b709"),
    hex32("6466061c5fa0fcf6ec39045c04ba05df71e4f6dcbd2d00d4a3e1e3bd3cde7a57"),
    hex32("241b7d6b4a675b7ab5bb4b62d0a6d4eb15748fc057ab8f4f979f2cfb7922d434"),
    hex32("8667b08b5a9da461c0b0a72cf0eb4a4940d780002ee2b2552d4e77d2d56e6a2f"),
    hex32("e0089845a21d0fa195350ecbe39d1410c05823eec9081f3e8b1c025f17f7377b"),
    hex32("c7829d074938d6ceec64c83640576b1f163fe731e9b4e3eec2939f6b35183e54"),
    hex32("8a807de8704f40f36bf4102d9576523afab0359da8bf32b607c8955c1b39fadb"),
    hex32("d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab"),
    hex32("d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab"),
    hex32("d51a543740627c0260abd1ea027bf7afd18eb9dff372c5857f2b8683f4ca4b7b"),
];

/// Pinned BLAKE3-256 of the complete manifest of a fully installed cell, PostgreSQL 16.
///
/// Pinned to PostgreSQL 16: the manifest carries `pg_get_functiondef` and `pg_get_indexdef` output,
/// whose exact rendering is a server-version property. A different major version is expected to
/// fail closed here and needs a re-measured pin, not a relaxed check.
pub const CELL_CATALOG_MANIFEST_BLAKE3_V1: [u8; 32] =
    hex32("560d0e9412459e94e500e2af79e66219983412293fe3cc7f4c81a1a3c9f0f2b2");

/// Const hex decoder for the pinned digests above.
const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "a pinned digest is 64 hex characters");
    let mut out = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        out[index] = const_nibble(bytes[index * 2]) * 16 + const_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    out
}

const fn const_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("a pinned digest uses lowercase hex only"),
    }
}

fn hex_to_bytes(text: &str, out: &mut [u8; 32]) -> Result<(), CellSchemaError> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Err(CellSchemaError::InvalidResponse("digest length"));
    }
    for index in 0..32 {
        let high = nibble(bytes[index * 2])?;
        let low = nibble(bytes[index * 2 + 1])?;
        out[index] = high * 16 + low;
    }
    Ok(())
}

fn nibble(byte: u8) -> Result<u8, CellSchemaError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CellSchemaError::InvalidResponse("digest alphabet")),
    }
}

/// Every failure this installer/attester can report.
///
/// Variants carry only fixed strings and closed enums. Connection strings, PEM material,
/// PostgreSQL diagnostics, and parameter values never reach `Display`, `Debug`, or `source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CellSchemaError {
    /// An install precondition was not met; nothing was changed.
    #[error("cell schema install precondition failed: {0}")]
    Precondition(&'static str),
    /// A database operation failed. The diagnostic is deliberately not carried.
    #[error("cell authority database operation failed")]
    Postgres,
    /// A response did not have the shape the contract requires.
    #[error("cell authority response has an unexpected shape: {0}")]
    InvalidResponse(&'static str),
    /// A layer's identity tuple was partially present, which is never a valid state.
    #[error("cell schema layer identity tuple is partially present")]
    PartialLayerIdentity(CellSchemaLayerId),
    /// A layer's identity tuple did not match its frozen artifact contract.
    #[error("cell schema layer identity tuple does not match the frozen artifact")]
    LayerIdentityDrift(CellSchemaLayerId),
    /// A live catalog section did not match its pinned manifest digest.
    #[error("cell authority catalog section does not match the pinned manifest: {0}")]
    CatalogDrift(&'static str),
    /// A service role still held EXECUTE on a function the install set replaced.
    #[error("a service role still holds EXECUTE on a replaced function")]
    ResidualServicePrivilege,
    /// The expected inert retention state was not what CR-033 D5 records.
    #[error("the expected inert retention state is absent: {0}")]
    InertStateMismatch(&'static str),
    /// A provisioning entrypoint that must be retired was still reachable.
    #[error("a retired provisioning entrypoint is still reachable: {0}")]
    RetiredEntrypointReachable(&'static str),
    /// A retired entrypoint failed, but not the way its retirement mode requires.
    ///
    /// Distinct from [`CellSchemaError::RetiredEntrypointReachable`] because the outcomes differ:
    /// reachable means the boundary is gone, while this means the boundary may hold for some other
    /// reason entirely, such as the function having been dropped (`42883`). Reporting the second as
    /// the first would name the wrong problem.
    #[error("a retired provisioning entrypoint failed with an unexpected sqlstate: {0}")]
    RetiredEntrypointUnexpectedFailure(&'static str),
    /// The schema is present but does not attest; the installer refuses to touch it.
    ///
    /// Carries the attestation's own reason, so a refusal says which surface disagreed rather than
    /// only that something did.
    #[error("cell schema install refused: the schema is present and does not attest ({0})")]
    RefusedUnattestedSchema(&'static str),
    /// An install procedure returned a result code outside `CREATED`/`REPLAY`.
    #[error("a cell schema install procedure returned an unexpected result code")]
    UnexpectedInstallResult,
}

impl CellSchemaError {
    /// A fixed, non-sensitive label for this failure, safe to carry into another error.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Precondition(_) => "precondition",
            Self::Postgres => "database",
            Self::InvalidResponse(_) => "response shape",
            Self::PartialLayerIdentity(_) => "partial layer identity",
            Self::LayerIdentityDrift(_) => "layer identity drift",
            Self::CatalogDrift(_) => "catalog drift",
            Self::ResidualServicePrivilege => "residual service privilege",
            Self::InertStateMismatch(_) => "inert state",
            Self::RetiredEntrypointReachable(_) => "retired entrypoint reachable",
            Self::RetiredEntrypointUnexpectedFailure(_) => "retired entrypoint sqlstate",
            Self::RefusedUnattestedSchema(_) => "unattested schema",
            Self::UnexpectedInstallResult => "install result",
        }
    }

    fn postgres(_error: tokio_postgres::Error) -> Self {
        // The driver error is dropped, not carried: it can hold parameter values, the connection
        // string, and PostgreSQL diagnostics, none of which may reach Display, Debug or source.
        Self::Postgres
    }
}

/// A layer's attested identity tuple: all four fields absent, or all four present and valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerIdentity {
    /// Every field of the tuple is absent.
    Absent,
    /// Every field is present and individually valid.
    Valid {
        /// The pinned install revision.
        install_revision: u64,
        /// Database-minted install time.
        installed_at_unix_ms: i64,
    },
}

/// The result of calling one layer's install procedure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerInstallOutcome {
    /// The tuple was minted by this call.
    Created,
    /// The install procedure was re-executed and reported an exact replay.
    Replayed,
    /// The tuple was attested but not re-executed, because this layer's install entrypoint is
    /// unusable at full chain depth.
    ///
    /// 0011 revokes `object_store_dispatch_authority_install_v1` outright, and
    /// `object_store_dispatch_put_reservation_install_v1` projects its result through 0011's
    /// whole-schema catalog manifest, which 0012 through 0017 invalidate. Neither is a defect and
    /// neither can be re-called on an installed cell; the identity tuple and the live catalog
    /// manifest carry the evidence instead.
    AttestedOnly,
}

/// What one attestation observed. Every field is non-sensitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellAttestation {
    /// Each layer's identity tuple, in [`CELL_SCHEMA_LAYERS`] order.
    pub layers: [(CellSchemaLayerId, LayerIdentity); 3],
    /// Per-section live catalog digests, in [`CELL_CATALOG_MANIFEST_SECTIONS`] order.
    pub catalog_sections: [[u8; 32]; 12],
    /// BLAKE3-256 over the whole manifest.
    pub catalog_blake3: [u8; 32],
    /// Result code returned by 0003's readback. This module is its first live caller.
    pub retention_read_state_result: String,
    /// Readback entrypoints confirmed retired: the layer label and the exact SQLSTATE it raised.
    pub retired_readbacks: Vec<(&'static str, &'static str)>,
    /// Distinct replaced-function signatures proven unreachable by every service role.
    pub replaced_functions_revoked: usize,
    /// Count of present-but-inert 0002 tables.
    pub inert_tables_present: usize,
}

/// Whether an install call created the cell schema or replayed an already-attesting one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellInstallDisposition {
    /// The schema did not exist and the full plan ran.
    Created,
    /// The schema already existed, attested, and only the replay-safe steps ran.
    Replayed,
}

/// What one install run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellInstallReport {
    /// Whether this run created or replayed.
    pub disposition: CellInstallDisposition,
    /// Each layer's install-procedure outcome, in [`CELL_SCHEMA_LAYERS`] order.
    pub layer_outcomes: [(CellSchemaLayerId, LayerInstallOutcome); 3],
    /// The attestation taken after the run.
    pub attestation: CellAttestation,
}

const SCHEMA_PRESENT_SQL: &str = "SELECT count(*)::bigint FROM pg_catalog.pg_namespace \
     WHERE nspname = 'object_store_retention'";

const SESSION_USER_SQL: &str = "SELECT session_user::text";

// MEMBER, not USAGE: the install path issues `SET LOCAL ROLE`, which needs membership, and every
// frozen migration opens with `SET LOCAL ROLE object_dispatch_retention_owner`.
const OWNER_MEMBERSHIP_SQL: &str =
    "SELECT pg_catalog.pg_has_role(session_user, 'object_dispatch_retention_owner', 'MEMBER')";

// ...and the membership must NOT be inheriting. 0008's and 0011's catalog asserts reject any of the
// three service roles holding a table privilege on an authority table, and `has_table_privilege`
// counts privileges reached through an inheriting membership. A plain
// `GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator` therefore makes the
// cell's own attestation fail from the first install call onward, with no object having drifted.
// The grant must be `WITH INHERIT FALSE, SET TRUE`: the migrator may become the owner, never
// silently act with the owner's privileges.
const OWNER_INHERITANCE_SQL: &str =
    "SELECT pg_catalog.pg_has_role(session_user, 'object_dispatch_retention_owner', 'USAGE')";

const OWNER_CREATE_SQL: &str = "SELECT pg_catalog.has_database_privilege(
       'object_dispatch_retention_owner', pg_catalog.current_database(), 'CREATE'
     )";

const ROLES_PRESENT_SQL: &str = "SELECT count(*)::bigint FROM pg_catalog.pg_roles
     WHERE rolname IN (
       'object_dispatch_retention_owner', 'object_dispatch_retention_runtime',
       'object_dispatch_retention_maintenance', 'object_dispatch_retention_migrator'
     )";

const SCHEMA_STATE_SQL: &str = "SELECT
    schema_revision,
    pg_catalog.encode(migration_blake3, 'hex'),
    install_revision::text,
    installed_at_unix_ms,
    local_authority_schema_revision,
    pg_catalog.encode(local_authority_migration_blake3, 'hex'),
    local_authority_install_revision::text,
    local_authority_installed_at_unix_ms,
    put_reservation_schema_revision,
    pg_catalog.encode(put_reservation_migration_blake3, 'hex'),
    put_reservation_install_revision::text,
    put_reservation_installed_at_unix_ms
  FROM object_store_retention.object_dispatch_retention_schema_state
 WHERE singleton";

// A truncated chain does not merely leave a later layer's tuple null: the columns that hold it do
// not exist at all, because 0008 and 0011 add them. Probing for them first is what turns an
// interrupted install into a named partial-identity refusal instead of a raw driver error.
const IDENTITY_COLUMNS_PRESENT_SQL: &str = "SELECT count(*)::bigint
     FROM pg_catalog.pg_attribute AS attribute
     JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
     JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
    WHERE space.nspname = 'object_store_retention'
      AND relation.relname = 'object_dispatch_retention_schema_state'
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attname = ANY($1)";

const INERT_TABLE_SQL: &str = "SELECT count(*)::bigint FROM pg_catalog.pg_class AS relation
     JOIN pg_catalog.pg_namespace AS space ON space.oid = relation.relnamespace
    WHERE space.nspname = 'object_store_retention'
      AND relation.relkind = 'r'
      AND relation.relname = ANY($1)";

const DEFERRED_PROCEDURE_SQL: &str = "SELECT count(*)::bigint FROM pg_catalog.pg_proc AS procedure
     JOIN pg_catalog.pg_namespace AS space ON space.oid = procedure.pronamespace
    WHERE space.nspname = 'object_store_retention'
      AND procedure.proname = ANY($1)";

const INERT_TABLE_WRITABLE_SQL: &str = "SELECT count(*)::bigint
     FROM unnest($1::text[]) AS denied_role(role_name)
     CROSS JOIN unnest($2::text[]) AS inert_table(table_name)
    WHERE pg_catalog.has_table_privilege(
      denied_role.role_name,
      pg_catalog.format('object_store_retention.%I', inert_table.table_name),
      'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
    )";

const TRANSACTION_PROBE_SAVEPOINT_SQL: &str = "SAVEPOINT cell_schema_transaction_probe";

const TRANSACTION_PROBE_RELEASE_SQL: &str = "ROLLBACK TO SAVEPOINT cell_schema_transaction_probe; \
     RELEASE SAVEPOINT cell_schema_transaction_probe";

// Matched on name AND identity arguments, as a pair. Matching on name alone would silently exempt a
// same-name overload with a different signature, which is exactly the object a replacement is most
// likely to leave behind.
// One array of rendered `name(identity arguments)` signatures rather than two parallel arrays: the
// two-argument form of `unnest` is a special FROM-clause construct that cannot be schema-qualified,
// and this module qualifies every catalog reference. Comparing the rendered signature keeps the
// match on name AND arguments.
// Resolution goes through `regprocedure`, which is the same parser `REVOKE ALL ON FUNCTION` uses.
// That is the point: the signature strings here and the revoke statements are then guaranteed to
// name the same functions, and cannot drift into naming different ones. A signature that does not
// resolve raises 42883 and fails closed rather than silently matching nothing.
//
// Returns two counts, and both matter. `matched` is how many frozen signatures actually exist in
// the live schema; without it, this check could inspect nothing and report success. `residual` is
// the finding itself.
const RESIDUAL_PRIVILEGE_SQL: &str = "SELECT
  (SELECT count(*)::bigint
     FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = ANY(ARRAY(
      SELECT signature::regprocedure FROM pg_catalog.unnest($1::text[]) AS signature))
  ) AS matched,
  (SELECT count(*)::bigint
     FROM pg_catalog.pg_proc AS procedure
     CROSS JOIN LATERAL pg_catalog.aclexplode(
       COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
     ) AS entry
    WHERE procedure.oid = ANY(ARRAY(
      SELECT signature::regprocedure FROM pg_catalog.unnest($1::text[]) AS signature))
      AND entry.privilege_type = 'EXECUTE'
      AND entry.grantee <> 0
      AND pg_catalog.pg_get_userbyid(entry.grantee) = ANY($2)
  ) AS residual";

/// Install the cell authority schema out of band, under the migrator role.
///
/// A fresh database runs the whole plan. A database that already carries the schema is never
/// re-migrated: it is attested first, and the run is refused unless every layer already attests.
/// A partial or drifted install is refused and left exactly as found; this function never repairs.
///
/// **The fresh plan is not one transaction, and cannot be made one.** Each frozen artifact opens
/// with its own `BEGIN` and closes with its own `COMMIT`, so an outer transaction would be
/// terminated by the first artifact's `COMMIT` rather than wrapping it, and making it one would
/// mean editing frozen migrations. A failure part way through therefore leaves the artifacts that
/// already committed in place. That state fails closed on every later run, and the documented
/// recovery is to drop and recreate the cell database rather than to resume: forward migrations are
/// one-shot, so there is no safe "continue from step k".
///
/// # Errors
///
/// Returns [`CellSchemaError`] when a precondition fails, the database refuses a step, or the
/// post-install attestation does not hold. Nothing is repaired on failure.
pub async fn install_cell_schema(client: &Client) -> Result<CellInstallReport, CellSchemaError> {
    let (disposition, layer_outcomes) = apply_cell_install_plan(client).await?;
    let attestation = attest_cell_schema(client).await?;
    Ok(CellInstallReport {
        disposition,
        layer_outcomes,
        attestation,
    })
}

/// Run the install plan without the closing attestation.
///
/// [`install_cell_schema`] is this plus [`attest_cell_schema`], and is what operators run. This
/// seam exists so a harness can measure a freshly installed catalog's manifest before any pinned
/// digest exists to compare it against.
///
/// # Errors
///
/// Returns [`CellSchemaError`] when a precondition fails, an existing schema does not attest, or a
/// step is refused by the database.
pub async fn apply_cell_install_plan(
    client: &Client,
) -> Result<
    (
        CellInstallDisposition,
        [(CellSchemaLayerId, LayerInstallOutcome); 3],
    ),
    CellSchemaError,
> {
    if !validate_cell_install_set_digests() {
        return Err(CellSchemaError::Precondition("embedded migration digests"));
    }
    assert_install_preconditions(client).await?;

    let mut layer_outcomes = [
        (CellSchemaLayerId::Retention, LayerInstallOutcome::Created),
        (CellSchemaLayerId::Authority, LayerInstallOutcome::Created),
        (
            CellSchemaLayerId::PutReservation,
            LayerInstallOutcome::Created,
        ),
    ];

    let disposition = if schema_is_present(client).await? {
        // Forward migrations are one-shot, not idempotent, so an existing schema is never
        // re-migrated. It must already attest, or this run refuses and changes nothing.
        attest_cell_schema(client)
            .await
            .map_err(|error| CellSchemaError::RefusedUnattestedSchema(error.reason()))?;
        for (index, layer) in CELL_SCHEMA_LAYERS.iter().enumerate() {
            layer_outcomes[index].1 = if layer.install_retired_after.is_some() {
                LayerInstallOutcome::AttestedOnly
            } else {
                call_layer_install(client, layer).await?
            };
        }
        CellInstallDisposition::Replayed
    } else {
        for step in cell_install_plan() {
            match step {
                CellInstallStep::Migration(index) => {
                    let migration = CELL_INSTALL_SET[index];
                    client
                        .batch_execute(migration.sql)
                        .await
                        .map_err(CellSchemaError::postgres)?;
                }
                CellInstallStep::InstallLayer(index) => {
                    layer_outcomes[index].1 =
                        call_layer_install(client, &CELL_SCHEMA_LAYERS[index]).await?;
                }
            }
        }
        CellInstallDisposition::Created
    };

    revoke_replaced_function_privileges(client).await?;
    Ok((disposition, layer_outcomes))
}

/// Explicitly revoke prior service-role privileges from every function the install set replaced.
///
/// Idempotent, and a no-op against a correctly installed cell: the frozen migrations already issue
/// these revokes. It exists so the install path states the obligation itself rather than inheriting
/// it, and so a cell whose ACLs were widened out of band is brought back before attestation.
///
/// # Errors
///
/// Returns [`CellSchemaError::Postgres`] if a revoke cannot be issued.
pub async fn revoke_replaced_function_privileges(
    client: &Client,
) -> Result<usize, CellSchemaError> {
    assert_migrator_session(client).await?;
    let mut statements = String::new();
    let mut issued = 0;
    for (name, arguments) in distinct_replaced_signatures() {
        // Signatures come from this module's frozen inventory, never from caller input.
        if writeln!(
            statements,
            "REVOKE ALL ON FUNCTION {CELL_AUTHORITY_SCHEMA}.{name}({arguments}) FROM {}, {}, {};",
            CELL_SERVICE_ROLES[0], CELL_SERVICE_ROLES[1], CELL_SERVICE_ROLES[2]
        )
        .is_err()
        {
            return Err(CellSchemaError::InvalidResponse("revoke statement"));
        }
        issued += 1;
    }
    if issued == 0 {
        return Ok(0);
    }
    client
        .batch_execute(&format!(
            "SET ROLE {CELL_OWNER_ROLE};\n{statements}RESET ROLE;"
        ))
        .await
        .map_err(CellSchemaError::postgres)?;
    Ok(issued)
}

/// Attest the installed cell authority schema against the live PostgreSQL catalog.
///
/// # Errors
///
/// Returns [`CellSchemaError`] on any partial identity tuple, identity drift, catalog drift,
/// residual service-role privilege on a replaced function, missing inert state, or a retired
/// readback entrypoint that is still reachable.
pub async fn attest_cell_schema(client: &Client) -> Result<CellAttestation, CellSchemaError> {
    assert_migrator_session(client).await?;
    let layers = read_layer_identities(client).await?;
    for (index, (id, identity)) in layers.iter().enumerate() {
        if *identity == LayerIdentity::Absent {
            return Err(CellSchemaError::PartialLayerIdentity(*id));
        }
        debug_assert_eq!(*id, CELL_SCHEMA_LAYERS[index].id);
    }

    let (catalog_sections, catalog_blake3) = read_catalog_manifest(client).await?;
    for (index, section) in catalog_sections.iter().enumerate() {
        if *section != CELL_CATALOG_SECTION_BLAKE3_V1[index] {
            return Err(CellSchemaError::CatalogDrift(
                CELL_CATALOG_MANIFEST_SECTIONS[index],
            ));
        }
    }
    if catalog_blake3 != CELL_CATALOG_MANIFEST_BLAKE3_V1 {
        return Err(CellSchemaError::CatalogDrift("manifest"));
    }

    let replaced_functions_revoked = assert_no_residual_service_privilege(client).await?;
    let inert_tables_present = assert_inert_state(client).await?;
    let retention_read_state_result = read_retention_state(client).await?;
    let retired_readbacks = assert_retired_readbacks(client).await?;

    Ok(CellAttestation {
        layers,
        catalog_sections,
        catalog_blake3,
        retention_read_state_result,
        retired_readbacks,
        replaced_functions_revoked,
        inert_tables_present,
    })
}

/// Read the live catalog manifest without comparing it, for measuring the pinned digests.
///
/// # Errors
///
/// Returns [`CellSchemaError`] if the manifest cannot be read or has an unexpected shape.
pub async fn measure_catalog_manifest(
    client: &Client,
) -> Result<([[u8; 32]; 12], [u8; 32]), CellSchemaError> {
    assert_migrator_session(client).await?;
    read_catalog_manifest(client).await
}

/// Every entry point starts here.
///
/// `session_user` is the right check rather than `current_user`: `SET ROLE` cannot forge it, so a
/// caller cannot borrow the migrator identity. It is enforced by attestation and by the revoke pass
/// too, not only by install. Attestation reads privileged state, the revoke pass writes ACLs, and a
/// documented "this refuses unless you are the migrator" boundary that only one of the three
/// enforces is a false statement rather than a weak one.
async fn assert_migrator_session(client: &Client) -> Result<(), CellSchemaError> {
    let session_user: String = query_one_value(client, SESSION_USER_SQL).await?;
    if session_user != CELL_MIGRATOR_ROLE {
        return Err(CellSchemaError::Precondition(
            "session_user is not migrator",
        ));
    }
    Ok(())
}

/// Refuse if the caller already has a transaction open.
///
/// Install is not transaction-safe and cannot be made so: each frozen artifact carries its own
/// `BEGIN`/`COMMIT`, and every layer install procedure requires `SERIALIZABLE`, which cannot be
/// entered from inside another transaction. Running it inside a caller's transaction would end that
/// transaction at the first artifact and commit the caller's uncommitted work with it. PostgreSQL
/// answers "is a transaction open" through `SAVEPOINT`, which raises 25P01 when there is none.
async fn assert_no_open_transaction(client: &Client) -> Result<(), CellSchemaError> {
    match client.batch_execute(TRANSACTION_PROBE_SAVEPOINT_SQL).await {
        Ok(()) => {
            // The savepoint succeeded, so a transaction is open and the install is already
            // refused. Tidy up on a best-effort basis, but report the precondition either way: a
            // failure to release is less informative than the finding it would otherwise mask.
            let _ = client.batch_execute(TRANSACTION_PROBE_RELEASE_SQL).await;
            Err(CellSchemaError::Precondition(
                "install must not run inside an open transaction",
            ))
        }
        Err(error) => {
            let Some(database_error) = error.as_db_error() else {
                return Err(CellSchemaError::Postgres);
            };
            if database_error.code().code() == "25P01" {
                Ok(())
            } else {
                Err(CellSchemaError::Postgres)
            }
        }
    }
}

async fn assert_install_preconditions(client: &Client) -> Result<(), CellSchemaError> {
    assert_migrator_session(client).await?;
    assert_no_open_transaction(client).await?;
    let roles_present: i64 = query_one_value(client, ROLES_PRESENT_SQL).await?;
    if roles_present != 4 {
        return Err(CellSchemaError::Precondition("authority roles"));
    }
    let owner_member: bool = query_one_value(client, OWNER_MEMBERSHIP_SQL).await?;
    if !owner_member {
        return Err(CellSchemaError::Precondition("owner role membership"));
    }
    let owner_inherited: bool = query_one_value(client, OWNER_INHERITANCE_SQL).await?;
    if owner_inherited {
        return Err(CellSchemaError::Precondition(
            "owner membership must be WITH INHERIT FALSE",
        ));
    }
    let owner_can_create: bool = query_one_value(client, OWNER_CREATE_SQL).await?;
    if !owner_can_create {
        return Err(CellSchemaError::Precondition("owner CREATE on database"));
    }

    // `INHERIT FALSE` is only half the grant this needs; `SET TRUE` is the other half, and no
    // catalog predicate reports it directly. Probe it. Without this, a `SET FALSE` grant passes
    // every check above and then fails at the first artifact's `SET LOCAL ROLE` as an opaque
    // database error with no carried reason, which is exactly the misleading-failure mode this
    // module's own `INHERIT FALSE` precondition exists to prevent.
    if client
        .batch_execute(&format!("SET ROLE {CELL_OWNER_ROLE}; RESET ROLE;"))
        .await
        .is_err()
    {
        return Err(CellSchemaError::Precondition(
            "owner membership must be WITH SET TRUE",
        ));
    }
    Ok(())
}

async fn schema_is_present(client: &Client) -> Result<bool, CellSchemaError> {
    let present: i64 = query_one_value(client, SCHEMA_PRESENT_SQL).await?;
    Ok(present == 1)
}

async fn call_layer_install(
    client: &Client,
    layer: &CellSchemaLayer,
) -> Result<LayerInstallOutcome, CellSchemaError> {
    let sql = format!(
        "SELECT ({CELL_AUTHORITY_SCHEMA}.{}('{}', '{}', pg_catalog.decode('{}', 'hex'), 1)).result_code",
        layer.install_function,
        layer.api_revision,
        layer.schema_revision,
        layer.migration_blake3_hex
    );
    client
        .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;")
        .await
        .map_err(CellSchemaError::postgres)?;
    let result = client.query_one(&sql, &[]).await;
    let row = match result {
        Ok(row) => {
            client
                .batch_execute("COMMIT;")
                .await
                .map_err(CellSchemaError::postgres)?;
            row
        }
        Err(error) => {
            client
                .batch_execute("ROLLBACK;")
                .await
                .map_err(CellSchemaError::postgres)?;
            return Err(CellSchemaError::postgres(error));
        }
    };
    let code: String = row
        .try_get(0)
        .map_err(|_| CellSchemaError::InvalidResponse("install result code"))?;
    match code.as_str() {
        "CREATED" => Ok(LayerInstallOutcome::Created),
        "REPLAY" => Ok(LayerInstallOutcome::Replayed),
        _ => Err(CellSchemaError::UnexpectedInstallResult),
    }
}

async fn read_layer_identities(
    client: &Client,
) -> Result<[(CellSchemaLayerId, LayerIdentity); 3], CellSchemaError> {
    // 0011 revokes every privilege on the schema-state table from all three service roles, so the
    // tuples are readable only as the schema owner. The migrator is a member of the owner role by
    // the install precondition above, which is what makes this legitimate rather than a widening.
    //
    for layer in CELL_SCHEMA_LAYERS {
        let columns: Vec<&str> = layer.identity_columns.to_vec();
        let present: i64 =
            query_one_value_with(client, IDENTITY_COLUMNS_PRESENT_SQL, &[&columns]).await?;
        if present != layer.identity_columns.len() as i64 {
            return Err(CellSchemaError::PartialLayerIdentity(layer.id));
        }
    }

    // `SET ROLE`/`RESET ROLE` rather than a transaction: attestation must be callable from inside a
    // caller's open transaction, and an inner `BEGIN` there would be ignored while the inner
    // `COMMIT` would commit the caller's work.
    client
        .batch_execute(&format!("SET ROLE {CELL_OWNER_ROLE};"))
        .await
        .map_err(CellSchemaError::postgres)?;
    let read = client.query(SCHEMA_STATE_SQL, &[]).await;
    client
        .batch_execute("RESET ROLE;")
        .await
        .map_err(CellSchemaError::postgres)?;
    let rows = read.map_err(CellSchemaError::postgres)?;
    if rows.len() > 1 {
        return Err(CellSchemaError::InvalidResponse("schema state cardinality"));
    }
    let Some(row) = rows.first() else {
        // No singleton row at all: the retention layer's own tuple is absent, which for a schema
        // that exists is a partial install, never a valid state.
        return Err(CellSchemaError::PartialLayerIdentity(
            CellSchemaLayerId::Retention,
        ));
    };

    let mut identities = [
        (CellSchemaLayerId::Retention, LayerIdentity::Absent),
        (CellSchemaLayerId::Authority, LayerIdentity::Absent),
        (CellSchemaLayerId::PutReservation, LayerIdentity::Absent),
    ];
    for (index, layer) in CELL_SCHEMA_LAYERS.iter().enumerate() {
        identities[index] = (layer.id, read_layer_identity(row, index * 4, layer)?);
    }
    Ok(identities)
}

fn read_layer_identity(
    row: &Row,
    offset: usize,
    layer: &CellSchemaLayer,
) -> Result<LayerIdentity, CellSchemaError> {
    let revision: Option<String> = row
        .try_get(offset)
        .map_err(|_| CellSchemaError::InvalidResponse("layer schema revision"))?;
    let digest: Option<String> = row
        .try_get(offset + 1)
        .map_err(|_| CellSchemaError::InvalidResponse("layer migration digest"))?;
    let install_revision: Option<String> = row
        .try_get(offset + 2)
        .map_err(|_| CellSchemaError::InvalidResponse("layer install revision"))?;
    let installed_at: Option<i64> = row
        .try_get(offset + 3)
        .map_err(|_| CellSchemaError::InvalidResponse("layer install time"))?;

    let present = usize::from(revision.is_some())
        + usize::from(digest.is_some())
        + usize::from(install_revision.is_some())
        + usize::from(installed_at.is_some());
    match present {
        0 => return Ok(LayerIdentity::Absent),
        4 => {}
        _ => return Err(CellSchemaError::PartialLayerIdentity(layer.id)),
    }

    let (Some(revision), Some(digest), Some(install_revision), Some(installed_at)) =
        (revision, digest, install_revision, installed_at)
    else {
        return Err(CellSchemaError::PartialLayerIdentity(layer.id));
    };
    if revision != layer.schema_revision || digest != layer.migration_blake3_hex {
        return Err(CellSchemaError::LayerIdentityDrift(layer.id));
    }
    let Ok(install_revision) = install_revision.parse::<u64>() else {
        return Err(CellSchemaError::LayerIdentityDrift(layer.id));
    };
    if install_revision == 0 || installed_at < 0 {
        return Err(CellSchemaError::LayerIdentityDrift(layer.id));
    }
    Ok(LayerIdentity::Valid {
        install_revision,
        installed_at_unix_ms: installed_at,
    })
}

async fn read_catalog_manifest(
    client: &Client,
) -> Result<([[u8; 32]; 12], [u8; 32]), CellSchemaError> {
    let row = client
        .query_one(CELL_CATALOG_MANIFEST_SQL, &[])
        .await
        .map_err(CellSchemaError::postgres)?;
    let mut sections = [[0u8; 32]; 12];
    let mut whole = blake3::Hasher::new();
    for (index, name) in CELL_CATALOG_MANIFEST_SECTIONS.iter().enumerate() {
        let text: String = row
            .try_get(index)
            .map_err(|_| CellSchemaError::InvalidResponse("catalog manifest section"))?;
        sections[index] = *blake3::hash(text.as_bytes()).as_bytes();
        whole.update(name.as_bytes());
        whole.update(b"\n");
        whole.update(text.as_bytes());
        whole.update(b"\n");
    }
    Ok((sections, *whole.finalize().as_bytes()))
}

/// The distinct replaced signatures, deduplicated by name **and** identity arguments.
///
/// `project_dispatch_reserved_put_v1` is replaced twice, by 0014 and again by 0016, at the same
/// signature. That is one signature to revoke, not two. A same-name overload at a different
/// signature would be a separate entry, which is the case name-only dedup would drop.
fn distinct_replaced_signatures() -> Vec<(&'static str, &'static str)> {
    let mut signatures: Vec<(&'static str, &'static str)> =
        Vec::with_capacity(CELL_REPLACED_FUNCTIONS.len());
    for replaced in CELL_REPLACED_FUNCTIONS {
        let signature = (replaced.name, replaced.argument_types);
        if !signatures.contains(&signature) {
            signatures.push(signature);
        }
    }
    signatures
}

async fn assert_no_residual_service_privilege(client: &Client) -> Result<usize, CellSchemaError> {
    let signatures = distinct_replaced_signatures();
    let rendered: Vec<String> = signatures
        .iter()
        .map(|(name, arguments)| format!("{CELL_AUTHORITY_SCHEMA}.{name}({arguments})"))
        .collect();
    let roles: Vec<&str> = CELL_SERVICE_ROLES.to_vec();
    let row = client
        .query_one(RESIDUAL_PRIVILEGE_SQL, &[&rendered, &roles])
        .await
        .map_err(CellSchemaError::postgres)?;
    let matched: i64 = row
        .try_get(0)
        .map_err(|_| CellSchemaError::InvalidResponse("matched signature count"))?;
    let residual: i64 = row
        .try_get(1)
        .map_err(|_| CellSchemaError::InvalidResponse("residual privilege count"))?;
    if usize::try_from(matched).unwrap_or(usize::MAX) != signatures.len() {
        // Every frozen signature must resolve to exactly one live function. If one does not, this
        // check silently inspected nothing, which is worse than reporting drift.
        return Err(CellSchemaError::InvalidResponse(
            "replaced signature does not resolve",
        ));
    }
    if residual != 0 {
        return Err(CellSchemaError::ResidualServicePrivilege);
    }
    Ok(signatures.len())
}

async fn assert_inert_state(client: &Client) -> Result<usize, CellSchemaError> {
    let inert: Vec<&str> = CELL_INERT_RETENTION_TABLES.to_vec();
    let deferred: Vec<&str> = CELL_DEFERRED_PROCEDURES.to_vec();
    let roles: Vec<&str> = CELL_SERVICE_ROLES.to_vec();

    let present: i64 = query_one_value_with(client, INERT_TABLE_SQL, &[&inert]).await?;
    let Ok(present) = usize::try_from(present) else {
        return Err(CellSchemaError::InvalidResponse("inert table count"));
    };
    if present != CELL_INERT_RETENTION_TABLES.len() {
        return Err(CellSchemaError::InertStateMismatch("inert tables"));
    }
    let installed: i64 = query_one_value_with(client, DEFERRED_PROCEDURE_SQL, &[&deferred]).await?;
    if installed != 0 {
        return Err(CellSchemaError::InertStateMismatch("deferred procedures"));
    }
    let writable: i64 =
        query_one_value_with(client, INERT_TABLE_WRITABLE_SQL, &[&roles, &inert]).await?;
    if writable != 0 {
        return Err(CellSchemaError::InertStateMismatch("inert table privilege"));
    }
    Ok(present)
}

async fn read_retention_state(client: &Client) -> Result<String, CellSchemaError> {
    // 0003's readback previously had no live caller anywhere (WP-114 CD-1 caveat N2). This is it.
    let layer = CELL_SCHEMA_LAYERS[0];
    let sql = format!(
        "SELECT ({CELL_AUTHORITY_SCHEMA}.{}('{}')).result_code",
        layer.read_state_function, layer.api_revision
    );
    let row = client
        .query_one(&sql, &[])
        .await
        .map_err(CellSchemaError::postgres)?;
    let code: String = row
        .try_get(0)
        .map_err(|_| CellSchemaError::InvalidResponse("retention read result"))?;
    if code != "READ" {
        return Err(CellSchemaError::InvalidResponse("retention read result"));
    }
    Ok(code)
}

async fn assert_retired_readbacks(
    client: &Client,
) -> Result<Vec<(&'static str, &'static str)>, CellSchemaError> {
    let mut retired = Vec::new();
    for layer in CELL_SCHEMA_LAYERS {
        if layer.read_state_retired_after.is_none() {
            continue;
        }
        let Some(expected_sqlstate) = layer.read_state_retired_sqlstate else {
            return Err(CellSchemaError::InvalidResponse("retirement sqlstate"));
        };
        let sql = format!(
            "SELECT ({CELL_AUTHORITY_SCHEMA}.{}('{}')).result_code",
            layer.read_state_function, layer.api_revision
        );
        // These probes are expected to fail, and a failed statement inside an open transaction
        // aborts it. Attestation must be callable from inside a caller's transaction, so each probe
        // runs under a savepoint when there is one to attach to. PostgreSQL itself answers whether
        // there is: `SAVEPOINT` outside a transaction block raises 25P01, which is the one
        // reliable signal available to a client here.
        let guarded = match client.batch_execute(TRANSACTION_PROBE_SAVEPOINT_SQL).await {
            Ok(()) => true,
            Err(error) => {
                let Some(database_error) = error.as_db_error() else {
                    return Err(CellSchemaError::Postgres);
                };
                if database_error.code().code() != "25P01" {
                    return Err(CellSchemaError::Postgres);
                }
                false
            }
        };

        let probe = client.query_one(&sql, &[]).await;
        if guarded {
            client
                .batch_execute(TRANSACTION_PROBE_RELEASE_SQL)
                .await
                .map_err(CellSchemaError::postgres)?;
        }

        match probe {
            Ok(_) => {
                return Err(CellSchemaError::RetiredEntrypointReachable(
                    layer.id.label(),
                ));
            }
            Err(error) => {
                let Some(database_error) = error.as_db_error() else {
                    return Err(CellSchemaError::Postgres);
                };
                // The exact code per layer, not either code for either layer. 42501 means the
                // EXECUTE privilege was revoked; 55000 means the entrypoint survives but its own
                // catalog manifest no longer matches. Accepting both everywhere would let one
                // retirement mode silently stand in for the other, and the records claim the two
                // apart.
                if database_error.code().code() != expected_sqlstate {
                    return Err(CellSchemaError::RetiredEntrypointUnexpectedFailure(
                        layer.id.label(),
                    ));
                }
                retired.push((layer.id.label(), expected_sqlstate));
            }
        }
    }
    Ok(retired)
}

async fn query_one_value<T>(client: &Client, sql: &str) -> Result<T, CellSchemaError>
where
    T: for<'a> tokio_postgres::types::FromSql<'a>,
{
    query_one_value_with(client, sql, &[]).await
}

async fn query_one_value_with<T>(
    client: &Client,
    sql: &str,
    parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<T, CellSchemaError>
where
    T: for<'a> tokio_postgres::types::FromSql<'a>,
{
    let row = client
        .query_one(sql, parameters)
        .await
        .map_err(CellSchemaError::postgres)?;
    row.try_get(0)
        .map_err(|_| CellSchemaError::InvalidResponse("scalar column"))
}

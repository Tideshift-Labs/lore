// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Live PostgreSQL 16 proof for WP-114 CD-1's out-of-band cell schema installer/attester.
//!
//! Every test here is `#[ignore]` and gated on its own `LORE_TEST_CELL_SCHEMA_*_PG_URL`, which must
//! name a **fresh disposable** database whose connection authenticates as
//! `object_dispatch_retention_migrator`.
//!
//! An `--ignored` run with the environment unset **panics in `connect` and reports FAIL**. It does
//! not exit early with zero tests run. That is deliberate and is the safer of the two: a missing
//! fixture is louder as a failure than as a silent skip. NOT RUN here means the filter matched no
//! test at all, which is what `tests/run-cell-schema-install-live.ps1` detects and reports as its
//! own third state. Do not restate the older tiers' "exits early with zero tests run" sentence for
//! this suite; it is not true here.

use lore_object_dispatch::cell_schema_install::CELL_INSTALL_SET;
use lore_object_dispatch::cell_schema_install::CELL_OWNER_ROLE;
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_LAYERS;
use lore_object_dispatch::cell_schema_install::CellInstallDisposition;
use lore_object_dispatch::cell_schema_install::CellSchemaError;
use lore_object_dispatch::cell_schema_install::CellSchemaLayerId;
use lore_object_dispatch::cell_schema_install::LayerIdentity;
use lore_object_dispatch::cell_schema_install::LayerInstallOutcome;
use lore_object_dispatch::cell_schema_install::apply_cell_install_plan;
use lore_object_dispatch::cell_schema_install::attest_cell_schema;
use lore_object_dispatch::cell_schema_install::install_cell_schema;
use lore_object_dispatch::cell_schema_install::measure_catalog_manifest;
use lore_object_dispatch::cell_schema_install::revoke_replaced_function_privileges;
use tokio_util::task::AbortOnDropHandle;

struct LiveCell {
    client: tokio_postgres::Client,
    _connection: AbortOnDropHandle<()>,
}

async fn connect(variable: &str) -> LiveCell {
    connect_as(
        variable,
        "a fresh disposable database",
        Some("object_dispatch_retention_migrator"),
    )
    .await
}

/// Open one connection and, when `expected_session_user` is given, pin who it authenticated as.
///
/// The migrator-role tests must fail loudly if the runner ever hands them a differently
/// authenticated URL, because every refusal they assert would then be trivially satisfied for the
/// wrong reason.
async fn connect_as(
    variable: &str,
    purpose: &str,
    expected_session_user: Option<&str>,
) -> LiveCell {
    let url = std::env::var(variable).unwrap_or_else(|_| panic!("{variable} must name {purpose}"));
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect disposable cell database");
    let handle = AbortOnDropHandle::new(lore_base::lore_spawn!("cell-schema-live", async move {
        let _ = connection.await;
    }));
    let session_user: String = client
        .query_one("SELECT session_user::text", &[])
        .await
        .expect("read session_user")
        .get(0);
    if let Some(expected) = expected_session_user {
        assert_eq!(
            session_user, expected,
            "{variable} must authenticate as {expected}; the installer refuses otherwise"
        );
    } else {
        assert_ne!(
            session_user, "object_dispatch_retention_migrator",
            "{variable} must NOT authenticate as the migrator, or it proves nothing"
        );
    }
    LiveCell {
        client,
        _connection: handle,
    }
}

/// Run one statement as the schema owner and leave the session as it was.
async fn as_owner(client: &tokio_postgres::Client, sql: &str) {
    client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE {CELL_OWNER_ROLE}; {sql} COMMIT;"
        ))
        .await
        .unwrap_or_else(|error| panic!("owner statement failed: {error}"));
}

async fn function_count(client: &tokio_postgres::Client) -> i64 {
    client
        .query_one(
            "SELECT count(*)::bigint FROM pg_catalog.pg_proc AS procedure
             JOIN pg_catalog.pg_namespace AS space ON space.oid = procedure.pronamespace
             WHERE space.nspname = 'object_store_retention'",
            &[],
        )
        .await
        .expect("count authority functions")
        .get(0)
}

fn assert_all_layers_valid(
    attestation: &lore_object_dispatch::cell_schema_install::CellAttestation,
) {
    for (index, (id, identity)) in attestation.layers.iter().enumerate() {
        assert_eq!(*id, CELL_SCHEMA_LAYERS[index].id);
        match identity {
            LayerIdentity::Valid {
                install_revision,
                installed_at_unix_ms,
            } => {
                assert_eq!(*install_revision, 1, "{} install revision", id.label());
                assert!(*installed_at_unix_ms > 0, "{} install time", id.label());
            }
            LayerIdentity::Absent => panic!("{} identity tuple is absent", id.label()),
        }
    }
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_installs_clean_and_attests() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_CLEAN_PG_URL").await;
    let report = install_cell_schema(&cell.client)
        .await
        .expect("clean install of the CR-033 D5 cell install set");

    assert_eq!(report.disposition, CellInstallDisposition::Created);
    for (id, outcome) in report.layer_outcomes {
        assert_eq!(
            outcome,
            LayerInstallOutcome::Created,
            "{} layer outcome",
            id.label()
        );
    }
    assert_all_layers_valid(&report.attestation);

    // 0003's readback had no live caller anywhere before this. This call is the first, and closes
    // the first half of WP-114 CD-1's caveat N2.
    assert_eq!(report.attestation.retention_read_state_result, "READ");

    // All three dispatch-layer readbacks are retired to the out-of-band migrator at full chain
    // depth, for two different reasons:
    // 0011 revokes the authority entrypoint (42501), and 0011's whole-schema catalog manifest no
    // longer matches once 0012-0017 add functions (55000). This is the executed proof of that
    // consequence; the offline suite can only observe the SQL that causes it. The exact code per
    // layer is asserted, not merely "both are retired": four records claim the two modes apart, so
    // accepting either code for either layer would leave that distinction unproven.
    assert_eq!(
        report.attestation.retired_readbacks,
        vec![
            ("authority", "42501"),
            ("put_reservation", "55000"),
            ("dispatcher_identity", "42501")
        ]
    );
    assert_eq!(report.attestation.replaced_functions_revoked, 4);
    assert_eq!(report.attestation.inert_tables_present, 4);

    // The install set is 16 artifacts; nothing outside it may have been applied. WP-114 CD-3 added
    // 0018 through 0020 (CR-033 D8's per-participant identity, provisioning/readback, and the
    // runtime-only monotonic registration fence).
    assert_eq!(CELL_INSTALL_SET.len(), 16);

    // An installed cell holds ZERO `pg_default_acl` rows, cluster-wide. Measured, not assumed, and
    // it is not what reading 0002 suggests: 0002:12-17 issues three `ALTER DEFAULT PRIVILEGES ...
    // REVOKE ... FROM PUBLIC` statements, and none of them leaves a catalog row. PostgreSQL stores
    // a default-ACL row only when the result differs from the built-in default, and revoking a
    // privilege PUBLIC does not hold by default is a no-op.
    //
    // Two consequences. The schema's function posture is carried by each migration's own explicit
    // `REVOKE ALL ON ALL FUNCTIONS ... FROM PUBLIC` after it creates functions, not by 0002's
    // default privileges. And because the correct baseline is empty, ANY default-ACL entry on an
    // installed cell is drift by definition, which is what the `default_acls` manifest section
    // pins. Assert the baseline here so a future change to it cannot pass as normal.
    let cluster_default_acls: i64 = cell
        .client
        .query_one(
            "SELECT count(*)::bigint FROM pg_catalog.pg_default_acl",
            &[],
        )
        .await
        .expect("count default ACLs")
        .get(0);
    assert_eq!(
        cluster_default_acls, 0,
        "an installed cell holds no default-privilege entries"
    );

    // A layer identity tuple is all-absent or all-valid. Nulling one layer's whole tuple, which the
    // table constraint does permit, must be refused as a partial install rather than read as "this
    // layer is simply not installed yet" on a chain that clearly has it.
    cell.client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE {CELL_OWNER_ROLE};
             UPDATE object_store_retention.object_dispatch_retention_schema_state
                SET put_reservation_schema_revision = NULL,
                    put_reservation_migration_blake3 = NULL,
                    put_reservation_install_revision = NULL,
                    put_reservation_installed_at_unix_ms = NULL;"
        ))
        .await
        .expect("doctor the put-reservation tuple");
    let doctored = attest_cell_schema(&cell.client).await;
    assert_eq!(
        doctored,
        Err(CellSchemaError::PartialLayerIdentity(
            CellSchemaLayerId::PutReservation
        ))
    );
    cell.client
        .batch_execute("ROLLBACK;")
        .await
        .expect("restore the doctored tuple");

    attest_cell_schema(&cell.client)
        .await
        .expect("attestation holds again after rollback");

    // The migrator-role boundary is documented for every entry point, not only install. Prove it
    // for attestation with a real second login on the same database. A superuser is the strongest
    // case: it can read every digest, so nothing here is fail-open, and refusing it anyway is what
    // makes the documented boundary a true statement rather than an aspiration.
    let outsider = connect_as(
        "LORE_TEST_CELL_SCHEMA_CLEAN_OUTSIDER_PG_URL",
        "the non-migrator login used to prove attest refuses",
        None,
    )
    .await;
    assert_eq!(
        attest_cell_schema(&outsider.client).await,
        Err(CellSchemaError::Precondition(
            "session_user is not migrator"
        ))
    );
    assert_eq!(
        measure_catalog_manifest(&outsider.client).await,
        Err(CellSchemaError::Precondition(
            "session_user is not migrator"
        ))
    );
    assert_eq!(
        revoke_replaced_function_privileges(&outsider.client).await,
        Err(CellSchemaError::Precondition(
            "session_user is not migrator"
        ))
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_install_is_idempotent() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_IDEMPOTENT_PG_URL").await;
    let first = install_cell_schema(&cell.client)
        .await
        .expect("first install");
    assert_eq!(first.disposition, CellInstallDisposition::Created);
    let functions_after_first = function_count(&cell.client).await;

    let second = install_cell_schema(&cell.client)
        .await
        .expect("second install must replay, never re-migrate");
    assert_eq!(second.disposition, CellInstallDisposition::Replayed);

    // Two of the four layer install entrypoints survive to full chain depth, and for different
    // reasons. Retention's is never retired. Dispatcher identity's survives because 0019 asserts
    // only the objects it names instead of manifesting the whole schema, so nothing later can
    // invalidate it. The two dispatch layers in between are attested rather than re-executed, and
    // say so.
    assert_eq!(
        second.layer_outcomes,
        [
            (CellSchemaLayerId::Retention, LayerInstallOutcome::Replayed),
            (
                CellSchemaLayerId::Authority,
                LayerInstallOutcome::AttestedOnly
            ),
            (
                CellSchemaLayerId::PutReservation,
                LayerInstallOutcome::AttestedOnly
            ),
            (
                CellSchemaLayerId::DispatcherIdentity,
                LayerInstallOutcome::Replayed
            ),
        ]
    );

    assert_eq!(
        second.attestation.catalog_blake3, first.attestation.catalog_blake3,
        "a replay must not move the live catalog"
    );
    assert_eq!(
        second.attestation.catalog_sections,
        first.attestation.catalog_sections
    );
    assert_eq!(
        second.attestation.layers, first.attestation.layers,
        "a replay must not re-mint an identity tuple"
    );
    assert_eq!(function_count(&cell.client).await, functions_after_first);
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_refuses_a_partial_install() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_PARTIAL_PG_URL").await;

    // Hand-build a truncated chain: 0002 and 0003's DDL and the retention layer install, and
    // nothing after it. This is exactly the shape an interrupted install leaves behind.
    for migration in CELL_INSTALL_SET.iter().take(2) {
        cell.client
            .batch_execute(migration.sql)
            .await
            .expect("apply truncated chain DDL");
    }
    let retention = CELL_SCHEMA_LAYERS[0];
    cell.client
        .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE;")
        .await
        .expect("open serializable install transaction");
    cell.client
        .query_one(
            &format!(
                "SELECT (object_store_retention.{}('{}', '{}', pg_catalog.decode('{}', 'hex'), 1)).result_code",
                retention.install_function,
                retention.api_revision,
                retention.schema_revision,
                retention.migration_blake3_hex
            ),
            &[],
        )
        .await
        .expect("install the retention layer only");
    cell.client
        .batch_execute("COMMIT;")
        .await
        .expect("commit retention install");

    let before = function_count(&cell.client).await;

    // Attestation must refuse: the authority layer's tuple is absent on a schema that exists.
    let attested = attest_cell_schema(&cell.client).await;
    assert_eq!(
        attested,
        Err(CellSchemaError::PartialLayerIdentity(
            CellSchemaLayerId::Authority
        ))
    );

    // And the installer must refuse to touch it rather than "finish" the chain. Forward migrations
    // are one-shot; resuming one blind is how a half-installed cell becomes an unrecoverable one.
    let refused = install_cell_schema(&cell.client).await;
    assert_eq!(
        refused,
        Err(CellSchemaError::RefusedUnattestedSchema(
            "partial layer identity"
        ))
    );
    assert_eq!(
        function_count(&cell.client).await,
        before,
        "a refused install must leave the schema exactly as it found it"
    );
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_refuses_a_drifted_catalog() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_DRIFT_PG_URL").await;
    install_cell_schema(&cell.client)
        .await
        .expect("clean install before drifting it");

    // Each case drifts one catalog surface inside a transaction, requires the exact section that
    // must notice, and rolls back. An installed-migration digest sees none of these.
    for (section, drift) in [
        (
            "functions",
            "CREATE OR REPLACE FUNCTION object_store_retention.local_canonical_u8_v1(value integer)
             RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
             SET search_path = pg_catalog AS 'SELECT pg_catalog.decode(''00'', ''hex'')';",
        ),
        (
            "columns",
            "ALTER TABLE object_store_retention.object_dispatch_spool_objects
             ADD COLUMN drift integer;",
        ),
        (
            // A storage-parameter change, not a DROP: dropping the index would also remove its
            // pg_class row and be caught one section earlier, in `relations`. This isolates the
            // index definition itself.
            "indexes",
            "ALTER INDEX object_store_retention.object_dispatch_spool_objects_expiry_idx
             SET (fillfactor = 50);",
        ),
        (
            "constraints",
            "ALTER DOMAIN object_store_retention.uint64 DROP CONSTRAINT uint64_check;",
        ),
        (
            "relations",
            "ALTER TABLE object_store_retention.object_dispatch_spool_objects
             FORCE ROW LEVEL SECURITY;",
        ),
        (
            "relation_acls",
            "GRANT SELECT (protocol_revision) ON object_store_retention.object_dispatch_spool_objects
             TO object_dispatch_retention_runtime;",
        ),
        (
            "function_acls",
            "GRANT EXECUTE ON FUNCTION object_store_retention.clock_unix_ms_v1()
             TO object_dispatch_retention_runtime;",
        ),
        (
            // The case that motivated the section. 0002 writes three default-privilege entries as
            // part of the security posture; before this section existed, this statement changed no
            // digest at all, attested clean, and made every future owner-created function
            // runtime-executable.
            "default_acls",
            "ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
             IN SCHEMA object_store_retention
             GRANT EXECUTE ON FUNCTIONS TO object_dispatch_retention_runtime;",
        ),
        (
            // The same widening written WITHOUT `IN SCHEMA`. It reaches functions created in
            // `object_store_retention` exactly the same way, but PostgreSQL stores it with
            // `defaclnamespace = 0`, so a section that inner-joins pg_namespace drops the row and
            // attests clean. That is the fail-open the first version of this section shipped with;
            // this case is why the section now treats a schema-less entry as in scope.
            "default_acls",
            "ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
             GRANT EXECUTE ON FUNCTIONS TO object_dispatch_retention_runtime;",
        ),
        (
            // A built-in trigger function, so this adds no row to pg_proc and cannot be caught one
            // section earlier by `functions`.
            "triggers",
            "CREATE TRIGGER drift_trigger
             BEFORE UPDATE ON object_store_retention.object_dispatch_spool_objects
             FOR EACH ROW EXECUTE FUNCTION pg_catalog.suppress_redundant_updates_trigger();",
        ),
        (
            // Creating a policy does not enable row security, so `relations` stays identical and
            // this isolates pg_policy.
            "rules_and_policies",
            "CREATE POLICY drift_policy ON object_store_retention.object_dispatch_spool_objects
             USING (true);",
        ),
        (
            "schema",
            "REVOKE USAGE ON SCHEMA object_store_retention
             FROM object_dispatch_retention_runtime;",
        ),
        (
            "types",
            "GRANT USAGE ON TYPE object_store_retention.uint64
             TO object_dispatch_retention_runtime;",
        ),
    ] {
        cell.client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL ROLE {CELL_OWNER_ROLE}; {drift}"
            ))
            .await
            .unwrap_or_else(|error| panic!("{section}: could not apply drift: {error}"));
        let verdict = attest_cell_schema(&cell.client).await;
        assert_eq!(
            verdict,
            Err(CellSchemaError::CatalogDrift(section)),
            "{section} drift must fail closed in its own section"
        );
        cell.client
            .batch_execute("ROLLBACK;")
            .await
            .unwrap_or_else(|error| panic!("{section}: could not roll back drift: {error}"));
    }

    attest_cell_schema(&cell.client)
        .await
        .expect("attestation holds once every drift is rolled back");

    // Both default-ACL cases above assert the same section name, so a regression that narrowed the
    // section back to schema-less entries only would still pass both. Pin the distinction itself:
    // the two forms must produce DIFFERENT manifest text, because one carries the schema name and
    // the other carries the empty string.
    let mut default_acl_texts = Vec::new();
    for statement in [
        "ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
         IN SCHEMA object_store_retention
         GRANT EXECUTE ON FUNCTIONS TO object_dispatch_retention_runtime;",
        "ALTER DEFAULT PRIVILEGES FOR ROLE object_dispatch_retention_owner
         GRANT EXECUTE ON FUNCTIONS TO object_dispatch_retention_runtime;",
    ] {
        cell.client
            .batch_execute(&format!(
                "BEGIN; SET LOCAL ROLE {CELL_OWNER_ROLE}; {statement}"
            ))
            .await
            .expect("apply a default-privilege widening");
        let text: String = cell
            .client
            .query_one(
                lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SQL,
                &[],
            )
            .await
            .expect("read the manifest")
            .get(9);
        assert_ne!(text, "[]", "the widening must be visible in default_acls");
        default_acl_texts.push(text);
        cell.client
            .batch_execute("ROLLBACK;")
            .await
            .expect("roll back the widening");
    }
    assert!(
        default_acl_texts[0].contains("object_store_retention"),
        "the IN SCHEMA form must record its schema"
    );
    assert_ne!(
        default_acl_texts[0], default_acl_texts[1],
        "the schema-scoped and schema-less forms must be distinguishable in the manifest"
    );

    // `RetiredEntrypointUnexpectedFailure` is defence in depth and is NOT reachable through
    // `attest_cell_schema` on a cell whose catalog still matches: every way to make a retired
    // entrypoint fail differently also moves the manifest, and the catalog comparison runs first.
    // Dropping the put-reservation readback proves exactly that ordering, which is the useful
    // assertion available here. The variant covers the residual case where the pinned digest is
    // stale but the entrypoint's behaviour changed; the offline redaction sweep constructs it, and
    // no live case can, so this records the limitation rather than faking coverage for it.
    cell.client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL ROLE {CELL_OWNER_ROLE};
             DROP FUNCTION object_store_retention.\
             object_store_dispatch_put_reservation_read_state_v1(text);"
        ))
        .await
        .expect("drop the retired readback");
    assert_eq!(
        attest_cell_schema(&cell.client).await,
        Err(CellSchemaError::CatalogDrift("functions")),
        "a dropped function is caught by the catalog comparison, before any retirement probe"
    );
    cell.client
        .batch_execute("ROLLBACK;")
        .await
        .expect("restore the dropped readback");

    attest_cell_schema(&cell.client)
        .await
        .expect("attestation holds after every probe is rolled back");

    // Attestation is documented as callable from inside a caller's open transaction. That is not
    // free: it probes two retired entrypoints with statements that are expected to fail, and a
    // failed statement aborts an open transaction. Prove the caller's transaction survives and can
    // still commit its own work afterwards.
    cell.client
        .batch_execute("BEGIN; CREATE TEMPORARY TABLE caller_work (marker integer);")
        .await
        .expect("open a caller transaction with work in it");
    attest_cell_schema(&cell.client)
        .await
        .expect("attestation inside a caller transaction");
    cell.client
        .batch_execute("INSERT INTO caller_work (marker) VALUES (1);")
        .await
        .expect("the caller transaction must not have been aborted by the attestation probes");
    let marker: i64 = cell
        .client
        .query_one("SELECT count(*)::bigint FROM caller_work", &[])
        .await
        .expect("read the caller's own work")
        .get(0);
    assert_eq!(marker, 1);
    cell.client
        .batch_execute("COMMIT;")
        .await
        .expect("the caller transaction must still be committable");
}

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_revokes_service_privileges_after_replacement() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_REVOKE_PG_URL").await;
    let installed = install_cell_schema(&cell.client)
        .await
        .expect("clean install");
    assert_eq!(installed.attestation.replaced_functions_revoked, 4);

    // `CREATE OR REPLACE FUNCTION` is not an ACL reset, so a privilege granted to a replaced
    // function's earlier definition would survive silently. Grant one for real and prove the
    // installer both notices it and removes it.
    as_owner(
        &cell.client,
        "GRANT EXECUTE ON FUNCTION object_store_retention.project_dispatch_reserved_put_v1(
           object_store_retention.object_dispatch_spool_objects, text
         ) TO object_dispatch_retention_runtime;",
    )
    .await;

    let widened = attest_cell_schema(&cell.client).await;
    assert_eq!(
        widened,
        Err(CellSchemaError::CatalogDrift("function_acls")),
        "a widened replaced-function ACL must fail closed"
    );

    let revoked = revoke_replaced_function_privileges(&cell.client)
        .await
        .expect("explicit post-replacement revoke");
    assert_eq!(revoked, 4, "four distinct replaced signatures");

    let restored = attest_cell_schema(&cell.client)
        .await
        .expect("attestation holds again after the explicit revoke");
    assert_eq!(
        restored.catalog_blake3, installed.attestation.catalog_blake3,
        "the revoke must restore the exact pinned ACL state, not merely a passing one"
    );
    assert_eq!(restored.replaced_functions_revoked, 4);
}

/// Not a gate: installs a fresh chain and prints the live manifest digests so the pinned constants
/// can be measured rather than guessed. Run through `run-cell-schema-install-live.ps1 -Measure`.
#[tokio::test]
#[ignore = "measurement helper; requires a fresh disposable PostgreSQL 16 database"]
async fn live_postgres_cell_schema_measure_catalog_manifest() {
    let cell = connect("LORE_TEST_CELL_SCHEMA_MEASURE_PG_URL").await;
    apply_cell_install_plan(&cell.client)
        .await
        .expect("install the chain without attesting it");
    let (sections, whole) = measure_catalog_manifest(&cell.client)
        .await
        .expect("measure the live catalog manifest");
    for (index, name) in lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SECTIONS
        .iter()
        .enumerate()
    {
        println!("MEASURED section {name} {}", hex(&sections[index]));
    }
    println!("MEASURED manifest {}", hex(&whole));
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

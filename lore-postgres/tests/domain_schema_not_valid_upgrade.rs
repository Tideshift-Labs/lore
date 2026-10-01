// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Live-Postgres cases for the domain and mediated-proof upgrade DDL on a
//! populated cell.
//!
//! `schema::SCHEMA` (receipts) and `MEDIATED_SCHEMA` (tombstones, completion
//! markers, proof namespaces) each add columns to a table that may already hold
//! rows. Their first spelling used inline column CHECKs and a plain
//! `ADD CONSTRAINT`, each of which validates every existing row under ACCESS
//! EXCLUSIVE inside `ensure_schema_online`'s 250 ms statement timeout. The
//! current spelling adds bare columns and named `NOT VALID` constraints.
//!
//! Timing is not the discriminator: a scan that overruns 250 ms needs a table
//! far larger than a test should seed. These cases discriminate on
//! `pg_constraint.convalidated`, which `PostgreSQL` sets exactly when it scanned
//! the rows, and a control step proves the old spelling sets it.
//!
//! Run via `pwsh -File lore-postgres/tests/run-domain-maintenance-live.ps1`,
//! which gives every case its own database.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> Result<PostgresDomainStore, String> {
    PostgresDomainStore::connect(url, 2, &TlsConfig::default()).await
}

async fn pg_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// A receipt backlog, the table that grows with every governed mutation.
const POPULATED_RECEIPT_ROWS: i64 = 50_000;

/// Rows in each mediated-proof table. Only a cell that booted the guarded
/// maintenance schema carries them, so they are fewer; nothing bounds them.
const POPULATED_MEDIATED_ROWS: i64 = 5_000;

const RECEIPTS: &str = "lore_domain_operation_receipts";
const TOMBSTONES: &str = "lore_domain_operation_reserve_release_tombstones";
const MARKERS: &str = "lore_domain_operation_tombstone_release_completion_markers";
const NAMESPACES: &str = "lore_domain_proof_namespaces";

/// The receipt upgrade constraints, by table and name.
const RECEIPT_CONSTRAINTS: [(&str, &str); 2] = [
    (
        RECEIPTS,
        "lore_domain_operation_receipts_client_attempt_id_check",
    ),
    (RECEIPTS, "lore_domain_receipt_direct_evidence"),
];

/// The mediated upgrade constraints, by table and name. The column bounds
/// carry the names `PostgreSQL` gives an inline column CHECK, cut to 63 bytes.
const MEDIATED_CONSTRAINTS: [(&str, &str); 17] = [
    (
        TOMBSTONES,
        "lore_domain_operation_reserve_rel_canonical_intent_digest_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserve_relea_phase1_request_digest_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserve__phase1_verification_digest_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserve_rel_terminal_receipt_sha256_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserv_release_proof_reservation_no_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserv_active_release_intent_revisi_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserve_active_release_intent_nonce_check",
    ),
    (TOMBSTONES, "lore_domain_tombstones_active_intent_shape"),
    (
        MARKERS,
        "lore_domain_operation_tombston_completion_request_binding_check",
    ),
    (
        MARKERS,
        "lore_domain_operation_tombstone_completion_request_digest_check",
    ),
    (
        MARKERS,
        "lore_domain_operation_tombst_completion_verification_dige_check",
    ),
    (
        MARKERS,
        "lore_domain_operation_tombstone_release_compl_byte_charge_check",
    ),
    (NAMESPACES, "lore_domain_proof_namespaces_org_uuid_check"),
    (
        NAMESPACES,
        "lore_domain_proof_namespaces_materialization_request_dige_check",
    ),
    (
        NAMESPACES,
        "lore_domain_proof_namespaces_materialization_verification_check",
    ),
    (
        NAMESPACES,
        "lore_domain_proof_namespaces_materialization_response_dig_check",
    ),
    (
        NAMESPACES,
        "lore_domain_proof_namespaces_namespace_revision_check",
    ),
];

/// The two tombstone column bounds the first upgrade spelling omitted, so a
/// cell that took it has neither. A fresh cell has both from `CREATE TABLE`;
/// the upgrade DDL adds them `NOT VALID` under the same `PostgreSQL` names.
const DRIFT_CONSTRAINTS: [(&str, &str); 2] = [
    (
        TOMBSTONES,
        "lore_domain_operation_reserv_platform_terminal_status_rev_check",
    ),
    (
        TOMBSTONES,
        "lore_domain_operation_reserv_release_proof_reservation_re_check",
    ),
];

/// Every constraint the mediated upgrade DDL guarantees.
fn all_mediated_constraints() -> Vec<(&'static str, &'static str)> {
    MEDIATED_CONSTRAINTS
        .iter()
        .chain(DRIFT_CONSTRAINTS.iter())
        .copied()
        .collect()
}

/// The receipt upgrade DDL `schema::SCHEMA` first shipped with: an inline
/// column CHECK and a plain `ADD CONSTRAINT`, both validating. Kept verbatim so
/// a case can build a cell that took the old spelling.
const VALIDATING_RECEIPT_DDL: &str = "\
ALTER TABLE lore_domain_operation_receipts
    ADD COLUMN IF NOT EXISTS client_attempt_id bytea
    CHECK (client_attempt_id IS NULL OR octet_length(client_attempt_id) = 16);
ALTER TABLE lore_domain_operation_receipts
    ADD COLUMN IF NOT EXISTS direct_authorization_id bytea,
    ADD COLUMN IF NOT EXISTS direct_authorization_revision numeric(20,0),
    ADD COLUMN IF NOT EXISTS direct_verification_nonce bytea,
    ADD COLUMN IF NOT EXISTS direct_bound_fields_digest bytea;
ALTER TABLE lore_domain_operation_receipts
    ADD CONSTRAINT lore_domain_receipt_direct_evidence CHECK (
        (direct_authorization_id IS NULL
         AND direct_authorization_revision IS NULL
         AND direct_verification_nonce IS NULL
         AND direct_bound_fields_digest IS NULL)
        OR
        (direct_authorization_id IS NOT NULL
         AND octet_length(direct_authorization_id) = 16
         AND direct_authorization_id = operation_id
         AND direct_authorization_revision IS NOT NULL
         AND direct_authorization_revision BETWEEN 1 AND 18446744073709551615
         AND direct_verification_nonce IS NOT NULL
         AND octet_length(direct_verification_nonce) = 32
         AND direct_bound_fields_digest IS NOT NULL
         AND octet_length(direct_bound_fields_digest) = 32
         AND authorization_id IS NULL
         AND authorization_revision IS NULL
         AND verification_nonce IS NULL
         AND bound_fields_digest IS NULL
         AND consumed_ticket_sha256 IS NULL)
    );";

/// The mediated upgrade DDL `MEDIATED_SCHEMA` first shipped with: inline
/// column CHECKs and a plain `ADD CONSTRAINT`, all validating. Kept verbatim.
const VALIDATING_MEDIATED_DDL: &str = "\
ALTER TABLE lore_domain_operation_reserve_release_tombstones
    ADD COLUMN IF NOT EXISTS canonical_intent_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(canonical_intent_digest) = 32),
    ADD COLUMN IF NOT EXISTS phase1_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(phase1_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS phase1_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(phase1_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS terminal_outcome smallint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS terminal_receipt_sha256 bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(terminal_receipt_sha256) = 32),
    ADD COLUMN IF NOT EXISTS platform_terminal_status_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS platform_acknowledged_at timestamptz NOT NULL DEFAULT '-infinity',
    ADD COLUMN IF NOT EXISTS release_proof_reservation_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS release_proof_reservation_nonce bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(release_proof_reservation_nonce) = 32),
    ADD COLUMN IF NOT EXISTS active_release_intent_revision bigint
        CHECK (active_release_intent_revision IS NULL OR active_release_intent_revision >= 0),
    ADD COLUMN IF NOT EXISTS active_release_intent_nonce bytea
        CHECK (active_release_intent_nonce IS NULL OR octet_length(active_release_intent_nonce) = 32);
ALTER TABLE lore_domain_operation_reserve_release_tombstones
    ADD CONSTRAINT lore_domain_tombstones_active_intent_shape CHECK (
        (active_release_intent_digest IS NULL
            AND active_release_intent_revision IS NULL
            AND active_release_intent_nonce IS NULL
            AND active_release_intent_ack_at IS NULL)
     OR (active_release_intent_digest IS NOT NULL
            AND active_release_intent_revision IS NOT NULL
            AND active_release_intent_nonce IS NOT NULL
            AND active_release_intent_ack_at IS NOT NULL)
    );
ALTER TABLE lore_domain_operation_tombstone_release_completion_markers
    ADD COLUMN IF NOT EXISTS completion_request_binding bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_request_binding) = 32),
    ADD COLUMN IF NOT EXISTS completion_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS completion_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(completion_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS byte_charge bigint NOT NULL DEFAULT 0 CHECK (byte_charge >= 0),
    ADD COLUMN IF NOT EXISTS final_prune_after timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE lore_domain_proof_namespaces
    ADD COLUMN IF NOT EXISTS org_uuid bytea NOT NULL
        DEFAULT decode(repeat('00', 16), 'hex') CHECK (octet_length(org_uuid) = 16),
    ADD COLUMN IF NOT EXISTS materialization_request_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_request_digest) = 32),
    ADD COLUMN IF NOT EXISTS materialization_verification_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_verification_digest) = 32),
    ADD COLUMN IF NOT EXISTS materialization_response_digest bytea NOT NULL
        DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(materialization_response_digest) = 32),
    ADD COLUMN IF NOT EXISTS namespace_revision bigint NOT NULL DEFAULT 1 CHECK (namespace_revision >= 1),
    ADD COLUMN IF NOT EXISTS materialized_global_counter_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS materialized_org_counter_revision bigint NOT NULL DEFAULT 0;";

/// Remove the receipt upgrade columns, which also drops their constraints and
/// the partial attempt-id index. What is left is a receipts table from before
/// WP-120 and P-029-3, as far as the upgrade DDL can tell.
async fn drop_receipt_upgrade_columns(client: &Client) {
    client
        .batch_execute(
            "ALTER TABLE lore_domain_operation_receipts \
                 DROP COLUMN client_attempt_id, \
                 DROP COLUMN direct_authorization_id, \
                 DROP COLUMN direct_authorization_revision, \
                 DROP COLUMN direct_verification_nonce, \
                 DROP COLUMN direct_bound_fields_digest",
        )
        .await
        .expect("remove the receipt upgrade columns");
}

/// Remove every column the mediated upgrade DDL adds, which also drops the
/// constraints that name them. What is left is a cell that booted the guarded
/// maintenance schema, as far as that DDL can tell.
async fn drop_mediated_upgrade_columns(client: &Client) {
    client
        .batch_execute(
            "ALTER TABLE lore_domain_operation_reserve_release_tombstones \
                 DROP COLUMN canonical_intent_digest, \
                 DROP COLUMN phase1_request_digest, \
                 DROP COLUMN phase1_verification_digest, \
                 DROP COLUMN terminal_outcome, \
                 DROP COLUMN terminal_receipt_sha256, \
                 DROP COLUMN platform_terminal_status_revision, \
                 DROP COLUMN platform_acknowledged_at, \
                 DROP COLUMN release_proof_reservation_revision, \
                 DROP COLUMN release_proof_reservation_nonce, \
                 DROP COLUMN active_release_intent_revision, \
                 DROP COLUMN active_release_intent_nonce; \
             ALTER TABLE lore_domain_operation_tombstone_release_completion_markers \
                 DROP COLUMN completion_request_binding, \
                 DROP COLUMN completion_request_digest, \
                 DROP COLUMN completion_verification_digest, \
                 DROP COLUMN byte_charge, \
                 DROP COLUMN final_prune_after; \
             ALTER TABLE lore_domain_proof_namespaces \
                 DROP COLUMN org_uuid, \
                 DROP COLUMN materialization_request_digest, \
                 DROP COLUMN materialization_verification_digest, \
                 DROP COLUMN materialization_response_digest, \
                 DROP COLUMN namespace_revision, \
                 DROP COLUMN materialized_global_counter_revision, \
                 DROP COLUMN materialized_org_counter_revision",
        )
        .await
        .expect("remove the mediated upgrade columns");
}

/// `(table, conname, convalidated, definition)` for each named constraint that
/// exists, in `names` order. A name that occurs twice appears twice.
async fn named_checks(
    client: &impl tokio_postgres::GenericClient,
    names: &[(&str, &str)],
) -> Vec<(String, String, bool, String)> {
    let mut found = Vec::new();
    for (table, name) in names {
        for row in client
            .query(
                "SELECT conrelid::regclass::text AS relation, conname, convalidated, \
                        pg_get_constraintdef(oid) AS definition \
                   FROM pg_constraint \
                  WHERE conrelid = to_regclass($1) AND conname = $2 AND contype = 'c'",
                &[table, name],
            )
            .await
            .expect("read named constraints")
        {
            found.push((
                row.get("relation"),
                row.get("conname"),
                row.get("convalidated"),
                row.get("definition"),
            ));
        }
    }
    found
}

/// Every CHECK on `tables`, as `(table, conname, convalidated, definition)`.
async fn all_checks(client: &Client, tables: &[&str]) -> Vec<(String, String, bool, String)> {
    let tables: Vec<String> = tables.iter().map(|t| (*t).to_owned()).collect();
    client
        .query(
            "SELECT conrelid::regclass::text AS relation, conname, convalidated, \
                    pg_get_constraintdef(oid) AS definition \
               FROM pg_constraint \
              WHERE conrelid::regclass::text = ANY($1) AND contype = 'c' \
              ORDER BY 1, 2",
            &[&tables],
        )
        .await
        .expect("read table constraints")
        .iter()
        .map(|row| {
            (
                row.get("relation"),
                row.get("conname"),
                row.get("convalidated"),
                row.get("definition"),
            )
        })
        .collect()
}

/// Assert that `names` are present exactly once each, all `NOT VALID`.
async fn assert_named_not_valid(client: &Client, names: &[(&str, &str)], context: &str) {
    let found: Vec<(String, String, bool)> = named_checks(client, names)
        .await
        .into_iter()
        .map(|(relation, name, validated, _)| (relation, name, validated))
        .collect();
    let expected: Vec<(String, String, bool)> = names
        .iter()
        .map(|(table, name)| ((*table).to_owned(), (*name).to_owned(), false))
        .collect();
    assert_eq!(found, expected, "{context}");
}

/// Run `update` and require `PostgreSQL` to refuse it on exactly `constraint`.
async fn assert_refused_by(client: &Client, table: &str, assignment: &str, constraint: &str) {
    let update =
        format!("UPDATE {table} SET {assignment} WHERE ctid = (SELECT ctid FROM {table} LIMIT 1)");
    let refused = client.execute(&update, &[]).await;
    let db_error = refused.as_ref().err().and_then(|error| error.as_db_error());
    assert_eq!(
        db_error.map(|error| (error.code().clone(), error.constraint().map(str::to_owned))),
        Some((SqlState::CHECK_VIOLATION, Some(constraint.to_owned()))),
        "{table}: `{assignment}` must be refused by {constraint}: {refused:?}"
    );
}

async fn seed_receipts(client: &Client) {
    client
        .execute(
            "INSERT INTO lore_domain_operation_receipts \
                 (verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
                  method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                  state, outcome, uuid_timestamp, prepared_at, hard_expires_at, committed_at, \
                  full_result_expires_at, compact_expires_at) \
             SELECT 'issuer', 'subject', '\\x01'::bytea, \
                    decode(lpad(to_hex(g), 32, '0'), 'hex'), \
                    'lore.domain.v1.test/Populated', '\\x02'::bytea, 1, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    1, 0, clock_timestamp(), clock_timestamp(), clock_timestamp(), \
                    clock_timestamp(), clock_timestamp(), clock_timestamp() \
               FROM generate_series(1, $1::bigint) AS g",
            &[&POPULATED_RECEIPT_ROWS],
        )
        .await
        .expect("seed the receipt backlog");
    client
        .batch_execute("ANALYZE lore_domain_operation_receipts")
        .await
        .expect("analyze receipts");
}

async fn seed_mediated(client: &Client) {
    client
        .execute(
            "INSERT INTO lore_domain_operation_reserve_release_tombstones \
                 (verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
                  method, scope, fingerprint_version, fingerprint, authorization_id, \
                  authorization_revision, claim_id, claim_revision, reserve_charge_revision, \
                  reserve_charge_nonce, tombstone_reservation_revision, \
                  tombstone_reservation_nonce, terminal_ack_digest, receipt_prune_digest, \
                  fence_prune_digest, phase1_response, created_at, compact_after, \
                  final_prune_after, tombstone_digest) \
             SELECT 'issuer', 'subject', '\\x01'::bytea, \
                    decode(lpad(to_hex(g), 32, '0'), 'hex'), \
                    'lore.domain.v1.test/Populated', '\\x02'::bytea, 1, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 32, '0'), 'hex'), 0, '\\x03'::bytea, 0, 0, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), 0, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), '\\x04'::bytea, \
                    clock_timestamp(), clock_timestamp() + interval '1 day', \
                    clock_timestamp() + interval '2 days', \
                    decode(lpad(to_hex(g), 64, '0'), 'hex') \
               FROM generate_series(1, $1::bigint) AS g",
            &[&POPULATED_MEDIATED_ROWS],
        )
        .await
        .expect("seed the tombstones");
    client
        .execute(
            "INSERT INTO lore_domain_operation_tombstone_release_completion_markers \
                 (verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
                  namespace_epoch, sequence, tombstone_digest, release_intent_digest, \
                  final_prune_digest, marker_reservation_revision, marker_reservation_nonce, \
                  marker_digest, created_at, retain_until) \
             SELECT 'issuer', 'subject', '\\x01'::bytea, \
                    decode(lpad(to_hex(g), 32, '0'), 'hex'), \
                    decode(repeat('05', 16), 'hex'), g, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), 0, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), \
                    clock_timestamp(), clock_timestamp() + interval '1 day' \
               FROM generate_series(1, $1::bigint) AS g",
            &[&POPULATED_MEDIATED_ROWS],
        )
        .await
        .expect("seed the completion markers");
    client
        .execute(
            "INSERT INTO lore_domain_proof_namespaces \
                 (verified_issuer, authenticated_subject, tenant_scope_key, epoch, \
                  protocol_revision, quota_revision, marker_interval_schema_revision, \
                  claim_revision, claim_nonce, next_sequence, high_water, \
                  retained_marker_count, outstanding_proof_claims, fragment_count, state, \
                  created_at, updated_at) \
             SELECT 'issuer', 'subject', decode(lpad(to_hex(g), 32, '0'), 'hex'), \
                    decode(repeat('06', 16), 'hex'), 1, 1, 3, 0, \
                    decode(lpad(to_hex(g), 64, '0'), 'hex'), 1, 0, 0, 0, 0, 0, \
                    clock_timestamp(), clock_timestamp() \
               FROM generate_series(1, $1::bigint) AS g",
            &[&POPULATED_MEDIATED_ROWS],
        )
        .await
        .expect("seed the proof namespaces");
    client
        .batch_execute(&format!(
            "ANALYZE {TOMBSTONES}; ANALYZE {MARKERS}; ANALYZE {NAMESPACES}"
        ))
        .await
        .expect("analyze mediated tables");
}

/// The receipt upgrade DDL on a populated pre-WP-120 receipts table, through
/// the real boot path and its 250 ms / 100 ms timeouts. The first spelling
/// scanned every receipt under ACCESS EXCLUSIVE. The named `NOT VALID`
/// constraints skip that scan, still refuse a bad write, and a restart is a
/// no-op.
///
/// Such a cell also lacks the partial attempt-id index, and online bootstrap
/// never builds a missing index on a populated table. So the first boot applies
/// the column and constraint steps, which commit one by one, and then refuses
/// at the index. The operator builds it `CONCURRENTLY` out of band, the
/// procedure the refusal names, and the next boots succeed.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn receipt_upgrade_ddl_boots_on_a_populated_receipts_table_without_scanning() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    connect_domain_store(&url).await.expect("fresh boot");
    let mut raw = pg_client(&url).await;

    drop_receipt_upgrade_columns(&raw).await;
    seed_receipts(&raw).await;

    // Control: the first spelling produces VALIDATED constraints, PostgreSQL's
    // record that it scanned every row. Rolled back, so the boot path still
    // sees a pre-upgrade table.
    let tx = raw.transaction().await.expect("begin control");
    tx.batch_execute(VALIDATING_RECEIPT_DDL)
        .await
        .expect("control: the validating spelling");
    let control = named_checks(&tx, &RECEIPT_CONSTRAINTS).await;
    assert_eq!(control.len(), 2, "control makes both constraints");
    assert!(
        control.iter().all(|(_, _, validated, _)| *validated),
        "control: the old spelling validates, i.e. scans: {control:?}"
    );
    tx.rollback().await.expect("roll the control back");

    let started = std::time::Instant::now();
    let refusal = match connect_domain_store(&url).await {
        Ok(_) => panic!("a populated table lacks the attempt-id index, so boot must refuse"),
        Err(error) => error,
    };
    eprintln!(
        "first boot over {POPULATED_RECEIPT_ROWS} receipts reached the index step in {:?}",
        started.elapsed()
    );
    assert!(
        refusal.contains("out-of-band concurrent index build"),
        "boot must pass every column and constraint step and stop at the index: {refusal}"
    );
    assert_named_not_valid(
        &raw,
        &RECEIPT_CONSTRAINTS,
        "the committed steps before the index left both constraints NOT VALID",
    )
    .await;

    raw.batch_execute(
        "CREATE INDEX CONCURRENTLY lore_domain_operation_receipts_client_attempt \
             ON lore_domain_operation_receipts \
                (verified_issuer, authenticated_subject, client_attempt_id) \
             WHERE client_attempt_id IS NOT NULL",
    )
    .await
    .expect("out-of-band concurrent index build");

    // Boot, then restart.
    connect_domain_store(&url)
        .await
        .expect("boot after the index build");
    connect_domain_store(&url).await.expect("restart");

    assert_named_not_valid(
        &raw,
        &RECEIPT_CONSTRAINTS,
        "exactly the two named NOT VALID receipt constraints, once each after a restart",
    )
    .await;

    assert_refused_by(
        &raw,
        RECEIPTS,
        "client_attempt_id = '\\x00'::bytea",
        "lore_domain_operation_receipts_client_attempt_id_check",
    )
    .await;
    assert_refused_by(
        &raw,
        RECEIPTS,
        "direct_authorization_id = operation_id",
        "lore_domain_receipt_direct_evidence",
    )
    .await;
}

/// A cell that already took the validating receipt DDL keeps exactly the
/// constraints it has: the catalog guards find them by name and add nothing.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn receipt_upgrade_ddl_leaves_an_already_migrated_cell_unchanged() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    connect_domain_store(&url).await.expect("fresh boot");
    let raw = pg_client(&url).await;

    drop_receipt_upgrade_columns(&raw).await;
    raw.batch_execute(VALIDATING_RECEIPT_DDL)
        .await
        .expect("migrate with the validating spelling");
    let before = all_checks(&raw, &[RECEIPTS]).await;
    let upgraded = named_checks(&raw, &RECEIPT_CONSTRAINTS).await;
    assert_eq!(upgraded.len(), 2, "the old spelling makes both constraints");
    assert!(
        upgraded.iter().all(|(_, _, validated, _)| *validated),
        "the old spelling validates both: {upgraded:?}"
    );

    connect_domain_store(&url).await.expect("boot");
    connect_domain_store(&url).await.expect("restart");
    assert_eq!(
        all_checks(&raw, &[RECEIPTS]).await,
        before,
        "the boot path must leave an already-migrated cell's receipt constraints as they are"
    );
}

/// The mediated upgrade DDL on populated tombstone, completion-marker, and
/// proof-namespace tables, through the real boot path. The first spelling
/// scanned all three under ACCESS EXCLUSIVE. The nineteen named `NOT VALID`
/// constraints (the first spelling's seventeen plus the two revision bounds it
/// omitted) skip that scan, each still refuses its own bad write, and a
/// restart is a no-op.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn mediated_upgrade_ddl_boots_on_populated_tables_without_scanning() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    connect_domain_store(&url).await.expect("fresh boot");
    let mut raw = pg_client(&url).await;

    drop_mediated_upgrade_columns(&raw).await;
    seed_mediated(&raw).await;

    let tx = raw.transaction().await.expect("begin control");
    tx.batch_execute(VALIDATING_MEDIATED_DDL)
        .await
        .expect("control: the validating spelling");
    let control = named_checks(&tx, &MEDIATED_CONSTRAINTS).await;
    assert_eq!(
        control.len(),
        MEDIATED_CONSTRAINTS.len(),
        "control makes every constraint under the expected name: {control:?}"
    );
    assert!(
        control.iter().all(|(_, _, validated, _)| *validated),
        "control: the old spelling validates, i.e. scans: {control:?}"
    );
    tx.rollback().await.expect("roll the control back");

    let started = std::time::Instant::now();
    connect_domain_store(&url).await.expect("boot");
    eprintln!(
        "boot over {POPULATED_MEDIATED_ROWS} rows per mediated table applied the upgrade DDL in {:?}",
        started.elapsed()
    );
    connect_domain_store(&url).await.expect("restart");

    assert_named_not_valid(
        &raw,
        &all_mediated_constraints(),
        "exactly the nineteen named NOT VALID mediated constraints, once each after a restart",
    )
    .await;

    let digest = "decode(repeat('11', 32), 'hex')";
    let nonce = "decode(repeat('22', 32), 'hex')";
    let refusals: Vec<(&str, String, &str)> = vec![
        (
            TOMBSTONES,
            "canonical_intent_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[0].1,
        ),
        (
            TOMBSTONES,
            "phase1_request_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[1].1,
        ),
        (
            TOMBSTONES,
            "phase1_verification_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[2].1,
        ),
        (
            TOMBSTONES,
            "terminal_receipt_sha256 = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[3].1,
        ),
        (
            TOMBSTONES,
            "release_proof_reservation_nonce = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[4].1,
        ),
        (
            TOMBSTONES,
            format!(
                "active_release_intent_digest = {digest}, active_release_intent_revision = -1, \
                 active_release_intent_nonce = {nonce}, \
                 active_release_intent_ack_at = clock_timestamp()"
            ),
            MEDIATED_CONSTRAINTS[5].1,
        ),
        (
            TOMBSTONES,
            format!(
                "active_release_intent_digest = {digest}, active_release_intent_revision = 0, \
                 active_release_intent_nonce = '\\x00'::bytea, \
                 active_release_intent_ack_at = clock_timestamp()"
            ),
            MEDIATED_CONSTRAINTS[6].1,
        ),
        (
            TOMBSTONES,
            format!("active_release_intent_nonce = {nonce}"),
            MEDIATED_CONSTRAINTS[7].1,
        ),
        (
            MARKERS,
            "completion_request_binding = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[8].1,
        ),
        (
            MARKERS,
            "completion_request_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[9].1,
        ),
        (
            MARKERS,
            "completion_verification_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[10].1,
        ),
        (
            MARKERS,
            "byte_charge = -1".to_owned(),
            MEDIATED_CONSTRAINTS[11].1,
        ),
        (
            NAMESPACES,
            "org_uuid = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[12].1,
        ),
        (
            NAMESPACES,
            "materialization_request_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[13].1,
        ),
        (
            NAMESPACES,
            "materialization_verification_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[14].1,
        ),
        (
            NAMESPACES,
            "materialization_response_digest = '\\x00'::bytea".to_owned(),
            MEDIATED_CONSTRAINTS[15].1,
        ),
        (
            NAMESPACES,
            "namespace_revision = 0".to_owned(),
            MEDIATED_CONSTRAINTS[16].1,
        ),
    ];
    assert_eq!(refusals.len(), MEDIATED_CONSTRAINTS.len());
    for (table, assignment, constraint) in &refusals {
        assert_refused_by(&raw, table, assignment, constraint).await;
    }
    assert_refused_by(
        &raw,
        TOMBSTONES,
        "platform_terminal_status_revision = -1",
        DRIFT_CONSTRAINTS[0].1,
    )
    .await;
    assert_refused_by(
        &raw,
        TOMBSTONES,
        "release_proof_reservation_revision = -1",
        DRIFT_CONSTRAINTS[1].1,
    )
    .await;
}

/// `(relation, conname)` of every NOT VALID CHECK or foreign key in the
/// connection's schemas, sorted.
async fn not_valid(client: &Client) -> Vec<(String, String)> {
    client
        .query(
            "SELECT c.conrelid::regclass::text AS relation, c.conname::text AS name \
               FROM pg_constraint AS c \
               JOIN pg_class AS r ON r.oid = c.conrelid \
               JOIN pg_namespace AS n ON n.oid = r.relnamespace \
              WHERE NOT c.convalidated AND c.contype IN ('c', 'f') \
                AND n.nspname = ANY(current_schemas(false)) \
              ORDER BY r.relname, c.conname",
            &[],
        )
        .await
        .expect("read NOT VALID constraints")
        .iter()
        .map(|row| (row.get("relation"), row.get("name")))
        .collect()
}

/// `loreserver schema validate-constraints`' store half on an upgraded,
/// populated cell. Every `NOT VALID` constraint on a `lore_` table is validated
/// once; a constraint an old row breaks is reported `violated` and left
/// `NOT VALID`; a held table lock is reported `lock_timeout`; another
/// application's table is never touched; and a rerun retries only what is left.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn validate_constraints_proves_each_not_valid_constraint_once() {
    use std::time::Duration;

    use lore_postgres::domain::constraint_validation::ValidationOutcome;
    use lore_postgres::domain::constraint_validation::ValidationTimeouts;
    use lore_postgres::domain::constraint_validation::list_not_valid_constraints;
    use lore_postgres::domain::constraint_validation::validate_not_valid_constraints;

    const PROBE: &str = "lore_zz_validation_probe";
    const PROBE_CHECK: &str = "lore_zz_validation_probe_v_check";
    const FOREIGN: &str = "other_app_validation_probe";
    let timeouts = ValidationTimeouts {
        lock_timeout: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(600),
    };

    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    connect_domain_store(&url).await.expect("fresh boot");
    let raw = pg_client(&url).await;
    drop_mediated_upgrade_columns(&raw).await;
    seed_mediated(&raw).await;
    connect_domain_store(&url).await.expect("upgrade boot");

    // An old row that breaks a constraint, and another application's table.
    raw.batch_execute(&format!(
        "CREATE TABLE {PROBE} (v integer); INSERT INTO {PROBE} VALUES (-1); \
         ALTER TABLE {PROBE} ADD CONSTRAINT {PROBE_CHECK} CHECK (v >= 0) NOT VALID; \
         CREATE TABLE {FOREIGN} (v integer); INSERT INTO {FOREIGN} VALUES (-1); \
         ALTER TABLE {FOREIGN} ADD CONSTRAINT {FOREIGN}_v_check CHECK (v >= 0) NOT VALID;"
    ))
    .await
    .expect("seed the probes");

    let before = not_valid(&raw).await;
    let foreign = (FOREIGN.to_owned(), format!("{FOREIGN}_v_check"));
    let probe = (PROBE.to_owned(), PROBE_CHECK.to_owned());
    for (table, name) in all_mediated_constraints() {
        assert!(
            before.contains(&(table.to_owned(), name.to_owned())),
            "the upgrade left {name} NOT VALID: {before:?}"
        );
    }
    let in_scope: Vec<(String, String)> = before
        .iter()
        .filter(|entry| **entry != foreign)
        .cloned()
        .collect();
    assert_eq!(
        list_not_valid_constraints(&raw).await.expect("list"),
        in_scope,
        "the work list is every NOT VALID lore_ constraint and nothing else"
    );

    // A held SHARE UPDATE EXCLUSIVE lock on the probe: its validation times
    // out waiting, and every other constraint still validates.
    let holder = pg_client(&url).await;
    holder
        .batch_execute(&format!(
            "BEGIN; LOCK TABLE {PROBE} IN SHARE UPDATE EXCLUSIVE MODE"
        ))
        .await
        .expect("hold the probe's lock");
    let first = validate_not_valid_constraints(
        &raw,
        ValidationTimeouts {
            lock_timeout: Duration::from_millis(200),
            ..timeouts
        },
    )
    .await
    .expect("first run");
    holder.batch_execute("ROLLBACK").await.expect("release");
    assert_eq!(first.len(), in_scope.len());
    for result in &first {
        let entry = (result.relation.clone(), result.constraint.clone());
        let expected = if entry == probe {
            ValidationOutcome::LockTimeout
        } else {
            ValidationOutcome::Validated
        };
        assert_eq!(result.outcome, expected, "{entry:?}");
    }
    assert_eq!(
        not_valid(&raw).await,
        vec![probe.clone(), foreign.clone()],
        "only the locked probe and the other application's constraint remain"
    );

    // The rerun retries only the probe, and its old row breaks it.
    let second = validate_not_valid_constraints(&raw, timeouts)
        .await
        .expect("second run");
    assert_eq!(second.len(), 1, "{second:?}");
    assert_eq!(second[0].constraint, PROBE_CHECK);
    assert!(
        matches!(&second[0].outcome, ValidationOutcome::Violated(_)),
        "{second:?}"
    );

    // Repaired, it validates; after that there is nothing left to do.
    raw.batch_execute(&format!("UPDATE {PROBE} SET v = 0"))
        .await
        .expect("repair the row");
    let third = validate_not_valid_constraints(&raw, timeouts)
        .await
        .expect("third run");
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].outcome, ValidationOutcome::Validated);
    assert!(
        validate_not_valid_constraints(&raw, timeouts)
            .await
            .expect("fourth run")
            .is_empty()
    );
    assert_eq!(not_valid(&raw).await, vec![foreign]);

    // The session timeouts were reset.
    let row = raw
        .query_one(
            "SELECT current_setting('lock_timeout') AS lock, \
                    current_setting('statement_timeout') AS statement",
            &[],
        )
        .await
        .expect("read timeouts");
    assert_eq!(
        (
            row.get::<_, String>("lock"),
            row.get::<_, String>("statement")
        ),
        ("0".to_owned(), "0".to_owned())
    );
}

/// A fresh cell and a cell that already took the validating mediated DDL each
/// keep exactly the constraints they have. The column bounds carry the names
/// `PostgreSQL` gives an inline column CHECK, so the catalog guards find the
/// validated originals and add no duplicate.
#[tokio::test]
#[ignore = "needs an owned disposable Postgres database; run via run-domain-maintenance-live.ps1"]
async fn mediated_upgrade_ddl_leaves_fresh_and_already_migrated_cells_unchanged() {
    let url = pg_url().expect("disposable runner must provide LORE_TEST_PG_URL");
    connect_domain_store(&url).await.expect("fresh boot");
    let raw = pg_client(&url).await;
    let tables = [TOMBSTONES, MARKERS, NAMESPACES];

    // A fresh cell: every name comes from a CREATE TABLE body, validated, once.
    let all = all_mediated_constraints();
    let fresh = named_checks(&raw, &all).await;
    assert_eq!(
        fresh.len(),
        all.len(),
        "a fresh cell carries every name exactly once: {fresh:?}"
    );
    assert!(
        fresh.iter().all(|(_, _, validated, _)| *validated),
        "a fresh cell's constraints come from CREATE TABLE and are validated: {fresh:?}"
    );

    drop_mediated_upgrade_columns(&raw).await;
    raw.batch_execute(VALIDATING_MEDIATED_DDL)
        .await
        .expect("migrate with the validating spelling");
    let before = all_checks(&raw, &tables).await;
    let upgraded = named_checks(&raw, &MEDIATED_CONSTRAINTS).await;
    assert_eq!(
        upgraded.len(),
        MEDIATED_CONSTRAINTS.len(),
        "the old spelling makes every constraint under the expected name: {upgraded:?}"
    );
    assert!(
        upgraded.iter().all(|(_, _, validated, _)| *validated),
        "the old spelling validates every constraint: {upgraded:?}"
    );

    assert!(
        named_checks(&raw, &DRIFT_CONSTRAINTS).await.is_empty(),
        "the old spelling omitted the two revision bounds"
    );

    connect_domain_store(&url).await.expect("boot");
    connect_domain_store(&url).await.expect("restart");
    // The only change is the two bounds the old spelling omitted, added once
    // each and NOT VALID. Every constraint it did make stays as it was.
    let after = all_checks(&raw, &tables).await;
    let drift: Vec<(String, String, bool, String)> = after
        .iter()
        .filter(|check| !before.contains(check))
        .cloned()
        .collect();
    assert_eq!(
        after.len(),
        before.len() + DRIFT_CONSTRAINTS.len(),
        "the boot path adds only the two omitted bounds: {drift:?}"
    );
    assert!(
        before.iter().all(|check| after.contains(check)),
        "the boot path must leave an already-migrated cell's mediated constraints as they are"
    );
    assert_eq!(
        drift
            .iter()
            .map(|(relation, name, validated, _)| (relation.as_str(), name.as_str(), *validated))
            .collect::<Vec<_>>(),
        DRIFT_CONSTRAINTS
            .iter()
            .map(|(table, name)| (*table, *name, false))
            .collect::<Vec<_>>(),
        "the two omitted bounds arrive NOT VALID under PostgreSQL's names"
    );
}

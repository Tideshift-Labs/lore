// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Explicit live proof for the source-dark retention maintenance client.
//!
//! Run through `tests/run-retention-client-live.ps1`. The runner owns a disposable PostgreSQL 16
//! database, installs the exact retention migrations, and supplies distinct admin and exact
//! `object_dispatch_retention_maintenance` mTLS identities.

#[path = "common/retention_fixture.rs"]
mod retention_fixture;
#[path = "common/retention_live_proxy.rs"]
mod retention_live_proxy;

use std::fs;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::RetentionMaintenanceClient;
use lore_object_dispatch::RetentionTlsConfig;
use lore_object_dispatch::RetentionTransferState;
use lore_object_dispatch::*;
use retention_fixture::ATTEMPT_ID;
use retention_fixture::REQUEST_ID;
use retention_live_proxy::ProxyTlsMaterial;
use retention_live_proxy::RetentionFaultProxy;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

struct LiveEnvironment {
    maintenance_url: String,
    admin_url: String,
    root_ca_pem: String,
    maintenance_certificate_pem: String,
    maintenance_private_key_pem: String,
    admin_certificate_pem: String,
    admin_private_key_pem: String,
    server_certificate_pem: String,
    server_private_key_pem: String,
}

impl LiveEnvironment {
    fn load() -> Self {
        Self {
            maintenance_url: required_env("LORE_TEST_RETENTION_PG_URL"),
            admin_url: required_env("LORE_TEST_RETENTION_ADMIN_PG_URL"),
            root_ca_pem: required_pem("LORE_TEST_RETENTION_ROOT_CA_PEM_PATH"),
            maintenance_certificate_pem: required_pem("LORE_TEST_RETENTION_CLIENT_CERT_PEM_PATH"),
            maintenance_private_key_pem: required_pem("LORE_TEST_RETENTION_CLIENT_KEY_PEM_PATH"),
            admin_certificate_pem: required_pem("LORE_TEST_RETENTION_ADMIN_CLIENT_CERT_PEM_PATH"),
            admin_private_key_pem: required_pem("LORE_TEST_RETENTION_ADMIN_CLIENT_KEY_PEM_PATH"),
            server_certificate_pem: required_pem("LORE_TEST_RETENTION_SERVER_CERT_PEM_PATH"),
            server_private_key_pem: required_pem("LORE_TEST_RETENTION_SERVER_KEY_PEM_PATH"),
        }
    }

    fn maintenance_config(&self, postgres_url: String) -> RetentionTlsConfig {
        RetentionTlsConfig {
            postgres_url,
            root_ca_pem: self.root_ca_pem.clone(),
            client_certificate_chain_pem: self.maintenance_certificate_pem.clone(),
            private_key_pem: self.maintenance_private_key_pem.clone(),
            connect_timeout: Duration::from_secs(3),
            statement_timeout: Duration::from_millis(250),
            lock_timeout: Duration::from_millis(250),
            max_retry_attempts: 3,
        }
    }

    fn proxy_tls(&self) -> ProxyTlsMaterial {
        ProxyTlsMaterial {
            root_ca_pem: self.root_ca_pem.clone(),
            maintenance_certificate_chain_pem: self.maintenance_certificate_pem.clone(),
            maintenance_private_key_pem: self.maintenance_private_key_pem.clone(),
            server_certificate_chain_pem: self.server_certificate_pem.clone(),
            server_private_key_pem: self.server_private_key_pem.clone(),
            expected_client_common_name: "object_dispatch_retention_maintenance".to_string(),
        }
    }
}

struct AdminSession {
    client: tokio_postgres::Client,
    _connection_task: AbortOnDropHandle<()>,
}

async fn connect_admin(environment: &LiveEnvironment) -> AdminSession {
    let postgres = environment
        .admin_url
        .parse::<tokio_postgres::Config>()
        .expect("valid admin PostgreSQL URL");
    let tls = client_tls(
        &environment.root_ca_pem,
        &environment.admin_certificate_pem,
        &environment.admin_private_key_pem,
    );
    let (client, connection) = postgres
        .connect(tls)
        .await
        .expect("connect disposable admin over mTLS");
    let task = AbortOnDropHandle::new(lore_base::lore_spawn!("retention-live-admin", async move {
        let _ = connection.await;
    }));
    client
        .query_one("SELECT pg_advisory_lock(834215917042121)", &[])
        .await
        .expect("acquire exclusive retention live-test database lease");
    AdminSession {
        client,
        _connection_task: task,
    }
}

fn client_tls(
    root_ca_pem: &str,
    certificate_pem: &str,
    private_key_pem: &str,
) -> MakeRustlsConnect {
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(root_ca_pem.as_bytes())) {
        roots
            .add(certificate.expect("valid root CA PEM"))
            .expect("usable root CA certificate");
    }
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificate_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("valid client certificate PEM");
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(private_key_pem.as_bytes()))
        .expect("valid client private key PEM")
        .expect("nonempty client private key PEM");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("supported client TLS versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .expect("client certificate matches its key");
    MakeRustlsConnect::new(config)
}

async fn reset_and_seed_full_record(
    admin: &tokio_postgres::Client,
    source_authority_blake3: &[u8; 32],
) {
    admin
        .batch_execute(
            "TRUNCATE object_store_retention.object_dispatch_compact_prune_receipts_v2,
                      object_store_retention.object_dispatch_compact_receipts,
                      object_store_retention.object_dispatch_full_record_ownership;
             DELETE FROM object_store_retention.object_dispatch_record_storage_counters
             WHERE scope_kind > 1;
             UPDATE object_store_retention.object_dispatch_record_storage_counters
             SET full_record_rows = 0, full_record_bytes = 0,
                 compact_rows = 0, compact_bytes = 0, counter_revision = 1
             WHERE scope_kind = 1;
             UPDATE object_store_retention.object_dispatch_retention_schema_state
             SET compact_sequence_high_water = 0, compact_sequence_revision = 1;
             UPDATE object_store_retention.object_dispatch_compact_prune_watermark
             SET pruned_through_compact_sequence = 0, watermark_revision = 1,
                 last_prune_fingerprint = NULL, last_compact_blake3 = NULL,
                 last_pruned_at_unix_ms = NULL, last_backup_revision = NULL,
                 last_backup_manifest_blake3 = NULL;",
        )
        .await
        .expect("reset disposable retention authority");
    let source_authority_hex = source_authority_blake3
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    admin
        .execute(
            "INSERT INTO object_store_retention.object_dispatch_full_record_ownership (
               logical_request_id, attempt_id, provider_boundary_id, authenticated_cell_id,
               authenticated_tenant_id, source_authority_blake3, full_record_rows,
               full_record_bytes, full_record_concurrency, ownership_revision,
               closure_committed_at_unix_ms, created_at_unix_ms
             ) VALUES (
               $1, $2, 'boundary-1', 'cell-1', 'tenant-1',
               decode($3::text, 'hex'), 1, 7000, 0, 1, 2, 1
             )
             ON CONFLICT (logical_request_id, attempt_id) DO NOTHING",
            &[
                &Uuid::parse_str(REQUEST_ID).expect("fixture logical request UUID"),
                &Uuid::parse_str(ATTEMPT_ID).expect("fixture attempt UUID"),
                &source_authority_hex,
            ],
        )
        .await
        .expect("seed one full-record ownership row");
    admin
        .batch_execute(
            "UPDATE object_store_retention.object_dispatch_record_storage_counters
               SET full_record_rows = 1, full_record_bytes = 7000,
                   compact_rows = 0, compact_bytes = 0, counter_revision = 1
             WHERE scope_kind = 1;
             INSERT INTO object_store_retention.object_dispatch_record_storage_counters (
               scope_kind, scope_id, full_record_rows, full_record_bytes,
               compact_rows, compact_bytes, counter_revision
             ) VALUES
               (2, 'cell-1', 1, 7000, 0, 0, 1),
               (3, 'tenant-1', 1, 7000, 0, 0, 1)
             ON CONFLICT (scope_kind, scope_id) DO NOTHING;",
        )
        .await
        .expect("seed exact global, cell, and tenant storage counters");
}

fn upstream_address(url: &str) -> (String, u16) {
    let config = url
        .parse::<tokio_postgres::Config>()
        .expect("valid maintenance PostgreSQL URL");
    let [tokio_postgres::config::Host::Tcp(host)] = config.get_hosts() else {
        panic!("maintenance URL has one TCP host")
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    (host.clone(), port)
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("required live-test environment missing: {name}"))
}

fn required_pem(name: &str) -> String {
    fs::read_to_string(required_env(name))
        .unwrap_or_else(|_| panic!("read required live-test PEM from {name}"))
}

fn applied_compact(
    plan: &ObjectStoreCompactReceiptDecision,
) -> (&CanonicalObjectStoreCompactReceipt, [u8; 32]) {
    let ObjectStoreCompactReceiptDecision::ApplyCompaction {
        expected_authority_blake3,
        compact,
        ..
    } = plan
    else {
        panic!("live compact plan must apply")
    };
    (compact, *expected_authority_blake3)
}

fn transfer_decision(
    snapshot: &RetentionTransferSnapshot,
    compact_plan: &ObjectStoreCompactReceiptDecision,
    policy: &ObjectStoreFullToCompactPolicy,
) -> ObjectStoreFullToCompactDecision {
    let full = snapshot.full_record.as_ref().expect("full record snapshot");
    let cell = snapshot
        .cell_counter
        .as_ref()
        .expect("cell counter snapshot");
    let tenant = snapshot
        .tenant_counter
        .as_ref()
        .expect("tenant counter snapshot");
    decide_object_store_full_to_compact(&ObjectStoreFullToCompactInput {
        compact_plan,
        full_ownership: &full.ownership,
        global_counter: &snapshot.global_counter,
        cell_counter: cell,
        tenant_counter: tenant,
        policy,
        lifecycle: &ObjectStoreFullToCompactLifecycle::FullOwned {
            source_authority_blake3: full.ownership.source_authority_blake3,
        },
    })
    .expect("live transfer decision")
}

#[derive(Clone, Copy)]
enum RetryFault {
    Serialization,
    Deadlock,
}

impl RetryFault {
    fn name(self) -> &'static str {
        match self {
            Self::Serialization => "serialization",
            Self::Deadlock => "deadlock",
        }
    }

    fn sqlstate(self) -> &'static str {
        match self {
            Self::Serialization => "40001",
            Self::Deadlock => "40P01",
        }
    }
}

async fn install_transfer_fault(admin: &tokio_postgres::Client, fault: RetryFault) {
    let name = fault.name();
    let sqlstate = fault.sqlstate();
    admin
        .batch_execute(&format!(
            "CREATE SEQUENCE retention_live_{name}_attempts;
             CREATE FUNCTION retention_live_{name}_fault() RETURNS trigger
             LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
             BEGIN
               IF nextval('public.retention_live_{name}_attempts') = 1 THEN
                 RAISE EXCEPTION 'RETENTION_LIVE_{name}' USING ERRCODE = '{sqlstate}';
               END IF;
               RETURN NEW;
             END
             $$;
             CREATE TRIGGER retention_live_{name}_fault
             BEFORE INSERT ON object_store_retention.object_dispatch_compact_receipts
             FOR EACH ROW EXECUTE FUNCTION retention_live_{name}_fault();"
        ))
        .await
        .expect("install disposable transfer retry fault");
}

async fn assert_and_remove_transfer_fault(admin: &tokio_postgres::Client, fault: RetryFault) {
    let name = fault.name();
    let row = admin
        .query_one(
            &format!("SELECT last_value FROM retention_live_{name}_attempts"),
            &[],
        )
        .await
        .expect("read nontransactional retry-attempt sequence");
    assert_eq!(
        row.get::<_, i64>(0),
        2,
        "mutation must attempt exactly twice"
    );
    admin
        .batch_execute(&format!(
            "DROP TRIGGER retention_live_{name}_fault
             ON object_store_retention.object_dispatch_compact_receipts;
             DROP FUNCTION retention_live_{name}_fault();
             DROP SEQUENCE retention_live_{name}_attempts;"
        ))
        .await
        .expect("remove disposable transfer retry fault");
}

async fn prove_transfer_retry(fault: RetryFault) {
    let environment = LiveEnvironment::load();
    let admin = connect_admin(&environment).await;
    let compact_plan = retention_fixture::compact_plan().await;
    let (_, source_authority_blake3) = applied_compact(&compact_plan);
    reset_and_seed_full_record(&admin.client, &source_authority_blake3).await;
    install_transfer_fault(&admin.client, fault).await;
    let client = RetentionMaintenanceClient::connect(
        &environment.maintenance_config(environment.maintenance_url.clone()),
    )
    .await
    .expect("exact maintenance mTLS connection");
    let logical_request_id = Uuid::parse_str(REQUEST_ID).expect("logical request UUID");
    let attempt_id = Uuid::parse_str(ATTEMPT_ID).expect("attempt UUID");
    let snapshot = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect("authoritative pre-transfer snapshot");
    let policy = retention_fixture::policy();
    let decision = transfer_decision(&snapshot, &compact_plan, &policy);
    let applied = client
        .apply_transfer(&snapshot, &compact_plan, &policy, &decision)
        .await
        .expect("retryable fault must end in one authoritative transfer");
    assert_eq!(applied.result_code, "APPLIED");
    assert_and_remove_transfer_fault(&admin.client, fault).await;
    let readback = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect("authoritative post-transfer snapshot");
    assert_eq!(readback.state, RetentionTransferState::CompactInstalled);
    assert_eq!(readback.compact_record, Some(applied.compact_record));
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL 16 retention mTLS fixture"]
async fn exact_maintenance_mtls_read_is_bounded_and_reconnects_after_response_stall() {
    let environment = LiveEnvironment::load();
    let admin = connect_admin(&environment).await;
    reset_and_seed_full_record(&admin.client, &[7; 32]).await;
    let (upstream_host, upstream_port) = upstream_address(&environment.maintenance_url);
    let proxy =
        RetentionFaultProxy::start(upstream_host, upstream_port, environment.proxy_tls()).await;
    let client = RetentionMaintenanceClient::connect(
        &environment.maintenance_config(proxy.postgres_url(&environment.maintenance_url)),
    )
    .await
    .expect("exact maintenance identity connects through the TLS fault proxy");
    let logical_request_id = Uuid::parse_str(REQUEST_ID).expect("logical request UUID");
    let attempt_id = Uuid::parse_str(ATTEMPT_ID).expect("attempt UUID");
    let before = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect("authoritative transfer read over mTLS");
    assert_eq!(before.state, RetentionTransferState::FullOwned);

    proxy.stall_next_response();
    let stalled = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect_err("an established-socket response stall must be bounded");
    assert_eq!(stalled, RetentionError::OperationTimeout);

    let after = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect("the same client must reconnect after its bounded timeout");
    assert_eq!(after, before);
    proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with an admin-installed 40001 trigger"]
async fn transfer_retries_one_serialization_abort_then_applies_once() {
    prove_transfer_retry(RetryFault::Serialization).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 with an admin-installed 40P01 trigger"]
async fn transfer_retries_one_deadlock_abort_then_applies_once() {
    prove_transfer_retry(RetryFault::Deadlock).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL 16 and the TLS lost-COMMIT proxy"]
async fn prune_lost_commit_response_adopts_exact_immutable_receipt_without_duplicate_mutation() {
    let environment = LiveEnvironment::load();
    let admin = connect_admin(&environment).await;
    let compact_plan = retention_fixture::compact_plan().await;
    let (compact, source_authority_blake3) = applied_compact(&compact_plan);
    reset_and_seed_full_record(&admin.client, &source_authority_blake3).await;
    let (upstream_host, upstream_port) = upstream_address(&environment.maintenance_url);
    let proxy =
        RetentionFaultProxy::start(upstream_host, upstream_port, environment.proxy_tls()).await;
    let client = RetentionMaintenanceClient::connect(
        &environment.maintenance_config(proxy.postgres_url(&environment.maintenance_url)),
    )
    .await
    .expect("exact maintenance identity connects through the TLS fault proxy");
    let logical_request_id = Uuid::parse_str(REQUEST_ID).expect("logical request UUID");
    let attempt_id = Uuid::parse_str(ATTEMPT_ID).expect("attempt UUID");
    let transfer_snapshot = client
        .read_transfer(logical_request_id, attempt_id)
        .await
        .expect("authoritative pre-transfer snapshot");
    let policy = retention_fixture::policy();
    let transfer = transfer_decision(&transfer_snapshot, &compact_plan, &policy);
    let transfer_result = client
        .apply_transfer(&transfer_snapshot, &compact_plan, &policy, &transfer)
        .await
        .expect("install compact receipt before prune");
    let prune_snapshot = client
        .read_prune(transfer_result.compact_record.compact_sequence)
        .await
        .expect("authoritative pre-prune snapshot");
    let backup = ObjectStoreCompactPruneBackupCoverage {
        backup_revision: "retention-live-backup-1".to_string(),
        backup_manifest_blake3: [19; 32],
        durable_covered_through_compact_sequence: transfer_result.compact_record.compact_sequence,
        restore_verified_through_compact_sequence: transfer_result.compact_record.compact_sequence,
        observed_at_unix_ms: prune_snapshot.database_now_unix_ms,
    };
    let prune_decision = decide_object_store_compact_prune(&ObjectStoreCompactPruneInput {
        candidate: ObjectStoreCompactPruneCandidate::CompactInstalled {
            compact_sequence: transfer_result.compact_record.compact_sequence,
            compact,
        },
        watermark: &prune_snapshot.watermark,
        backup_coverage: &backup,
        database_now_unix_ms: prune_snapshot.database_now_unix_ms,
        global_counter: &prune_snapshot.global_counter,
        cell_counter: prune_snapshot.cell_counter.as_ref().expect("cell counter"),
        tenant_counter: prune_snapshot
            .tenant_counter
            .as_ref()
            .expect("tenant counter"),
    })
    .expect("live prune decision");

    proxy.drop_next_commit_response();
    let adopted = client
        .apply_prune(&prune_snapshot, compact, &backup, &prune_decision)
        .await
        .expect("lost COMMIT response must adopt the immutable receipt after reconnect");
    assert!(
        proxy.wait_for_commit_fault(Duration::from_secs(1)).await,
        "lost-COMMIT result is evidence only if the exact framed fault fired"
    );
    let authoritative = client
        .read_prune(transfer_result.compact_record.compact_sequence)
        .await
        .expect("authoritative post-prune readback");
    assert_eq!(authoritative.state, RetentionPruneState::Pruned);
    assert_eq!(authoritative.prune_receipt.as_ref(), Some(&adopted));
    let replay = client
        .apply_prune(&prune_snapshot, compact, &backup, &prune_decision)
        .await
        .expect("exact prune replay");
    assert_eq!(replay, adopted);
    let row = admin
        .client
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_compact_prune_receipts_v2",
            &[],
        )
        .await
        .expect("count immutable prune receipts");
    assert_eq!(row.get::<_, i64>(0), 1);
    proxy.shutdown().await;
}

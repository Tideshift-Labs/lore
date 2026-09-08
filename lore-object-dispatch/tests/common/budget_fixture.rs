// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::io::Cursor;
use std::sync::Arc;

use lore_object_dispatch::cell_schema_install::install_cell_schema;
use tokio_postgres::Client;
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::task::AbortOnDropHandle;

pub struct BudgetFixture {
    pub admin: Client,
    pub base: String,
    pub pem: String,
    pub system_identifier: u64,
    pub database_oid: u32,
    _connection: AbortOnDropHandle<()>,
}

fn tls(pem: &str) -> MakeRustlsConnect {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes())) {
        roots.add(cert.expect("CA PEM")).expect("CA root");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    MakeRustlsConnect::new(config)
}

pub async fn connect(url: &str, pem: &str) -> (Client, AbortOnDropHandle<()>) {
    let (client, connection) = tokio_postgres::connect(url, tls(pem))
        .await
        .expect("fixture TLS connection");
    let task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "budget-configure-live",
        async move {
            connection.await.expect("fixture connection remains usable");
        }
    ));
    (client, task)
}

impl BudgetFixture {
    pub async fn new() -> Self {
        let base =
            std::env::var("LORE_TEST_BUDGET_CONFIGURE_PG_URL").expect("owned runner database");
        let pem = std::fs::read_to_string(
            std::env::var("LORE_TEST_BUDGET_CONFIGURE_CA_PATH").expect("owned runner CA path"),
        )
        .expect("read CA");
        let (admin, connection) = connect(&base, &pem).await;
        let (migrator, _migrator_connection) = connect(
            &base.replace("postgres@", "object_dispatch_retention_migrator@"),
            &pem,
        )
        .await;
        install_cell_schema(&migrator)
            .await
            .expect("supported schema installer");
        let row = admin.query_one("SELECT (SELECT system_identifier::text FROM pg_control_system()), (SELECT oid FROM pg_database WHERE datname=current_database())", &[]).await.expect("physical database identity");
        Self {
            system_identifier: row.get::<_, String>(0).parse().unwrap(),
            database_oid: row.get(1),
            admin,
            base,
            pem,
            _connection: connection,
        }
    }

    pub fn maintenance_url(&self) -> String {
        self.base
            .replace("postgres@", "object_dispatch_retention_maintenance@")
    }

    pub async fn snapshot(&self) -> String {
        self.admin.query_one("SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY cap_class)::text, '[]') FROM object_store_retention.object_dispatch_budget_bucket_state s", &[]).await.expect("bucket snapshot").get(0)
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Shared Postgres connection-pool construction + error classification for the
//! three CR-007 stores.
//!
//! **TLS (A1):** DO Managed Postgres — the deployment target (ADR-00008) —
//! mandates SSL, so the pool is always built with a rustls connector. Whether
//! TLS is actually negotiated is driven by the URL's `sslmode` (libpq
//! semantics, parsed by `tokio-postgres`): `disable` skips it, the default
//! `prefer` tries TLS and falls back to plaintext (so the no-TLS local/CI
//! Postgres still works), and `require`/`verify-*` enforce it. An optional CA
//! PEM is added to the trust roots for clusters that present a private CA
//! (DO hands you a `ca-certificate.crt`).
//!
//! **Transient errors (A2):** pool/connection/serialization failures are
//! classified as *retryable* so each store can surface `SlowDown` (clients back
//! off and retry) instead of a hard `internal` error, mirroring how `lore-aws`
//! maps throttling/timeouts.

use std::sync::Arc;

use deadpool_postgres::Manager;
use deadpool_postgres::ManagerConfig;
use deadpool_postgres::Pool;
use deadpool_postgres::PoolError;
use deadpool_postgres::RecyclingMethod;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio_postgres_rustls::MakeRustlsConnect;

/// Advisory-lock key guarding schema provisioning. A single shared key
/// serializes all `CREATE TABLE/INDEX IF NOT EXISTS` across every store and
/// every replica: Postgres `IF NOT EXISTS` DDL is *not* concurrency-safe (two
/// simultaneous runs can fail with "tuple concurrently updated" /
/// "duplicate key … pg_type"), which bites when multiple loreserver replicas in
/// a cell boot at once. The value is arbitrary but must be stable across the
/// fleet.
const SCHEMA_LOCK_KEY: i64 = 0x_6C6F_7265_7067; // "lorepg"

/// Provision a store's schema under the shared advisory lock so concurrent
/// boots (multi-replica cells) can't race the `IF NOT EXISTS` DDL. The lock is
/// transaction-scoped, so it is released on commit.
pub async fn ensure_schema(pool: &Pool, ddl: &str) -> Result<(), String> {
    let mut client = pool
        .get()
        .await
        .map_err(|e| format!("postgres connect failed: {e}"))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| format!("postgres schema txn failed: {e}"))?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK_KEY])
        .await
        .map_err(|e| format!("postgres advisory lock failed: {e}"))?;
    tx.batch_execute(ddl)
        .await
        .map_err(|e| format!("postgres schema DDL failed: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("postgres schema commit failed: {e}"))?;
    Ok(())
}

/// Build a pooled Postgres connector with a rustls TLS provider.
///
/// `ca_cert` is an optional PEM bundle added to the trust roots (for a private
/// cluster CA). TLS negotiation itself follows the URL's `sslmode`.
pub fn build_pool(url: &str, pool_max: u32, ca_cert: Option<&str>) -> Result<Pool, String> {
    let pg_config = url
        .parse::<tokio_postgres::Config>()
        .map_err(|e| format!("invalid postgres url: {e}"))?;
    let tls = make_tls(ca_cert)?;
    let manager = Manager::from_config(
        pg_config,
        tls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(pool_max as usize)
        .build()
        .map_err(|e| format!("failed to build postgres pool: {e}"))
}

fn make_tls(ca_cert: Option<&str>) -> Result<MakeRustlsConnect, String> {
    let mut roots = RootCertStore::empty();
    // Platform trust store (covers public CAs; DO Spaces/managed certs that
    // chain to a public root are trusted without extra config).
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    // Optional private CA bundle (e.g. DO's per-cluster ca-certificate.crt).
    if let Some(pem) = ca_cert {
        let mut reader = std::io::Cursor::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| format!("invalid CA cert PEM: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("failed to add CA cert to trust store: {e}"))?;
        }
    }
    // Pin the ring provider explicitly so we never depend on a process-wide
    // default provider being installed (loreserver installs one for QUIC, but
    // we must not rely on ordering).
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("rustls protocol versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

/// Whether a `tokio-postgres` error is transient and worth a client retry: a
/// closed/broken connection, an IO failure, or a SQLSTATE in the
/// connection (`08`), insufficient-resources (`53`), or
/// transaction-rollback/serialization (`40`) classes, plus admin shutdown
/// (`57P01`/`57P03`).
pub fn is_transient_pg(err: &tokio_postgres::Error) -> bool {
    if err.is_closed() {
        return true;
    }
    if let Some(db) = err.as_db_error() {
        let code = db.code().code();
        return code.starts_with("08")
            || code.starts_with("53")
            || code.starts_with("40")
            || code == "57P01"
            || code == "57P03";
    }
    // No DB error attached ⇒ a transport/IO-level failure (connection reset,
    // timeout). Treat as transient.
    true
}

/// Whether a pool checkout error is transient (timeout waiting for a slot, the
/// pool/backend went away, or a transient backend error).
pub fn is_transient_pool(err: &PoolError) -> bool {
    match err {
        PoolError::Backend(e) => is_transient_pg(e),
        // Timeouts, a closed pool, and the no-runtime case are all retryable
        // load/availability conditions rather than permanent faults.
        _ => true,
    }
}

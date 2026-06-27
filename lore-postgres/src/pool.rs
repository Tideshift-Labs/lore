// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Shared Postgres connection-pool construction + error classification for the
//! three CR-007 stores.
//!
//! **TLS (A1):** DO Managed Postgres — the deployment target (ADR-00008) —
//! mandates SSL, so the pool is always built with a rustls connector. Whether
//! TLS is *attempted* is driven by the URL's `sslmode` (parsed by
//! `tokio-postgres`, which understands only `disable`/`prefer`/`require`):
//! `disable` skips it, the default `prefer` tries TLS and falls back to
//! plaintext (so the no-TLS local/CI Postgres still works), and `require`
//! enforces it.
//!
//! **Certificate verification — note the libpq mismatch.** `tokio-postgres`
//! delegates verification entirely to the connector, and rustls *always*
//! verifies the server cert against the trust roots. So with this backend
//! `sslmode=require` behaves like libpq's `verify-ca`, **not** libpq's lax
//! `require` (which encrypts without verifying). That is deliberately safer,
//! but it means:
//!
//!   - For DO Managed Postgres, point [`TlsConfig::ca_cert`] at the cluster's
//!     `ca-certificate.crt` (recommended) so `require` verifies and connects.
//!   - To reproduce libpq's encrypt-but-don't-verify `require`, set
//!     [`TlsConfig::insecure_skip_verify`] (it logs a warning; the connection is
//!     encrypted but **not** authenticated, so it is MITM-exposed).
//!
//! `prefer` (the default) can silently fall back to **plaintext** if the TLS
//! handshake fails — use `require` in production.
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
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use tokio_postgres_rustls::MakeRustlsConnect;

/// TLS settings for the Postgres connector. `Default` = verify against the
/// platform trust store with no extra CA (secure).
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Optional PEM CA bundle added to the trust roots (e.g. a DO cluster's
    /// `ca-certificate.crt`).
    pub ca_cert: Option<String>,
    /// Skip server-certificate verification entirely (encrypt-only, libpq
    /// `require` semantics). MITM-exposed; logs a warning. Default `false`.
    pub insecure_skip_verify: bool,
}

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

/// Build a pooled Postgres connector with a rustls TLS provider. TLS
/// negotiation follows the URL's `sslmode`; verification follows `tls` (see
/// [`TlsConfig`] and the module docs).
pub fn build_pool(url: &str, pool_max: u32, tls: &TlsConfig) -> Result<Pool, String> {
    let pg_config = url
        .parse::<tokio_postgres::Config>()
        .map_err(|e| format!("invalid postgres url: {e}"))?;
    let connector = make_tls(tls)?;
    let manager = Manager::from_config(
        pg_config,
        connector,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Pool::builder(manager)
        .max_size(pool_max as usize)
        .build()
        .map_err(|e| format!("failed to build postgres pool: {e}"))
}

fn make_tls(tls: &TlsConfig) -> Result<MakeRustlsConnect, String> {
    // Pin the ring provider explicitly so we never depend on a process-wide
    // default provider being installed (loreserver installs one for QUIC, but
    // we must not rely on ordering).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol versions: {e}"))?;

    let config = if tls.insecure_skip_verify {
        tracing::warn!(
            "Postgres TLS certificate verification is DISABLED (insecure_skip_verify); the \
             connection is encrypted but not authenticated and is exposed to MITM"
        );
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        // Platform trust store (covers public CAs; DO certs that chain to a
        // public root are trusted without extra config).
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        // Optional private CA bundle (e.g. DO's per-cluster ca-certificate.crt).
        if let Some(pem) = &tls.ca_cert {
            let mut reader = std::io::Cursor::new(pem.as_bytes());
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| format!("invalid CA cert PEM: {e}"))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("failed to add CA cert to trust store: {e}"))?;
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(MakeRustlsConnect::new(config))
}

/// A `ServerCertVerifier` that accepts any certificate. Used only when
/// [`TlsConfig::insecure_skip_verify`] is set, to reproduce libpq's encrypt-only
/// `sslmode=require`. Signature checks still run (so the handshake is
/// well-formed); only chain/identity verification is skipped.
#[derive(Debug)]
struct NoCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
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
        return sqlstate_is_transient(db.code().code());
    }
    // No DB error attached ⇒ a transport/IO-level failure (connection reset,
    // timeout). Treat as transient.
    true
}

/// Whether a Postgres SQLSTATE code denotes a transient/retryable condition:
/// the connection (`08`), insufficient-resources (`53`), and
/// transaction-rollback/serialization (`40`) classes, plus admin-shutdown
/// (`57P01`/`57P03`). Pure function split out so it is unit-testable without a
/// live `tokio_postgres::Error` (which has no public constructor).
pub fn sqlstate_is_transient(code: &str) -> bool {
    code.starts_with("08")
        || code.starts_with("53")
        || code.starts_with("40")
        || code == "57P01"
        || code == "57P03"
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

#[cfg(test)]
mod tests {
    use super::sqlstate_is_transient;

    #[test]
    fn sqlstate_is_transient_true_cases() {
        // connection-failure class (08*)
        assert!(sqlstate_is_transient("08006"), "08006 (connection_failure)");
        assert!(
            sqlstate_is_transient("08003"),
            "08003 (connection_does_not_exist)"
        );
        assert!(
            sqlstate_is_transient("08000"),
            "08000 (connection_exception generic)"
        );
        assert!(
            sqlstate_is_transient("08001"),
            "08001 (sqlclient_unable_to_establish_sqlconnection)"
        );
        // transaction-rollback / serialization class (40*)
        assert!(
            sqlstate_is_transient("40001"),
            "40001 (serialization_failure)"
        );
        assert!(sqlstate_is_transient("40P01"), "40P01 (deadlock_detected)");
        // insufficient-resources class (53*)
        assert!(
            sqlstate_is_transient("53300"),
            "53300 (too_many_connections)"
        );
        assert!(
            sqlstate_is_transient("53400"),
            "53400 (configuration_limit_exceeded)"
        );
        // admin-shutdown codes (exact matches)
        assert!(sqlstate_is_transient("57P01"), "57P01 (admin_shutdown)");
        assert!(sqlstate_is_transient("57P03"), "57P03 (cannot_connect_now)");
    }

    #[test]
    fn sqlstate_is_transient_false_cases() {
        // integrity-constraint violations — permanent
        assert!(
            !sqlstate_is_transient("23505"),
            "23505 (unique_violation) must not be transient"
        );
        assert!(
            !sqlstate_is_transient("23503"),
            "23503 (foreign_key_violation) must not be transient"
        );
        // schema errors — permanent
        assert!(
            !sqlstate_is_transient("42P01"),
            "42P01 (undefined_table) must not be transient"
        );
        // data-exception — permanent
        assert!(
            !sqlstate_is_transient("22P02"),
            "22P02 (invalid_text_representation) must not be transient"
        );
        // success — not an error at all
        assert!(
            !sqlstate_is_transient("00000"),
            "00000 (success) must not be transient"
        );
        // application-level raise — permanent
        assert!(
            !sqlstate_is_transient("P0001"),
            "P0001 (raise_exception) must not be transient"
        );
        // crash_shutdown is NOT in our set (57P02 ≠ 57P01/57P03)
        assert!(
            !sqlstate_is_transient("57P02"),
            "57P02 (crash_shutdown) is NOT in our set"
        );
        // lock_not_available — a 55* code, not 53*
        assert!(
            !sqlstate_is_transient("55P03"),
            "55P03 (lock_not_available) must not be transient"
        );
        // empty string — must not start-with-match anything
        assert!(
            !sqlstate_is_transient(""),
            "empty string must not be transient"
        );
    }
}

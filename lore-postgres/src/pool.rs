// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
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
//! **Transient errors (A2):** pool exhaustion, connection failures, and
//! transient database transaction failures are classified as *retryable* so
//! each store can surface `SlowDown` (clients back off and retry) instead of a
//! hard `internal` error, mirroring how `lore-aws` maps throttling/timeouts.

use std::sync::Arc;

/// The pool and pooled-client types this crate's stores and domain APIs take,
/// re-exported so a consumer crate can name them without declaring its own
/// `deadpool-postgres` dependency.
///
/// `lore-server` holds a relay pool and hands `&mut Client` to
/// [`crate::domain::outbox::relay::claim_batch`] (WP-119 Step B). A second
/// manifest declaration would unify only while both resolve to the same
/// version; a minor drift makes two distinct crates whose identically named
/// types do not unify, and the resulting error names a type that looks correct
/// in both places. Re-exporting removes the second declaration entirely.
pub use deadpool_postgres::Client;
use deadpool_postgres::Manager;
use deadpool_postgres::ManagerConfig;
pub use deadpool_postgres::Pool;
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
pub(crate) const SCHEMA_LOCK_KEY: i64 = 0x_6C6F_7265_7067; // "lorepg"

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

/// Domain replica bootstrap: never retain a DDL lock across statements.
///
/// Existing tables/indexes/columns are checked in the catalog before issuing
/// DDL. Guarded DO blocks retain their own catalog predicates. This preserves
/// the declarations' IF NOT EXISTS semantics; it is not schema attestation.
/// Missing indexes on populated tables require out-of-band concurrent builds.
pub async fn ensure_schema_online(pool: &Pool, ddl: &str) -> Result<(), String> {
    ensure_schema_online_inner(pool, ddl)
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, thiserror::Error)]
enum OnlineSchemaError {
    #[error("postgres bootstrap pool failed: {0}")]
    Pool(#[from] PoolError),
    #[error("postgres {stage} failed: {source:?}")]
    Postgres {
        stage: &'static str,
        #[source]
        source: tokio_postgres::Error,
    },
    #[error("unsupported online bootstrap SQL: {0}")]
    Unsupported(String),
    #[error(
        "postgres schema index {0} is invalid or belongs to another table; repair it out of band"
    )]
    InvalidIndex(String),
    #[error("invalid bootstrap SQL encoding: {0}")]
    Encoding(#[from] std::string::FromUtf8Error),
    #[error("{original}; schema rollback failed: {source}")]
    Rollback {
        original: Box<Self>,
        #[source]
        source: tokio_postgres::Error,
    },
}

fn online_pg(stage: &'static str) -> impl FnOnce(tokio_postgres::Error) -> OnlineSchemaError {
    move |source| OnlineSchemaError::Postgres { stage, source }
}

async fn ensure_schema_online_inner(pool: &Pool, ddl: &str) -> Result<(), OnlineSchemaError> {
    let statements = schema_fragments(ddl, b';', true)?;
    let mut client = pool.get().await?;
    for statement in statements {
        let step = SchemaStep::parse(&statement)?;
        if step.complete(&**client).await? {
            continue;
        }
        let tx = client
            .transaction()
            .await
            .map_err(online_pg("schema transaction"))?;
        let result = async {
            // Wait for another installer before taking any table lock. Existing
            // transaction-scoped installers use this same advisory key.
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK_KEY])
                .await.map_err(online_pg("schema advisory lock"))?;
            tx.batch_execute("SET LOCAL lock_timeout = '100ms'; SET LOCAL statement_timeout = '250ms'")
                .await.map_err(online_pg("schema timeouts"))?;
            if !step.complete(&*tx).await? {
                let execution = if let SchemaStep::Index { table, .. } = &step {
                    // One statement timeout covers lock, check, and build. No
                    // writer can populate the table between check and build.
                    // NOWAIT also avoids queuing behind an active writer.
                    format!("DO $online_index$ BEGIN \
                        LOCK TABLE \"{table}\" IN SHARE MODE NOWAIT; \
                        IF EXISTS (SELECT 1 FROM \"{table}\" LIMIT 1) THEN \
                        RAISE EXCEPTION 'postgres schema requires an out-of-band concurrent index build on {table}'; \
                        END IF; {statement}; END $online_index$;")
                } else { statement.clone() };
                tx.batch_execute(&execution).await.map_err(online_pg("bounded schema DDL"))?;
            }
            Ok::<(), OnlineSchemaError>(())
        }.await;
        if let Err(error) = result {
            if let Err(source) = tx.rollback().await {
                return Err(OnlineSchemaError::Rollback {
                    original: Box::new(error),
                    source,
                });
            }
            return Err(error);
        }
        tx.commit().await.map_err(online_pg("schema commit"))?;
    }
    Ok(())
}

enum SchemaStep {
    Table(String),
    Index { name: String, table: String },
    Columns { table: String, names: Vec<String> },
    GuardedBlock,
}

impl SchemaStep {
    fn parse(sql: &str) -> Result<Self, OnlineSchemaError> {
        let words: Vec<_> = sql.split_whitespace().collect();
        let identifier = |word: &str| -> Result<String, OnlineSchemaError> {
            if !word.is_empty()
                && word
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            {
                Ok(word.to_owned())
            } else {
                Err(OnlineSchemaError::Unsupported(format!("identifier {word}")))
            }
        };
        if words.starts_with(&["CREATE", "TABLE", "IF", "NOT", "EXISTS"]) && words.len() > 5 {
            return Ok(Self::Table(identifier(words[5])?));
        }
        let index_offset =
            if words.starts_with(&["CREATE", "UNIQUE", "INDEX", "IF", "NOT", "EXISTS"]) {
                Some(6)
            } else if words.starts_with(&["CREATE", "INDEX", "IF", "NOT", "EXISTS"]) {
                Some(5)
            } else {
                None
            };
        if let Some(offset) = index_offset
            && words.get(offset + 1) == Some(&"ON")
            && words.len() > offset + 2
        {
            return Ok(Self::Index {
                name: identifier(words[offset])?,
                table: identifier(words[offset + 2])?,
            });
        }
        if words.starts_with(&["ALTER", "TABLE"]) && words.len() > 3 {
            let actions = schema_fragments(&words[3..].join(" "), b',', false)?;
            let mut names = Vec::new();
            for action in actions {
                let tokens: Vec<_> = action.split_whitespace().collect();
                if !tokens.starts_with(&["ADD", "COLUMN", "IF", "NOT", "EXISTS"])
                    || tokens.len() < 7
                {
                    return Err(OnlineSchemaError::Unsupported(format!(
                        "ALTER action {action}"
                    )));
                }
                names.push(identifier(tokens[5])?);
            }
            if !names.is_empty() {
                return Ok(Self::Columns {
                    table: identifier(words[2])?,
                    names,
                });
            }
        }
        // The mediated schema seeds its singleton with ON CONFLICT DO NOTHING.
        // Execute that existing idempotent statement; never infer a new value
        // or overwrite counters that a serving replica has already advanced.
        if words.first() == Some(&"DO")
            || (words.starts_with(&["INSERT", "INTO"])
                && words.ends_with(&["ON", "CONFLICT", "(id)", "DO", "NOTHING"]))
        {
            return Ok(Self::GuardedBlock);
        }
        Err(OnlineSchemaError::Unsupported(format!(
            "statement {}",
            words.iter().take(6).copied().collect::<Vec<_>>().join(" ")
        )))
    }

    async fn complete(
        &self,
        client: &impl tokio_postgres::GenericClient,
    ) -> Result<bool, OnlineSchemaError> {
        let result = match self {
            Self::Table(name) => client.query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_class WHERE oid = to_regclass($1) AND relkind IN ('r', 'p'))", &[name]).await,
            Self::Index { name, table } => {
                let row = client.query_opt(
                    "SELECT COALESCE(i.indisvalid AND i.indisready AND i.indrelid = to_regclass($2), false) FROM pg_class c LEFT JOIN pg_index i ON i.indexrelid = c.oid WHERE c.oid = to_regclass($1)",
                    &[name, table]).await.map_err(online_pg("index catalog check"))?;
                return match row {
                    None => Ok(false),
                    Some(row) if row.get::<_, bool>(0) => Ok(true),
                    Some(_) => Err(OnlineSchemaError::InvalidIndex(name.clone())),
                };
            }
            Self::Columns { table, names } => client.query_one(
                "SELECT NOT EXISTS (SELECT 1 FROM unnest($2::text[]) AS wanted(name) WHERE NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass($1) AND attname = wanted.name AND attnum > 0 AND NOT attisdropped))", &[table, names]).await,
            Self::GuardedBlock => return Ok(false),
        };
        result
            .map(|row| row.get(0))
            .map_err(online_pg("schema catalog check"))
    }
}

/// Split the compiled SQL declarations, preserving quoted semicolons and DO
/// bodies. Strip comments only outside quotes. Reject unfinished input.
fn schema_fragments(
    ddl: &str,
    separator: u8,
    require_terminator: bool,
) -> Result<Vec<String>, OnlineSchemaError> {
    let bytes = ddl.as_bytes();
    let mut statements = Vec::new();
    let mut current = Vec::new();
    let mut offset = 0;
    let mut quote = None;
    let mut dollar: Option<Vec<u8>> = None;
    let mut depth = 0_u32;
    while offset < bytes.len() {
        if let Some(tag) = &dollar {
            if bytes[offset..].starts_with(tag) {
                current.extend_from_slice(tag);
                offset += tag.len();
                dollar = None;
            } else {
                current.push(bytes[offset]);
                offset += 1;
            }
            continue;
        }
        let byte = bytes[offset];
        if let Some(delimiter) = quote {
            current.push(byte);
            offset += 1;
            if byte == delimiter {
                if bytes.get(offset) == Some(&delimiter) {
                    current.push(delimiter);
                    offset += 1;
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if bytes[offset..].starts_with(b"--") {
            while offset < bytes.len() && bytes[offset] != b'\n' {
                offset += 1;
            }
            current.push(b' ');
            continue;
        }
        if bytes[offset..].starts_with(b"/*") {
            return Err(OnlineSchemaError::Unsupported("block comment".into()));
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'$' {
            let mut end = offset + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if bytes.get(end) == Some(&b'$') {
                let tag = bytes[offset..=end].to_vec();
                current.extend_from_slice(&tag);
                dollar = Some(tag);
                offset = end + 1;
                continue;
            }
        } else if byte == b'(' {
            depth += 1;
        } else if byte == b')' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| OnlineSchemaError::Unsupported("unbalanced parentheses".into()))?;
        } else if byte == separator && depth == 0 {
            let statement = String::from_utf8(std::mem::take(&mut current))?;
            if !statement.trim().is_empty() {
                statements.push(statement.trim().to_owned());
            }
            offset += 1;
            continue;
        }
        current.push(byte);
        offset += 1;
    }
    if quote.is_some() || dollar.is_some() || depth != 0 {
        return Err(OnlineSchemaError::Unsupported(
            "unterminated quote or parentheses".into(),
        ));
    }
    if !current.iter().all(u8::is_ascii_whitespace) {
        if require_terminator {
            return Err(OnlineSchemaError::Unsupported(
                "unterminated statement".into(),
            ));
        }
        statements.push(String::from_utf8(current)?.trim().to_owned());
    }
    Ok(statements)
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
    if error_chain_contains::<tokio_postgres::types::WrongType>(err) {
        return false;
    }
    // No DB error attached ⇒ a transport/IO-level failure (connection reset,
    // timeout), unless the source chain identified a permanent client-side
    // parameter type mismatch above. Treat the remaining cases as transient.
    true
}

fn error_chain_contains<T>(error: &(dyn std::error::Error + 'static)) -> bool
where
    T: std::error::Error + 'static,
{
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.is::<T>() {
            return true;
        }
        source = cause.source();
    }
    false
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
    use std::error::Error;
    use std::fmt;

    use tokio_postgres::types::Type;
    use tokio_postgres::types::WrongType;

    use super::error_chain_contains;
    use super::sqlstate_is_transient;

    #[derive(Debug)]
    struct WrappedError(WrongType);

    impl fmt::Display for WrappedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("wrapped parameter error")
        }
    }

    impl Error for WrappedError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn error_chain_detects_wrong_type_parameter_error() {
        let error = WrappedError(WrongType::new::<i16>(Type::TEXT));

        assert!(error_chain_contains::<WrongType>(&error));
        assert!(!error_chain_contains::<WrongType>(&std::io::Error::other(
            "connection reset"
        )));
    }

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

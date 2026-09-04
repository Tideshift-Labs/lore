// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Two independently constructed coordinator sets over one shared backend.
//!
//! # What "independently constructed" has to mean here
//!
//! WP-109 is explicit that two clients on one process are not a substitute for
//! two processes, and the reason is process-local state, not the socket count.
//! So a set here is built by its own `PostgresDomainStore::connect` call:
//! its own `deadpool` pool, its own S3 client where it has one, its own
//! coordinator handles. Nothing is cloned across the seam. What the two share
//! is exactly what a cell's two replicas share — one database and one bucket.
//!
//! What this shape still does **not** isolate, stated so no reader over-reads
//! the evidence: `LazyLock` process globals, chiefly the failpoint
//! configuration in `domain/fragments/failpoints.rs`, which is read once per
//! process and therefore applies to both sets. Every case that arms an anchor
//! is written so that only one participant can reach it (see
//! `publication.commit.settled`, which fires only on the `Published` arm).
//! Genuine per-process configuration divergence is WP-109 Phase 3's, with two
//! real loreserver processes.
//!
//! # Namespacing
//!
//! One [`CaseNamespace`] schema per case, shared by both sets — the schema arm
//! of WP-109's rule. The runner supplies the database arm by creating and
//! dropping a database around each case. `pool::ensure_schema`'s
//! `SCHEMA_LOCK_KEY` is database-wide, so the two sets serialise on bootstrap
//! rather than installing in parallel; that is expected and costs one
//! round of DDL, not correctness.

#![allow(dead_code)]

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::pool::Pool;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use tokio_postgres::Client;

use crate::case_namespace::CaseNamespace;

/// One replica's worth of coordinators.
pub struct CoordinatorSet {
    /// `a` or `b`. Appears in owner strings and object keys so an authoritative
    /// row names the set that wrote it.
    pub label: &'static str,
    /// The domain store this set built for itself.
    pub domain: PostgresDomainStore,
    /// A pool of this set's own, for the relay functions that take a
    /// `&mut deadpool_postgres::Client` and open their own transaction.
    pub pool: Pool,
    /// The namespaced URL both sets share.
    pub url: String,
}

impl CoordinatorSet {
    /// Build one set: its own connection, its own pool, both domain schemas
    /// installed.
    ///
    /// SCHEMA-117 is installed before any domain row can exist because
    /// `branch_push_commit` revalidates the CR-030 push witness against
    /// `lore_domain_lock_namespaces`, whose row is written by an after-insert
    /// trigger on `lore_domain_branches` (INV-EE P1-3). SCHEMA-118 follows so a
    /// fragment case need not bootstrap separately; both are idempotent, so the
    /// second set installing them again is a no-op.
    pub async fn connect(url: &str, label: &'static str, pool_max: u32) -> Self {
        let domain = PostgresDomainStore::connect(url, pool_max, &TlsConfig::default())
            .await
            .unwrap_or_else(|error| panic!("set {label}: connect domain store: {error}"));
        domain
            .lock_coordinator()
            .bootstrap()
            .await
            .unwrap_or_else(|error| panic!("set {label}: install SCHEMA-117: {error}"));
        domain
            .fragment_coordinator()
            .bootstrap()
            .await
            .unwrap_or_else(|error| panic!("set {label}: install SCHEMA-118: {error}"));
        let pool = build_pool(url, pool_max, &TlsConfig::default())
            .unwrap_or_else(|error| panic!("set {label}: build relay pool: {error}"));
        Self {
            label,
            domain,
            pool,
            url: url.to_owned(),
        }
    }

    /// This set's lock coordinator.
    pub fn locks(&self) -> PostgresLockCoordinator {
        self.domain.lock_coordinator()
    }

    /// This set's fragment lifecycle coordinator.
    pub fn fragments(&self) -> PostgresFragmentCoordinator {
        self.domain.fragment_coordinator()
    }

    /// Check out one of this set's pooled connections.
    pub async fn checkout(&self) -> deadpool_postgres::Client {
        self.pool.get().await.unwrap_or_else(|error| {
            panic!("set {}: checkout pooled connection: {error}", self.label)
        })
    }

    /// A raw connection owned by this set, for the module functions bound on
    /// `&impl GenericClient` and for direct authoritative SQL readback.
    pub async fn raw(&self) -> Client {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .unwrap_or_else(|error| panic!("set {}: connect raw client: {error}", self.label));
        let label = self.label;
        lore_base::lore_spawn!(async move {
            if let Err(error) = connection.await {
                eprintln!("set {label} raw connection error: {error}");
            }
        });
        client
    }
}

/// One case's shared backend: a namespace, and the two sets that share it.
pub struct SharedBackend {
    /// The first replica.
    pub a: CoordinatorSet,
    /// The second replica, built by its own independent `connect`.
    pub b: CoordinatorSet,
    /// The namespaced URL. Every connection in the case uses it.
    pub url: String,
    namespace: Option<CaseNamespace>,
}

impl SharedBackend {
    /// Acquire this case's schema and open both sets against it.
    pub async fn open(base_url: &str, case_label: &str) -> Self {
        let namespace = CaseNamespace::acquire(base_url, case_label).await;
        let url = namespace.pg_url().to_owned();
        let a = CoordinatorSet::connect(&url, "a", 8).await;
        let b = CoordinatorSet::connect(&url, "b", 8).await;
        Self {
            a,
            b,
            url,
            namespace: Some(namespace),
        }
    }

    /// Prove the case's relations really landed in its own schema.
    ///
    /// Asserting only that the case passed proves nothing about namespacing —
    /// the runner already hands each case a fresh database, so the case would
    /// pass with the `search_path` doing nothing at all. This asks
    /// `pg_tables` where a known domain relation actually is.
    pub async fn assert_namespaced(&self) {
        let namespace = self
            .namespace
            .as_ref()
            .expect("namespace is present until release");
        let schemas = namespace
            .schemas_containing("lore_domain_repositories")
            .await;
        assert_eq!(
            schemas,
            vec![namespace.schema_name().to_owned()],
            "the case's domain relations must exist only in its own schema"
        );
    }

    /// Drop the case's schema and record the disposition.
    pub async fn release(mut self) {
        if let Some(namespace) = self.namespace.take() {
            namespace.release().await;
        }
    }
}

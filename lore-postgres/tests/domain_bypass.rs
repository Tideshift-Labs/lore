// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Integration tests for the CR-029 domain-key bypass guard
//! (`lore-postgres/src/domain/bypass.rs`, R-SHOULD-4) wired into
//! `PostgresMutableStore`'s generic `store`/`compare_and_swap` path.
//!
//! `bypass.rs`'s own unit tests already pin the pure logic
//! (`is_domain_owned`, `DomainEnforcement`'s reversibility, the rejection
//! message). What's tested here is the actual wiring: a real
//! `PostgresMutableStore` built with `.with_domain_enforcement(..)` must
//! reject a domain-owned key write once enforcement is enabled, allow it
//! while disabled, and never fence a non-domain-owned key type — proving the
//! side-effect boundary end to end, not just the classification function in
//! isolation.
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated per test by
//! random partition/key values since `lore_mutable` is shared.

use std::sync::Arc;

use lore_base::types::KeyType;
use lore_postgres::domain::bypass::DomainEnforcement;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connected_store(url: &str, enforcement: DomainEnforcement) -> Arc<PostgresMutableStore> {
    Arc::new(
        PostgresMutableStore::connect(url, 2, &TlsConfig::default())
            .await
            .expect("connect mutable store")
            .with_domain_enforcement(enforcement),
    )
}

/// While enforcement is disabled (the default a fresh store starts with, and
/// the state every existing CR-007 test in this crate already relies on), a
/// domain-owned key type must write exactly as before — the guard must not
/// be accidentally always-on.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn domain_owned_key_writes_succeed_while_enforcement_is_disabled() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping bypass-guard disabled test");
        return;
    };
    let enforcement = DomainEnforcement::disabled();
    let store = connected_store(&url, enforcement).await;
    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let value: Hash = rand::random();

    store
        .clone()
        .store(part, key, value, KeyType::RepositoryId)
        .await
        .expect("a domain-owned key type must write normally while enforcement is off");
    assert_eq!(
        store
            .clone()
            .load(part, key, KeyType::RepositoryId)
            .await
            .unwrap(),
        value
    );

    store
        .clone()
        .compare_and_swap(part, key, value, Hash::default(), KeyType::RepositoryId)
        .await
        .expect("compare_and_swap on a domain-owned key must also succeed while disabled");
}

/// Once enforcement is enabled, every one of the five lifecycle key types
/// plus the deliberately-fenced `Instance` must be rejected by both `store`
/// and `compare_and_swap`, with the rejection naming the key type — no trait
/// default, no silent fallback.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn domain_owned_key_writes_are_rejected_once_enforcement_is_enabled() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping bypass-guard enabled test");
        return;
    };
    let enforcement = DomainEnforcement::disabled();
    let store = connected_store(&url, enforcement.clone()).await;
    enforcement.enable();

    for key_type in [
        KeyType::RepositoryId,
        KeyType::RepositoryMetadata,
        KeyType::BranchId,
        KeyType::BranchMetadata,
        KeyType::BranchLatestPointer,
        KeyType::Instance,
    ] {
        let part: Partition = rand::random();
        let key: Hash = rand::random();
        let value: Hash = rand::random();

        let err = store
            .clone()
            .store(part, key, value, key_type)
            .await
            .expect_err(&format!(
                "{key_type:?} must be rejected by store() while enforced"
            ));
        assert!(
            format!("{err}").contains(&format!("{key_type:?}")),
            "rejection for {key_type:?} must name the key type: {err}"
        );
        assert!(
            store.clone().load(part, key, key_type).await.is_err(),
            "a rejected store() must not have written anything for {key_type:?}"
        );

        let err = store
            .clone()
            .compare_and_swap(part, key, Hash::default(), value, key_type)
            .await
            .expect_err(&format!(
                "{key_type:?} must be rejected by compare_and_swap() while enforced"
            ));
        assert!(
            format!("{err}").contains(&format!("{key_type:?}")),
            "CAS rejection for {key_type:?} must name the key type: {err}"
        );
    }
}

/// `Resolve` and `Untyped` are explicitly not domain-owned (per the module
/// docs: content-address resolution and acceleration keys, neither
/// participating in repository/branch lifecycle) and must keep writing
/// normally even while enforcement is on.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn non_domain_owned_key_types_are_never_fenced() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping bypass-guard non-domain-key test");
        return;
    };
    let enforcement = DomainEnforcement::disabled();
    let store = connected_store(&url, enforcement.clone()).await;
    enforcement.enable();

    for key_type in [KeyType::Resolve, KeyType::Untyped] {
        let part: Partition = rand::random();
        let key: Hash = rand::random();
        let value: Hash = rand::random();
        store
            .clone()
            .store(part, key, value, key_type)
            .await
            .unwrap_or_else(|e| {
                panic!("{key_type:?} must never be fenced by domain enforcement: {e}")
            });
        assert_eq!(
            store.clone().load(part, key, key_type).await.unwrap(),
            value
        );
    }
}

/// Enforcement is reversible in place: a store built with a shared
/// `DomainEnforcement` handle must start rejecting the moment `enable()` is
/// called and go back to allowing writes the moment `disable()` is called —
/// no reconnect required, matching the documented rollback path.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn enforcement_toggles_live_without_reconnecting() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping bypass-guard live-toggle test");
        return;
    };
    let enforcement = DomainEnforcement::disabled();
    let store = connected_store(&url, enforcement.clone()).await;
    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let value: Hash = rand::random();

    store
        .clone()
        .store(part, key, value, KeyType::RepositoryId)
        .await
        .expect("write must succeed before enforcement is enabled");

    enforcement.enable();
    let key2: Hash = rand::random();
    store
        .clone()
        .store(part, key2, value, KeyType::RepositoryId)
        .await
        .expect_err("write must be rejected immediately after enable(), same store instance");

    enforcement.disable();
    store
        .clone()
        .store(part, key2, value, KeyType::RepositoryId)
        .await
        .expect("write must succeed again immediately after disable(), same store instance");
}

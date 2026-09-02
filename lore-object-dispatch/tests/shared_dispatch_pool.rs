// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline proof that CD-3 readback/mutations and CD-4 charging compose over one runtime pool.

use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::DispatchAuthorityError;
use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRuntimeClient;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::PostgresProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;

const CLIENT_SOURCE: &str = include_str!("../src/dispatch_client.rs");
const CHARGE_SOURCE: &str = include_str!("../src/provider_charge.rs");
const POOL_SOURCE: &str = include_str!("../src/dispatch_pool.rs");

#[test]
fn one_runtime_pool_value_constructs_both_runtime_consumers() {
    let pool = Arc::new(
        DispatchRuntimePool::new(pool_config(DispatchPoolRole::Runtime)).expect("runtime pool"),
    );

    let runtime = DispatchRuntimeClient::new(Arc::clone(&pool));
    let charge = PostgresProviderChargeAuthority::new(Arc::clone(&pool));

    assert!(
        runtime.is_ok(),
        "the typed runtime client must accept the shared pool"
    );
    assert!(
        charge.is_ok(),
        "the charge authority must accept the same shared pool"
    );
    assert_eq!(
        Arc::strong_count(&pool),
        3,
        "both consumers must retain that one pool"
    );
}

#[test]
fn both_runtime_consumers_fail_closed_on_the_maintenance_role() {
    let pool = Arc::new(
        DispatchRuntimePool::new(pool_config(DispatchPoolRole::Maintenance))
            .expect("maintenance pool"),
    );

    assert_eq!(
        DispatchRuntimeClient::new(Arc::clone(&pool)).err(),
        Some(DispatchAuthorityError::WrongPoolRole)
    );
    assert_eq!(
        PostgresProviderChargeAuthority::new(pool).err(),
        Some(ProviderChargeError::ConfigurationUnresolved)
    );
}

#[test]
fn charge_uses_the_pool_envelope_and_never_opens_a_raw_connection() {
    for required in [
        "pool: Arc<DispatchRuntimePool>",
        "self.pool.acquire().await",
        "pool.bounded_execution_preamble()",
    ] {
        assert!(
            CHARGE_SOURCE.contains(required),
            "the charge authority must contain {required:?}"
        );
    }
    for forbidden in [
        "PostgresProviderChargeConfig",
        "tokio_postgres::connect",
        "Client::connect",
        "DispatchRuntimePool::new(",
    ] {
        assert!(
            !CHARGE_SOURCE.contains(forbidden),
            "the charge authority must not contain {forbidden:?}"
        );
    }
}

#[test]
fn ambiguous_commit_and_dead_sessions_poison_while_retry_sleep_follows_release() {
    assert_charge_session_disposition(CHARGE_SOURCE);

    let dead_session_bypass = CHARGE_SOURCE.replacen(
        "Err(ChargeExecutionError::SessionUnusable(_)) => lease.poison(),",
        "Err(ChargeExecutionError::SessionUnusable(_)) => lease.release().await,",
        1,
    );
    let failure =
        std::panic::catch_unwind(|| assert_charge_session_disposition(&dead_session_bypass))
            .expect_err("returning a dead session to the pool must fail this proof");
    assert!(panic_text(failure).contains("every unusable session must poison the lease"));

    let rollback_release = CHARGE_SOURCE.replacen(
        "Err(_) => failure.on_unusable_session(),",
        "Err(_) => failure,",
        1,
    );
    let failure = std::panic::catch_unwind(|| assert_charge_session_disposition(&rollback_release))
        .expect_err("a failed rollback that releases must fail this proof");
    assert!(
        panic_text(failure)
            .contains("failed rollback must retain semantics and mark the session unusable")
    );

    let known_abort_poison = CHARGE_SOURCE.replacen(
        "ChargeExecutionError::Retryable\n        }\n        _ =>",
        "ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Retryable)\n        }\n        _ =>",
        1,
    );
    let failure =
        std::panic::catch_unwind(|| assert_charge_session_disposition(&known_abort_poison))
            .expect_err("poisoning a known commit abort must fail this proof");
    assert!(
        panic_text(failure).contains("known commit aborts must remain reusable retryable failures")
    );

    let ambiguous_release = CHARGE_SOURCE.replacen(
        "_ => ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(\n            ProviderChargeError::AmbiguousCommit,\n        )),",
        "_ => ChargeExecutionError::Public(ProviderChargeError::AmbiguousCommit),",
        1,
    );
    let failure =
        std::panic::catch_unwind(|| assert_charge_session_disposition(&ambiguous_release))
            .expect_err("releasing an unknown commit outcome must fail this proof");
    assert!(
        panic_text(failure)
            .contains("unknown commit outcomes must be ambiguous and poison the session")
    );

    let charge = section(CHARGE_SOURCE, "async fn charge(", "\n}\n\n");
    let attempt = charge
        .find("self.charge_once(request).await")
        .expect("charge must call charge_once");
    let sleep = charge
        .find("tokio::time::sleep(delay).await")
        .expect("known-aborted retries must use the bounded schedule");
    assert!(
        attempt < sleep,
        "the attempt must finish and release its lease before retry sleep"
    );
}

#[test]
fn outer_charge_timeout_distinguishes_precommit_from_commit_started_and_retires_the_session() {
    assert_charge_timeout_wall(CHARGE_SOURCE, POOL_SOURCE);

    let no_outer_wall = CHARGE_SOURCE.replacen("tokio::time::timeout(", "missing_timeout(", 1);
    let failure =
        std::panic::catch_unwind(|| assert_charge_timeout_wall(&no_outer_wall, POOL_SOURCE))
            .expect_err("removing the outer wall-clock bound must fail this proof");
    assert!(panic_text(failure).contains("outer wall-clock timeout"));

    let inverted_commit_boundary = CHARGE_SOURCE.replacen(
        "let error = if commit_started {",
        "let error = if !commit_started {",
        1,
    );
    let failure = std::panic::catch_unwind(|| {
        assert_charge_timeout_wall(&inverted_commit_boundary, POOL_SOURCE)
    })
    .expect_err("inverting the COMMIT boundary must fail this proof");
    assert!(
        panic_text(failure).contains("before COMMIT is unavailable; after COMMIT is ambiguous")
    );

    let constant_timeout_phase =
        CHARGE_SOURCE.replacen("commit_started.load(Ordering::SeqCst)", "false", 1);
    let failure = std::panic::catch_unwind(|| {
        assert_charge_timeout_wall(&constant_timeout_phase, POOL_SOURCE)
    })
    .expect_err("disconnecting the COMMIT marker from timeout classification must fail this proof");
    assert!(
        panic_text(failure).contains("actual COMMIT marker load must feed timeout classification")
    );

    let reusable_timeout = CHARGE_SOURCE.replacen(
        "Err(ChargeExecutionError::SessionUnusable(_)) => lease.poison(),",
        "Err(ChargeExecutionError::SessionUnusable(_)) => lease.release().await,",
        1,
    );
    let failure =
        std::panic::catch_unwind(|| assert_charge_timeout_wall(&reusable_timeout, POOL_SOURCE))
            .expect_err("returning a timed-out session must fail this proof");
    assert!(panic_text(failure).contains("timed-out and otherwise unusable sessions are retired"));
}

fn assert_charge_timeout_wall(charge_source: &str, pool_source: &str) {
    let charge_once = section(
        charge_source,
        "async fn charge_once(",
        "\n}\n\nasync fn charge_on_lease",
    );
    assert!(
        charge_once.contains("tokio::time::timeout(")
            && charge_once.contains("self.pool.operation_timeout()")
            && charge_once.contains("classify_charge_timeout("),
        "provider charge needs one outer wall-clock timeout around the leased transaction"
    );
    assert!(charge_once.contains("let commit_started = AtomicBool::new(false);"));
    assert!(
        charge_once.contains(
            "Err(_) => Err(classify_charge_timeout(\n                commit_started.load(Ordering::SeqCst),\n            )),"
        ),
        "the actual COMMIT marker load must feed timeout classification"
    );
    assert!(
        charge_once.contains("Err(ChargeExecutionError::SessionUnusable(_)) => lease.poison(),"),
        "timed-out and otherwise unusable sessions are retired"
    );

    let on_lease = section(
        charge_source,
        "async fn charge_on_lease(",
        "\n}\n\nimpl fmt::Debug",
    );
    let commit_boundary = on_lease
        .find("commit_started.store(true, Ordering::SeqCst);")
        .expect("COMMIT-start marker");
    let commit = on_lease[commit_boundary..]
        .find(".commit()")
        .map(|offset| commit_boundary + offset)
        .expect("transaction COMMIT");
    assert!(
        commit_boundary < commit,
        "COMMIT must be marked before it may enter the wire path"
    );

    let classification = section(
        charge_source,
        "fn classify_charge_timeout(",
        "\n}\n\n/// Classify a SQLSTATE",
    );
    assert!(
        classification.contains("let error = if commit_started {")
            && classification.contains("ProviderChargeError::AmbiguousCommit")
            && classification.contains("ProviderChargeError::AuthorityUnavailable"),
        "before COMMIT is unavailable; after COMMIT is ambiguous"
    );
    assert!(classification.contains(
        "ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(error))"
    ));

    let poison = section(
        pool_source,
        "pub(crate) fn poison(mut self)",
        "\n    }\n}\n\nimpl Drop",
    );
    assert!(poison.contains("drop(self.session.take());"));
    assert!(!poison.contains("self.pool.release"));
}

fn assert_charge_session_disposition(source: &str) {
    let charge_once = section(
        source,
        "async fn charge_once(",
        "\n}\n\nasync fn charge_on_lease",
    );
    assert_eq!(
        charge_once.matches("lease.poison()").count(),
        1,
        "every unusable session must poison the lease"
    );
    assert!(charge_once.contains("Err(ChargeExecutionError::SessionUnusable(_))"));
    assert!(charge_once.contains("_ => lease.release().await"));

    let rollback = section(
        source,
        "async fn rollback_after_failure(",
        "\n}\n\nfn parse_uuid",
    );
    assert!(
        rollback.contains("Err(_) => failure.on_unusable_session(),"),
        "failed rollback must retain semantics and mark the session unusable"
    );
    let unusable = section(
        source,
        "fn on_unusable_session(self)",
        "\n}\n\nfn decode_charge_row",
    );
    assert!(unusable.contains(
        "Self::Retryable => Self::SessionUnusable(SessionUnusableChargeError::Retryable)"
    ));
    assert!(unusable.contains(
        "Self::Public(error) => Self::SessionUnusable(SessionUnusableChargeError::Public(error))"
    ));

    let commit = section(
        source,
        "fn classify_commit_sqlstate(",
        "\n}\n\nfn classify_precommit_error",
    );
    assert!(
        commit.contains("ChargeExecutionError::Retryable\n        }"),
        "known commit aborts must remain reusable retryable failures"
    );
    assert!(
        commit.contains("_ => ChargeExecutionError::SessionUnusable(SessionUnusableChargeError::Public(\n            ProviderChargeError::AmbiguousCommit,\n        )),"),
        "unknown commit outcomes must be ambiguous and poison the session"
    );
}

#[test]
fn the_typed_runtime_client_also_retains_the_shared_arc_pool() {
    assert!(CLIENT_SOURCE.contains("pool: Arc<DispatchRuntimePool>"));
    assert!(CLIENT_SOURCE.contains(
        "pub fn new(pool: Arc<DispatchRuntimePool>) -> Result<Self, DispatchAuthorityError>"
    ));
}

fn pool_config(role: DispatchPoolRole) -> DispatchPoolConfig {
    DispatchPoolConfig {
        postgres_url: format!(
            "postgres://{}:secret@cell.invalid:5432/lorecell?sslmode=disable",
            role.role_name()
        ),
        role,
        expected_database_identity: DispatchDatabaseIdentity::new(1, 1)
            .expect("test physical database identity"),
        pool_max: 5,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_millis(2_000),
        lock_timeout: Duration::from_millis(1_000),
        tls: DispatchTlsMode::Disabled,
        budget: DispatchConnectionBudget::new(1, 1, 1, 1, 5).expect("test process budget"),
    }
}

fn section<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing section marker {start_marker:?}"));
    let rest = &source[start..];
    let end = rest
        .find(end_marker)
        .unwrap_or_else(|| panic!("missing section end {end_marker:?}"));
    &rest[..end]
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|value| (*value).to_string())
        })
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

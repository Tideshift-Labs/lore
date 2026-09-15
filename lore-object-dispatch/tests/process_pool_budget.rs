// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Runtime controls for the exact six-pool process connection budget.

use std::time::Duration;

use lore_object_dispatch::DISPATCH_PROCESS_CONNECTION_LIMIT;
use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolError;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;

fn assert_invalid(values: [u32; 6], expected: &'static str) -> DispatchPoolError {
    let [immutable, mutable, lock, domain, dispatch, relay] = values;
    let error = DispatchConnectionBudget::new(immutable, mutable, lock, domain, dispatch, relay)
        .expect_err("invalid six-pool inventory must be refused");
    assert_eq!(error, DispatchPoolError::InvalidConfiguration(expected));
    error
}

#[test]
fn under_cap_exact_cap_and_heterogeneous_inventory_preserve_all_six_components() {
    let under = DispatchConnectionBudget::new(1, 2, 3, 4, 5, 0).expect("total 15");
    assert_eq!(under.connections_per_replica(), 15);

    // Domain and dispatch are kept distinct so a transposition of the two is
    // still visible here; six distinct values cannot sum to 20, so the repeat
    // is pushed onto immutable/mutable instead.
    let exact = DispatchConnectionBudget::new(2, 2, 4, 6, 5, 1).expect("exact total 20");
    assert_eq!(
        exact.connections_per_replica(),
        DISPATCH_PROCESS_CONNECTION_LIMIT
    );
    assert_eq!(exact.domain_pool_max(), 6);
    assert_eq!(exact.dispatch_pool_max(), 5);
    assert_eq!(exact.relay_pool_max(), 1);
}

#[test]
fn real_store_defaults_are_not_silently_admitted_with_an_enabled_dispatch_pool() {
    assert_invalid(
        [10, 10, 10, 4, 2, 0],
        "process pool inventory exceeds the hard per-process connection limit",
    );
}

#[test]
fn every_zero_overflow_and_above_limit_inventory_fails_closed() {
    // Only the first five. The relay's maximum is legitimately zero whenever
    // `[outbox_relay]` is disabled, so refusing a zero there would refuse every
    // cell running the relay off -- which is every cell today.
    for index in 0..5 {
        let mut values = [1, 1, 1, 1, 1, 1];
        values[index] = 0;
        assert_invalid(
            values,
            "every declared process pool maximum must be positive",
        );
    }
    assert!(
        DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0).is_ok(),
        "a zero relay pool is a disabled relay, not an undeclared pool"
    );
    assert_invalid(
        [u32::MAX, 1, 1, 1, 1, 0],
        "process pool inventory overflows the connection count",
    );
    assert_invalid(
        [4, 4, 4, 4, 5, 0],
        "process pool inventory exceeds the hard per-process connection limit",
    );
}

/// CR-032's relay pool is counted, so enabling the relay can push an otherwise
/// legal inventory over the ceiling. That refusal is the point of counting it:
/// the connections are opened either way, and an uncounted pool is a process
/// quietly exceeding a limit the budget exists to enforce.
#[test]
fn enabling_the_relay_can_push_a_legal_inventory_over_the_ceiling() {
    let relay_off = DispatchConnectionBudget::new(5, 5, 4, 2, 1, 0).expect("17 without the relay");
    assert_eq!(relay_off.connections_per_replica(), 17);

    // The same five pools plus CR-032's five relay connections is 22.
    assert_invalid(
        [5, 5, 4, 2, 1, 5],
        "process pool inventory exceeds the hard per-process connection limit",
    );
}

#[test]
fn dispatch_pool_max_must_match_its_declared_inventory_component() {
    let budget = DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0).expect("budget");
    let error = DispatchRuntimePool::new(DispatchPoolConfig {
        postgres_url: "postgresql://runtime@cell.example/cell?sslmode=disable".to_owned(),
        role: DispatchPoolRole::Runtime,
        expected_database_identity: DispatchDatabaseIdentity::new(1, 1)
            .expect("test physical database identity"),
        pool_max: 2,
        connect_timeout: Duration::from_secs(1),
        acquire_timeout: Duration::from_secs(1),
        statement_timeout: Duration::from_secs(1),
        lock_timeout: Duration::from_secs(1),
        tls: DispatchTlsMode::Disabled,
        budget,
    })
    .expect_err("dispatch pool cannot exceed its own declared component");
    assert_eq!(
        error,
        DispatchPoolError::InvalidConfiguration(
            "dispatch pool_max does not match the declared process inventory"
        )
    );
}

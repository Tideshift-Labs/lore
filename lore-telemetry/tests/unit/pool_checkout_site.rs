// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/pool_checkout_site.rs` when the crate's lib test harness was turned off.
use std::time::Duration;

use lore_telemetry::*;

struct TestProvider;

impl InstrumentProvider for TestProvider {
    fn namespace(&self) -> &'static str {
        "test.pool_checkout_site"
    }
}

#[track_caller]
fn helper_site() -> CheckoutSite {
    CheckoutSite::caller()
}

#[test]
fn caller_names_the_line_that_called_a_track_caller_helper() {
    let here = line!() + 1;
    let site = helper_site();
    assert_eq!(site.line(), here);
    assert!(site.file().ends_with("pool_checkout_site.rs"), "{site}");
}

#[test]
fn two_sites_are_tallied_apart_and_ordered_by_checkouts() {
    let metrics = PoolCheckoutSiteMetrics::new(&TestProvider, "domain");
    let first = CheckoutSite::caller();
    let second = CheckoutSite::caller();
    assert_ne!(first, second);

    metrics.record_wait(first, Duration::from_millis(2), AcquireOutcome::Acquired);
    metrics.record_hold(first, Duration::from_millis(10));
    for _ in 0..3 {
        metrics.record_wait(second, Duration::from_millis(4), AcquireOutcome::Acquired);
        metrics.record_hold(second, Duration::from_millis(30));
    }
    metrics.record_wait(second, Duration::from_millis(9), AcquireOutcome::Failed);
    metrics.record_wait(second, Duration::from_millis(9), AcquireOutcome::Abandoned);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.len(), 2);
    let top = snapshot[0];
    assert_eq!(top.site(), second);
    assert_eq!(
        (top.acquired(), top.failed(), top.abandoned(), top.holds()),
        (3, 1, 1, 3)
    );
    assert_eq!(top.wait_mean_ms(), Some(4.0));
    assert_eq!(top.hold_mean_ms(), Some(30.0));
    assert_eq!(top.hold_max_ms(), 30.0);
    let next = snapshot[1];
    assert_eq!(next.site(), first);
    assert_eq!((next.acquired(), next.holds()), (1, 1));
    assert_eq!(next.wait_max_ms(), 2.0);
}

#[tokio::test]
async fn a_cancelled_measure_is_recorded_as_abandoned_at_its_site() {
    let metrics = PoolCheckoutSiteMetrics::new(&TestProvider, "domain");
    let site = CheckoutSite::caller();
    let pending = metrics.measure(site, std::future::pending::<Result<(), ()>>());
    let timed_out = tokio::time::timeout(Duration::from_millis(5), pending).await;
    assert!(timed_out.is_err());
    let ok: Result<u8, ()> = metrics.measure(site, async { Ok(1) }).await;
    assert_eq!(ok, Ok(1));
    let failed: Result<u8, ()> = metrics.measure(site, async { Err(()) }).await;
    assert_eq!(failed, Err(()));

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        (
            snapshot[0].acquired(),
            snapshot[0].failed(),
            snapshot[0].abandoned()
        ),
        (1, 1, 1)
    );
}

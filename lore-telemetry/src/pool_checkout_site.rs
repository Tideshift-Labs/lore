// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Pool checkouts **per call site**: how often each source location checks a
//! connection out, how long it waits, and how long it holds the connection.
//!
//! [`crate::PoolAcquireMetrics`] answers "is this pool contended?". It cannot
//! answer "who is contending it?", because every checkout of one pool shares
//! one label. WP-115 row 79 needed the second answer: a dev cell made about
//! 1,000 domain-pool checkouts a second and nothing said which code made them.
//!
//! The site is the caller's source location, taken with `#[track_caller]`
//! ([`CheckoutSite::caller`]). It is a fixed set bounded by the source, so it
//! is safe as a metric label: no repository, branch, hash, or tenant value can
//! reach it. A checkout helper that wraps `get` must itself be
//! `#[track_caller]` and capture the site synchronously, or every caller of the
//! helper is attributed to the helper's one line.
//!
//! Like `PoolAcquireMetrics`, every recorder keeps an in-process tally beside
//! the OpenTelemetry histograms, fed from the same measurement, so a test or an
//! operator surface can read it without a collector.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::panic::Location;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;

use crate::AcquireOutcome;
use crate::InstrumentProvider;
use crate::METRICS_ACQUIRE_OUTCOME_ATTRIBUTE_NAME;
use crate::METRICS_POOL_ATTRIBUTE_NAME;
use crate::POOL_ACQUIRE_BUCKET_BOUNDARIES_MS;

/// Per-site checkout wait, in milliseconds. Its count per site is the
/// per-site checkout counter.
pub const METRICS_POOL_CHECKOUT_WAIT_METRIC_NAME: &str = "pool_checkout_wait_duration";

/// Per-site time from a successful checkout to the connection's return.
pub const METRICS_POOL_CHECKOUT_HOLD_METRIC_NAME: &str = "pool_checkout_hold_duration";

/// The OpenTelemetry semantic-convention attribute for the source file.
pub const METRICS_CODE_FILEPATH_ATTRIBUTE_NAME: &str = "code.filepath";

/// The OpenTelemetry semantic-convention attribute for the source line.
pub const METRICS_CODE_LINENO_ATTRIBUTE_NAME: &str = "code.lineno";

/// Hold-time bucket boundaries, in milliseconds. A hold runs from a quick
/// single read (well under a millisecond) to a promotion holding one
/// connection across its steps (seconds).
pub const POOL_CHECKOUT_HOLD_BUCKET_BOUNDARIES_MS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
    10000.0, 30000.0,
];

/// The source location that checked a connection out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CheckoutSite {
    file: &'static str,
    line: u32,
}

impl CheckoutSite {
    /// The location of the nearest caller not marked `#[track_caller]`.
    #[track_caller]
    pub fn caller() -> Self {
        Self::from_location(Location::caller())
    }

    /// The site for `location`.
    pub fn from_location(location: &'static Location<'static>) -> Self {
        Self {
            file: location.file(),
            line: location.line(),
        }
    }

    /// The source file, as the compiler recorded it.
    pub const fn file(&self) -> &'static str {
        self.file
    }

    /// The source line.
    pub const fn line(&self) -> u32 {
        self.line
    }
}

impl std::fmt::Display for CheckoutSite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.file, self.line)
    }
}

/// One site's in-process tally.
#[derive(Clone, Copy, Debug, Default)]
struct SiteTally {
    acquired: u64,
    failed: u64,
    abandoned: u64,
    wait_nanos: u64,
    wait_max_nanos: u64,
    holds: u64,
    hold_nanos: u64,
    hold_max_nanos: u64,
}

/// One pool's per-site recorder. Build one per pool and share it.
#[derive(Debug)]
pub struct PoolCheckoutSiteMetrics {
    wait: Histogram<f64>,
    hold: Histogram<f64>,
    pool: Cow<'static, str>,
    tally: Mutex<HashMap<CheckoutSite, SiteTally>>,
}

impl PoolCheckoutSiteMetrics {
    /// Build a recorder for `pool` under `provider`'s namespace.
    pub fn new(provider: &impl InstrumentProvider, pool: impl Into<Cow<'static, str>>) -> Self {
        let meter = provider.meter();
        Self {
            wait: meter
                .f64_histogram(provider.scope_name(METRICS_POOL_CHECKOUT_WAIT_METRIC_NAME))
                .with_unit("milliseconds")
                .with_boundaries(POOL_ACQUIRE_BUCKET_BOUNDARIES_MS.to_vec())
                .build(),
            hold: meter
                .f64_histogram(provider.scope_name(METRICS_POOL_CHECKOUT_HOLD_METRIC_NAME))
                .with_unit("milliseconds")
                .with_boundaries(POOL_CHECKOUT_HOLD_BUCKET_BOUNDARIES_MS.to_vec())
                .build(),
            pool: pool.into(),
            tally: Mutex::new(HashMap::new()),
        }
    }

    fn site_labels(&self, site: CheckoutSite) -> [KeyValue; 3] {
        [
            KeyValue::new(METRICS_POOL_ATTRIBUTE_NAME, self.pool.clone()),
            KeyValue::new(METRICS_CODE_FILEPATH_ATTRIBUTE_NAME, site.file),
            KeyValue::new(METRICS_CODE_LINENO_ATTRIBUTE_NAME, i64::from(site.line)),
        ]
    }

    fn update(&self, site: CheckoutSite, change: impl FnOnce(&mut SiteTally)) {
        // A poisoned lock means a panic while updating a counter; the counts
        // are still usable, so keep counting rather than dropping the sample.
        let mut tally = self
            .tally
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        change(tally.entry(site).or_default());
    }

    /// Record one checkout's wait at `site`.
    pub fn record_wait(&self, site: CheckoutSite, waited: Duration, outcome: AcquireOutcome) {
        let [pool, file, line] = self.site_labels(site);
        let outcome_label = KeyValue::new(
            METRICS_ACQUIRE_OUTCOME_ATTRIBUTE_NAME,
            match outcome {
                AcquireOutcome::Acquired => "acquired",
                AcquireOutcome::Failed => "failed",
                AcquireOutcome::Abandoned => "abandoned",
            },
        );
        self.wait.record(
            waited.as_secs_f64() * 1000.0,
            &[pool, file, line, outcome_label],
        );
        let nanos = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
        self.update(site, |tally| match outcome {
            AcquireOutcome::Acquired => {
                tally.acquired += 1;
                tally.wait_nanos = tally.wait_nanos.saturating_add(nanos);
                tally.wait_max_nanos = tally.wait_max_nanos.max(nanos);
            }
            AcquireOutcome::Failed => tally.failed += 1,
            AcquireOutcome::Abandoned => tally.abandoned += 1,
        });
    }

    /// Record how long a connection checked out at `site` was held.
    pub fn record_hold(&self, site: CheckoutSite, held: Duration) {
        self.hold
            .record(held.as_secs_f64() * 1000.0, &self.site_labels(site));
        let nanos = u64::try_from(held.as_nanos()).unwrap_or(u64::MAX);
        self.update(site, |tally| {
            tally.holds += 1;
            tally.hold_nanos = tally.hold_nanos.saturating_add(nanos);
            tally.hold_max_nanos = tally.hold_max_nanos.max(nanos);
        });
    }

    /// Time `checkout` at `site` and record its wait, classified by how it
    /// ended. A cancelled checkout is recorded as
    /// [`AcquireOutcome::Abandoned`], for the reason
    /// [`crate::PoolAcquireMetrics::measure`] gives.
    pub async fn measure<T, E, F>(&self, site: CheckoutSite, checkout: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut guard = SiteWaitGuard {
            metrics: self,
            site,
            start: Instant::now(),
            outcome: AcquireOutcome::Abandoned,
        };
        let result = checkout.await;
        guard.outcome = if result.is_ok() {
            AcquireOutcome::Acquired
        } else {
            AcquireOutcome::Failed
        };
        result
    }

    /// Every site seen so far, most checkouts first, then by location.
    pub fn snapshot(&self) -> Vec<CheckoutSiteSnapshot> {
        let tally = self
            .tally
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sites: Vec<CheckoutSiteSnapshot> = tally
            .iter()
            .map(|(site, tally)| CheckoutSiteSnapshot {
                site: *site,
                acquired: tally.acquired,
                failed: tally.failed,
                abandoned: tally.abandoned,
                wait_nanos: tally.wait_nanos,
                wait_max_nanos: tally.wait_max_nanos,
                holds: tally.holds,
                hold_nanos: tally.hold_nanos,
                hold_max_nanos: tally.hold_max_nanos,
            })
            .collect();
        sites.sort_by(|a, b| b.acquired.cmp(&a.acquired).then(a.site.cmp(&b.site)));
        sites
    }
}

struct SiteWaitGuard<'a> {
    metrics: &'a PoolCheckoutSiteMetrics,
    site: CheckoutSite,
    start: Instant,
    outcome: AcquireOutcome,
}

impl Drop for SiteWaitGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .record_wait(self.site, self.start.elapsed(), self.outcome);
    }
}

/// One site's tally at a point in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckoutSiteSnapshot {
    site: CheckoutSite,
    acquired: u64,
    failed: u64,
    abandoned: u64,
    wait_nanos: u64,
    wait_max_nanos: u64,
    holds: u64,
    hold_nanos: u64,
    hold_max_nanos: u64,
}

impl CheckoutSiteSnapshot {
    /// The site.
    pub const fn site(&self) -> CheckoutSite {
        self.site
    }

    /// Checkouts at this site that produced a connection.
    pub const fn acquired(&self) -> u64 {
        self.acquired
    }

    /// Checkouts at this site that failed or timed out.
    pub const fn failed(&self) -> u64 {
        self.failed
    }

    /// Checkouts at this site whose caller left while waiting.
    pub const fn abandoned(&self) -> u64 {
        self.abandoned
    }

    /// Connections from this site that have been returned. Lower than
    /// [`Self::acquired`] while some are still held.
    pub const fn holds(&self) -> u64 {
        self.holds
    }

    /// Mean successful wait, in milliseconds.
    pub fn wait_mean_ms(&self) -> Option<f64> {
        (self.acquired > 0).then(|| self.wait_nanos as f64 / self.acquired as f64 / 1_000_000.0)
    }

    /// Longest successful wait, in milliseconds.
    pub fn wait_max_ms(&self) -> f64 {
        self.wait_max_nanos as f64 / 1_000_000.0
    }

    /// Mean hold of the returned connections, in milliseconds.
    pub fn hold_mean_ms(&self) -> Option<f64> {
        (self.holds > 0).then(|| self.hold_nanos as f64 / self.holds as f64 / 1_000_000.0)
    }

    /// Longest hold, in milliseconds.
    pub fn hold_max_ms(&self) -> f64 {
        self.hold_max_nanos as f64 / 1_000_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

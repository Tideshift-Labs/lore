// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-119 Phase 8 and WP-109 Phase 5: the **load and capacity proof** for
//! CR-032's initial admission limits, relay throughput, and Postgres budget.
//!
//! CR-032 states initial limits and then requires them to be earned:
//!
//! > WP-119 must load-test and revise these initial limits before production
//! > activation rather than silently widening them.
//!
//! and WP-109 Phase 5 asks for the connection, latency and capacity numbers a
//! safe replica count is derived from. This file is the instrument that
//! produces both. It is the load-scale sibling of
//! [`outbox_drain_rate.rs`](./outbox_drain_rate.rs), which measured one payload
//! size through an in-process fake and set `ADMISSION_RETRY_DELAY`; this one
//! measures three sizes through the **real** private gateway and a **real**
//! JetStream broker, with one and with two relay workers.
//!
//! # What this proves, and what it does not
//!
//! Every case below is a measurement first. Only the invariants CR-032 states
//! outright are asserted, and a number that suggests an initial limit is wrong
//! is **recorded as evidence with a proposed value**. This file never changes
//! a limit.
//!
//! Four honesty notes, because a load number is worthless without them:
//!
//! * **"Two workers" here means two `EventRelayWorker`s with distinct owners
//!   over one database and one pool, not two operating-system processes.** It
//!   proves the claim/lease fencing under contention and gives an aggregate
//!   drain rate; it does not prove anything about process boundaries. The
//!   process-level exactly-once claim is WP-109 Phase 3's, whose cases B, D and
//!   E run two real `loreserver` binaries
//!   (`lore-integration-tests/tests/run-active-active-two-process-live.ps1`).
//!   Sharing one pool also means the two workers here contend for connections
//!   in a way two processes with their own pools would not, which biases the
//!   two-worker aggregate rate **down**.
//! * **The build is `debug` unless the runner is told otherwise.** A debug
//!   build under-states every rate. The runner prints the profile; a rate
//!   quoted without it is not evidence.
//! * **The gateway, the broker, the database and the test all share one
//!   machine.** Every latency here includes contention a deployed cell would
//!   not have, and excludes network latency a deployed cell would.
//! * **The row and byte admission limits are crossed at *scaled* limits.**
//!   One million rows and 5 GiB are not seedable on a developer machine in a
//!   bounded run. The crossing behaviour is proven against
//!   [`AdmissionLimits`] values this file sets; the **age** limit is crossed at
//!   CR-032's real 300 seconds, by back-dating `unpublished_since`. The probe
//!   cost at the real limits is *extrapolated* from measured cost at seeded
//!   backlogs, and labelled as an extrapolation everywhere it appears.
//!
//! # Four more biases, from cold review of the first run
//!
//! Each one was found by a reviewer who did not write this file, and each
//! moves a number this rig reports:
//!
//! * **The drain rate is an over-estimate, because this loop is not
//!   `EventRelayWorker::run`.** It calls `relay::claim_batch` and
//!   `process_claimed` directly, so it omits what the real loop does between
//!   batches: the readiness backlog probe, the admission refresh, the idle
//!   interval, and the retention sweep beside it. Only the backlog probe is
//!   reproduced here (as the curve sample). Biases the rate **up**, by roughly
//!   one admission probe per `readiness_probe_interval`.
//! * **The gateway latency p99 is truncated whenever a publish times out.**
//!   `PrivateGatewayClient` wraps this transport in a `tokio::time::timeout` at
//!   `publish_deadline`, so a publish that exceeds it is dropped mid-await and
//!   records **no sample**: the slowest publishes are exactly the ones missing.
//!   A run with zero requeued rows had no timeouts and is untruncated, which is
//!   why the outcome tally is printed beside the latency. Biases p99 **down**
//!   when it bites at all. The first sample of each run also carries the lazy
//!   channel's TLS handshake, which biases p99 **up** by one sample in a few
//!   thousand.
//! * **The pool budget is not stressed and cannot be from here.** The drain
//!   loop holds at most one pooled client at a time per worker, so `deadpool`
//!   never opens anywhere near `POOL_MAX` and the measured backend count says
//!   what this loop uses, not what a cell under real RPC load uses. **This rig
//!   cannot establish a safe replica count**; it can only say the relay's own
//!   share is small. WP-109 Phase 5's replica-count question needs the RPC path
//!   loaded too.
//! * **The one-worker and two-worker rates are indicative, not controlled.**
//!   Both sample the curve on the same cadence, but the two-worker case seeds
//!   twice the rows and shares one pool and one process, so the ratio between
//!   them is not a scaling factor.
//!
//! # Running it
//!
//! Through its runner, which provisions everything and prints the results
//! table:
//!
//! ```text
//! pwsh lore-server/tests/run-outbox-load-proof.ps1
//! ```
//!
//! The runner is the only supported entry point: every case needs a gateway,
//! its mTLS material, and a provisioned JetStream stream, and a case whose
//! prerequisites are absent prints `[[NOTRUN]]` and returns rather than
//! passing vacuously.
//!
//! # Measured results
//!
//! 2026-09-04, Lore fork at `dea3841`. Windows 11, PostgreSQL 16 in
//! `lorehub-dataplane-test-postgres-1` on `127.0.0.1:11832`, NATS JetStream on
//! `127.0.0.1:4222`, the gateway from `lorehub/apps/notification-gateway`, cell
//! `sfo3-cell-a`, **debug** build, 2,000 rows per size, all on one machine with
//! other build lanes active. Command:
//! `pwsh lore-server/tests/run-outbox-load-proof.ps1`.
//!
//! ```text
//! event size                bytes   drain s   rows/s   pub p50   pub p99
//! branch.pushed (typical)    1024     12.35      162    2.2 ms    3.6 ms
//! bounded summary           16384     12.45      161    2.3 ms    4.3 ms
//! F-032-2 cap               65536     14.44      138    2.9 ms    7.0 ms
//!
//! two workers, 4,000 rows at 1 KiB   11.35 s   352 rows/s aggregate
//!   4,000 accepted for 4,000 distinct ids, 0 retries, 0 dead letters
//!
//! Postgres backends: baseline 2, one worker peak 3, two workers peak 6,
//!   pool max 8. See the pool-budget bias note above before reading these.
//!
//! admission probe cost at 2,000 pending rows, empty-table floor 2.07 ms
//!   1 KiB 4.79 ms   16 KiB 5.87 ms   64 KiB 4.30 ms
//!   extrapolated to 1,000,000 rows: 1.1 to 1.9 s (an order-of-magnitude
//!   sanity check, not a measurement)
//!
//! real Lore client RESOURCE_EXHAUSTED budget: 538.1 s over 60 attempts
//! ```
//!
//! # What the numbers say about CR-032's initial limits
//!
//! **Confirmed, all four.**
//!
//! * *Relay readiness false above 30 seconds oldest-unpublished age.* A 2,000
//!   row backlog of any of the three widths drains in 12 to 15 seconds, so the
//!   oldest row never approached 30 seconds. The threshold has room at this
//!   scale, and the facet flips at the right place: the readiness case sweeps
//!   1, 29, 30, 31 and 120 seconds of real measured age against the real
//!   `relay::backlog` query and the facet agrees with the contract at every
//!   point.
//! * *Admission closed above five minutes oldest-unpublished age.* Crossed at
//!   the real 300 seconds, in both directions, and it is the age probe that
//!   decides when age and rows are both over -- which is what makes the common
//!   rejection cost one index lookup.
//! * *Admission closed above one million rows or 5 GiB.* Crossing behaviour
//!   holds at scaled limits. The reason the shipped values are not obviously
//!   wrong is the probe cost: extrapolated to a million rows the refresh probe
//!   is on the order of one second, against a five-second
//!   `readiness_probe_interval`, so the cached-verdict design absorbs it.
//! * *`RESOURCE_EXHAUSTED` with `RetryInfo` inside one measured budget.* See
//!   below. This is the one that does not hold.
//!
//! **Contradicted: `ADMISSION_RETRY_DELAY`'s justification, not its value.**
//!
//! That constant's doc comment reasons about "a six-attempt client inside one
//! minute of elapsed time". The shipped Lore client is a sixty-attempt client
//! that retries `RESOURCE_EXHAUSTED` for a measured 538 seconds, and it never
//! reads the server's `RetryInfo` at all. CR-032 blocks activation if generic
//! client retry can exceed one documented budget, so this is an activation
//! question rather than a tuning one.
//!
//! **Proposed record, not applied here.** Changing `ADMISSION_RETRY_DELAY`
//! would achieve nothing, because no client reads it; the value stays as it is.
//! What needs to change is one of two other things, and the choice is not this
//! file's to make: either CR-032's documented budget is written down as at
//! least 538 seconds **per refused RPC** and accepted at that size, or
//! `lore-transport`'s `handle_error` is changed to honour the server's
//! `RetryInfo` -- which CR-032 already anticipates as "a reviewed client-path
//! change rather than multiplying retries", and which is `[CLIENT]`-gated.

#![allow(clippy::print_stdout)]

#[path = "common/case_namespace.rs"]
mod case_namespace;
#[path = "common/relay_harness.rs"]
mod relay_harness;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::AdmissionRejection;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_postgres::domain::outbox::relay::admission_check;
use lore_postgres::domain::outbox::relay::backlog;
use lore_postgres::domain::outbox::relay::claim_batch;
use lore_postgres::pool::Pool;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::event_relay::EventRelayConfig;
use lore_server::event_relay::EventRelayReadiness;
use lore_server::event_relay::EventRelayWorker;
use lore_server::event_relay::RelayBackoff;
use lore_server::event_relay::RetentionConfig;
use lore_server::event_relay::RowOutcome;
use lore_server::event_relay::admission::ADMISSION_RETRY_DELAY;
use lore_server::event_relay::readiness::REASON_OLDEST_UNPUBLISHED;
use lore_server::event_relay::retry_info::retry_info_details;
use lore_server::plugins::remote_notification::client::GrpcPublishTransport;
use lore_server::plugins::remote_notification::client::PrivateGatewayClient;
use lore_server::plugins::remote_notification::client::PublishTransport;
use lore_server::plugins::remote_notification::config::RemoteNotificationConfig;
use lore_server::plugins::remote_notification::wire;

// ---------------------------------------------------------------------------
// The environment contract with the runner
// ---------------------------------------------------------------------------

/// Payload widths under measurement, with the name each one stands for.
///
/// Not arbitrary: 1 KiB is a realistic `branch.pushed` identity/version
/// projection, 16 KiB is a wide bounded summary such as
/// `fragment.lifecycle_generation_advanced` over a large fanout, and 64 KiB is
/// `schema::MAX_PAYLOAD_BYTES` itself -- the widest row the outbox will ever
/// hold, and one byte under what the gateway refuses as `payload_too_large`
/// (`apps/notification-gateway/src/contract.ts`'s `payload_max_bytes`).
const EVENT_SIZES: [(&str, usize); 3] = [
    ("branch.pushed (typical)", 1024),
    ("bounded summary", 16 * 1024),
    ("F-032-2 cap", 64 * 1024),
];

/// Rows seeded per size, unless the runner overrides it.
const DEFAULT_ROWS: i64 = 2_000;

/// Pool size every case builds. Named rather than defaulted so the connection
/// budget below is measured against a stated number.
const POOL_MAX: u32 = 8;

fn pg_url() -> Option<String> {
    non_empty("LORE_TEST_PG_URL")
}

fn non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Below this a "measurement" is noise: the drain finishes inside one claim
/// batch, the latency sample is too small for a p99 to mean anything, and the
/// probe-cost extrapolation scales by ten thousand.
const MIN_ROWS: i64 = 500;

fn seeded_rows() -> i64 {
    let Some(raw) = non_empty("LORE_LOAD_ROWS") else {
        return DEFAULT_ROWS;
    };
    let rows: i64 = raw
        .parse()
        .unwrap_or_else(|_| panic!("LORE_LOAD_ROWS must be an integer, got {raw:?}"));
    // A panic rather than a silent fall back to the default. A run that quietly
    // measured a different backlog than the operator asked for would report a
    // number with the wrong environment beside it, which is worse than not
    // running -- and worse still, it would report it as MEASURED.
    assert!(
        rows >= MIN_ROWS,
        "LORE_LOAD_ROWS={rows} is below the {MIN_ROWS}-row floor; a backlog that small produces \
         noise, not a measurement"
    );
    rows
}

/// The gateway half of the contract. Absent means NOT RUN, never a pass.
struct GatewayEnv {
    uri: String,
    client_cert: String,
    client_key: String,
    trust_roots: String,
}

impl GatewayEnv {
    fn from_process() -> Option<Self> {
        Some(Self {
            uri: non_empty("LORE_LOAD_GATEWAY_URI")?,
            client_cert: non_empty("LORE_LOAD_CLIENT_CERT")?,
            client_key: non_empty("LORE_LOAD_CLIENT_KEY")?,
            trust_roots: non_empty("LORE_LOAD_TRUST_ROOTS")?,
        })
    }

    /// A real `[plugins.remote]` config: same cell, epoch and producer identity
    /// the shared harness uses, so an envelope built from
    /// `relay_harness::envelope_source()` agrees with it, but pointed at the
    /// live gateway with real mTLS material rather than the fake.
    fn config(&self) -> RemoteNotificationConfig {
        let toml_text = format!(
            r#"
            gateway_uri = "{uri}"
            cell_id = "{cell}"
            placement_epoch = {epoch}
            producer_instance_id = "{producer}"
            client_cert_path = "{cert}"
            client_key_path = "{key}"
            trust_roots_path = "{roots}"
            "#,
            uri = self.uri,
            cell = relay_harness::TEST_CELL_ID,
            epoch = relay_harness::TEST_PLACEMENT_EPOCH,
            producer = relay_harness::TEST_PRODUCER_INSTANCE_ID,
            cert = toml_path(&self.client_cert),
            key = toml_path(&self.client_key),
            roots = toml_path(&self.trust_roots),
        );
        let table: toml::Value = toml::from_str(&toml_text).expect("valid TOML");
        RemoteNotificationConfig::parse(&table).expect("valid live-gateway config")
    }
}

/// Backslashes are TOML escapes, so a Windows path pasted into a basic string
/// silently corrupts. Every consumer here accepts forward slashes.
fn toml_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Print the machine-readable NOT RUN marker the runner keys on, and say which
/// variable was missing.
fn not_run(case: &str, reason: &str) {
    println!("[[NOTRUN]] {case} :: {reason}");
}

/// Print the machine-readable marker that says this case produced a real
/// measurement, so the runner can tell a measured pass from an early return.
fn measured(case: &str) {
    println!("[[MEASURED]] {case}");
}

// ---------------------------------------------------------------------------
// The timing transport
// ---------------------------------------------------------------------------

/// Wraps the production transport and records one wall-clock sample per
/// `Publish` call, plus the event id and outcome the gateway answered with.
///
/// This is the closest available point to **gateway acceptance latency**:
/// timing `process_claimed` instead would fold in the claim read and the
/// settle write, and timing the whole batch would fold in the claim query.
/// Nothing here interprets or retries -- it delegates verbatim, exactly as the
/// `PublishTransport` contract requires -- so the classification the client
/// runs is the production one.
///
/// It is not a complete sample, and the module header says which way that
/// cuts: `PrivateGatewayClient` applies its `publish_deadline` timeout
/// **outside** this call, so a publish that exceeds the deadline is dropped
/// before it records anything, and the tail loses exactly its slowest members.
/// Read the p99 next to the outcome tally: zero requeued rows means no publish
/// timed out and nothing was dropped.
#[derive(Debug)]
struct TimingTransport {
    inner: GrpcPublishTransport,
    samples: Mutex<Vec<Duration>>,
    /// Event ids the gateway was asked to accept, in call order.
    ///
    /// A duplicate here is a **retry**, not a violation: a transient publish
    /// failure legitimately re-offers the same row with its original keys. It
    /// is recorded and reported, never asserted on.
    offered: Mutex<Vec<Vec<u8>>>,
    /// Event ids the gateway **accepted**, in call order.
    ///
    /// A duplicate here is a double publish **only when the same id was never
    /// re-offered**. A publish that timed out client-side may already have been
    /// accepted by the broker, and its retry is then accepted again -- which is
    /// the at-least-once delivery contract, not a fence failure. The two lists
    /// are kept apart so a caller can tell those cases apart; neither list
    /// alone can.
    accepted_ids: Mutex<Vec<Vec<u8>>>,
    non_accepted: Mutex<u64>,
}

impl TimingTransport {
    fn new(inner: GrpcPublishTransport) -> Self {
        Self {
            inner,
            samples: Mutex::new(Vec::new()),
            offered: Mutex::new(Vec::new()),
            accepted_ids: Mutex::new(Vec::new()),
            non_accepted: Mutex::new(0),
        }
    }

    fn latencies(&self) -> Vec<Duration> {
        self.samples.lock().expect("timing samples").clone()
    }

    fn offered_ids(&self) -> Vec<Vec<u8>> {
        self.offered.lock().expect("offered ids").clone()
    }

    fn accepted_ids(&self) -> Vec<Vec<u8>> {
        self.accepted_ids.lock().expect("accepted ids").clone()
    }

    fn non_accepted_count(&self) -> u64 {
        *self.non_accepted.lock().expect("non-accepted count")
    }
}

#[async_trait::async_trait]
impl PublishTransport for TimingTransport {
    async fn publish(
        &self,
        envelope: wire::PrivateEnvelopeV1,
    ) -> Result<wire::PublishResultV1, tonic::Status> {
        let event_id = envelope.event_id.to_vec();
        let started = Instant::now();
        let result = self.inner.publish(envelope).await;
        let elapsed = started.elapsed();
        self.samples.lock().expect("timing samples").push(elapsed);
        self.offered
            .lock()
            .expect("offered ids")
            .push(event_id.clone());
        match &result {
            Ok(answer) if answer.outcome == wire::PublishOutcomeV1::Accepted as i32 => {
                self.accepted_ids
                    .lock()
                    .expect("accepted ids")
                    .push(event_id);
            }
            _ => {
                *self.non_accepted.lock().expect("non-accepted count") += 1;
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Percentiles
// ---------------------------------------------------------------------------

/// Nearest-rank percentile over a sorted sample.
///
/// Nearest-rank rather than an interpolating definition on purpose: with a few
/// thousand samples the two agree to well inside the run-to-run spread, and
/// nearest-rank always reports a value that was actually observed, which is
/// what a latency table should say.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Bulk-seed `count` pending rows of `payload_bytes` each, in one statement.
///
/// Deliberately not the production `append()` path, for the reason
/// `outbox_drain_rate.rs` records: one transaction per row would take longer
/// than the drain under measurement, and the relay is what is being measured.
/// Every column is still shaped so `envelope_map::map_event` accepts the row,
/// and the first batch's outcomes are asserted, so a seed that drifted out of
/// that shape fails loudly instead of measuring a rejection loop.
///
/// Two details are load-bearing and are the real differences from the
/// drain-rate seed:
///
/// **`salt`.** The idempotency key reaches the broker as the message's dedupe
/// identity, and this rig publishes into a **long-lived** JetStream stream
/// that outlives a run. A second run reusing the first run's keys would be
/// answered from the broker's dedupe window rather than accepted, and the
/// measured rate would be of deduplication rather than of publication.
///
/// **An incompressible payload.** `payload` is `bytea`, whose storage is
/// `extended`, so PostgreSQL compresses before it TOASTs. A payload of one
/// repeated byte -- which the drain-rate instrument used, at a width where it
/// did not matter -- compresses to almost nothing, and then a 64 KiB row costs
/// the database about what a 1 KiB row costs. That would flatten the size
/// curve this case exists to measure and would report the flatness as a
/// property of the relay. Random bytes do not compress, so the stored width is
/// the declared width. Caught in cold review of the first run, whose 1/16/64
/// KiB rates were 157/168/133 rows per second -- a curve with no size in it.
async fn seed_pending(
    url: &str,
    repository_id: &[u8],
    salt: &[u8],
    payload_bytes: usize,
    count: i64,
) -> Duration {
    let client = relay_harness::raw_client(url).await;
    let payload: Vec<u8> = (0..payload_bytes).map(|_| rand::random()).collect();
    let started = Instant::now();
    client
        .execute(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, \
                 repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, \
                 state, created_at, available_at, unpublished_since \
             ) \
             SELECT gen_random_uuid(), $1, sha256($5 || int8send(i)), \
                    $2, 1, \
                    'branch.pushed', 'branch', sha256($5 || int8send(i + 1000000000)), \
                    int8send(i), \
                    1, $3, \
                    'pending', clock_timestamp(), clock_timestamp(), clock_timestamp() \
               FROM generate_series(1, $4::bigint) AS i",
            &[
                &relay_harness::TEST_CELL_ID,
                &repository_id,
                &payload,
                &count,
                &salt,
            ],
        )
        .await
        .expect("bulk seed pending outbox rows");
    started.elapsed()
}

/// A fresh 16-byte salt for this run's keys.
fn run_salt() -> [u8; 16] {
    rand::random()
}

// ---------------------------------------------------------------------------
// Probes taken beside the pool, never through it
// ---------------------------------------------------------------------------

/// Backends currently connected to this database.
///
/// Taken over the harness's own raw connection rather than a pooled one: a
/// probe that borrows from the pool it is measuring changes the number it
/// reports. The absolute value includes this harness's own connections, so
/// every case records a baseline before the drain and reports the delta as the
/// relay's own use.
async fn database_backends(client: &tokio_postgres::Client) -> i64 {
    client
        .query_one(
            "SELECT count(*)::bigint AS backends FROM pg_stat_activity \
               WHERE datname = current_database()",
            &[],
        )
        .await
        .expect("pg_stat_activity probe")
        .get("backends")
}

/// One sample of the backlog curve during a drain.
#[derive(Debug, Clone, Copy)]
struct CurvePoint {
    elapsed: Duration,
    oldest_age: Option<Duration>,
    pending: i64,
    backends: i64,
}

/// Move every pending row's `unpublished_since` back by `seconds`.
///
/// `unpublished_since` rather than `created_at`, because that is the column
/// both `relay::backlog` and `relay::admission_check` read for age. Writing
/// `created_at` instead would produce a rig that looks like it aged the
/// backlog and measures nothing -- see WP-119 Phase 8's own recovery-clock
/// defect for the same column being the load-bearing one.
async fn backdate_pending(client: &tokio_postgres::Client, seconds: i64) -> u64 {
    client
        .execute(
            "UPDATE lore_outbox_events \
                SET unpublished_since = clock_timestamp() - ($1::bigint * interval '1 second') \
              WHERE state = 'pending'",
            &[&seconds],
        )
        .await
        .expect("back-date pending rows")
}

// ---------------------------------------------------------------------------
// Worker construction
// ---------------------------------------------------------------------------

/// A relay config with CR-032's **real** timings, not the fast test ones.
///
/// `relay_harness::fast_test_config` shortens `claim_lease` to 300ms and
/// `publish_deadline` to 100ms so a reclaim-after-expiry case need not wait 30
/// seconds. Both would corrupt a load measurement: a 300ms lease expires
/// mid-publish under real gateway latency and every row would be fenced and
/// re-claimed, and a 100ms deadline would time out publishes the deployed cell
/// would complete. So this builds the shipped shape instead.
fn load_config(owner: &str, admission: AdmissionLimits) -> EventRelayConfig {
    EventRelayConfig {
        enabled: true,
        owner: owner.to_string(),
        batch_size: MAX_CLAIM_BATCH,
        claim_lease: Duration::from_secs(30),
        publish_deadline: Duration::from_secs(10),
        idle_interval: Duration::from_millis(200),
        backoff: RelayBackoff {
            base: Duration::from_millis(200),
            cap: Duration::from_secs(10),
        },
        readiness_probe_interval: Duration::from_secs(5),
        max_oldest_unpublished: Duration::from_secs(30),
        admission,
        retention: RetentionConfig::default(),
    }
}

fn build_live_worker(
    pool: Pool,
    config: &RemoteNotificationConfig,
    transport: Arc<TimingTransport>,
    owner: &str,
) -> EventRelayWorker {
    let publisher = Arc::new(PrivateGatewayClient::with_transport(config, transport));
    let relay_config = load_config(owner, AdmissionLimits::default());
    let readiness = Arc::new(EventRelayReadiness::new(
        relay_config.max_oldest_unpublished,
        relay_config.readiness_probe_interval,
        relay_config.publish_deadline,
    ));
    EventRelayWorker::new(
        pool,
        publisher,
        relay_config,
        readiness,
        relay_harness::envelope_source(),
    )
}

/// Outcome tallies for one drain.
#[derive(Debug, Default, Clone, Copy)]
struct Outcomes {
    accepted: u64,
    requeued: u64,
    dead_lettered: u64,
    fenced: u64,
    duplicate: u64,
    deferred: u64,
}

impl Outcomes {
    fn record(&mut self, outcome: RowOutcome) {
        match outcome {
            RowOutcome::Accepted => self.accepted += 1,
            RowOutcome::Requeued => self.requeued += 1,
            RowOutcome::DeadLettered => self.dead_lettered += 1,
            RowOutcome::Fenced => self.fenced += 1,
            RowOutcome::Duplicate => self.duplicate += 1,
            RowOutcome::Deferred => self.deferred += 1,
        }
    }

    fn merge(&mut self, other: Outcomes) {
        self.accepted += other.accepted;
        self.requeued += other.requeued;
        self.dead_lettered += other.dead_lettered;
        self.fenced += other.fenced;
        self.duplicate += other.duplicate;
        self.deferred += other.deferred;
    }
}

/// Claim and process until the backlog is empty, sampling the curve between
/// batches.
///
/// An empty claim does **not** end the drain on its own. A row that hit a
/// transient publish failure goes back to `pending` with a backoff-delayed
/// `available_at`, so the claim query correctly returns nothing for a moment
/// while the backlog is not yet empty. Breaking there would end the drain with
/// rows still owed and report a rate over a partial backlog -- so the loop
/// only stops when the **backlog probe** says zero, or the deadline passes.
///
/// `deadline` bounds the whole drain: a gateway that started refusing every
/// row would otherwise loop until the harness timed out, and a hung case
/// reports nothing. Hitting it is a measured fact the caller's assertions
/// catch, not a silent truncation.
async fn drain(
    pool: &Pool,
    probe: &tokio_postgres::Client,
    worker: &EventRelayWorker,
    owner: &str,
    deadline: Duration,
    curve: Option<&Mutex<Vec<CurvePoint>>>,
) -> (Outcomes, u64) {
    let started = Instant::now();
    let mut outcomes = Outcomes::default();
    let mut batches = 0_u64;
    loop {
        if started.elapsed() > deadline {
            break;
        }
        let claimed = {
            let mut client = pool.get().await.expect("checkout pool client");
            claim_batch(&mut client, owner, MAX_CLAIM_BATCH, Duration::from_secs(30))
                .await
                .expect("claim_batch")
        };
        if claimed.is_empty() {
            let remaining = {
                let client: &tokio_postgres::Client = probe;
                backlog(client).await.expect("backlog probe").pending_count
            };
            if remaining == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        for row in claimed {
            outcomes.record(worker.process_claimed(row).await);
        }
        batches += 1;
        if let Some(curve) = curve {
            let observed = {
                let client: &tokio_postgres::Client = probe;
                backlog(client).await.expect("backlog probe")
            };
            let backends = database_backends(probe).await;
            curve.lock().expect("curve").push(CurvePoint {
                elapsed: started.elapsed(),
                oldest_age: observed.oldest_pending_age,
                pending: observed.pending_count,
                backends,
            });
        }
    }
    (outcomes, batches)
}

// ---------------------------------------------------------------------------
// Case 1: drain rate and gateway latency at three event sizes
// ---------------------------------------------------------------------------

/// One worker, real gateway, real broker, three payload widths.
///
/// Produces the rows/second, oldest-age curve and gateway acceptance
/// p50/p99 that WP-109 Phase 5 asks for, at the three widths CR-032's payload
/// cap makes possible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load instrument; needs live Postgres, gateway and broker (see run-outbox-load-proof.ps1)"]
async fn measure_drain_rate_and_gateway_latency_at_three_event_sizes() {
    const CASE: &str = "drain-sizes";
    let Some(base_url) = pg_url() else {
        not_run(CASE, "LORE_TEST_PG_URL is unset");
        return;
    };
    let Some(gateway) = GatewayEnv::from_process() else {
        not_run(
            CASE,
            "one of LORE_LOAD_GATEWAY_URI/CLIENT_CERT/CLIENT_KEY/TRUST_ROOTS is unset",
        );
        return;
    };
    let config = gateway.config();
    let rows = seeded_rows();

    println!("=== drain rate and gateway latency by event size ===");

    // A warm-up drain whose numbers are thrown away.
    //
    // Measured, not assumed: across three runs the FIRST size in the sweep came
    // out at 48, 109 and 157 rows per second while the two after it sat inside
    // a narrow band, and the ordering never changed. The first case pays the
    // lazy channel's TLS handshake, a cold buffer cache, the freshly written
    // test binary's page-ins, and whatever a sibling `cargo` build is doing to
    // the machine. Charging all of that to whichever payload width happens to
    // be first would report it as a property of that width.
    //
    // It does not fix the machine being shared -- nothing here can -- but it
    // moves the systematic part of that cost out of the measured sweep.
    {
        let warmup = CaseNamespace::acquire(&base_url, "load-warm").await;
        let warmup_url = warmup.pg_url().to_owned();
        let pool = build_load_pool(&warmup_url).await;
        let probe = relay_harness::raw_client(&warmup_url).await;
        seed_pending(
            &warmup_url,
            &relay_harness::rand_repository_id(),
            &run_salt(),
            1024,
            200,
        )
        .await;
        let transport = Arc::new(TimingTransport::new(
            GrpcPublishTransport::connect_lazy(&config).expect("live gateway transport"),
        ));
        let worker = build_live_worker(pool.clone(), &config, transport, "load-warmup");
        let (outcomes, _) = drain(
            &pool,
            &probe,
            &worker,
            "load-warmup",
            Duration::from_secs(120),
            None,
        )
        .await;
        println!(
            "warm-up drain (discarded): {} rows accepted",
            outcomes.accepted
        );
        warmup.release().await;
    }

    println!(
        "{:<26} {:>7} {:>9} {:>8} {:>9} {:>9} {:>9} {:>8} {:>8}",
        "event size",
        "bytes",
        "seed s",
        "drain s",
        "rows/s",
        "pub p50ms",
        "pub p99ms",
        "peak pg",
        "batches"
    );

    for (label, payload_bytes) in EVENT_SIZES {
        let namespace = CaseNamespace::acquire(&base_url, "load-size").await;
        let url = namespace.pg_url().to_owned();
        let pool = build_load_pool(&url).await;
        let probe = relay_harness::raw_client(&url).await;
        let repository_id = relay_harness::rand_repository_id();
        let salt = run_salt();

        let seed_elapsed = seed_pending(&url, &repository_id, &salt, payload_bytes, rows).await;
        let before = {
            let client: &tokio_postgres::Client = &probe;
            backlog(client).await.expect("backlog probe")
        };
        assert_eq!(
            before.pending_count, rows,
            "the seed must produce exactly the backlog under measurement"
        );
        let baseline_backends = database_backends(&probe).await;

        let transport = Arc::new(TimingTransport::new(
            GrpcPublishTransport::connect_lazy(&config).expect("live gateway transport"),
        ));
        let owner = format!("load-{payload_bytes}");
        let worker = build_live_worker(pool.clone(), &config, transport.clone(), &owner);

        let curve = Mutex::new(Vec::new());
        let started = Instant::now();
        let (outcomes, batches) = drain(
            &pool,
            &probe,
            &worker,
            &owner,
            Duration::from_secs(480),
            Some(&curve),
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(
            outcomes.accepted, rows as u64,
            "every seeded row must be accepted by the real gateway; outcomes were {outcomes:?}. \
             Fewer accepted than seeded means the drain ended owing rows, and the rate below \
             would be over a partial backlog."
        );
        assert_eq!(
            outcomes.dead_lettered, 0,
            "a dead letter means the gateway refused a row terminally; this run measured a \
             rejection path, not a drain: {outcomes:?}"
        );
        // A single-worker drain has no second claimant, so a fence or a
        // duplicate would mean the claim CAS itself misbehaved.
        assert_eq!(outcomes.fenced, 0, "single worker, so nothing may fence it");
        assert_eq!(
            outcomes.duplicate, 0,
            "single worker, so no row may already have been published"
        );
        let accepted_ids = transport.accepted_ids();
        let offered_ids = transport.offered_ids();
        let distinct_accepted: HashSet<Vec<u8>> = accepted_ids.iter().cloned().collect();
        assert_eq!(
            distinct_accepted.len(),
            rows as usize,
            "every seeded row must have been accepted"
        );
        // Only meaningful when nothing was re-offered; see case 2's longer note
        // on why a duplicate acceptance after a retry is the delivery contract
        // rather than a violation.
        if offered_ids.len() == rows as usize {
            assert_eq!(
                distinct_accepted.len(),
                accepted_ids.len(),
                "no row was re-offered, so a duplicate acceptance has no innocent explanation: {} \
                 accepts for {} distinct ids",
                accepted_ids.len(),
                distinct_accepted.len()
            );
        }

        let after = {
            let client: &tokio_postgres::Client = &probe;
            backlog(client).await.expect("backlog probe")
        };
        assert_eq!(after.pending_count, 0, "the backlog must be empty");

        let mut latencies = transport.latencies();
        latencies.sort_unstable();
        let points = curve.lock().expect("curve").clone();
        let peak_backends = points.iter().map(|p| p.backends).max().unwrap_or(0);
        let rows_per_second = rows as f64 / elapsed.as_secs_f64();

        println!(
            "{label:<26} {payload_bytes:>7} {:>9.2} {:>8.2} {rows_per_second:>9.0} {:>9.1} \
             {:>9.1} {peak_backends:>8} {batches:>8}",
            seed_elapsed.as_secs_f64(),
            elapsed.as_secs_f64(),
            ms(percentile(&latencies, 50.0)),
            ms(percentile(&latencies, 99.0)),
        );
        println!(
            "    baseline pg backends {baseline_backends}, pool max {POOL_MAX}, \
             relay-attributable peak {}",
            peak_backends - baseline_backends
        );
        println!(
            "    gateway answers: accepted {} non-accepted {} (retries: {} offers for {} rows), \
             outcomes {outcomes:?}",
            accepted_ids.len(),
            transport.non_accepted_count(),
            offered_ids.len(),
            rows
        );
        print_curve(&points);

        namespace.release().await;
    }
    measured(CASE);
}

async fn build_load_pool(url: &str) -> Pool {
    relay_harness::ensure_schema_bootstrapped(url).await;
    build_pool(url, POOL_MAX, &TlsConfig::default()).expect("build load pool")
}

/// The oldest-unpublished-age curve, thinned to at most eight rows.
///
/// Printed rather than asserted: CR-032's 30-second relay-readiness threshold
/// is asserted against real database facts in
/// [`readiness_flips_at_the_thirty_second_oldest_unpublished_threshold`]; here
/// the curve is evidence of whether a seeded backlog crosses it during an
/// ordinary drain.
fn print_curve(points: &[CurvePoint]) {
    if points.is_empty() {
        return;
    }
    let step = points.len().div_ceil(8).max(1);
    println!("    oldest-age curve (t s / oldest s / pending / pg backends)");
    for point in points.iter().step_by(step) {
        println!(
            "      {:>7.2}  {:>8}  {:>8}  {:>4}",
            point.elapsed.as_secs_f64(),
            point
                .oldest_age
                .map(|a| format!("{:.2}", a.as_secs_f64()))
                .unwrap_or_else(|| "-".to_string()),
            point.pending,
            point.backends
        );
    }
    let crossed = points
        .iter()
        .filter_map(|p| p.oldest_age)
        .any(|age| age > Duration::from_secs(30));
    println!(
        "    crossed CR-032's 30s relay-readiness threshold during the drain: {}",
        if crossed { "YES" } else { "no" }
    );
}

// ---------------------------------------------------------------------------
// Case 2: two workers over one backlog
// ---------------------------------------------------------------------------

/// Two relay workers with distinct owners drain one backlog.
///
/// The invariant asserted is CR-032's: **no row is published twice**. It is
/// asserted three ways, because each alone is defeatable --
///
/// * the outcome tally: exactly `rows` accepted across both workers and no
///   more processed outcomes than rows;
/// * the transport's own record: the set of event ids offered to the gateway
///   has exactly `rows` distinct members and exactly `rows` entries, so no id
///   was offered twice; and
/// * the database: every row is in one terminal state.
///
/// See this module's honesty note about what "two workers" does and does not
/// mean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load instrument; needs live Postgres, gateway and broker (see run-outbox-load-proof.ps1)"]
async fn measure_two_workers_draining_one_backlog_without_publishing_a_row_twice() {
    const CASE: &str = "two-workers";
    let Some(base_url) = pg_url() else {
        not_run(CASE, "LORE_TEST_PG_URL is unset");
        return;
    };
    let Some(gateway) = GatewayEnv::from_process() else {
        not_run(
            CASE,
            "one of LORE_LOAD_GATEWAY_URI/CLIENT_CERT/CLIENT_KEY/TRUST_ROOTS is unset",
        );
        return;
    };
    let config = gateway.config();
    let rows = seeded_rows() * 2;

    let namespace = CaseNamespace::acquire(&base_url, "load-2w").await;
    let url = namespace.pg_url().to_owned();
    let pool = build_load_pool(&url).await;
    let probe = relay_harness::raw_client(&url).await;
    let repository_id = relay_harness::rand_repository_id();
    let salt = run_salt();

    let seed_elapsed = seed_pending(&url, &repository_id, &salt, 1024, rows).await;
    let baseline_backends = database_backends(&probe).await;

    // One shared transport across both workers, so the offered-id record below
    // covers every publish either of them made. Two transports would each hold
    // half the evidence and neither could see a cross-worker duplicate.
    let transport = Arc::new(TimingTransport::new(
        GrpcPublishTransport::connect_lazy(&config).expect("live gateway transport"),
    ));
    let worker_a = Arc::new(build_live_worker(
        pool.clone(),
        &config,
        transport.clone(),
        "load-worker-a",
    ));
    let worker_b = Arc::new(build_live_worker(
        pool.clone(),
        &config,
        transport.clone(),
        "load-worker-b",
    ));

    // Both workers sample into ONE curve, on the same per-batch cadence case 1
    // uses. That is not decoration: without it this case would carry two extra
    // queries per batch fewer than case 1, and the one-worker-to-two-worker
    // comparison below would credit the second worker with case 1's sampling
    // overhead. It is also the only way the backend count is a peak rather
    // than a single post-drain reading.
    let curve: Arc<Mutex<Vec<CurvePoint>>> = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for (worker, owner) in [(worker_a, "load-worker-a"), (worker_b, "load-worker-b")] {
        let pool = pool.clone();
        let url = url.clone();
        let curve = curve.clone();
        lore_base::lore_spawn!(tasks, async move {
            let probe = relay_harness::raw_client(&url).await;
            drain(
                &pool,
                &probe,
                &worker,
                owner,
                Duration::from_secs(480),
                Some(curve.as_ref()),
            )
            .await
        });
    }
    let mut combined = Outcomes::default();
    let mut batches = 0_u64;
    while let Some(joined) = tasks.join_next().await {
        let (outcomes, worker_batches) = joined.expect("relay worker task");
        combined.merge(outcomes);
        batches += worker_batches;
    }
    let elapsed = started.elapsed();

    // 1. Outcome tally.
    assert_eq!(
        combined.accepted, rows as u64,
        "both workers together must accept exactly the seeded backlog: {combined:?}"
    );

    // 2. The transport's own record of what the gateway ACCEPTED.
    //
    // Acceptance, not offers: a re-offer after a transient failure is ordinary
    // at-least-once behaviour, and asserting on offers would fail on it.
    //
    // But a second ACCEPTANCE is not automatically a violation either, and the
    // first version of this case wrongly said it was. A publish that times out
    // client-side may already have been accepted by the broker; the retry is
    // then accepted a second time, and that is the delivery contract working,
    // not the claim fence failing. What distinguishes the two is whether the
    // row was ever offered more than once: with no retries at all, a duplicate
    // acceptance has no innocent explanation and means two workers published
    // one row.
    let offered = transport.offered_ids();
    let accepted_ids = transport.accepted_ids();
    let distinct: HashSet<Vec<u8>> = accepted_ids.iter().cloned().collect();
    let retries = offered.len().saturating_sub(rows as usize);
    assert_eq!(
        distinct.len(),
        rows as usize,
        "every seeded row must have been accepted by the gateway"
    );
    let duplicate_acceptances = accepted_ids.len() - distinct.len();
    if retries == 0 {
        assert_eq!(
            duplicate_acceptances,
            0,
            "no row was ever re-offered, so a duplicate acceptance has no innocent explanation: \
             {} acceptances for {} distinct ids means the claim fence let two workers publish one \
             row",
            accepted_ids.len(),
            distinct.len()
        );
    } else {
        assert!(
            duplicate_acceptances <= retries,
            "there were {retries} re-offers but {duplicate_acceptances} duplicate acceptances; a \
             duplicate acceptance with no re-offer behind it is a double publish"
        );
        println!(
            "NOTE: {retries} re-offer(s) and {duplicate_acceptances} duplicate acceptance(s). \
             Each duplicate is accounted for by a retry, so this is at-least-once delivery, not a \
             fence failure -- but the drain rate above was measured over a run that retried."
        );
    }

    // 3. The database's own answer, over a connection neither worker owns.
    let states: Vec<(String, i64)> = probe
        .query(
            "SELECT state, count(*)::bigint AS n FROM lore_outbox_events GROUP BY state \
             ORDER BY state",
            &[],
        )
        .await
        .expect("state census")
        .into_iter()
        .map(|row| (row.get("state"), row.get("n")))
        .collect();
    assert_eq!(
        states,
        vec![("broker_accepted".to_string(), rows)],
        "every row must be in exactly one terminal state after the drain"
    );

    let mut latencies = transport.latencies();
    latencies.sort_unstable();
    let points = curve.lock().expect("curve").clone();
    let peak_backends = points
        .iter()
        .map(|p| p.backends)
        .max()
        .unwrap_or(baseline_backends);

    println!("=== two workers over one backlog ===");
    println!("seeded rows            {rows} at 1024 bytes");
    println!("seed elapsed           {:.2}s", seed_elapsed.as_secs_f64());
    println!("drain elapsed          {:.2}s", elapsed.as_secs_f64());
    println!(
        "aggregate rows/second  {:.0}",
        rows as f64 / elapsed.as_secs_f64()
    );
    println!("claim batches          {batches} (both workers, batch {MAX_CLAIM_BATCH})");
    println!(
        "publish p50 / p99      {:.1}ms / {:.1}ms",
        ms(percentile(&latencies, 50.0)),
        ms(percentile(&latencies, 99.0))
    );
    println!("outcomes               {combined:?}");
    println!(
        "gateway acceptances    {} for {} distinct ids ({} total offers, so {} retries)",
        accepted_ids.len(),
        distinct.len(),
        offered.len(),
        offered.len().saturating_sub(accepted_ids.len())
    );
    println!(
        "pg backends            baseline {baseline_backends}, peak {peak_backends}, pool max {POOL_MAX} per pool (ONE shared pool here)"
    );

    namespace.release().await;
    measured(CASE);
}

// ---------------------------------------------------------------------------
// Case 3: readiness at the 30-second threshold, against real database facts
// ---------------------------------------------------------------------------

/// CR-032: "healthy relay oldest-unpublished age at most 30 seconds;
/// degraded/event-readiness false above 30 seconds".
///
/// `readiness.rs`'s own unit tests already pin this against a hand-built
/// `OutboxBacklog`. This asserts the same threshold against a backlog the real
/// `relay::backlog` query read out of a real database, which is the half a
/// synthetic struct cannot cover: it proves the age the query computes from
/// `unpublished_since` is the age the facet compares.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "load instrument; needs live Postgres (see run-outbox-load-proof.ps1)"]
async fn readiness_flips_at_the_thirty_second_oldest_unpublished_threshold() {
    const CASE: &str = "readiness-threshold";
    let Some(base_url) = pg_url() else {
        not_run(CASE, "LORE_TEST_PG_URL is unset");
        return;
    };

    let namespace = CaseNamespace::acquire(&base_url, "load-ready").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let probe = relay_harness::raw_client(&url).await;
    let repository_id = relay_harness::rand_repository_id();
    let salt = run_salt();
    seed_pending(&url, &repository_id, &salt, 1024, 64).await;

    println!("=== relay readiness at the 30s oldest-unpublished threshold ===");
    println!(
        "{:<18} {:>12} {:>12} {:>34}",
        "backdated to", "measured s", "relay_ready", "reason"
    );

    // The assertion below is against the **measured** age, never the
    // back-dating target, and that distinction is the whole correctness of
    // this case. A row back-dated to exactly 30 seconds measures 30.01 by the
    // time `backlog` reads it, because real time passes between the UPDATE and
    // the SELECT. The first version of this case asserted "back-dated to 30
    // must be ready" and failed -- correctly, on its own bad premise, since
    // the facet had been handed 30.01 seconds and CR-032 says false above 30.
    //
    // So the exact-boundary equality case is **unreachable through a real
    // database clock** and is not attempted here; `readiness.rs`'s
    // `the_threshold_itself_is_still_ready` pins it against a synthetic
    // backlog, which is the right layer for it. What this case covers is the
    // half that unit test cannot: that the age `relay::backlog` computes from
    // `unpublished_since` is the age the facet compares, over a real database.
    let mut observations = Vec::new();
    for seconds in [1_i64, 29, 30, 31, 120] {
        backdate_pending(&probe, seconds).await;
        let observed = {
            let client: &tokio_postgres::Client = &probe;
            backlog(client).await.expect("backlog probe")
        };
        let readiness = EventRelayReadiness::new(
            Duration::from_secs(30),
            Duration::from_secs(5),
            Duration::from_secs(10),
        );
        readiness.set_loop_running(true);
        readiness.record_backlog(&observed);
        let snapshot = readiness.snapshot();
        println!(
            "{:<18} {:>12.2} {:>12} {:>34}",
            format!("-{seconds}s"),
            observed
                .oldest_pending_age
                .map(|a| a.as_secs_f64())
                .unwrap_or(0.0),
            snapshot.relay_ready,
            snapshot.relay_reason.unwrap_or("-")
        );
        let measured_age = observed
            .oldest_pending_age
            .expect("a seeded backlog always has an oldest pending row");
        observations.push((
            seconds,
            measured_age,
            snapshot.relay_ready,
            snapshot.relay_reason,
        ));
    }

    let mut saw_ready = false;
    let mut saw_unready = false;
    for (seconds, measured_age, ready, reason) in observations {
        if measured_age <= Duration::from_secs(30) {
            saw_ready = true;
            assert!(
                ready,
                "CR-032 says the relay facet is false ABOVE 30 seconds, and this observation \
                 measured {measured_age:?} (back-dated {seconds}s), so it must be ready; reason \
                 was {reason:?}"
            );
        } else {
            saw_unready = true;
            assert!(
                !ready,
                "{measured_age:?} of measured lag (back-dated {seconds}s) is above 30 seconds and \
                 must fail the relay facet"
            );
            assert_eq!(
                reason,
                Some(REASON_OLDEST_UNPUBLISHED),
                "the facet must fail for the lag it measured, not for some other reason -- a \
                 negative that passes for the wrong reason proves nothing"
            );
        }
    }
    // Without both, this case could pass having only ever seen one side of the
    // threshold, which is the shape of a probe that cannot tell "it held" from
    // "it never ran".
    assert!(
        saw_ready && saw_unready,
        "the sweep must observe the facet on BOTH sides of the threshold"
    );

    namespace.release().await;
    measured(CASE);
}

// ---------------------------------------------------------------------------
// Case 4: admission closes and reopens, and what the probe costs
// ---------------------------------------------------------------------------

/// The admission gate's three limits, crossed in both directions, plus the
/// probe cost that answers `relay::admission_check`'s own open TODO.
///
/// The **age** limit is crossed at CR-032's real 300 seconds. The row and byte
/// limits are crossed at scaled values, for the reason this module's header
/// records, and the real limits' probe cost is extrapolated from measured
/// cost -- labelled as such in the output.
///
/// It also asserts the CR-032 property that makes this gate legal at all:
/// **admission closes only from local facts**. That is proven by observation
/// rather than by reading the signature -- the verdict is taken with the
/// gateway credential pointed at a port with nothing on it, so a gate that
/// consulted broker or gateway health could not answer `Admit` at all, and the
/// verdict is shown to track only the rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "load instrument; needs live Postgres (see run-outbox-load-proof.ps1)"]
async fn admission_closes_and_reopens_as_the_backlog_crosses_each_limit() {
    const CASE: &str = "admission-limits";
    let Some(base_url) = pg_url() else {
        not_run(CASE, "LORE_TEST_PG_URL is unset");
        return;
    };
    let rows = seeded_rows();

    let namespace = CaseNamespace::acquire(&base_url, "load-admit").await;
    let url = namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&url).await;
    let probe = relay_harness::raw_client(&url).await;
    let repository_id = relay_harness::rand_repository_id();
    let salt = run_salt();

    println!("=== admission limits: crossing and probe cost ===");

    // -- the AGE limit, at CR-032's real 300 seconds -----------------------
    seed_pending(&url, &repository_id, &salt, 1024, rows).await;
    let real_limits = AdmissionLimits::default();
    assert_eq!(
        real_limits.max_oldest_pending_age,
        Duration::from_secs(300),
        "this case crosses the shipped age limit, so it must be reading the shipped value"
    );

    backdate_pending(&probe, 299).await;
    let under = admission_check(&probe, &real_limits)
        .await
        .expect("admission probe");
    assert_eq!(
        under,
        AdmissionVerdict::Admit,
        "299 seconds is inside CR-032's five-minute limit and must admit"
    );

    backdate_pending(&probe, 301).await;
    let over = admission_check(&probe, &real_limits)
        .await
        .expect("admission probe");
    let AdmissionVerdict::Reject(AdmissionRejection::OldestPendingAge { observed, limit }) = &over
    else {
        panic!("301 seconds must close admission on the AGE limit, got {over:?}");
    };
    assert_eq!(*limit, Duration::from_secs(300));
    assert!(*observed > Duration::from_secs(300));

    // And it REOPENS: the gate is a function of the current facts, not a latch.
    backdate_pending(&probe, 1).await;
    let reopened = admission_check(&probe, &real_limits)
        .await
        .expect("admission probe");
    assert_eq!(
        reopened,
        AdmissionVerdict::Admit,
        "a backlog whose age fell back under the limit must reopen admission"
    );
    println!("age limit (REAL 300s):   closed at 301s, reopened at 1s  PASS");

    // -- the ROW limit, scaled ---------------------------------------------
    let scaled_rows = AdmissionLimits {
        max_pending_rows: rows - 1,
        ..AdmissionLimits::default()
    };
    let row_verdict = admission_check(&probe, &scaled_rows)
        .await
        .expect("admission probe");
    let AdmissionVerdict::Reject(AdmissionRejection::PendingRows { observed, limit }) =
        &row_verdict
    else {
        panic!("a backlog above the row limit must close on ROWS, got {row_verdict:?}");
    };
    assert_eq!(*limit, rows - 1);
    assert!(*observed > rows - 1);
    let row_reopened = admission_check(
        &probe,
        &AdmissionLimits {
            max_pending_rows: rows + 1,
            ..AdmissionLimits::default()
        },
    )
    .await
    .expect("admission probe");
    assert_eq!(row_reopened, AdmissionVerdict::Admit);
    println!(
        "row limit (SCALED to {}):  closed, reopened at {}  PASS  \
         [the shipped limit is 1,000,000 and is not seedable here]",
        rows - 1,
        rows + 1
    );

    // -- the BYTE limit, scaled --------------------------------------------
    let observed_bytes = {
        let client: &tokio_postgres::Client = &probe;
        backlog(client).await.expect("backlog probe").pending_bytes
    };
    let byte_verdict = admission_check(
        &probe,
        &AdmissionLimits {
            max_pending_bytes: observed_bytes - 1,
            ..AdmissionLimits::default()
        },
    )
    .await
    .expect("admission probe");
    assert!(
        matches!(
            byte_verdict,
            AdmissionVerdict::Reject(AdmissionRejection::PendingBytes { .. })
        ),
        "a backlog above the byte budget must close on BYTES, got {byte_verdict:?}"
    );
    let byte_reopened = admission_check(
        &probe,
        &AdmissionLimits {
            max_pending_bytes: observed_bytes + 1,
            ..AdmissionLimits::default()
        },
    )
    .await
    .expect("admission probe");
    assert_eq!(byte_reopened, AdmissionVerdict::Admit);
    println!(
        "byte limit (SCALED to {} B): closed, reopened  PASS  \
         [the shipped limit is 5 GiB and is not seedable here]",
        observed_bytes - 1
    );

    // -- ordering: age is checked first, and only local facts are read ------
    //
    // Both limits are made to fail at once. CR-032 wants the cheapest probe
    // first, and `admission_check` documents that it returns on age before it
    // runs either counting probe -- so the reported rejection must name AGE,
    // not ROWS.
    backdate_pending(&probe, 400).await;
    let both = admission_check(&probe, &scaled_rows)
        .await
        .expect("admission probe");
    assert!(
        matches!(
            both,
            AdmissionVerdict::Reject(AdmissionRejection::OldestPendingAge { .. })
        ),
        "with age and rows both over, the cheap age probe must decide: got {both:?}"
    );
    println!("precedence:              age decides before the counting probes  PASS");

    // -- probe cost, which answers admission_check's own TODO ---------------
    backdate_pending(&probe, 1).await;
    println!();

    // The floor: what one `admission_check` costs against an EMPTY table.
    //
    // This is the part of every measurement below that does NOT scale with the
    // backlog -- the round trip, the parse, the plan lookup. Extrapolating the
    // whole measured figure to a million rows, as the first version of this
    // case did, multiplies that fixed cost by five hundred and reports a
    // number that is mostly round trips. Only the marginal part above this
    // floor is extrapolated.
    let floor_namespace = CaseNamespace::acquire(&base_url, "load-floor").await;
    let floor_url = floor_namespace.pg_url().to_owned();
    relay_harness::ensure_schema_bootstrapped(&floor_url).await;
    let floor_probe = relay_harness::raw_client(&floor_url).await;
    let floor_ms = time_admission_probe(&floor_probe).await;
    floor_namespace.release().await;
    println!("fixed round-trip floor (empty table): {floor_ms:.2}ms per admission probe");

    println!(
        "{:<12} {:>10} {:>14} {:>16} {:>16}",
        "payload B", "pending", "backlog ms", "admit-probe ms", "extrapolated*"
    );
    for (_, payload_bytes) in EVENT_SIZES {
        let inner = CaseNamespace::acquire(&base_url, "load-cost").await;
        let inner_url = inner.pg_url().to_owned();
        relay_harness::ensure_schema_bootstrapped(&inner_url).await;
        let inner_probe = relay_harness::raw_client(&inner_url).await;
        seed_pending(&inner_url, &repository_id, &run_salt(), payload_bytes, rows).await;

        let backlog_ms = time_backlog_probe(&inner_probe).await;
        let admit_ms = time_admission_probe(&inner_probe).await;

        // Only the MARGINAL cost is scaled. `admission_check`'s own doc comment
        // says the cost tracks the pending ROW count rather than the payload
        // bytes, so the marginal part is taken as linear in rows; the floor is
        // added back once, not five hundred times.
        let marginal = (admit_ms - floor_ms).max(0.0);
        let extrapolated = floor_ms + marginal * (1_000_000.0 / rows as f64);
        println!(
            "{payload_bytes:<12} {rows:>10} {backlog_ms:>14.2} {admit_ms:>16.2} {:>15.1}s",
            extrapolated / 1000.0
        );
        inner.release().await;
    }
    println!(
        "  * floor + (measured - floor) scaled linearly to the shipped 1,000,000-row limit. NOT a \
         measurement, and three things could each move it by more than the scaling does: a real \
         million-row backlog changes the planner's choices, changes the buffer cache hit rate, \
         and puts the table past what fits in shared_buffers. This rig cannot seed one, so the \
         figure is an order-of-magnitude sanity check and nothing stronger."
    );
    println!(
        "  The mutation path does NOT pay this: DomainContext::admit reads OutboxAdmission's \
         cached verdict, refreshed once per readiness_probe_interval. These are the cost of that \
         REFRESH, not of a governed write."
    );

    namespace.release().await;
    measured(CASE);
}

/// Elapsed milliseconds for one `relay::backlog`, after an untimed warm-up.
///
/// The warm-up is load-bearing: the first execution of a statement pays plan
/// generation and a cold buffer cache, and reporting that as the probe's cost
/// would over-state it by an amount that varies with nothing the system does.
///
/// Written as two near-identical functions rather than one taking a closure:
/// an `async` closure over a borrowed client needs a higher-ranked bound this
/// signature cannot express, and the workarounds are less readable than the
/// duplication.
async fn time_backlog_probe(client: &tokio_postgres::Client) -> f64 {
    backlog(client).await.expect("backlog probe");
    let started = Instant::now();
    backlog(client).await.expect("backlog probe");
    ms(started.elapsed())
}

/// Elapsed milliseconds for one `relay::admission_check` at the shipped
/// limits, after an untimed warm-up. See [`time_backlog_probe`].
async fn time_admission_probe(client: &tokio_postgres::Client) -> f64 {
    let limits = AdmissionLimits::default();
    admission_check(client, &limits)
        .await
        .expect("admission probe");
    let started = Instant::now();
    admission_check(client, &limits)
        .await
        .expect("admission probe");
    ms(started.elapsed())
}

// ---------------------------------------------------------------------------
// Case 5: the real Lore client's RESOURCE_EXHAUSTED retry budget
// ---------------------------------------------------------------------------

/// CR-032: "Activation is blocked if generic client `RESOURCE_EXHAUSTED` retry
/// can exceed that budget; fixing that requires a reviewed client-path change
/// rather than multiplying retries."
///
/// That reviewed client-path change has since been made. `lore-transport`'s
/// `handle_error` now reads this gate's `RetryInfo` and waits
/// `max(its own backoff step, the hint)` per attempt, counting it as one
/// attempt. So the budget question is answered against the **real** client
/// policy in its current shape, and this case measures both halves: what a
/// refused client does with our hint, and what it would still do without one.
///
/// Three things make the measurement sound rather than a restatement of source:
///
/// * the schedule is driven through `lore_transport`'s own `wait_with_hint` and
///   `util::Retry` -- the same code path `handle_error` runs -- under a paused
///   tokio clock, so the totals are the policy's own arithmetic and not this
///   file's;
/// * the hint is not hand-fed. It is encoded by *this crate's*
///   `retry_info_details`, attached to a real `tonic::Status`, and read back by
///   the client's own `retry_delay_hint`, so the two halves of the contract are
///   joined on real bytes rather than on a shared assumption; and
/// * the constants and the call sites that parameterise it are **pinned against
///   the source file**, so a policy change on either side breaks this case
///   instead of silently invalidating the numbers.
///
/// This case needs no infrastructure and is therefore NOT `#[ignore]`d: it
/// runs in the ordinary `cargo test -p lore-server` gate, where a client-path
/// change will trip it.
#[tokio::test(start_paused = true)]
async fn measure_the_real_lore_client_resource_exhausted_retry_budget() {
    const CASE: &str = "client-retry-budget";

    // -- pin the policy this measurement is of -----------------------------
    let source = include_str!("../../lore-transport/src/grpc/mod.rs");
    for pin in [
        "const RETRY_START_BACKOFF_MS: u64 = 50;",
        "const RETRY_MAX_BACKOFF_MS: u64 = 10_000;",
        "const RETRY_MAX_ATTEMPTS: usize = 60;",
        "tonic::Code::ResourceExhausted => {",
        // The hint read, and the wait that honours it. Both, because a decoder
        // that nothing calls would leave the old budget in force while looking
        // like the new one.
        "pub fn retry_delay_hint(status: &Status) -> Option<Duration> {",
        "let hint = retry_delay_hint(&status);",
        "if !wait_with_hint(retry, hint).await {",
        // Everything that is not RESOURCE_EXHAUSTED still fails immediately.
        // The hint reader does not look at the status code, so this arm is the
        // only thing keeping UNAVAILABLE out of the retry path -- and a retried
        // UNAVAILABLE would redispatch a mutation, not merely lengthen a wait.
        "_ => return Err(ProtocolError::from(status)),",
    ] {
        assert!(
            source.contains(pin),
            "lore-transport's RESOURCE_EXHAUSTED retry policy has changed: {pin:?} is no longer in \
             lore-transport/src/grpc/mod.rs. Re-measure this budget and update CR-032's record \
             before assuming the numbers below still hold."
        );
    }
    // Nothing in THIS file truncates the retry loop. The budget below counts
    // waits under the assumption that a refused RPC runs to the end of its
    // schedule; a per-request deadline would cut it short and make these numbers
    // an over-estimate rather than a floor.
    //
    // Scope, stated because the pin is narrower than the claim it supports: this
    // reads `grpc/mod.rs` only. A deadline introduced on the `Endpoint` in
    // `lore-transport/src/connection.rs`, in a tower layer, or in one of the
    // per-verb client files under `lore-transport/src/grpc/` would not trip it.
    // The pin is worth having anyway -- `grpc/mod.rs` is where the endpoint is
    // actually built (`connect_to_endpoint`), so it is where such a deadline
    // would most likely land -- but it is not a proof that no deadline exists
    // anywhere, and it must not be read as one.
    assert!(
        !source.contains(".timeout("),
        "lore-transport/src/grpc/mod.rs now sets a request timeout. That truncates the retry \
         budget measured below, which is derived as an untruncated floor -- re-derive it rather \
         than re-asserting it."
    );

    // -- join the two halves on real bytes ---------------------------------
    // This gate's own encoder, through a real status, into the client's own
    // decoder. A hand-built Duration here would prove only that arithmetic
    // works; this proves the client reads what this gate actually sends.
    let refusal = tonic::Status::with_details(
        tonic::Code::ResourceExhausted,
        "the backlog is too old",
        retry_info_details(ADMISSION_RETRY_DELAY, "the backlog is too old"),
    );
    let hint = lore_transport::grpc::retry_delay_hint(&refusal);
    assert_eq!(
        hint,
        Some(ADMISSION_RETRY_DELAY),
        "the client's retry_delay_hint did not read this gate's own RetryInfo bytes"
    );

    // -- the hinted budget: what a refused client actually does now ---------
    let mut retry = lore_transport::util::retry(50, 10_000, 60);
    let started = tokio::time::Instant::now();
    let mut attempts = 0_usize;
    let mut first_waits = Vec::new();
    let mut previous = Duration::ZERO;
    while lore_transport::grpc::wait_with_hint(&mut retry, hint).await {
        attempts += 1;
        let elapsed = started.elapsed();
        if first_waits.len() < 8 {
            first_waits.push(elapsed - previous);
        }
        previous = elapsed;
    }
    let total = started.elapsed();

    assert_eq!(attempts, 60, "the shipped attempt limit is 60");
    assert_eq!(
        retry.counter(),
        60,
        "honouring the hint must lengthen an attempt, never consume an extra one"
    );
    // The first eight waits are the ones the hint changes: unhinted they would
    // be 50, 100, 200, 400, 800, 1600, 3200 and 6400 ms, every one of them
    // shorter than a readiness interval.
    for (index, wait) in first_waits.iter().enumerate() {
        assert!(
            *wait >= ADMISSION_RETRY_DELAY,
            "hinted wait {index} was {wait:?}, shorter than the {ADMISSION_RETRY_DELAY:?} this \
             gate asked for"
        );
    }
    // Attempts 1-8 have a base step below the hint, so the hint dominates at
    // exactly 10,000 ms each = 80,000 ms. Attempts 9-60 (52 of them) sit at the
    // client's own 10,000 ms ceiling, where the base step dominates and jitter
    // adds at most 100 ms per wait = 520,000 to 525,200 ms.
    assert!(
        total >= Duration::from_millis(600_000) && total <= Duration::from_millis(605_200),
        "measured hinted retry budget {total:?} is outside the schedule the pinned constants and \
         ADMISSION_RETRY_DELAY imply; the policy, the hint or the jitter rule has changed"
    );

    // -- the unhinted baseline, still reachable and still measured ---------
    // A server that sends no RetryInfo -- every server on this wire but the
    // admission gate -- gets the client's own schedule unchanged. Pinned so the
    // hint path cannot quietly become the only path.
    let mut baseline = lore_transport::util::retry(50, 10_000, 60);
    let baseline_started = tokio::time::Instant::now();
    let mut baseline_attempts = 0_usize;
    while lore_transport::grpc::wait_with_hint(&mut baseline, None).await {
        baseline_attempts += 1;
    }
    let baseline_total = baseline_started.elapsed();

    assert_eq!(baseline_attempts, 60);
    // 50+100+200+400+800+1600+3200+6400 = 12,750 ms, then 52 waits capped at
    // 10,000 ms = 520,000 ms, so 532.75 s before jitter.
    assert!(
        baseline_total >= Duration::from_millis(532_750)
            && baseline_total <= Duration::from_secs(539),
        "measured unhinted retry budget {baseline_total:?} is outside the schedule the pinned \
         constants imply; honouring the hint must not have changed the no-hint path"
    );

    let attempts_inside_one_minute = {
        let mut probe = lore_transport::util::retry(50, 10_000, 60);
        let start = tokio::time::Instant::now();
        let mut n = 0_usize;
        while start.elapsed() < Duration::from_secs(60)
            && lore_transport::grpc::wait_with_hint(&mut probe, hint).await
        {
            n += 1;
        }
        n
    };

    println!("=== the real Lore client's RESOURCE_EXHAUSTED retry budget ===");
    println!("policy source          lore-transport/src/grpc/mod.rs (grpc_retry)");
    println!("start / cap / attempts 50ms / 10,000ms / 60");
    println!("honours server RetryInfo?  YES -- max(own backoff step, hint), hint clamped to cap");
    println!("server RetryInfo hint  {ADMISSION_RETRY_DELAY:?}");
    println!("  read back by the client's own decoder from this crate's own encoder: {hint:?}");
    println!(
        "measured HINTED total  {:.1}s over {attempts} attempts",
        total.as_secs_f64()
    );
    println!(
        "measured UNHINTED total {:.1}s over {baseline_attempts} attempts (unchanged path)",
        baseline_total.as_secs_f64()
    );
    println!("attempts inside 60s    {attempts_inside_one_minute}");
    println!("first eight waits      {first_waits:?}");
    println!(
        "VERDICT: a client refused continuously now retries for about {:.0} seconds ({:.1} \
         minutes) before giving up, against {:.0} seconds unhinted. Honouring the hint made the \
         worst case LONGER by about {:.0} seconds -- that is the trade, and it is the right one: \
         unhinted, the first eight attempts all landed inside 12.75 s and were guaranteed to \
         re-read the identical cached verdict, because this gate refreshes on a five-second \
         readiness tick. Every retry now arrives after at least one whole refresh. \
         ADMISSION_RETRY_DELAY's doc comment used to reason about 'a six-attempt client inside \
         one minute'; with the hint honoured that client finally exists -- {} attempts inside the \
         first minute -- but it does not stop there, and 600 s per refused RPC is the number \
         CR-032's activation gate has to accept or refuse.",
        total.as_secs_f64(),
        total.as_secs_f64() / 60.0,
        baseline_total.as_secs_f64(),
        total.as_secs_f64() - baseline_total.as_secs_f64(),
        attempts_inside_one_minute
    );
    println!(
        "  This is a FLOOR, not a ceiling, in three ways. It counts only the waits, not the RPC \
         round trips between them. `grpc_retry()` is constructed per RPC, so a client operation \
         that issues several refused RPCs pays this budget several times over. And nothing \
         truncates it: the endpoint carries no request timeout (pinned above), and \
         GRPC_CONNECT_TIMEOUT_SECS bounds channel setup only. The activation question CR-032 asks \
         is therefore answered a fortiori."
    );
    measured(CASE);
}

// ---------------------------------------------------------------------------
// Coverage this rig deliberately does not claim
// ---------------------------------------------------------------------------

/// Receiver checkpoint lag under load is **NOT RUN** here, and this case says
/// so in the runner's own vocabulary rather than leaving a silent gap.
///
/// Running a real durable receiver needs the `receiver`-role mTLS leaf, the
/// cell's authoritative placement stamped into `lore_outbox_membership_state`
/// at the broker's own derived stream epoch, and a `ReceiverRuntime` over
/// `GrpcDurableStream` -- the bring-up WP-109 Phase 3's runner already owns.
/// Reproducing it here would be a second copy of that harness, and a second
/// copy that drifts is worse than a named gap.
///
/// Where the behaviour IS covered: WP-109 Phase 3 case D asserts process B's
/// checkpoint frontier reaches `consumer_safe`, and case G asserts
/// `receiver_ready` on both processes
/// (`lore-integration-tests/tests/run-active-active-two-process-live.ps1`).
/// Neither measures lag under a seeded backlog, which is the gap.
#[test]
#[ignore = "declares a known measurement gap; runs with the rest of the load tier"]
fn receiver_checkpoint_lag_under_load_is_not_run_here() {
    not_run(
        "receiver-lag",
        "needs the WP-109 Phase 3 receiver bring-up (receiver-role leaf, stamped placement \
         epoch, GrpcDurableStream); covered behaviourally by that runner's cases D and G, not \
         measured under load anywhere",
    );
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! FORK-LOCAL (Tideshift), WP-115 K11: the stage liveness exchange against a
//! real Postgres, with two replicas of one cell.
//!
//! What only a live database can show: the migration's table is created at
//! domain boot, freshness and the prove margin are computed from the database
//! clock, a peer of another cell never counts, and the verdict each replica
//! reaches from a real exchange is the one `/lb_health` answers.
//!
//! Needs `LORE_TEST_PG_URL` (a database the run may create schemas in). An
//! unset URL under `--ignored` panics: an unconfigured live case is NOT RUN,
//! never a pass. Run:
//!
//! ```text
//! cargo test -p lore-server --test stage_liveness_live -- --ignored
//! ```

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::time::Duration;
use std::time::Instant;

use axum::http::StatusCode;
use case_namespace::CaseNamespace;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::pool::TlsConfig;
use lore_server::fragment_write_behind::WriteBehindRole;
use lore_server::fragment_write_behind::combined_replica_fault;
use lore_server::http::lb_health::verdict_from;
use lore_server::stage_liveness::LivenessTick;
use lore_server::stage_liveness::RETAIN;
use lore_server::stage_liveness::STAGE_UNAVAILABLE_LOCAL;
use lore_server::stage_liveness::StageLiveness;
use lore_server::stage_liveness::exchange_once;
use lore_server::stage_liveness::liveness_tick;

const CELL: &str = "k11-cell";
const STALE_AFTER: Duration = Duration::from_millis(1500);
/// The prove margin, scaled down with `STALE_AFTER`.
const MARGIN: Duration = Duration::from_millis(1000);

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN")
}

/// `age` before now, on this process's clock.
fn ago(age: Duration) -> Instant {
    Instant::now()
        .checked_sub(age)
        .expect("the monotonic clock is older than the test's ages")
}

async fn exchange(coordinator: &PostgresFragmentCoordinator, cell: &str, replica: &StageLiveness) {
    let ok = exchange_once(
        replica,
        |last_good| {
            coordinator.exchange_stage_liveness(
                cell,
                replica.replica_id(),
                last_good,
                replica.stale_after(),
                replica.prove_margin(),
                RETAIN,
            )
        },
        Duration::from_secs(5),
        &mut None,
    )
    .await;
    assert!(ok, "the exchange for {} must succeed", replica.replica_id());
}

/// What `/lb_health` answers for a stage replica with no other fault.
fn lb_health(replica: &StageLiveness) -> (StatusCode, &'static str) {
    verdict_from(
        None,
        combined_replica_fault(WriteBehindRole::Stage, None, replica.fault(Instant::now())),
    )
}

fn replica(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(id.to_owned(), STALE_AFTER, Duration::from_secs(10), MARGIN)
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn only_the_stale_replica_is_ejected_and_both_stale_eject_neither() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-two").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store, which creates the liveness table");
    let coordinator = store.fragment_coordinator();

    let stale = replica("web-a");
    let fresh = replica("web-b");
    // A replica of ANOTHER cell, always fresh. It must never count.
    let other_cell = replica("web-z");

    // Both fresh at boot: nobody is ejected.
    exchange(&coordinator, CELL, &stale).await;
    exchange(&coordinator, CELL, &fresh).await;
    assert_eq!(lb_health(&stale), (StatusCode::OK, "ok"));
    assert_eq!(lb_health(&fresh), (StatusCode::OK, "ok"));

    // web-a's probe stops succeeding; web-b's (and the other cell's) keep
    // succeeding.
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    fresh.note_good(Instant::now());
    other_cell.note_good(Instant::now());
    exchange(&coordinator, "k11-other-cell", &other_cell).await;
    exchange(&coordinator, CELL, &fresh).await;
    exchange(&coordinator, CELL, &stale).await;
    exchange(&coordinator, CELL, &fresh).await;
    assert_eq!(
        lb_health(&stale),
        (StatusCode::SERVICE_UNAVAILABLE, STAGE_UNAVAILABLE_LOCAL),
        "a stale replica with a fresh peer must be ejected"
    );
    assert_eq!(lb_health(&fresh), (StatusCode::OK, "ok"));
    let stale_view = stale.snapshot(Instant::now());
    assert_eq!(stale_view.fresh_peers, Some(1));
    assert_eq!(
        stale_view.proving_peers,
        Some(1),
        "web-b wrote well after web-a stopped"
    );
    assert_eq!(
        stale_view.peers,
        Some(1),
        "another cell's row must not count"
    );
    let fresh_view = fresh.snapshot(Instant::now());
    assert_eq!(
        fresh_view.fresh_peers,
        Some(0),
        "web-a must read stale in SQL"
    );

    // Now web-b goes stale too: a cell-wide fault ejects neither.
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    other_cell.note_good(Instant::now());
    exchange(&coordinator, "k11-other-cell", &other_cell).await;
    exchange(&coordinator, CELL, &stale).await;
    exchange(&coordinator, CELL, &fresh).await;
    assert_eq!(lb_health(&stale), (StatusCode::OK, "ok"));
    assert_eq!(lb_health(&fresh), (StatusCode::OK, "ok"));

    // web-a recovers: one good probe is enough.
    stale.note_good(Instant::now());
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(lb_health(&stale), (StatusCode::OK, "ok"));

    drop(store);
    namespace.release().await;
}

/// The reviewer's double eject. A cell-wide NFS hang stops both probes
/// within 200 ms. Each replica exchanged just before it went stale, so each
/// holds a view that shows the other fresh. Neither may be ejected.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn both_probes_stopping_together_eject_neither() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-both").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    // The hang: a's last good probe, then b's 200 ms later. Neither probes
    // again.
    let stopped = Instant::now();
    a.note_good(stopped);
    tokio::time::sleep(Duration::from_millis(200)).await;
    b.note_good(Instant::now());
    // Exchanges right before a's stale threshold: each sees the other fresh.
    tokio::time::sleep_until((stopped + STALE_AFTER - Duration::from_millis(150)).into()).await;
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    exchange(&coordinator, CELL, &a).await;
    // Both are now stale; the views are well inside their max age.
    tokio::time::sleep_until((stopped + STALE_AFTER + Duration::from_millis(400)).into()).await;
    assert_eq!(
        (lb_health(&a), lb_health(&b)),
        ((StatusCode::OK, "ok"), (StatusCode::OK, "ok")),
        "(web-a, web-b): a cell-wide fault must eject neither"
    );
    drop(store);
    namespace.release().await;
}

/// The prove margin. A cell-wide hang reaches web-b 600 ms after web-a (less
/// than the margin). When web-a crosses its threshold, web-b is still inside
/// the freshness window, and web-a's view is taken after it went stale. web-b
/// is fresh, but it stopped too close to web-a to prove the fault is local.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_peer_that_stopped_just_after_self_proves_nothing() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-margin").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    let stopped = Instant::now();
    a.note_good(stopped);
    tokio::time::sleep(Duration::from_millis(600)).await;
    b.note_good(Instant::now());
    // web-a is stale (1.6 s); web-b is not (1.0 s).
    tokio::time::sleep_until((stopped + STALE_AFTER + Duration::from_millis(100)).into()).await;
    exchange(&coordinator, CELL, &b).await;
    exchange(&coordinator, CELL, &a).await;
    let view = a.snapshot(Instant::now());
    assert!(
        b.last_good_age(Instant::now()) < STALE_AFTER,
        "the case needs web-b inside the window; the run was too slow"
    );
    assert_eq!(view.fresh_peers, Some(1), "web-b is fresh in SQL");
    assert_eq!(view.proving_peers, Some(0), "but proves nothing");
    assert_eq!(lb_health(&a), (StatusCode::OK, "ok"));
    assert_eq!(lb_health(&b), (StatusCode::OK, "ok"));
    drop(store);
    namespace.release().await;
}

/// A peer's freshness is the database's verdict on the age it published, so
/// a published age just over the window reads stale and just under reads
/// fresh, whatever this host's clock says.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn freshness_is_decided_in_sql_from_the_published_age() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-sql").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let window = Duration::from_secs(15);
    let publish = |replica: &'static str, age: Duration, margin: Duration| {
        coordinator.exchange_stage_liveness(CELL, replica, ago(age), window, margin, RETAIN)
    };
    let margin = Duration::from_secs(5);
    publish("peer-old", Duration::from_secs(16), margin)
        .await
        .unwrap();
    publish("peer-new", Duration::from_secs(14), margin)
        .await
        .unwrap();
    let view = publish("observer", Duration::ZERO, margin).await.unwrap();
    assert_eq!(view.peers, 2);
    assert_eq!(view.fresh_peers, 1);

    // The prove margin, on database time: an observer whose own last good
    // probe was 17 s ago counts peer-new (14 s ago, 3 s later) only under a
    // margin below 3 s.
    let view = publish("observer", Duration::from_secs(17), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!((view.fresh_peers, view.proving_peers), (1, 1));
    let view = publish("observer", Duration::from_secs(17), Duration::from_secs(4))
        .await
        .unwrap();
    assert_eq!(
        (view.fresh_peers, view.proving_peers),
        (1, 0),
        "a peer only 3 s later than self proves nothing under a 4 s margin"
    );

    // A row is republished, not duplicated, and each exchange returns the
    // row it found, as the last one left it.
    let first = publish("peer-old", Duration::ZERO, margin).await.unwrap();
    let second = publish("peer-old", Duration::ZERO, margin).await.unwrap();
    assert!(first.prior_last_good_micros.is_some());
    assert_eq!(
        second.prior_last_good_micros,
        first.published_last_good_micros
    );
    let view = publish("observer", Duration::ZERO, margin).await.unwrap();
    assert_eq!(view.peers, 2);
    assert_eq!(view.fresh_peers, 2);

    drop(store);
    namespace.release().await;
}

/// Rows not published for `retain` are pruned, so restarts do not grow the
/// table; ids are bounded.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn departed_rows_are_pruned_and_ids_are_bounded() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-prune").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let window = Duration::from_secs(15);
    coordinator
        .exchange_stage_liveness(CELL, "departed", Instant::now(), window, MARGIN, RETAIN)
        .await
        .unwrap();
    let (client, connection) = tokio_postgres::connect(namespace.pg_url(), tokio_postgres::NoTls)
        .await
        .expect("raw connection");
    let _connection = lore_base::lore_spawn!(connection);
    client
        .execute(
            "UPDATE lore_domain_write_behind_liveness \
             SET published_at = now() - interval '2 hours', \
                 last_good_at = now() - interval '2 hours' \
             WHERE replica_id = 'departed'",
            &[],
        )
        .await
        .expect("age the departed row");
    let view = coordinator
        .exchange_stage_liveness(CELL, "survivor", Instant::now(), window, MARGIN, RETAIN)
        .await
        .unwrap();
    // The pruning statement still sees the row it deletes; the next one not.
    assert_eq!(view.fresh_peers, 0);
    let view = coordinator
        .exchange_stage_liveness(CELL, "survivor", Instant::now(), window, MARGIN, RETAIN)
        .await
        .unwrap();
    assert_eq!(view.peers, 0, "the departed row must be pruned");

    for (cell, replica) in [("", "a"), (CELL, ""), (CELL, &*"x".repeat(129))] {
        assert!(
            coordinator
                .exchange_stage_liveness(cell, replica, Instant::now(), window, MARGIN, RETAIN)
                .await
                .is_err(),
            "cell {cell:?} replica of {} bytes must be refused",
            replica.len()
        );
    }

    drop(store);
    namespace.release().await;
}

/// A draining peer must not count as fresh. During a one-host roll the host
/// going down is the fresh one; if the remaining host's mount is stale it
/// must stay in the pool, or the cell goes dark.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_draining_peer_withdraws_and_no_longer_ejects_a_stale_replica() {
    let base_url = pg_url();
    let namespace = CaseNamespace::acquire(&base_url, "k11-drain").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();

    let stale = replica("web-a");
    let leaving = replica("web-b");
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    leaving.note_good(Instant::now());
    exchange(&coordinator, CELL, &leaving).await;
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(
        lb_health(&stale),
        (StatusCode::SERVICE_UNAVAILABLE, STAGE_UNAVAILABLE_LOCAL),
        "control: a stale replica with a fresh serving peer is ejected"
    );

    // web-b starts to drain (lame duck or SIGTERM): it withdraws.
    let mut withdrawn = false;
    let tick = liveness_tick(
        &leaving,
        true,
        &mut withdrawn,
        |last_good| {
            coordinator.exchange_stage_liveness(
                CELL,
                leaving.replica_id(),
                last_good,
                STALE_AFTER,
                MARGIN,
                RETAIN,
            )
        },
        || coordinator.withdraw_stage_liveness(CELL, leaving.replica_id()),
        Duration::from_secs(5),
        &mut None,
    )
    .await;
    assert_eq!(tick, LivenessTick::Withdrew);

    // web-b is still fresh by its own probe, but it no longer counts.
    leaving.note_good(Instant::now());
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(lb_health(&stale), (StatusCode::OK, "ok"));
    let view = stale.snapshot(Instant::now());
    assert_eq!(view.peers, Some(0), "the draining peer's row must be gone");
    assert_eq!(view.fresh_peers, Some(0));

    drop(store);
    namespace.release().await;
}

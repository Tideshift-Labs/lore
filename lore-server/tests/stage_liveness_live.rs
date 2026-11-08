// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! FORK-LOCAL (Tideshift), WP-115 K11: the stage liveness exchange against a
//! real Postgres, with two replicas of one cell.
//!
//! What only a live database can show: the migration's table is created at
//! domain boot, freshness is computed from the database clock, a peer of
//! another cell never counts, and the verdict each replica reaches from a real
//! exchange is the one `/lb_health` answers.
//!
//! Needs `LORE_TEST_PG_URL` (a database the run may create schemas in). Run:
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

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn exchange(coordinator: &PostgresFragmentCoordinator, cell: &str, replica: &StageLiveness) {
    let ok = exchange_once(
        replica,
        |age| {
            coordinator.exchange_stage_liveness(
                cell,
                replica.replica_id(),
                age,
                replica.stale_after(),
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
    StageLiveness::with_thresholds(id.to_owned(), STALE_AFTER, Duration::from_secs(10))
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn only_the_stale_replica_is_ejected_and_both_stale_eject_neither() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
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

/// A peer's freshness is the database's verdict on the age it published, so
/// a published age just over the window reads stale and just under reads
/// fresh, whatever this host's clock says.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn freshness_is_decided_in_sql_from_the_published_age() {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "k11-sql").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let window = Duration::from_secs(15);
    let publish = |replica: &'static str, age: Duration| {
        coordinator.exchange_stage_liveness(CELL, replica, age, window, RETAIN)
    };
    publish("peer-old", Duration::from_secs(16)).await.unwrap();
    publish("peer-new", Duration::from_secs(14)).await.unwrap();
    let view = publish("observer", Duration::ZERO).await.unwrap();
    assert_eq!(view.peers, 2);
    assert_eq!(view.fresh_peers, 1);

    // A row is republished, not duplicated.
    publish("peer-old", Duration::ZERO).await.unwrap();
    let view = publish("observer", Duration::ZERO).await.unwrap();
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
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "k11-prune").await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store");
    let coordinator = store.fragment_coordinator();
    let window = Duration::from_secs(15);
    coordinator
        .exchange_stage_liveness(CELL, "departed", Duration::ZERO, window, RETAIN)
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
        .exchange_stage_liveness(CELL, "survivor", Duration::ZERO, window, RETAIN)
        .await
        .unwrap();
    // The pruning statement still sees the row it deletes; the next one not.
    assert_eq!(view.fresh_peers, 0);
    let view = coordinator
        .exchange_stage_liveness(CELL, "survivor", Duration::ZERO, window, RETAIN)
        .await
        .unwrap();
    assert_eq!(view.peers, 0, "the departed row must be pruned");

    for (cell, replica) in [("", "a"), (CELL, ""), (CELL, &*"x".repeat(129))] {
        assert!(
            coordinator
                .exchange_stage_liveness(cell, replica, Duration::ZERO, window, RETAIN)
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
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
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
        |age| {
            coordinator.exchange_stage_liveness(
                CELL,
                leaving.replica_id(),
                age,
                STALE_AFTER,
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

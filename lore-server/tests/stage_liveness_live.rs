// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! FORK-LOCAL (Tideshift), WP-115 K11: the stage liveness exchange against a
//! real Postgres, with two replicas of one cell.
//!
//! What only a live database can show: the migration's table is created at
//! domain boot, the stored count never goes down, an increase is accepted
//! only while fresh and on time on the database clock, a peer of another cell
//! never counts, and the verdict each replica reaches from real exchanges is
//! the one `/lb_health` answers. Some cases put a TCP proxy between a replica
//! and Postgres that holds back the publish statement or its COMMIT, as a
//! slow network or a stalled host would.
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
use lore_postgres::domain::fragments::StageLivenessClock;
use lore_postgres::domain::fragments::StageLivenessPublication;
use lore_postgres::domain::fragments::StageLivenessRole;
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_postgres::pool::TlsConfig;
use lore_server::fragment_write_behind::WriteBehindRole;
use lore_server::fragment_write_behind::combined_replica_fault;
use lore_server::http::lb_health::verdict_from;
use lore_server::stage_liveness::LivenessThresholds;
use lore_server::stage_liveness::LivenessTick;
use lore_server::stage_liveness::STAGE_UNAVAILABLE_LOCAL;
use lore_server::stage_liveness::ShareMarkers;
use lore_server::stage_liveness::ShareVerdict;
use lore_server::stage_liveness::StageLiveness;
use lore_server::stage_liveness::exchange_once;
use lore_server::stage_liveness::liveness_tick;

const CELL: &str = "k11-cell";
/// The production thresholds scaled by 0.1.
const STALE_AFTER: Duration = Duration::from_millis(1500);
const PUBLISH_FRESH: Duration = Duration::from_millis(400);
const PUBLISH_DEADLINE: Duration = Duration::from_millis(200);

fn thresholds() -> LivenessThresholds {
    LivenessThresholds {
        stale_after: STALE_AFTER,
        peer_view_max_age: Duration::from_secs(10),
        publish_fresh: PUBLISH_FRESH,
        publish_deadline: PUBLISH_DEADLINE,
        statement_timeout: Duration::from_secs(2),
        progress_window: Duration::from_secs(1),
        ..LivenessThresholds::default()
    }
}

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN")
}

async fn try_exchange(
    coordinator: &PostgresFragmentCoordinator,
    cell: &str,
    replica: &StageLiveness,
) -> bool {
    exchange_once(
        replica,
        |publication| async move {
            coordinator
                .exchange_stage_liveness(cell, replica.replica_id(), &publication, replica.limits())
                .await
        },
        Duration::from_secs(5),
        &mut None,
    )
    .await
}

async fn exchange(coordinator: &PostgresFragmentCoordinator, cell: &str, replica: &StageLiveness) {
    assert!(
        try_exchange(coordinator, cell, replica).await,
        "the exchange for {} must succeed",
        replica.replica_id()
    );
}

/// What `/lb_health` answers for a stage replica with no other fault.
fn lb_health(replica: &StageLiveness) -> (StatusCode, &'static str) {
    verdict_from(
        None,
        combined_replica_fault(WriteBehindRole::Stage, None, replica.fault(Instant::now())),
    )
}

const OK: (StatusCode, &str) = (StatusCode::OK, "ok");
const EJECTED: (StatusCode, &str) = (StatusCode::SERVICE_UNAVAILABLE, STAGE_UNAVAILABLE_LOCAL);

fn replica(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(id.to_owned(), thresholds())
}

async fn boot(label: &str) -> (CaseNamespace, PostgresDomainStore) {
    let namespace = CaseNamespace::acquire(&pg_url(), label).await;
    let store = PostgresDomainStore::connect(namespace.pg_url(), 2, &TlsConfig::default())
        .await
        .expect("boot the domain store, which creates the liveness table");
    (namespace, store)
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn only_the_stale_replica_is_ejected_and_both_stale_eject_neither() {
    let (namespace, store) = boot("k11-two").await;
    let coordinator = store.fragment_coordinator();

    let stale = replica("web-a");
    let fresh = replica("web-b");
    // A replica of ANOTHER cell, always progressing. It must never count.
    let other_cell = replica("web-z");

    // Both fresh at boot: nobody is ejected.
    exchange(&coordinator, CELL, &stale).await;
    exchange(&coordinator, CELL, &fresh).await;
    exchange(&coordinator, "k11-other-cell", &other_cell).await;
    assert_eq!(lb_health(&stale), OK);
    assert_eq!(lb_health(&fresh), OK);

    // web-a's probe stops succeeding; web-b's keeps succeeding.
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    fresh.note_good(Instant::now());
    exchange(&coordinator, CELL, &fresh).await;
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(lb_health(&stale), OK, "the first stale view is a baseline");
    fresh.note_good(Instant::now());
    exchange(&coordinator, CELL, &fresh).await;
    other_cell.note_good(Instant::now());
    exchange(&coordinator, "k11-other-cell", &other_cell).await;
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(
        lb_health(&stale),
        EJECTED,
        "a stale replica whose peer keeps writing must be ejected"
    );
    assert_eq!(lb_health(&fresh), OK);
    let stale_view = stale.snapshot(Instant::now());
    assert_eq!(stale_view.progressing_peers, Some(1));
    assert_eq!(
        stale_view.peers,
        Some(1),
        "another cell's row must not count"
    );

    // Now web-b goes stale too: a cell-wide fault ejects neither.
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    for _ in 0..2 {
        other_cell.note_good(Instant::now());
        exchange(&coordinator, "k11-other-cell", &other_cell).await;
        exchange(&coordinator, CELL, &stale).await;
        exchange(&coordinator, CELL, &fresh).await;
    }
    assert_eq!(lb_health(&stale), OK);
    assert_eq!(lb_health(&fresh), OK);

    // web-a recovers: one good probe is enough.
    stale.note_good(Instant::now());
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(lb_health(&stale), OK);

    drop(store);
    namespace.release().await;
}

/// The first review's double eject. A cell-wide NFS hang stops both probes
/// within 200 ms. Each replica exchanged just before it went stale, after the
/// other's last success was published. Neither may be ejected, even though
/// each saw the other's count rise before the threshold.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn both_probes_stopping_together_eject_neither() {
    let (namespace, store) = boot("k11-both").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    // The hang: a's last good probe, then b's 200 ms later. Each is
    // published at once. Neither probes again.
    let stopped = Instant::now();
    a.note_good(stopped);
    exchange(&coordinator, CELL, &a).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    b.note_good(Instant::now());
    exchange(&coordinator, CELL, &b).await;
    // Exchanges right before a's stale threshold.
    tokio::time::sleep_until((stopped + STALE_AFTER - Duration::from_millis(150)).into()).await;
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    exchange(&coordinator, CELL, &a).await;
    // Both are now stale; each takes a baseline and a later view.
    tokio::time::sleep_until((stopped + STALE_AFTER + Duration::from_millis(400)).into()).await;
    for _ in 0..2 {
        exchange(&coordinator, CELL, &a).await;
        exchange(&coordinator, CELL, &b).await;
    }
    assert_eq!(
        (lb_health(&a), lb_health(&b)),
        (OK, OK),
        "(web-a, web-b): a cell-wide fault must eject neither"
    );
    drop(store);
    namespace.release().await;
}

mod delay_proxy {
    //! A TCP proxy in front of Postgres that can hold back one frontend
    //! message type (Bind) for a set time, as a slow network or a stalled
    //! peer host would. The client has already sent the message; it runs late.
    //! Only the Bind of the liveness publish is held back.

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    /// Only the liveness publish is held back, not the pool's own checks.
    const PUBLISH_NEEDLE: &str = "INSERT INTO lore_domain_write_behind_stage_progress";

    pub struct DelayProxy {
        pub addr: SocketAddr,
        delay_millis: Arc<AtomicU64>,
        commit_millis: Arc<AtomicU64>,
    }

    impl DelayProxy {
        pub async fn start(upstream: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let delay_millis = Arc::new(AtomicU64::new(0));
            let commit_millis = Arc::new(AtomicU64::new(0));
            let delay = delay_millis.clone();
            let commit = commit_millis.clone();
            lore_base::lore_spawn!(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let delay = delay.clone();
                    let commit = commit.clone();
                    lore_base::lore_spawn!(async move {
                        let _ = relay(client, upstream, delay, commit).await;
                    });
                }
            });
            Self {
                addr,
                delay_millis,
                commit_millis,
            }
        }

        /// Hold back every liveness publish that reaches the proxy from now on.
        pub fn delay_publishes(&self, delay: Duration) {
            self.delay_millis
                .store(u64::try_from(delay.as_millis()).unwrap(), Ordering::SeqCst);
        }

        /// Hold back every `COMMIT` that reaches the proxy from now on. The
        /// statement before it has run, so its writes exist but are not yet
        /// visible to other sessions.
        pub fn delay_commits(&self, delay: Duration) {
            self.commit_millis
                .store(u64::try_from(delay.as_millis()).unwrap(), Ordering::SeqCst);
        }
    }

    async fn relay(
        client: TcpStream,
        upstream: SocketAddr,
        delay: Arc<AtomicU64>,
        commit: Arc<AtomicU64>,
    ) -> std::io::Result<()> {
        let server = TcpStream::connect(upstream).await?;
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        lore_base::lore_spawn!(async move {
            let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
        });
        // Untyped startup messages: SSLRequest/GSSENCRequest, then StartupMessage.
        loop {
            let mut length = [0_u8; 4];
            client_read.read_exact(&mut length).await?;
            let mut body = vec![0_u8; usize::try_from(u32::from_be_bytes(length)).unwrap() - 4];
            client_read.read_exact(&mut body).await?;
            server_write.write_all(&length).await?;
            server_write.write_all(&body).await?;
            let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            if code != 80_877_103 && code != 80_877_104 {
                break;
            }
        }
        // Prepared statement name -> whether it is the liveness publish.
        let mut statements = std::collections::HashMap::<Vec<u8>, bool>::new();
        loop {
            let mut header = [0_u8; 5];
            client_read.read_exact(&mut header).await?;
            let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let mut body = vec![0_u8; usize::try_from(length).unwrap() - 4];
            client_read.read_exact(&mut body).await?;
            let mut fields = body.split(|byte| *byte == 0);
            match header[0] {
                b'P' => {
                    let name = fields.next().unwrap_or_default().to_vec();
                    let query = String::from_utf8_lossy(fields.next().unwrap_or_default());
                    statements.insert(name, query.contains(PUBLISH_NEEDLE));
                }
                // Bind, not Execute: outside an explicit transaction the
                // implicit one, and so `now()`, starts at Bind.
                b'B' => {
                    let _portal = fields.next();
                    let name = fields.next().unwrap_or_default();
                    let millis = delay.load(Ordering::SeqCst);
                    if statements.get(name).copied().unwrap_or(false) && millis > 0 {
                        tokio::time::sleep(Duration::from_millis(millis)).await;
                    }
                }
                // A simple query: `transaction().commit()` sends `COMMIT`.
                b'Q' => {
                    let query = String::from_utf8_lossy(&body).to_uppercase();
                    let millis = commit.load(Ordering::SeqCst);
                    if query.trim_end_matches('\0').trim() == "COMMIT" && millis > 0 {
                        tokio::time::sleep(Duration::from_millis(millis)).await;
                    }
                }
                _ => {}
            }
            server_write.write_all(&header).await?;
            server_write.write_all(&body).await?;
        }
    }
}

/// `url` with its `host:port` replaced by `addr`.
fn via(url: &str, upstream: std::net::SocketAddr, addr: std::net::SocketAddr) -> String {
    let from = upstream.to_string();
    assert!(url.contains(&from), "{url} must name {from}");
    url.replacen(&from, &addr.to_string(), 1)
}

fn upstream_addr(url: &str) -> std::net::SocketAddr {
    let after_at = url.rsplit_once('@').map_or(url, |(_, rest)| rest);
    let host_port = after_at.split('/').next().unwrap();
    std::net::ToSocketAddrs::to_socket_addrs(host_port)
        .unwrap()
        .next()
        .unwrap()
}

/// The second review's double eject. A cell-wide hang, and each replica's
/// publish of its last success is held back by the network. Each delayed
/// publish runs after the other replica's baseline view and before its next
/// one. Neither may be ejected: an increase that runs after its sender's own
/// timeout changes nothing.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn delayed_publishes_in_a_cell_wide_hang_eject_neither() {
    let (namespace, store) = boot("k11-delay").await;
    let coordinator = store.fragment_coordinator();
    let upstream = upstream_addr(namespace.pg_url());
    let proxy_a = delay_proxy::DelayProxy::start(upstream).await;
    let proxy_b = delay_proxy::DelayProxy::start(upstream).await;
    let store_a = PostgresDomainStore::connect(
        &via(namespace.pg_url(), upstream, proxy_a.addr),
        1,
        &TlsConfig::default(),
    )
    .await
    .expect("boot through proxy a");
    let store_b = PostgresDomainStore::connect(
        &via(namespace.pg_url(), upstream, proxy_b.addr),
        1,
        &TlsConfig::default(),
    )
    .await
    .expect("boot through proxy b");
    let delayed_a = store_a.fragment_coordinator();
    let delayed_b = store_b.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    for _ in 0..2 {
        exchange(&coordinator, CELL, &a).await;
        exchange(&coordinator, CELL, &b).await;
    }

    // The hang: a's last good probe, then b's 200 ms later.
    let t0 = Instant::now();
    a.note_good(t0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    b.note_good(Instant::now());
    let at = |millis: u64| tokio::time::sleep_until((t0 + Duration::from_millis(millis)).into());

    // Each replica sends its last success at once; the network holds the
    // statement back for 2.3 s (a) and 2.0 s (b), well past the deadline.
    at(300).await;
    proxy_a.delay_publishes(Duration::from_millis(2300));
    proxy_b.delay_publishes(Duration::from_millis(2000));
    let late = |coordinator: PostgresFragmentCoordinator, replica: &StageLiveness| {
        let publication = replica.publication();
        let id = replica.replica_id().to_owned();
        let limits = replica.limits();
        async move {
            let result = coordinator
                .exchange_stage_liveness(CELL, &id, &publication, limits)
                .await;
            (t0.elapsed(), publication.progress, result)
        }
    };
    let late_a = late(delayed_a, &a);
    let late_b = late(delayed_b, &b);
    let honest = async {
        // a's baseline, then b's baseline.
        at(1700).await;
        exchange(&coordinator, CELL, &a).await;
        at(1900).await;
        exchange(&coordinator, CELL, &b).await;
        // b's delayed publish has run (2.3 s); a reads it.
        at(2450).await;
        exchange(&coordinator, CELL, &a).await;
        // a's delayed publish has run (2.6 s); b reads it.
        at(2750).await;
        exchange(&coordinator, CELL, &b).await;
        (lb_health(&a), lb_health(&b))
    };
    let (late_a, late_b, verdicts) = tokio::join!(late_a, late_b, honest);
    for (name, (ran_at, sent, result)) in [("web-a", late_a), ("web-b", late_b)] {
        let view = result.unwrap_or_else(|error| panic!("{name}'s delayed publish ran: {error}"));
        assert!(
            ran_at >= Duration::from_millis(2200),
            "control: {name}'s publish was held back ({ran_at:?})"
        );
        let stored = view.published.expect("published").progress;
        assert!(
            stored < i64::try_from(sent).unwrap(),
            "{name}'s late increase to {sent} must not be stored (stored {stored})"
        );
    }
    assert_eq!(
        verdicts,
        (OK, OK),
        "(web-a, web-b): delayed publishes in a cell-wide hang must eject neither"
    );
    drop((store, store_a, store_b));
    namespace.release().await;
}

/// The second review's slow probes: 4 s each, so two replicas' last good
/// probes can be 6 s apart, then a cell-wide hang. Scaled by 0.1. Nobody may
/// be ejected at any moment.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn slow_probes_then_a_cell_wide_hang_eject_nobody() {
    let (namespace, store) = boot("k11-slow").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    let start = Instant::now();
    let hang = start + Duration::from_millis(1300);
    // Successes every 600 ms (a 400 ms probe plus a 200 ms interval). a's
    // last one finished 600 ms (scaled 6 s) before the hang; b's right at it.
    let mut a_successes = vec![
        hang - Duration::from_millis(1200),
        hang - Duration::from_millis(600),
    ];
    let mut b_successes = vec![
        hang - Duration::from_millis(1200),
        hang - Duration::from_millis(600),
        hang,
    ];
    let mut ejected = Vec::new();
    let mut ticks = 0;
    while Instant::now() < hang + STALE_AFTER + Duration::from_millis(1500) {
        let now = Instant::now();
        for (replica, successes) in [(&a, &mut a_successes), (&b, &mut b_successes)] {
            while successes.first().is_some_and(|at| *at <= now) {
                replica.note_good(successes.remove(0));
            }
        }
        exchange(&coordinator, CELL, &a).await;
        exchange(&coordinator, CELL, &b).await;
        for (name, replica) in [("web-a", &a), ("web-b", &b)] {
            if lb_health(replica) != OK {
                ejected.push((name, (Instant::now() - hang).as_millis()));
            }
        }
        ticks += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ticks > 20, "control: the run kept exchanging ({ticks})");
    assert!(
        a.fault(Instant::now()).is_none() && a.last_good_age(Instant::now()) >= STALE_AFTER,
        "control: web-a is stale at the end"
    );
    assert!(
        ejected.is_empty(),
        "a cell-wide hang must eject nobody; ejected (replica, ms after the hang): {ejected:?}"
    );
    drop(store);
    namespace.release().await;
}

/// The other side of the slow-probe case: a peer whose probes are slow but
/// still succeed is real evidence, so the stale replica is ejected, and the
/// peer never is.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_slow_but_working_peer_still_ejects_a_stale_replica() {
    let (namespace, store) = boot("k11-slowok").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    let start = Instant::now();
    let mut next_b = start;
    let mut first_eject = None;
    let mut b_ejected = false;
    while Instant::now() < start + STALE_AFTER + Duration::from_millis(1500) {
        let now = Instant::now();
        if now >= next_b {
            b.note_good(now);
            next_b = now + Duration::from_millis(600);
        }
        exchange(&coordinator, CELL, &b).await;
        exchange(&coordinator, CELL, &a).await;
        if first_eject.is_none() && lb_health(&a) == EJECTED {
            first_eject = Some(Instant::now() - start);
        }
        b_ejected |= lb_health(&b) != OK;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let first_eject = first_eject.expect("web-a must be ejected while web-b keeps writing");
    assert!(first_eject >= STALE_AFTER, "{first_eject:?}");
    assert!(!b_ejected, "a replica that keeps writing is never ejected");
    drop(store);
    namespace.release().await;
}

/// A success that is published late (the exchanges failed for a while, or
/// the peer was slow to send) is no evidence: it may date from before the
/// hang. Only a fresh success counts.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_late_publish_of_an_old_success_proves_nothing() {
    let (namespace, store) = boot("k11-fresh").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let b = replica("web-b");
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    // b's last success, then no exchange for a while.
    b.note_good(Instant::now());
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), OK, "a success published 1.8 s late");
    // Control: a fresh success counts.
    b.note_good(Instant::now());
    exchange(&coordinator, CELL, &b).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), EJECTED);
    drop(store);
    namespace.release().await;
}

/// A restarted peer (same replica id, new incarnation) starts a new
/// sequence. Its row replaces the old one, the stale replica takes a new
/// baseline for it, and only progress in the new incarnation counts, though
/// its count is below the old process's.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_restarted_peer_resets_the_baseline() {
    let (namespace, store) = boot("k11-restart").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let old = StageLiveness::with_incarnation("web-b".to_owned(), "b-old".to_owned(), thresholds());
    exchange(&coordinator, CELL, &a).await;
    for _ in 0..5 {
        old.note_good(Instant::now());
        exchange(&coordinator, CELL, &old).await;
    }
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), OK, "baseline");

    // web-b restarts: same id, a new process.
    let new = StageLiveness::with_incarnation("web-b".to_owned(), "b-new".to_owned(), thresholds());
    exchange(&coordinator, CELL, &new).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), OK, "a restart is not progress");
    new.note_good(Instant::now());
    exchange(&coordinator, CELL, &new).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(
        lb_health(&a),
        EJECTED,
        "progress in the new incarnation counts"
    );
    drop(store);
    namespace.release().await;
}

/// Two processes share one replica id (a misconfiguration), so the row goes
/// X, Y, X. X's return carries a higher count from a stale success. A stale
/// observer that never saw Y must not count it: a new incarnation's write is
/// held to the same fresh-and-on-time test as any increase.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn an_incarnation_flip_back_with_a_stale_success_proves_nothing() {
    let (namespace, store) = boot("k11-flip").await;
    let coordinator = store.fragment_coordinator();
    let a = replica("web-a");
    let x = StageLiveness::with_incarnation("web-b".to_owned(), "b-x".to_owned(), thresholds());
    let y = StageLiveness::with_incarnation("web-b".to_owned(), "b-y".to_owned(), thresholds());
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &x).await;
    // X's last success, never published while fresh.
    x.note_good(Instant::now());
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), OK, "baseline");
    // Y writes the row; a does not look. Then X writes it back.
    exchange(&coordinator, CELL, &y).await;
    let back = coordinator
        .exchange_stage_liveness(CELL, "web-b", &x.publication(), x.limits())
        .await
        .expect("X publishes again");
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(
        lb_health(&a),
        OK,
        "a stale success carried across an incarnation change"
    );
    let stored = back.published.expect("published");
    assert_eq!((stored.incarnation.as_str(), stored.progress), ("b-x", 1));
    assert_eq!(
        stored.progressed_micros, 0,
        "a stale success on an incarnation change must not be stamped"
    );
    // Control: a fresh X success counts.
    x.note_good(Instant::now());
    exchange(&coordinator, CELL, &x).await;
    exchange(&coordinator, CELL, &a).await;
    assert_eq!(lb_health(&a), EJECTED);
    drop(store);
    namespace.release().await;
}

/// The SQL rules on one row, on the database clock: the stored count never
/// goes down; an increase needs a fresh success, a clock anchor, and a
/// statement that runs by the deadline; a new incarnation replaces the row.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_stored_count_only_moves_forward_and_only_on_time() {
    let (namespace, store) = boot("k11-sql").await;
    let coordinator = store.fragment_coordinator();
    let replica = replica("web-b");
    let limits = replica.limits();
    let publish = |incarnation: &str, progress: u64, age: Duration, clock| {
        let publication = StageLivenessPublication {
            incarnation: incarnation.to_owned(),
            progress,
            last_good: Instant::now().checked_sub(age).unwrap(),
            clock,
            role: StageLivenessRole::Stage,
        };
        let coordinator = &coordinator;
        async move {
            coordinator
                .exchange_stage_liveness(CELL, "web-b", &publication, limits)
                .await
                .unwrap()
        }
    };
    let stored = |view: &StagePeerLiveness| {
        let record = view.published.clone().expect("published");
        (
            record.incarnation,
            record.progress,
            record.progressed_micros,
        )
    };
    let anchor = |view: &StagePeerLiveness| {
        Some(StageLivenessClock {
            db_micros: view.db_clock_micros,
            received: Instant::now(),
        })
    };
    // A first row for an incarnation is written without an anchor.
    let first = publish("i", 5, Duration::ZERO, None).await;
    assert_eq!(stored(&first).1, 5);
    // No anchor: an increase is not accepted.
    let view = publish("i", 6, Duration::ZERO, None).await;
    assert_eq!(stored(&view), stored(&first));
    // Fresh and on time: accepted, stamped later.
    let view = publish("i", 6, Duration::ZERO, anchor(&view)).await;
    assert_eq!(stored(&view).1, 6);
    assert!(stored(&view).2 > stored(&first).2);
    let six = stored(&view);
    // Lower: never stored.
    let view = publish("i", 3, Duration::ZERO, anchor(&view)).await;
    assert_eq!(stored(&view), six, "a lower count must not be stored");
    // A stale success: not accepted.
    let view = publish(
        "i",
        7,
        PUBLISH_FRESH + Duration::from_millis(100),
        anchor(&view),
    )
    .await;
    assert_eq!(stored(&view), six, "a stale success must not be accepted");
    // Past its deadline (an anchor that says the database was already
    // later): not accepted.
    let past = Some(StageLivenessClock {
        db_micros: view.db_clock_micros
            - i64::try_from((PUBLISH_DEADLINE + Duration::from_millis(500)).as_micros()).unwrap(),
        received: Instant::now(),
    });
    let view = publish("i", 7, Duration::ZERO, past).await;
    assert_eq!(stored(&view), six, "a late statement must not be accepted");
    // Control: the same increase, on time.
    let view = publish("i", 7, Duration::ZERO, anchor(&view)).await;
    assert_eq!(stored(&view).1, 7);
    // A new incarnation replaces the row, whatever its count.
    let view = publish("j", 1, Duration::from_secs(60), None).await;
    assert_eq!(
        (stored(&view).0.as_str(), stored(&view).1),
        ("j", 1),
        "a restart starts a new sequence"
    );
    // The prior row is reported as the statement found it.
    let again = publish("j", 1, Duration::ZERO, anchor(&view)).await;
    assert_eq!(again.prior, view.published);
    drop(store);
    namespace.release().await;
}

/// Rows not published for `retain` are pruned, so restarts do not grow the
/// table; ids are bounded.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn departed_rows_are_pruned_and_ids_are_bounded() {
    let (namespace, store) = boot("k11-prune").await;
    let coordinator = store.fragment_coordinator();
    let departed = replica("departed");
    let survivor = replica("survivor");
    exchange(&coordinator, CELL, &departed).await;
    let (client, connection) = tokio_postgres::connect(namespace.pg_url(), tokio_postgres::NoTls)
        .await
        .expect("raw connection");
    let _connection = lore_base::lore_spawn!(connection);
    client
        .execute(
            "UPDATE lore_domain_write_behind_stage_progress \
             SET published_at = now() - interval '2 hours' \
             WHERE replica_id = 'departed'",
            &[],
        )
        .await
        .expect("age the departed row");
    exchange(&coordinator, CELL, &survivor).await;
    // The pruning statement still sees the row it deletes; the next one not.
    assert_eq!(survivor.snapshot(Instant::now()).peers, Some(1));
    exchange(&coordinator, CELL, &survivor).await;
    assert_eq!(
        survivor.snapshot(Instant::now()).peers,
        Some(0),
        "the departed row must be pruned"
    );

    let publication = |incarnation: &str| StageLivenessPublication {
        incarnation: incarnation.to_owned(),
        progress: 0,
        last_good: Instant::now(),
        clock: None,
        role: StageLivenessRole::Stage,
    };
    let long_id = "x".repeat(129);
    let long_incarnation = "y".repeat(65);
    for (cell, id, incarnation) in [
        ("", "a", "i"),
        (CELL, "", "i"),
        (CELL, long_id.as_str(), "i"),
        (CELL, "a", ""),
        (CELL, "a", long_incarnation.as_str()),
    ] {
        assert!(
            coordinator
                .exchange_stage_liveness(cell, id, &publication(incarnation), survivor.limits())
                .await
                .is_err(),
            "cell {cell:?}, replica of {} bytes, incarnation of {} bytes must be refused",
            id.len(),
            incarnation.len()
        );
    }

    drop(store);
    namespace.release().await;
}

/// A draining peer must not count. During a one-host roll the host going
/// down is the healthy one; if the remaining host's mount is stale it must
/// stay in the pool, or the cell goes dark.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_draining_peer_withdraws_and_no_longer_ejects_a_stale_replica() {
    let (namespace, store) = boot("k11-drain").await;
    let coordinator = store.fragment_coordinator();

    let stale = replica("web-a");
    let leaving = replica("web-b");
    exchange(&coordinator, CELL, &leaving).await;
    tokio::time::sleep(STALE_AFTER + Duration::from_millis(300)).await;
    exchange(&coordinator, CELL, &stale).await;
    leaving.note_good(Instant::now());
    exchange(&coordinator, CELL, &leaving).await;
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(
        lb_health(&stale),
        EJECTED,
        "control: a stale replica with a progressing serving peer is ejected"
    );

    // web-b starts to drain (lame duck or SIGTERM): it withdraws.
    let mut withdrawn = false;
    let shared = &coordinator;
    let tick = liveness_tick(
        &leaving,
        true,
        &mut withdrawn,
        |publication| {
            let (id, limits) = (leaving.replica_id(), leaving.limits());
            async move {
                shared
                    .exchange_stage_liveness(CELL, id, &publication, limits)
                    .await
            }
        },
        || coordinator.withdraw_stage_liveness(CELL, leaving.replica_id()),
        Duration::from_secs(5),
        &mut None,
    )
    .await;
    assert_eq!(tick, LivenessTick::Withdrew);

    // web-b still probes well, but it no longer counts.
    leaving.note_good(Instant::now());
    exchange(&coordinator, CELL, &stale).await;
    assert_eq!(lb_health(&stale), OK);
    let view = stale.snapshot(Instant::now());
    assert_eq!(view.peers, Some(0), "the draining peer's row must be gone");
    assert_eq!(view.progressing_peers, Some(0));

    drop(store);
    namespace.release().await;
}

// ---------------------------------------------------------------------------
// WP-115 K11 guard: real exchanges, real stage directories, a drain anchor.
// ---------------------------------------------------------------------------

const SHARE_GRACE: Duration = Duration::from_millis(600);
const SHARE_PEER_FRESH: Duration = Duration::from_secs(1);
const NOT_SHARED: (StatusCode, &str) = (
    StatusCode::SERVICE_UNAVAILABLE,
    lore_server::stage_liveness::STAGE_NOT_SHARED,
);
const UNVERIFIED: (StatusCode, &str) = (
    StatusCode::SERVICE_UNAVAILABLE,
    lore_server::stage_liveness::STAGE_SHARE_UNVERIFIED,
);
/// The wire word for a replica whose first exchange has not succeeded for
/// the grace.
const PENDING_TOO_LONG: (StatusCode, &str) =
    (StatusCode::SERVICE_UNAVAILABLE, "stage_share_pending");

fn guarded(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(
        id.to_owned(),
        LivenessThresholds {
            share_grace: SHARE_GRACE,
            share_peer_fresh: SHARE_PEER_FRESH,
            ..thresholds()
        },
    )
    .with_share_guard()
}

fn drain(id: &str) -> StageLiveness {
    StageLiveness::with_thresholds(id.to_owned(), thresholds()).with_role(StageLivenessRole::Drain)
}

/// One probe-thread (or drain marker-thread) step, as the real thread runs
/// it.
fn markers_step(replica: &StageLiveness, markers: &ShareMarkers) {
    replica
        .share_step(markers)
        .expect("the own marker must be written");
}

/// Whether staging is off: the gate the stage reads.
fn held(replica: &StageLiveness) -> bool {
    replica
        .share_gate()
        .load(std::sync::atomic::Ordering::Acquire)
}

/// The role this cell's table holds for `id`, as a peer reads it.
async fn stored_role(
    coordinator: &PostgresFragmentCoordinator,
    reader: &StageLiveness,
    id: &str,
) -> Option<StageLivenessRole> {
    coordinator
        .exchange_stage_liveness(
            CELL,
            reader.replica_id(),
            &reader.publication(),
            reader.limits(),
        )
        .await
        .expect("raw exchange")
        .peers
        .iter()
        .find(|peer| peer.replica_id == id)
        .map(|peer| peer.role)
}

/// The first web replica, no drain row: it serves (200) and never stages.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn the_first_replica_alone_serves_without_staging() {
    let (namespace, store) = boot("k11-guard-alone").await;
    let coordinator = store.fragment_coordinator();
    let stage = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(stage.path());
    let first = guarded("web-a");
    assert!(
        held(&first),
        "control: nothing is proven before an exchange"
    );
    assert_eq!(lb_health(&first), OK, "pending is 200");
    markers_step(&first, &markers);
    exchange(&coordinator, CELL, &first).await;
    markers_step(&first, &markers);
    assert_eq!(lb_health(&first), OK);
    assert!(held(&first), "no drain row proves the stage, so no staging");
    assert_eq!(first.share_verdict(Instant::now()), ShareVerdict::NoAnchor);
    drop(store);
    namespace.release().await;
}

/// The drain and two web replicas on one stage: both web replicas stage once
/// they see the drain's marker.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn two_replicas_on_the_drains_stage_both_stage() {
    let (namespace, store) = boot("k11-guard-shared").await;
    let coordinator = store.fragment_coordinator();
    let stage = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(stage.path());
    let worker = drain("drain-1");
    markers_step(&worker, &markers);
    exchange(&coordinator, CELL, &worker).await;
    let a = guarded("web-a");
    let b = guarded("web-b");
    for replica in [&a, &b] {
        markers_step(replica, &markers);
        exchange(&coordinator, CELL, replica).await;
        // The real probe thread checks markers after the exchange names them.
        markers_step(replica, &markers);
    }
    tokio::time::sleep(SHARE_GRACE + Duration::from_millis(100)).await;
    markers_step(&worker, &markers);
    exchange(&coordinator, CELL, &worker).await;
    exchange(&coordinator, CELL, &a).await;
    exchange(&coordinator, CELL, &b).await;
    assert_eq!(lb_health(&a), OK);
    assert_eq!(lb_health(&b), OK);
    assert!(!held(&a) && !held(&b));
    assert_eq!(
        a.snapshot(Instant::now()).peers,
        Some(1),
        "the drain row is not a K11 peer"
    );
    drop(store);
    namespace.release().await;
}

/// Review probe R2, now a test. Cold boot with no drain row: web-a (first)
/// on a WRONG directory, web-b on the real stage. For three graces neither
/// stages and neither is ejected. (Before this fix web-a, the earliest by
/// join, opened staging on the wrong directory and web-b answered 503.)
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn with_no_drain_row_no_replica_stages_and_none_is_ejected() {
    let (namespace, store) = boot("k11-guard-r2").await;
    let coordinator = store.fragment_coordinator();
    let (real, wrong) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (real_markers, wrong_markers) = (
        ShareMarkers::new(real.path()),
        ShareMarkers::new(wrong.path()),
    );
    let a = guarded("web-a");
    let b = guarded("web-b");
    markers_step(&a, &wrong_markers);
    exchange(&coordinator, CELL, &a).await;
    let deadline = Instant::now() + SHARE_GRACE * 3;
    while Instant::now() < deadline {
        markers_step(&a, &wrong_markers);
        markers_step(&b, &real_markers);
        exchange(&coordinator, CELL, &a).await;
        exchange(&coordinator, CELL, &b).await;
        for replica in [&a, &b] {
            assert!(held(replica), "{} must not stage", replica.replica_id());
            assert_eq!(lb_health(replica), OK, "{}", replica.replica_id());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(a.share_verdict(Instant::now()), ShareVerdict::NoAnchor);
    assert_eq!(b.share_verdict(Instant::now()), ShareVerdict::NoAnchor);
    drop(store);
    namespace.release().await;
}

/// Review probe R1, now a test. Both web replicas ARE on the drain's stage,
/// the drain's row is fresh, but the drain cannot write its marker (a
/// directory sits at the marker path, as an EACCES or a wrong-uid
/// `liveness/` would). The drain publishes `drain_unverified`, so it anchors
/// nobody: both web replicas answer 200 and write directly, past the grace.
/// (Before this fix both answered 503, a whole-cell eject.) When the drain
/// can write its marker again, both web replicas see it and stage.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_drain_that_cannot_read_its_marker_back_anchors_nobody() {
    let (namespace, store) = boot("k11-guard-r1").await;
    let coordinator = store.fragment_coordinator();
    let real = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(real.path());
    let worker = drain("drain-1");
    let blocker = real.path().join("liveness").join("drain-1.present");
    std::fs::create_dir_all(&blocker).unwrap();
    assert!(
        worker.share_step(&markers).is_err(),
        "control: the drain marker write fails"
    );
    let a = guarded("web-a");
    let b = guarded("web-b");
    let deadline = Instant::now() + SHARE_GRACE + Duration::from_millis(300);
    while Instant::now() < deadline {
        assert!(worker.share_step(&markers).is_err());
        exchange(&coordinator, CELL, &worker).await;
        markers_step(&a, &markers);
        markers_step(&b, &markers);
        exchange(&coordinator, CELL, &a).await;
        exchange(&coordinator, CELL, &b).await;
        for replica in [&a, &b] {
            assert_eq!(lb_health(replica), OK, "{}", replica.replica_id());
            assert!(held(replica), "{} must not stage", replica.replica_id());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        stored_role(&coordinator, &a, "drain-1").await,
        Some(StageLivenessRole::DrainUnverified)
    );
    assert_eq!(
        worker.fault(Instant::now()),
        Some(lore_server::stage_liveness::STAGE_ANCHOR_UNVERIFIED)
    );

    // The drain's marker becomes writable again: it anchors, and both web
    // replicas, on the same stage, see it and stage.
    std::fs::remove_dir(&blocker).unwrap();
    markers_step(&worker, &markers);
    exchange(&coordinator, CELL, &worker).await;
    assert_eq!(worker.fault(Instant::now()), None);
    for replica in [&a, &b] {
        exchange(&coordinator, CELL, replica).await;
        markers_step(replica, &markers);
        assert_eq!(lb_health(replica), OK);
        assert!(!held(replica), "{} stages", replica.replica_id());
    }
    assert_eq!(
        stored_role(&coordinator, &a, "drain-1").await,
        Some(StageLivenessRole::Drain)
    );
    drop(store);
    namespace.release().await;
}

/// Review probe RV3-B, now a test. The drain anchors on the real stage, and
/// both web replicas boot unproven while every read of the drain's marker on
/// their hosts fails with an I/O error (a directory at the marker path, as a
/// stale handle or `EIO` would). That is "cannot decide": past the grace both
/// answer 200 and keep staging off, so new fragments are written directly.
/// (Before this fix both answered 503 `stage_share_unverified`, then
/// `stage_not_shared`: a whole-cell eject.) When the reads work again and
/// show the marker, both stage.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn marker_read_errors_on_both_unproven_replicas_answer_200_with_direct_writes() {
    let (namespace, store) = boot("k11-guard-rv3b").await;
    let coordinator = store.fragment_coordinator();
    let real = tempfile::tempdir().unwrap();
    let real_markers = ShareMarkers::new(real.path());
    let worker = drain("drain-1");
    markers_step(&worker, &real_markers);
    exchange(&coordinator, CELL, &worker).await;
    // The verdict `Undecided` below needs a fresh `drain` row (without one it
    // is `NoAnchor`), so each loop step also proves the drain anchors.

    let a = guarded("web-a");
    let b = guarded("web-b");
    let (stage_a, stage_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let blockers: Vec<_> = [&stage_a, &stage_b]
        .iter()
        .map(|stage| stage.path().join("liveness").join("drain-1.present"))
        .collect();
    for blocker in &blockers {
        std::fs::create_dir_all(blocker).unwrap();
    }
    let (markers_a, markers_b) = (
        ShareMarkers::new(stage_a.path()),
        ShareMarkers::new(stage_b.path()),
    );
    assert!(
        markers_a.read("drain-1").is_err() && markers_b.read("drain-1").is_err(),
        "control: the web replicas' marker reads fail with an I/O error"
    );
    let deadline = Instant::now() + SHARE_GRACE + Duration::from_millis(300);
    while Instant::now() < deadline {
        markers_step(&worker, &real_markers);
        exchange(&coordinator, CELL, &worker).await;
        for (replica, markers) in [(&a, &markers_a), (&b, &markers_b)] {
            exchange(&coordinator, CELL, replica).await;
            markers_step(replica, markers);
            assert_eq!(lb_health(replica), OK, "{}", replica.replica_id());
            assert!(held(replica), "{} writes directly", replica.replica_id());
            assert_eq!(
                replica.share_verdict(Instant::now()),
                ShareVerdict::Undecided,
                "{}",
                replica.replica_id()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(a.snapshot(Instant::now()).share, Some("undecided"));

    // The reads work again and show the drain's marker: both stage.
    let incarnation = worker.incarnation().to_owned();
    for (blocker, markers) in blockers.iter().zip([&markers_a, &markers_b]) {
        std::fs::remove_dir(blocker).unwrap();
        markers.ensure("drain-1", &incarnation).unwrap();
    }
    markers_step(&worker, &real_markers);
    exchange(&coordinator, CELL, &worker).await;
    for (replica, markers) in [(&a, &markers_a), (&b, &markers_b)] {
        exchange(&coordinator, CELL, replica).await;
        markers_step(replica, markers);
        assert_eq!(lb_health(replica), OK);
        assert!(!held(replica), "{} stages", replica.replica_id());
    }
    drop(store);
    namespace.release().await;
}

/// The anchor. The first web replica is on its own directory; the drain and
/// a later web replica share the real stage. The misplaced one answers 503
/// and never stages; the other stages. A proven replica stays proven: the
/// drain's restart (marker not yet written) does not hold it.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_drain_anchors_the_check_and_holds_a_misplaced_replica() {
    let (namespace, store) = boot("k11-guard-anchor").await;
    let coordinator = store.fragment_coordinator();
    let (real, wrong) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (real_markers, wrong_markers) = (
        ShareMarkers::new(real.path()),
        ShareMarkers::new(wrong.path()),
    );
    let worker = drain("drain-1");
    markers_step(&worker, &real_markers);
    exchange(&coordinator, CELL, &worker).await;
    let early = guarded("web-a");
    let late = guarded("web-b");
    markers_step(&early, &wrong_markers);
    exchange(&coordinator, CELL, &early).await;
    markers_step(&late, &real_markers);
    exchange(&coordinator, CELL, &late).await;
    markers_step(&early, &wrong_markers);
    markers_step(&late, &real_markers);
    assert_eq!(lb_health(&late), OK, "web-b sees the drain's marker");
    assert!(!held(&late));
    assert_eq!(lb_health(&early), UNVERIFIED);
    assert!(held(&early));
    tokio::time::sleep(SHARE_GRACE + Duration::from_millis(100)).await;
    markers_step(&worker, &real_markers);
    exchange(&coordinator, CELL, &worker).await;
    exchange(&coordinator, CELL, &early).await;
    markers_step(&early, &wrong_markers);
    assert_eq!(lb_health(&early), NOT_SHARED);
    assert!(held(&early));
    assert_eq!(worker.share_verdict(Instant::now()), ShareVerdict::Shared);
    assert_eq!(
        worker.fault(Instant::now()),
        None,
        "the drain is never held"
    );

    let restarted = drain("drain-1");
    exchange(&coordinator, CELL, &restarted).await;
    exchange(&coordinator, CELL, &late).await;
    markers_step(&late, &real_markers);
    assert_eq!(lb_health(&late), OK);
    assert!(!held(&late));
    drop(store);
    namespace.release().await;
}

/// A drain row older than the fresh window is no anchor: the replica serves
/// and does not stage. It never waits for the drain.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_stale_drain_row_is_no_anchor() {
    let (namespace, store) = boot("k11-guard-stale-drain").await;
    let coordinator = store.fragment_coordinator();
    let real = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(real.path());
    let worker = drain("drain-1");
    markers_step(&worker, &markers);
    exchange(&coordinator, CELL, &worker).await;
    tokio::time::sleep(SHARE_PEER_FRESH + Duration::from_millis(200)).await;
    let first = guarded("web-a");
    markers_step(&first, &markers);
    exchange(&coordinator, CELL, &first).await;
    markers_step(&first, &markers);
    assert_eq!(lb_health(&first), OK, "a stale drain row is not an anchor");
    assert!(held(&first));
    assert_eq!(first.share_verdict(Instant::now()), ShareVerdict::NoAnchor);
    drop(store);
    namespace.release().await;
}

/// Review probe P1, the cold-boot race. Two web replicas exchange before the
/// drain's first row: web-a on a WRONG directory, web-c on the real stage.
/// Neither stages and both answer 200 until the drain row appears. Then
/// web-a answers 503 (unverified, then not shared) and still never stages;
/// web-c sees the marker and stages, for life. A web replica that boots
/// after the drain on the real stage stages too.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_cold_boot_stages_nothing_until_the_drains_marker_is_seen() {
    let (namespace, store) = boot("k11-guard-cold-boot").await;
    let coordinator = store.fragment_coordinator();
    let (real, wrong) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (real_markers, wrong_markers) = (
        ShareMarkers::new(real.path()),
        ShareMarkers::new(wrong.path()),
    );
    let early = guarded("web-a");
    let other = guarded("web-c");
    markers_step(&early, &wrong_markers);
    exchange(&coordinator, CELL, &early).await;
    markers_step(&other, &real_markers);
    exchange(&coordinator, CELL, &other).await;
    for replica in [&early, &other] {
        assert_eq!(lb_health(replica), OK, "no drain row: 200");
        assert!(held(replica), "no drain row: no staging");
    }

    let worker = drain("drain-1");
    markers_step(&worker, &real_markers);
    exchange(&coordinator, CELL, &worker).await;
    exchange(&coordinator, CELL, &early).await;
    exchange(&coordinator, CELL, &other).await;
    assert_eq!(lb_health(&early), UNVERIFIED);
    assert!(held(&early));
    let deadline = Instant::now() + SHARE_GRACE + Duration::from_millis(200);
    while Instant::now() < deadline {
        markers_step(&early, &wrong_markers);
        markers_step(&other, &real_markers);
        markers_step(&worker, &real_markers);
        exchange(&coordinator, CELL, &worker).await;
        exchange(&coordinator, CELL, &early).await;
        exchange(&coordinator, CELL, &other).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        lb_health(&early),
        NOT_SHARED,
        "the misplaced replica leaves"
    );
    assert!(held(&early));
    assert_eq!(lb_health(&other), OK, "web-c sees the drain's marker");
    assert!(!held(&other));

    let restarted = drain("drain-1");
    exchange(&coordinator, CELL, &restarted).await;
    exchange(&coordinator, CELL, &other).await;
    markers_step(&other, &real_markers);
    assert_eq!(lb_health(&other), OK);
    assert!(!held(&other), "an anchor proof is for life");

    markers_step(&restarted, &real_markers);
    exchange(&coordinator, CELL, &restarted).await;
    let late = guarded("web-b");
    markers_step(&late, &real_markers);
    exchange(&coordinator, CELL, &late).await;
    markers_step(&late, &real_markers);
    assert_eq!(lb_health(&late), OK);
    assert!(!held(&late));
    drop(store);
    namespace.release().await;
}

/// The network holds the drain's COMMIT back 800 ms. A web replica that
/// exchanges in that window sees no drain row: it answers 200 and does not
/// stage. Once the row is visible it answers 503 unverified until its next
/// marker step, then stages. Every step checks the `/lb_health` word.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_late_drain_commit_keeps_web_replicas_direct_until_it_is_visible() {
    let (namespace, store) = boot("k11-guard-late-commit").await;
    let coordinator = store.fragment_coordinator();
    let upstream = upstream_addr(namespace.pg_url());
    let proxy = delay_proxy::DelayProxy::start(upstream).await;
    let drain_store = PostgresDomainStore::connect(
        &via(namespace.pg_url(), upstream, proxy.addr),
        1,
        &TlsConfig::default(),
    )
    .await
    .expect("boot through the proxy");
    let delayed = drain_store.fragment_coordinator();
    let stage = tempfile::tempdir().unwrap();
    let markers = ShareMarkers::new(stage.path());
    let worker = drain("drain-1");
    let b = guarded("web-b");
    markers_step(&worker, &markers);
    markers_step(&b, &markers);

    proxy.delay_commits(Duration::from_millis(800));
    let b_early = std::sync::Mutex::new(None);
    let drain_first = exchange(&delayed, CELL, &worker);
    let web_first = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        exchange(&coordinator, CELL, &b).await;
        markers_step(&b, &markers);
        *b_early.lock().unwrap() = Some((lb_health(&b), held(&b), b.share_verdict(Instant::now())));
    };
    tokio::join!(drain_first, web_first);
    proxy.delay_commits(Duration::ZERO);
    assert_eq!(
        b_early.into_inner().unwrap(),
        Some((OK, true, ShareVerdict::NoAnchor)),
        "before the drain row is visible: 200, no staging"
    );

    // Keep the drain row inside the (scaled) fresh window: the delayed
    // statement stamped `published_at` at its start.
    markers_step(&worker, &markers);
    exchange(&coordinator, CELL, &worker).await;
    exchange(&coordinator, CELL, &b).await;
    assert_eq!(
        lb_health(&b),
        UNVERIFIED,
        "the row is visible, marker not yet checked"
    );
    assert!(held(&b));
    markers_step(&b, &markers);
    assert_eq!(lb_health(&b), OK);
    assert!(!held(&b), "the drain's marker is seen: staging opens");
    drop((store, drain_store));
    namespace.release().await;
}

/// Review probe P3. Postgres is slower than the exchange timeout at boot,
/// so no exchange completes. Staging stays off, and after the grace
/// `/lb_health` answers 503 `stage_share_pending`, not 200.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_replica_with_no_exchange_after_the_grace_answers_503() {
    let a = guarded("web-a");
    assert_eq!(lb_health(&a), OK, "inside the grace pending is 200");
    let deadline = Instant::now() + SHARE_GRACE + Duration::from_millis(100);
    while Instant::now() < deadline {
        let ok = exchange_once(
            &a,
            |_publication| async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Err::<StagePeerLiveness, String>("slow".to_owned())
            },
            Duration::from_millis(200),
            &mut None,
        )
        .await;
        assert!(!ok, "control: the exchange times out");
    }
    assert!(held(&a));
    assert_eq!(lb_health(&a), PENDING_TOO_LONG);
}

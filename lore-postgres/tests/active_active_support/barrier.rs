// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Deterministic barriers, and the attestation that makes them evidence.
//!
//! # The failure mode this module exists to prevent
//!
//! The way a two-process proof lies is not by asserting the wrong thing: it is
//! by asserting the right thing about two operations that never actually
//! overlapped. `tokio::join!` on two futures gives no such guarantee — the
//! first may complete before the second is polled, and the case still passes,
//! because "exactly one winner" is trivially true of a serial pair.
//!
//! So every barrier here is **attested by PostgreSQL itself** rather than by
//! elapsed time. [`wait_for_lock_waiters`] returns only once the server reports
//! that some other backend is blocked on a heavyweight lock; and it
//! **panics** if that never happens. A case built on it therefore fails when
//! its race degenerates into a sequence, instead of passing on a race it did
//! not run. That is the discriminating property `#[serial]`, a `sleep`, and a
//! bare `join!` all lack.
//!
//! The polling interval below is not the barrier. The *condition* is the
//! barrier; the interval only decides how often it is asked.
//!
//! # The barrier kinds, and when each applies
//!
//! 1. **Table gate** ([`TableGate`]). A raw transaction takes
//!    `LOCK TABLE ... IN EXCLUSIVE MODE` on the table both racers must write,
//!    both racers are started, [`wait_for_lock_waiters`] proves that many
//!    backends are concurrently blocked mid-operation, and only then is the
//!    gate released. This is the workhorse: it pins the interleaving without
//!    touching a single row, so it changes no outcome, and it needs no
//!    `failure_generator` build. `EXCLUSIVE` is the weakest mode that conflicts
//!    with `ROW EXCLUSIVE` (what an `INSERT` or `UPDATE` takes) while still
//!    admitting a plain `SELECT` — which is also what lets it hold a writer
//!    *after* a read it has already done, the placement `d2` depends on.
//! 2. **Advisory gate** ([`AdvisoryGate`]). The same idea one level down, for
//!    `PostgresImmutableStore`, whose per-hash critical section is
//!    `pg_advisory_xact_lock(hash[..8])` rather than a table write.
//! 3. **Failpoint rendezvous** ([`FailpointHold`]). The mechanism WP-118
//!    Phase 9 built for exactly this: a filesystem gate inside a named window
//!    of a coordinator method, which takes no database resource of its own.
//!    Needed where the contention point is *inside* one transaction and cannot
//!    be reached from outside at all.
//! 4. **Row-lock attestation** ([`wait_for_row_share_holders`]). For a
//!    `SKIP LOCKED` claimer, which by construction never blocks and so can
//!    never be caught by kind 1: the proof that two claimers overlapped is that
//!    both hold a `RowShareLock` on the claimed relation inside an open
//!    transaction at the same instant.
//!
//! `PAUSE_CEILING` in `failpoints.rs` is 60 seconds, so every ceiling here is
//! shorter: a harness that gives up first reports the barrier that failed,
//! whereas one that gives up second reports a downstream symptom.

#![allow(dead_code)]

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use tokio_postgres::Client;

/// How long any attestation waits before declaring the barrier dead.
///
/// Shorter than `failpoints::PAUSE_CEILING` (60s) on purpose; see the module
/// docs.
pub const ATTEST_CEILING: Duration = Duration::from_secs(20);

/// How often the attestation asks PostgreSQL. Not a barrier — see module docs.
const ATTEST_POLL: Duration = Duration::from_millis(10);

/// Open a connection dedicated to observing `pg_stat_activity`.
///
/// Deliberately its own connection rather than a pooled one from either set: a
/// probe that borrowed a coordinator's pool could itself be the connection a
/// race is waiting for.
pub async fn observer(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect the pg_stat_activity observer");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("observer connection error: {error}");
        }
    });
    client
}

async fn count_lock_waiters(observer: &Client) -> i64 {
    observer
        .query_one(
            "SELECT count(*)::bigint FROM pg_stat_activity \
             WHERE datname = current_database() \
               AND pid <> pg_backend_pid() \
               AND wait_event_type = 'Lock'",
            &[],
        )
        .await
        .expect("sample pg_stat_activity for lock waiters")
        .get(0)
}

/// Block until at least `at_least` other backends on this database are waiting
/// on a heavyweight lock, and return the number observed.
///
/// Panics at [`ATTEST_CEILING`]. That panic is the point: it says the race did
/// not interleave, which is a harness defect and must not be reported as a
/// passing race.
///
/// **What the count does and does not say.** It counts backends blocked on any
/// heavyweight lock, not backends blocked on the gate. A racer that reaches the
/// contended table only after taking an earlier row lock can end up blocked
/// behind the *other racer* rather than behind the gate — `branch_push_commit`
/// and `repository_delete` both take the repository row first, so this happens
/// in the push cases. The claim to make from a count of two is therefore "two
/// backends were concurrently blocked mid-operation", which is the overlap
/// these cases need; it is not "both were queued at the gate". Nothing else on
/// a case's fresh database can contribute to the count: the gate holder is not
/// waiting, and the observer and the readback connections are idle.
pub async fn wait_for_lock_waiters(observer: &Client, at_least: i64, what: &str) -> i64 {
    let started = Instant::now();
    loop {
        let observed = count_lock_waiters(observer).await;
        if observed >= at_least {
            println!("barrier attested: {observed} backend(s) blocked on a lock while {what}");
            return observed;
        }
        if started.elapsed() >= ATTEST_CEILING {
            panic!(
                "barrier never engaged while {what}: expected at least {at_least} backend(s) \
                 concurrently blocked on a heavyweight lock within {:?}, observed {observed}. \
                 The contenders did not overlap, so any outcome this case would assert is \
                 about a serial pair",
                ATTEST_CEILING
            );
        }
        tokio::time::sleep(ATTEST_POLL).await;
    }
}

async fn count_row_share_holders(observer: &Client, relation: &str) -> i64 {
    observer
        .query_one(
            "SELECT count(DISTINCT a.pid)::bigint \
             FROM pg_stat_activity a \
             JOIN pg_locks l ON l.pid = a.pid \
             WHERE a.datname = current_database() \
               AND a.pid <> pg_backend_pid() \
               AND a.state = 'idle in transaction' \
               AND l.locktype = 'relation' \
               AND l.relation = to_regclass($1) \
               AND l.mode = 'RowShareLock'",
            &[&relation],
        )
        .await
        .expect("sample pg_locks for row-share holders")
        .get(0)
}

/// Block until at least `at_least` other backends hold a `RowShareLock` on
/// `relation` inside an open transaction, and return the number observed.
///
/// `RowShareLock` on a relation is what `SELECT ... FOR UPDATE` takes, and a
/// backend cannot hold it before its locking select has run. Combined with
/// `state = 'idle in transaction'` — the backend has finished a statement and
/// not committed — this is an authoritative statement that two claimers each
/// completed a `FOR UPDATE` select and are both still inside their
/// transactions. That is the overlap a `SKIP LOCKED` case needs and that
/// [`wait_for_lock_waiters`] cannot give, because a `SKIP LOCKED` claimer never
/// blocks.
///
/// `relation` is resolved through `regclass` on the observer's own
/// `search_path`, so it names the case's schema, not another case's.
pub async fn wait_for_row_share_holders(
    observer: &Client,
    relation: &str,
    at_least: i64,
    what: &str,
) -> i64 {
    let started = Instant::now();
    loop {
        let observed = count_row_share_holders(observer, relation).await;
        if observed >= at_least {
            println!(
                "barrier attested: {observed} backend(s) holding row locks on {relation} while {what}"
            );
            return observed;
        }
        if started.elapsed() >= ATTEST_CEILING {
            panic!(
                "barrier never engaged while {what}: expected at least {at_least} backend(s) \
                 holding a RowShareLock on {relation} within {:?}, observed {observed}. The \
                 claimers did not overlap",
                ATTEST_CEILING
            );
        }
        tokio::time::sleep(ATTEST_POLL).await;
    }
}

/// A held `LOCK TABLE ... IN EXCLUSIVE MODE`.
///
/// Nothing is written, so releasing the gate leaves the database exactly as the
/// racers found it and the race's own outcome is untouched. What it buys is
/// that both racers are provably *at* the contended write when it opens,
/// instead of one having finished before the other started.
pub struct TableGate<'a> {
    tx: tokio_postgres::Transaction<'a>,
    table: String,
}

impl<'a> TableGate<'a> {
    /// Take the gate on `table`.
    ///
    /// `table` is interpolated into the statement because `LOCK TABLE` takes no
    /// bind parameters. Every caller in this harness passes a literal from
    /// `lore-postgres`'s own schema, and the assertion below refuses anything
    /// that is not a bare lowercase identifier.
    pub async fn take(client: &'a mut Client, table: &str) -> TableGate<'a> {
        assert!(
            table
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "table gate target must be a bare lowercase identifier, got {table:?}"
        );
        let tx = client
            .transaction()
            .await
            .unwrap_or_else(|error| panic!("begin table gate on {table}: {error}"));
        tx.execute(&format!("LOCK TABLE {table} IN EXCLUSIVE MODE"), &[])
            .await
            .unwrap_or_else(|error| panic!("lock table {table}: {error}"));
        println!("table gate taken: {table}");
        TableGate {
            tx,
            table: table.to_owned(),
        }
    }

    /// Release the gate. Commits an empty transaction; no row is touched.
    pub async fn release(self) {
        let table = self.table;
        self.tx
            .commit()
            .await
            .unwrap_or_else(|error| panic!("release table gate on {table}: {error}"));
        println!("table gate released: {table}");
    }
}

/// A held `pg_advisory_xact_lock` on the key `PostgresImmutableStore` derives
/// from a fragment hash.
///
/// `store/immutable_store.rs::lock_hash` takes
/// `pg_advisory_xact_lock(i64::from_be_bytes(hash[..8]))` as the first
/// statement of `put`, `copy`, and `obliterate`, so holding that exact key
/// stops every one of them at the same point, before any state is read.
pub struct AdvisoryGate<'a> {
    tx: tokio_postgres::Transaction<'a>,
    key: i64,
}

/// The advisory key `PostgresImmutableStore` derives from a fragment hash.
///
/// Duplicated from `store/immutable_store.rs::advisory_key`, which is private.
/// A copy in a test is normally a smell, and this one carries a real risk: a
/// gate computing a *different* key would stop nothing.
///
/// What stops that being silent is the attestation the callers pair it with,
/// not a source-text pin. Every case using this gate races **two**
/// participants and demands two blocked backends. With the wrong key the gate
/// holds nothing, so the two participants contend on the store's own advisory
/// lock, one of them wins immediately, and at most one backend is ever blocked
/// — [`wait_for_lock_waiters`] then panics on its ceiling. The failure mode is
/// a red case, not a green one.
pub fn advisory_key(hash: &[u8]) -> i64 {
    let mut key = [0u8; 8];
    key.copy_from_slice(&hash[..8]);
    i64::from_be_bytes(key)
}

impl<'a> AdvisoryGate<'a> {
    /// Take the gate for `hash`.
    pub async fn take(client: &'a mut Client, hash: &[u8]) -> AdvisoryGate<'a> {
        let key = advisory_key(hash);
        let tx = client
            .transaction()
            .await
            .unwrap_or_else(|error| panic!("begin advisory gate on {key}: {error}"));
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap_or_else(|error| panic!("take advisory lock {key}: {error}"));
        println!("advisory gate taken: key={key}");
        AdvisoryGate { tx, key }
    }

    /// Release the gate.
    pub async fn release(self) {
        let key = self.key;
        self.tx
            .commit()
            .await
            .unwrap_or_else(|error| panic!("release advisory gate {key}: {error}"));
        println!("advisory gate released: key={key}");
    }
}

/// One armed failpoint rendezvous.
///
/// The protocol is `failpoints.rs`'s, verbatim: create `<anchor>.hold` before
/// the operation starts, wait for the operation to write `<anchor>.reached`,
/// then delete the hold so it proceeds.
///
/// The anchor's *action* is not set here — it comes from
/// `LORE_FRAGMENT_FAILPOINTS`, which the coordinator reads once per process, so
/// the runner owns it and [`super::env::failpoints`] checks it.
pub struct FailpointHold {
    anchor: String,
    hold: PathBuf,
    reached: PathBuf,
    released: bool,
}

impl FailpointHold {
    /// Arm `anchor` in `dir`, clearing any marker a previous run left behind.
    pub fn arm(dir: &Path, anchor: &str) -> Self {
        let hold = dir.join(format!("{anchor}.hold"));
        let reached = dir.join(format!("{anchor}.reached"));
        // A stale `.reached` from an aborted run would make `wait_reached`
        // return before the operation ever arrived, which is the same
        // false-barrier failure this module exists to prevent.
        let _ = std::fs::remove_file(&reached);
        std::fs::write(&hold, b"held")
            .unwrap_or_else(|error| panic!("arm failpoint hold {}: {error}", hold.display()));
        println!("failpoint armed: {anchor}");
        Self {
            anchor: anchor.to_owned(),
            hold,
            reached,
            released: false,
        }
    }

    /// Block until the coordinator announces it is paused at this anchor.
    ///
    /// Panics at [`ATTEST_CEILING`] rather than proceeding: an operation that
    /// never reached the anchor was never held, and releasing a hold nobody
    /// took would hand the case a race it did not run.
    pub async fn wait_reached(&self) {
        let started = Instant::now();
        loop {
            if self.reached.try_exists().unwrap_or(false) {
                println!("failpoint reached: {}", self.anchor);
                return;
            }
            if started.elapsed() >= ATTEST_CEILING {
                panic!(
                    "no operation reached failpoint {} within {:?}; the anchor is not on the \
                     path this case drives, or the build lacks `--features failure_generator`",
                    self.anchor, ATTEST_CEILING
                );
            }
            tokio::time::sleep(ATTEST_POLL).await;
        }
    }

    /// Release the hold, letting the paused operation continue.
    pub fn release(mut self) {
        std::fs::remove_file(&self.hold).unwrap_or_else(|error| {
            panic!("release failpoint hold {}: {error}", self.hold.display())
        });
        self.released = true;
        println!("failpoint released: {}", self.anchor);
    }
}

impl Drop for FailpointHold {
    fn drop(&mut self) {
        if !self.released {
            // A panicking case unwinds past `release`. Removing the hold on the
            // way out keeps a paused coordinator from sitting on a pool
            // connection for the full 60-second `PAUSE_CEILING` and turning one
            // failed case into a stalled run.
            let _ = std::fs::remove_file(&self.hold);
            println!(
                "failpoint hold removed during unwind (case did not release it): {}",
                self.anchor
            );
        }
    }
}

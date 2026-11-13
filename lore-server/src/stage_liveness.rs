// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 K11: eject a `role = "stage"` replica whose
//! own mount of the shared stage is stale, but only while a peer is seen
//! writing it.
//!
//! In the multi-host cell every web replica hard-mounts one NFS stage. A stage
//! fault is normally cell-wide, and `/lb_health` must not eject on a cell-wide
//! signal: ejecting replicas one after another refuses the whole cell (see
//! `lorehub/docs/learnings/backpressure-routed-into-a-binary-liveness-verdict-ejects-every-replica-at-once.md`).
//! But one host's mount can go stale alone, and that host then keeps taking
//! connections whose uploads hang. A peer that keeps writing the same stage
//! is the evidence that the fault is local.
//!
//! Three parts:
//!
//! 1. **Probe.** One dedicated OS thread (not the tokio pool: a hard-mount write
//!    can block forever) writes, fsyncs and removes one small file under
//!    `<stage>/liveness/`. Each full success adds one to this process's
//!    progress count. If a write hangs, the thread hangs with it. No second
//!    thread is ever started, so at most one probe is in flight.
//! 2. **Exchange.** A tokio task publishes the count, with this process's
//!    incarnation id, to Postgres and reads every peer's. The database never
//!    lowers a stored count, and accepts a higher one only if the success is
//!    at most [`PUBLISH_FRESH`] old when sent and the statement runs within
//!    [`PUBLISH_DEADLINE`] of being sent (see the module docs of
//!    `lore-postgres/src/domain/fragments/stage_liveness.rs` and
//!    `PostgresFragmentCoordinator::exchange_stage_liveness`).
//! 3. **Decision.** This replica is stale after [`STALE_AFTER`] with no own
//!    success, on its monotonic clock. The first peer view taken after that is
//!    the baseline. A later view in which a peer of the same incarnation has a
//!    higher count, accepted after the baseline view and within
//!    [`PROGRESS_WINDOW`], proves the stage still works for that peer: 503
//!    `stage_unavailable_local`. Anything else is 200. When the peer stops
//!    too, its last increase leaves the window and the replica is readmitted.
//!
//! One own success brings the replica back.
//!
//! ## What an eject proves
//!
//! Write `S` = [`STALE_AFTER`] (15 s), `F` = [`PUBLISH_FRESH`] (4 s) and
//! `D` = [`PUBLISH_DEADLINE`] (2 s).
//!
//! **Guarantee.** If replica A answers `stage_unavailable_local`, then a peer
//! made a real probe success at least `S - F - D` (9 s) after A's last own
//! success. It does NOT say that the peer still works now.
//!
//! **Assumptions.** The proof holds only while all of these hold:
//!
//! - (A1) The database clock and every replica's monotonic clock run at the
//!   same rate. Their offsets may differ.
//! - (A2) There is one database clock and it never goes back: no failover to
//!   a server with another clock, and no backward step.
//! - (A3) Replica ids are unique: one process at a time publishes under one
//!   id. [`default_replica_id`] adds a random part, so two containers with
//!   the same host name and process id do not share one. A duplicate is
//!   logged, not prevented.
//! - (A4) A probe returns success only when the stage really worked for that
//!   process: the write and the fsync reached the server.
//! - (A5) One replica's exchanges are serialized: an exchange starts only
//!   after the previous one ended, so the clock anchor it sends came from a
//!   reply received before the send.
//!
//! **Proof.** All times below are real times; A1 lets us move a difference
//! between clocks without change.
//!
//! 1. A ejects at its view V2 only if V2 holds a peer B with the same
//!    incarnation as A's baseline view V1, a higher count, and a stored
//!    `progressed_at` `p` later than V1's database clock `c1`.
//! 2. V1 is the first view after A went stale, so V1's exchange started at
//!    least `S` after A's last success `L`. `c1` is read during that exchange,
//!    so `c1 >= L + S`.
//! 3. By A2, `p > c1` means the statement that stamped `p` ran after `c1`.
//!    `p` is never the epoch stamp (0), so that statement passed the
//!    fresh-and-on-time test. Every stamp other than the epoch passes that
//!    test, also on a new incarnation's first write. The test and the stamp
//!    are one `clock_timestamp()` read (the `stamp` CTE and the `take`
//!    predicate in `PostgresFragmentCoordinator::exchange_stage_liveness`;
//!    the rule is in the module docs of
//!    `lore-postgres/src/domain/fragments/stage_liveness.rs`).
//! 4. Deadline: `p <= anchor + (sent - received) + D` on the database clock.
//!    The anchor was read no later than `received` (A5), so by A1 and A2
//!    `p <= sent + D`. So `sent >= p - D`. The stamp is read before any wait
//!    for the row lock; a later commit only hides the increase from views
//!    taken before it, which errs toward "no eject".
//! 5. Freshness: the success it reports, at `g`, was at most `F` old at
//!    `sent`. So `g >= sent - F >= p - D - F > c1 - F - D >= L + S - F - D`.
//! 6. By A3 and A4, `g` is a real success of B's own process. So B
//!    succeeded at least 9 s after `L`.
//!
//! **No double eject.** By the guarantee, at any moment the replica with the
//! latest own success is not ejected: no peer can have succeeded 9 s after
//! it. So the whole cell is never ejected at once, and in a two-replica cell
//! the two never both eject. A fault that hits every host within 9 s ejects
//! nobody.
//!
//! **Known limits.**
//!
//! - Staggered hang. If the fault hits host B more than about 9 s after it
//!   hits host A, B's successes in that gap eject A, although B is failing
//!   too by then. A stays ejected until B's last increase leaves
//!   [`PROGRESS_WINDOW`]. A live probe showed this: A's last success was 12 s
//!   before the hang reached B, and A was ejected for about 10 s.
//! - Flapping. A peer that succeeds less often than once per
//!   [`PROGRESS_WINDOW`] readmits the stale replica between its successes.
//!   With a success every 12 s, the stale replica is ejected for about 10 s
//!   and readmitted for about 2 s, again and again. A longer window would
//!   shorten that gap, but it would also make the staggered-hang eject and
//!   the readmit after a cell-wide fault longer, so it is left as is.
//! - The proof does not hold if an assumption fails, for example after a
//!   database failover with a clock step, or with two processes sharing one
//!   replica id.
//!
//! ## Shared-stage guard
//!
//! Two stage replicas that each mount a valid but DIFFERENT stage lose data:
//! a replica reads a peer's staged fragment, finds no file, and marks it
//! `Missing` (WP-115 D1, 179 fragments), and its own staged files are never
//! seen by the drain. K6's mount lock stops a silent local fallback, but not
//! two good mounts of two directories.
//!
//! 1. **Marker.** Each stage replica's probe thread, and the drain worker's
//!    marker thread, keep `<stage>/liveness/<replica>.present` holding the
//!    process's incarnation. The file is rewritten when it is missing or
//!    holds another value, and removed when the thread stops.
//! 2. **Drain row.** The liveness row carries `role`. The drain worker
//!    publishes `drain` only while a read-back of its own marker, at most
//!    [`ANCHOR_VERIFY_MAX_AGE`] old, shows its current incarnation; else it
//!    publishes `drain_unverified`, raises [`STAGE_ANCHOR_UNVERIFIED`] in its
//!    own snapshot, the `stage_share_anchor_unverified` gauge and a log line.
//!    A drain row runs no probe, so its count never rises: it is never a K11
//!    eject peer (also not for an older binary), and the drain is never held
//!    or ejected itself.
//! 3. **Anchor proof.** A stage replica opens staging only when the cell has
//!    a `drain` row published within [`SHARE_PEER_FRESH`] and this replica
//!    has seen the marker of every such drain, holding its current
//!    incarnation. That proof latches for the life of the process.
//! 4. **Until then, direct writes.** Before the proof (no exchange yet, no
//!    fresh `drain` row, or a drain marker not seen yet) the stage writes
//!    every new fragment directly to the object store (`DirectFallback`), so
//!    nothing is staged into a directory nobody has verified, and nothing is
//!    refused. A PUT that chose `Stage` and re-checks after the gate rose
//!    refuses with `SlowDown`; its retry writes directly. The gate only ever
//!    opens, so this re-check is a defence, not a path production takes. A
//!    staged read that finds no file answers `SlowDown`, never "absent", so
//!    nothing is demoted to `Missing`.
//! 5. **`/lb_health`.** 200 with no exchange yet (inside [`SHARE_GRACE`]),
//!    and 200 with no fresh `drain` row: the replica serves, only without
//!    staging. With a fresh `drain` row whose marker this replica has not
//!    seen, 503 [`STAGE_SHARE_UNVERIFIED`], and [`STAGE_NOT_SHARED`] after
//!    [`SHARE_GRACE`]. With no successful exchange for [`SHARE_GRACE`] since
//!    boot, 503 [`STAGE_SHARE_PENDING`].
//! 6. **"Cannot decide" is 200.** Only a marker read that completes and
//!    finds no matching marker (the file is absent or holds another
//!    incarnation) counts toward the 503 words above. A read that fails with
//!    any other I/O error (a stale handle, `EIO`, a permission fault) and a
//!    probe-thread step that has hung for [`MARKER_STUCK_AFTER`] (an NFS
//!    hard mount whose server is gone) say nothing about which directory
//!    this is. The verdict is then [`ShareVerdict::Undecided`]: `/lb_health`
//!    answers 200, staging stays off (new fragments are written directly,
//!    and a staged read that finds no file is not evidence of absence), and
//!    the `stage_share_undecided` gauge is 1. The next completed read
//!    decides again. A hung step does not undo a completed read: a marker
//!    that a completed read already found absent still counts toward 503,
//!    so a misplaced replica does not flap 503 -> 200 when its step hangs.
//!
//! **Never all, never both.** A web replica answers a shared-stage 503 only
//! in two cases:
//!
//! - It is not yet anchor-proven, a fresh `drain` row exists, and its
//!   marker step completes but does not find that drain's marker. The drain
//!   row exists only while the drain itself reads its marker back (step 2),
//!   so the marker is really there. Replicas that are anchor-proven are
//!   never held again, so no later fault (NFS hang, Postgres outage, drain
//!   restart, drain marker loss) touches them. A marker read fault or a hung
//!   step is "cannot decide" (step 6), so it never starts a 503; a hung step
//!   only keeps a 503 that a completed read already decided. So both web
//!   replicas answer 503 only if both are unproven at the same time and both
//!   READ a liveness directory that does not hold the drain's marker: a
//!   wrong mount on both hosts.
//! - No exchange has succeeded for [`SHARE_GRACE`] since boot. Both answer
//!   this only if Postgres is unreachable from both for that long, and then
//!   the cell cannot serve anyway.
//!
//! With no drain row (the drain down, its marker unverifiable, or a cell
//! that boots web-first), no replica answers a shared-stage 503 at all.
//!
//! **Limits.**
//!
//! - The drain is the reference: web replicas do not check the drain's
//!   directory. A drain on the wrong directory cannot demote fragments (see
//!   "Drain guard" below), but the web replicas it anchors stage where it
//!   reads. Two fresh drains on two directories hold every replica that is
//!   not yet anchor-proven.
//! - While no `drain` row is fresh, unproven replicas stage nothing, so
//!   writes cost a direct object-store round trip.
//! - Start-up 503 (review probe RV3-C). A fresh drain row that this replica
//!   has not yet looked for counts as "not seen". So from the first view
//!   that names a fresh drain until the next marker step completes, an
//!   unproven replica answers 503 [`STAGE_SHARE_UNVERIFIED`]. That is at
//!   most one [`PROBE_INTERVAL`] (about 2 s) when the step completes. If
//!   that step hangs, the 503 lasts until [`MARKER_STUCK_AFTER`] (6 s), and
//!   then the replica answers 200 (cannot decide). At a cell start both web
//!   replicas can do this at once.
//! - Web-only roll with an old drain. A drain worker built before this
//!   guard publishes no `drain` role, so the cell has no anchor: every web
//!   replica stays at [`ShareVerdict::NoAnchor`], answers 200 and stages
//!   nothing. Staging is then off cell-wide with no alert, only an info log
//!   per replica and `stage_share_unproven` = 1. Roll the drain worker too.
//! - A hung step is noticed only after [`MARKER_STUCK_AFTER`]; until then
//!   the last completed read stands.
//! - Turning `stage_liveness_probe` off turns this guard off too.
//!
//! ## Drain guard
//!
//! The shared-stage guard keeps an unproven web replica from staging, but it
//! trusts the drain's directory. A drain worker on another directory than
//! the web replicas (a wrong mount on the drain host, a copy of the stage,
//! or a drain restarted there while web replicas proven against an earlier
//! drain keep staging) reads each staged fragment's `ENOENT` as absent, and
//! `mark_missing` demotes acknowledged fragments. A drain-wide gate is not
//! enough: a web replica that staged into another directory and then left
//! (a withdraw, or its row pruned after a crash) is no longer in any view,
//! but its files are still in that other directory.
//!
//! So the decision is per fragment. A staged read on a READER (the drain
//! worker, or a web replica, see below) that finds no file reads as absent
//! only when the fragment's own stager is proven, to this reader process, to
//! write the reader's directory. Otherwise it answers `SlowDown`: the
//! promotion is deferred and retried, and the fragment stays `Staged`.
//! Found files promote as usual, and admission does not change.
//!
//! 1. **Stager.** A web stage replica records its (replica id, incarnation)
//!    with every representation it stages, in the transaction that reserves
//!    the stage custody (`lore_domain_write_behind_stagers`).
//! 2. **Challenge.** Every reader writes a fresh random challenge into its
//!    own `<stage>/liveness/<replica>.challenge` (`<incarnation>
//!    <challenge>`) and rotates it every [`CHALLENGE_EVERY_STEPS`] steps. A
//!    challenge counts as CURRENT only after its write completed. Outside
//!    the stage's liveness files the challenge is stored nowhere: not in
//!    Postgres, not in a log.
//! 3. **Echo.** Each web stage replica reads the challenge file of the other
//!    processes in its last view, in its OWN liveness directory, and writes
//!    what it found as a FILE in that same directory:
//!    `<stage>/liveness/<replica>.echo`, its own incarnation on the first
//!    line, then one `<reader incarnation> <challenge>` line per reader
//!    (temporary file, fsync, rename). Only rows published within
//!    [`SHARE_PEER_FRESH`] count, drain rows first, at most
//!    [`MAX_CHALLENGE_ECHOES`]: a dead row never takes the drain's place.
//! 4. **Confirmation.** A reader reads the echo file of each web replica of
//!    its last view (fresh rows only) in ITS OWN liveness directory. It
//!    confirms that process only when the file names the process's
//!    incarnation and echoes the reader's CURRENT challenge under the
//!    reader's own incarnation, and then, after a rotation, echoes a LATER
//!    current challenge. An echo of an older challenge, or of another
//!    reader's, counts for nothing. A process never echoes, nor confirms
//!    from, its own files. The confirmations live in the reader's
//!    memory, for its current incarnation only: a restarted reader starts
//!    with none, and nothing about them is stored.
//! 5. **Decision.** On `ENOENT` the reader reads the fragment's stager row
//!    and asks its own confirmations. Only a confirmed stager reads as
//!    absent, and only once the representation was published `Staged` at
//!    least `MIN_STAGED_ABSENCE_AGE` (60 s, six rotations) ago by the
//!    database clock; a younger one is kept (`too_recent`). The `ENOENT`
//!    itself comes from an open beneath the stage's pinned `staged/`
//!    directory, with the stage tree checked before the read and after the
//!    miss, so it is a miss in that directory and in no other one.
//!
//! Why this proves the directory (review B1 of round 3): a confirmation needs
//! data to move BOTH ways through one directory. The reader's new challenge
//! must reach the web replica's directory (the web replica read it), and the
//! web replica's echo of it must reach the reader's directory (the reader
//! read it). So:
//!
//! - A copy of the reader's directory (rsync, a volume clone, a snapshot)
//!   never shows the reader's NEW challenges to a web replica on the
//!   original.
//! - A one-way copy loop either way fails: from the web replica's directory
//!   to the reader's, the challenge never reaches the web replica; from the
//!   reader's directory to the web replica's, the echo never reaches the
//!   reader.
//! - A union or overlay mount (reads see the shared directory, writes stay
//!   local) on either side fails the same way: one direction never arrives.
//! - One stray copy of one challenge cannot confirm, because a later,
//!   rotated challenge must be echoed too.
//!
//! What goes through the pinned stage tree (review B1 of round 4). At open
//! the stage pins its root (device, inode, a held descriptor) and `staged/`;
//! it pins `liveness/` on first use. Both are opened beneath the held root
//! descriptor with `openat2(RESOLVE_BENEATH | RESOLVE_NO_XDEV |
//! RESOLVE_NO_SYMLINKS)` and `O_NOFOLLOW`: a symlink or a mount point (a bind
//! mount included) at `staged` refuses to start, and at `liveness` fails
//! every liveness file and root check. `O_NOFOLLOW` refuses a symlink at the
//! last component and `RESOLVE_BENEATH` keeps the middle components inside
//! the pinned directory, so `RESOLVE_NO_SYMLINKS` is defence in depth here.
//! `openat2` needs Linux 5.6 or later: where it fails (`ENOSYS`, or `EPERM`
//! from a seccomp filter) the stage does not open and the server does not
//! boot. Then:
//!
//! - every challenge, echo and share marker file is read and written through
//!   the held `liveness/` descriptor, never by path;
//! - every staged read opens its file beneath the held `staged/` descriptor,
//!   confined the same way, and the finalizer creates its fan-out
//!   directories and renames into them there too;
//! - every proof I/O (challenge write, echo write, echo or challenge read)
//!   runs only while the root check holds before and after it: the root path
//!   still names the pinned root, and `staged` and `liveness` under it,
//!   opened confined now, are still the pinned directories (device and
//!   inode). A failed check after a challenge write leaves no current
//!   challenge; after an echo write it removes the echo file and nothing
//!   counts as written; after a read it drops what was read.
//!
//! So a liveness file proves something about one `liveness/` directory, and
//! a directory has one parent: two processes that exchange a challenge and
//! its echo share one root, and so one `staged/`. A process never changes
//! its pinned tree, so one confirmation covers every file that process
//! staged, also after it left. Off Linux there is no `openat2`, so the root
//! check is always false and a guarded read never proves a miss.
//!
//! Not through the pinned tree: the finalizer's temporary file under
//! `incoming/` (a rename from elsewhere fails across a mount, or still lands
//! in the pinned leaf), the boot probe, the free-space sample, and the K11
//! probe file (`file_probe`), which tests the mount, not the tree.
//!
//! The web replica's marker no longer holds a nonce (round 2's two-nonce
//! rule). Its only job was to show the marker advancing in the reader's
//! directory, and a one-way copy loop does that too (S1). The challenge
//! proves the stronger fact, so the nonce adds nothing.
//!
//! Costs (liveness only; nothing is lost while a file is kept):
//!
//! - A file with no recorded stager (staged by an older binary, by a replica
//!   with stage liveness off, or by a full-role replica) is never read as
//!   absent by a guarded reader. The `no_stager` count shows it.
//! - A web replica that leaves before this reader process confirmed it
//!   (about two [`CHALLENGE_EVERY_STEPS`] rotations, 10 to 25 s) leaves
//!   files this reader never reads as absent. So does every web replica that
//!   left before a READER RESTART: a restarted drain has no confirmations.
//!   The `unconfirmed` count shows them. A web replica that is still running
//!   and confirmed that stager earlier still decides them on a GET. Such a
//!   replica's row stops being fresh within [`SHARE_PEER_FRESH`]; it then
//!   leaves the "not confirmed yet" signal (`absence_unconfirmed`, the
//!   gauge), but its files stay kept: only a confirmation reads a file as
//!   absent, and a departed process can never be confirmed.
//! - Two directories kept in step by a sync in BOTH directions faster than a
//!   rotation act as one directory for the challenge and the echo, but not
//!   for the staged files. The minimum staged age (step 5) covers a sync
//!   that carries a file within 60 s; a slower one that still keeps up with
//!   the echo is not covered. **Operator rule: never run a sync or copy tool
//!   on the stage directory.** The stage is one shared directory.
//! - A path change and change back inside one step is not seen by the root
//!   check, but no proof I/O follows the path any more: it goes through the
//!   held descriptors.
//! - Removing `<stage>/liveness` while replicas run fails their liveness
//!   root checks until each restarts. Staging continues on every replica
//!   already anchor-proven (admission checks only the root and `staged/`,
//!   and a proven replica is never held again; one not yet proven stays
//!   direct). Only absence proofs stop: no new confirmation, and every
//!   missing file is kept. Do not remove it.
//! - Recreating `staged/` (`rm -rf` and `mkdir` on the file server) leaves
//!   every replica's pinned `staged/` descriptor stale (`ESTALE` on NFS) for
//!   good. Admission then reports `RootUnavailable`: staging is off and PUTs
//!   write directly, `/health_check` shows `root_unavailable`, and
//!   `/lb_health` stays 200. No staged read is absent. Every replica must
//!   restart. Do not recreate it.
//! - Accepted risk T1 (review B of round 5): a process with write access to
//!   the stage that renames `<root>/staged` away and back at each step can
//!   make a reader confirm a stager whose pinned `staged/` differs from its
//!   own. Such a process can also delete staged files outright, so it is
//!   outside the threat model.
//!
//! Cost of the echo (review A of round 4): with five or more readers the
//! echo content changes almost every step, because readers rotate out of
//! phase. So each web replica writes its echo (temporary file, fsync,
//! rename) about every 2 s for its whole life. With 10 web replicas and 1
//! drain that is about 55 file opens a second and 5 fsync-renames a second
//! cell-wide (computed, not measured). The root checks add three directory
//! opens per check, a few checks per step.
//!
//! Every process leaves `.present`, `.challenge` and `.echo` files under
//! `<stage>/liveness/` (about 100 bytes each). A clean stop removes its own;
//! a crashed process's stay. Nothing else removes them.
//!
//! **Operator action** when the drain's `absence_counts.unconfirmed` or
//! `no_stager` keeps rising, or its log names a staged file kept because it
//! is not proven gone: first check the stage mount on the drain host and on
//! every web host (the usual cause is a wrong or stale mount; fix it, and the
//! files are found and promoted). A file that is truly gone and whose stager
//! has left stays `Staged` after a drain restart: each pass retries it, and a
//! GET of it answers `SlowDown`. No command marks it `Missing` today; a GET
//! on a web replica that confirmed the stager before it left does. Each kept
//! log line names one sample file (`hash`, `epoch`), not every kept file.
//! The full list is in the database: the staged heads with a live custody
//! row whose stager is absent or not fresh. A coming
//! `loreserver stage resolve-lost list` command will print it. Record that
//! list and escalate.
//!
//! **Web replicas run the same guard.** A web replica proven against one
//! drain keeps that proof for its life, so in the same split (web-a latched
//! on A, web-c proven on B) a GET on web-a for a web-c fragment would read
//! ENOENT on A. So a `stage` web replica is a reader too: it writes its own
//! challenge, confirms peer web replicas that echo it, and confirms itself
//! (its own files are in its own pinned root, which its reads use). While
//! the K11 share gate holds, a missing file is never absent, as before. The
//! guard changes only how a staged read that finds no file answers:
//! `/lb_health`, the K11 eject rule and the shared-stage verdicts are
//! unchanged, and only the drain prunes the stager table.
//!
//! A GET whose miss the guard cannot prove re-reads the lifecycle head: if
//! the head is no longer that `Staged` epoch (a promotion and purge won the
//! race), it answers for the new head, not `SlowDown` (review N1 of round 2).
//!
//! `/health_check` shows `absence` (`guarded`, or [`ABSENCE_NO_CHALLENGE`]
//! while this reader has no current challenge), the fresh web replicas in the
//! last view not yet confirmed, how many are confirmed, and the decision
//! counts. On every reader (the drain and each guarded web replica), the
//! `stage_share_absence_unproven` gauge is 1 while a fresh web replica in the
//! view is unconfirmed or there is no current challenge, and a state change
//! logs one line; one held for [`SHARE_GRACE`] logs one error. The
//! `stage_drain_absence_kept` gauge is the number of kept decisions since
//! boot (a kept file adds one per retry). Both gauges are local; nothing
//! exports them to Lorehub.
//!
//! Turning `stage_liveness_probe` off turns this guard off too.
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use lore_postgres::domain::fragments::MAX_STAGE_LIVENESS_ID_BYTES;
use lore_postgres::domain::fragments::StageLivenessClock;
use lore_postgres::domain::fragments::StageLivenessLimits;
use lore_postgres::domain::fragments::StageLivenessPublication;
use lore_postgres::domain::fragments::StageLivenessRole;
use lore_postgres::domain::fragments::StagePeerLiveness;
use lore_postgres::domain::fragments::StagePeerProgress;
use lore_postgres::domain::fragments::StageProgressRecord;
use lore_postgres::domain::fragments::StagerIdentity;
use lore_postgres::store::fragment_write_behind::DrainAbsenceCounts;
use lore_postgres::store::fragment_write_behind::DrainAbsenceSnapshot;
use lore_telemetry::InstrumentProvider;
use opentelemetry::metrics::Gauge;
use serde::Serialize;
use tracing::error;
use tracing::info;
use tracing::warn;

/// The `/lb_health` word for a replica whose own stage mount is stale while a
/// peer is seen writing it.
pub const STAGE_UNAVAILABLE_LOCAL: &str = "stage_unavailable_local";

/// The `/lb_health` word for a replica that has not yet seen the marker of a
/// fresh drain row in its stage, inside [`SHARE_GRACE`].
pub const STAGE_SHARE_UNVERIFIED: &str = "stage_share_unverified";

/// The `/lb_health` word for a replica that has not seen a fresh drain's
/// marker for [`SHARE_GRACE`]: its stage is very likely not the cell's
/// shared stage.
pub const STAGE_NOT_SHARED: &str = "stage_not_shared";

/// The `/lb_health` word for a replica whose first liveness exchange has not
/// succeeded within [`SHARE_GRACE`] of boot.
pub const STAGE_SHARE_PENDING: &str = "stage_share_pending";

/// The drain worker's own fault word (its `/health_check` snapshot; its
/// `/lb_health` answers `drain_role` anyway): no read-back of its own stage
/// marker within [`ANCHOR_VERIFY_MAX_AGE`] showed its incarnation, so it
/// publishes `drain_unverified` and anchors nobody.
pub const STAGE_ANCHOR_UNVERIFIED: &str = "stage_anchor_unverified";

/// A drain row counts for the shared-stage check only if it was published
/// within this window, on database time. Five exchange intervals.
pub const SHARE_PEER_FRESH: Duration = Duration::from_secs(10);

/// How old the drain's last good read-back of its own marker may be while
/// it still publishes `drain`. Three marker intervals, so one slow step does
/// not withdraw the anchor, but a hung marker thread does within seconds.
pub const ANCHOR_VERIFY_MAX_AGE: Duration = Duration::from_secs(6);

/// A probe-thread step (probe plus marker reads) running longer than this
/// is hung: the shared-stage check cannot decide, so it answers 200. Three
/// probe intervals.
pub const MARKER_STUCK_AFTER: Duration = Duration::from_secs(6);

/// How long an unseen drain marker reads as "unverified" before it reads as
/// "not shared". Both words answer 503 and both keep staging off; only the
/// word and the log level differ, so a long grace costs nothing in safety.
///
/// It covers a peer that has published but not yet written its marker, and
/// NFS caching. Our stage mounts use `lookupcache=positive`, so a lookup of a
/// missing name always asks the server and a new marker is seen at once;
/// `open` revalidates attributes (close-to-open), so new content is seen too.
/// Under the default `lookupcache=all`, a cached negative entry can hide a
/// new file until the directory's attributes expire (`acdirmax`, 60 s by
/// default). 90 s covers that with one more probe interval to spare.
pub const SHARE_GRACE: Duration = Duration::from_secs(90);

/// The marker file suffix under `<stage>/liveness/`.
pub const SHARE_MARKER_SUFFIX: &str = ".present";

/// The challenge file suffix under `<stage>/liveness/` (drain guard).
pub const CHALLENGE_SUFFIX: &str = ".challenge";

/// The echo file suffix under `<stage>/liveness/` (drain guard): a web stage
/// replica's echoes of the challenges it read in its own stage.
pub const ECHO_SUFFIX: &str = ".echo";

/// The `/health_check` `absence` word while this reader has no current
/// challenge: no staged file it cannot find reads as absent.
pub const ABSENCE_NO_CHALLENGE: &str = "no_challenge";

/// A reader writes a new challenge every this many steps (about 10 s at
/// [`PROBE_INTERVAL`]). Longer than one echo round trip (the web replica's
/// next step reads it and writes the echo file, then the reader's next step
/// reads that: about 4 s), so an echo usually arrives while its challenge is
/// still current.
pub const CHALLENGE_EVERY_STEPS: u64 = 5;

/// The most reader challenges a web stage replica echoes: the fresh drain
/// rows of its view first, then fresh web rows (review S1 of round 3). Each
/// echo line is under 70 bytes.
pub const MAX_CHALLENGE_ECHOES: usize = 64;

/// The most echo files a reader reads in one step: one per fresh web row of
/// its view that it has not confirmed yet.
pub const MAX_ECHO_READS: usize = 256;

/// The longest echo file content read, in bytes. A full echo file
/// ([`MAX_CHALLENGE_ECHOES`] lines) is shorter.
const ECHO_READ_LIMIT: u64 = 16 * 1024;

/// The most confirmations a reader keeps; the oldest goes first. Losing one
/// only keeps that stager's missing files `Staged`.
pub const MAX_CONFIRMED_STAGERS: usize = 4096;

/// The drain prunes the stager table every this many exchanges (about one
/// minute).
pub const DRAIN_GUARD_PRUNE_EVERY: u64 = 30;

/// The most stager rows one prune pass deletes.
pub const DRAIN_GUARD_PRUNE_LIMIT: i64 = 1000;

/// The most prune passes per prune tick. A pass that deletes a full
/// [`DRAIN_GUARD_PRUNE_LIMIT`] runs another, so one tick deletes up to
/// 10,000 rows a minute; the drain stages and promotes about 25 a second
/// (review S2 of round 2).
pub const DRAIN_GUARD_PRUNE_MAX_PASSES: u32 = 10;

/// The `statement_timeout` of one drain guard prune pass.
pub const DRAIN_GUARD_PRUNE_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest marker content read, in bytes. An incarnation is shorter.
const MARKER_READ_LIMIT: u64 = 256;

/// How often the probe thread writes its file.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// A replica is stale after this long with no good probe.
///
/// 15 s is about seven probe intervals: a single slow NFS round trip, or a
/// short server hiccup that every host sees, does not eject anyone. It is
/// also well under the time a hard mount stays hung after a real fault.
pub const STALE_AFTER: Duration = Duration::from_secs(15);
/// How often this replica publishes and reads peers.
pub const EXCHANGE_INTERVAL: Duration = Duration::from_secs(2);
/// The budget for one exchange, and its transaction's `statement_timeout`.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
/// A peer view older than this is "cannot decide". Five exchange intervals,
/// so a few slow exchanges do not drop the evidence, but a Postgres outage
/// does within seconds.
pub const PEER_VIEW_MAX_AGE: Duration = Duration::from_secs(10);
/// The oldest success an accepted increase may report, measured when the
/// statement is sent. A success is published by the next exchange, at most
/// one [`EXCHANGE_INTERVAL`] plus a checkout ([`EXCHANGE_TIMEOUT`]) later.
pub const PUBLISH_FRESH: Duration = Duration::from_secs(4);
/// How long after it is sent an increase may still run. The client has given
/// up on the exchange by then, so a later run changes nothing.
pub const PUBLISH_DEADLINE: Duration = EXCHANGE_TIMEOUT;
/// A peer's increase counts only while it is this recent, on database time,
/// so when the peer stops too (the fault became cell-wide) the stale replica
/// is readmitted. Long enough to cover the gap between a slow peer's
/// successes (a 4 s probe every 6 s) plus one exchange.
///
/// Known limit (flapping): a peer whose successes are further apart than
/// this window readmits the stale replica between them. With a peer success
/// every 12 s, the stale replica is ejected for about 10 s, then readmitted
/// for about 2 s, in a loop. The no-double-eject proof in the module docs
/// does not use this window.
pub const PROGRESS_WINDOW: Duration = Duration::from_secs(10);
/// Rows not published for this long are deleted, so restarts do not grow the
/// table.
pub const RETAIN: Duration = Duration::from_secs(3600);

const WARN_EVERY: Duration = Duration::from_secs(30);

struct LivenessInstrumentProvider;
impl InstrumentProvider for LivenessInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.fragment.write_behind"
    }
}

struct Instruments {
    /// 1 while this replica answers `stage_unavailable_local`, else 0.
    ejected: Gauge<u64>,
    /// Seconds since this replica's last good stage probe.
    probe_age: Gauge<u64>,
    /// Peers seen making progress since this replica went stale.
    progressing_peers: Gauge<u64>,
    /// 1 while this replica keeps staging off because its stage is not
    /// proven shared, else 0.
    share_unproven: Gauge<u64>,
    /// 1 while the shared-stage check cannot decide (a marker read fault or
    /// a hung step), else 0. `/lb_health` stays 200 then.
    share_undecided: Gauge<u64>,
    /// 1 while the drain worker publishes `drain_unverified` (its own marker
    /// read-back fails or is too old), else 0. Only the drain records it.
    share_anchor_unverified: Gauge<u64>,
    /// 1 while a fresh web stage replica in a reader's last view is not
    /// confirmed by that reader process, or the reader has no current
    /// challenge, else 0. Every reader (the drain, and each web stage replica
    /// with the guard) records it for itself. Local only.
    share_absence_unproven: Gauge<u64>,
    /// Decisions since boot that kept a staged file a reader could not find
    /// `Staged`, because it could not prove the file gone. A kept file adds
    /// one per retry. Every reader records it for itself. Local only.
    drain_absence_kept: Gauge<u64>,
}

fn instruments() -> &'static Instruments {
    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let provider = LivenessInstrumentProvider;
        let meter = provider.meter();
        Instruments {
            ejected: meter
                .u64_gauge(provider.scope_name("stage_liveness_ejected"))
                .build(),
            probe_age: meter
                .u64_gauge(provider.scope_name("stage_probe_age_seconds"))
                .build(),
            progressing_peers: meter
                .u64_gauge(provider.scope_name("stage_liveness_progressing_peers"))
                .build(),
            share_unproven: meter
                .u64_gauge(provider.scope_name("stage_share_unproven"))
                .build(),
            share_undecided: meter
                .u64_gauge(provider.scope_name("stage_share_undecided"))
                .build(),
            share_anchor_unverified: meter
                .u64_gauge(provider.scope_name("stage_share_anchor_unverified"))
                .build(),
            share_absence_unproven: meter
                .u64_gauge(provider.scope_name("stage_share_absence_unproven"))
                .build(),
            drain_absence_kept: meter
                .u64_gauge(provider.scope_name("stage_drain_absence_kept"))
                .build(),
        }
    })
}

/// What the last peer view says, once its own age is taken into account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEvidence {
    /// No peer view, one older than the max age (Postgres is unreachable or
    /// slow), or one taken before this replica went stale. Never ejects.
    Unknown,
    /// A recent view, taken after this replica went stale, in which no peer
    /// has made progress since the baseline view.
    NoProgress,
    /// A recent view in which at least one peer of the same incarnation has
    /// made progress that was accepted after the baseline view.
    ProgressingPeer,
}

/// The K11 rule. Pure, so every case is a table test.
pub fn decide(self_stale: bool, peers: PeerEvidence) -> Option<&'static str> {
    (self_stale && peers == PeerEvidence::ProgressingPeer).then_some(STAGE_UNAVAILABLE_LOCAL)
}

/// The thresholds of one replica. Tests scale them down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessThresholds {
    pub stale_after: Duration,
    pub peer_view_max_age: Duration,
    pub publish_fresh: Duration,
    pub publish_deadline: Duration,
    pub statement_timeout: Duration,
    pub progress_window: Duration,
    pub share_peer_fresh: Duration,
    pub share_grace: Duration,
    pub anchor_verify_max_age: Duration,
    pub marker_stuck_after: Duration,
}

impl Default for LivenessThresholds {
    fn default() -> Self {
        Self {
            stale_after: STALE_AFTER,
            peer_view_max_age: PEER_VIEW_MAX_AGE,
            publish_fresh: PUBLISH_FRESH,
            publish_deadline: PUBLISH_DEADLINE,
            statement_timeout: EXCHANGE_TIMEOUT,
            progress_window: PROGRESS_WINDOW,
            share_peer_fresh: SHARE_PEER_FRESH,
            share_grace: SHARE_GRACE,
            anchor_verify_max_age: ANCHOR_VERIFY_MAX_AGE,
            marker_stuck_after: MARKER_STUCK_AFTER,
        }
    }
}

/// The shared-stage verdict. Every verdict but [`Self::Shared`] keeps
/// staging off: new fragments are written directly to the object store, and
/// a missing staged file is not evidence of absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareVerdict {
    /// No successful exchange yet, inside the grace. `/lb_health` is 200
    /// ("cannot decide").
    Pending,
    /// No successful exchange for [`SHARE_GRACE`] since boot. `/lb_health`
    /// answers 503 [`STAGE_SHARE_PENDING`].
    PendingTooLong,
    /// No fresh `drain` row: nothing can prove this stage is the drain's.
    /// `/lb_health` is 200; the replica serves without staging.
    NoAnchor,
    /// A fresh drain's marker is not seen yet, inside the grace. 503
    /// [`STAGE_SHARE_UNVERIFIED`].
    Unverified,
    /// A fresh drain's marker has not been seen for longer than the grace.
    /// 503 [`STAGE_NOT_SHARED`].
    NotShared,
    /// A fresh drain's marker is not seen, but no completed read found it
    /// absent: every unseen marker's last read failed with an I/O error, or
    /// the probe-thread step hung for [`MARKER_STUCK_AFTER`] before reading
    /// it.
    /// `/lb_health` is 200 ("cannot decide"); staging stays off.
    Undecided,
    /// Every fresh drain's marker was seen once: latched for the life of the
    /// process. Staging is open.
    Shared,
}

impl ShareVerdict {
    /// Every verdict, for tests and docs.
    pub const ALL: [Self; 7] = [
        Self::Pending,
        Self::PendingTooLong,
        Self::NoAnchor,
        Self::Unverified,
        Self::NotShared,
        Self::Undecided,
        Self::Shared,
    ];

    /// Whether staging is off: PUTs write directly, and a missing staged
    /// file is not evidence of absence.
    pub fn holds_staging(self) -> bool {
        self != Self::Shared
    }

    /// The `/lb_health` fault, if any.
    pub fn fault(self) -> Option<&'static str> {
        match self {
            Self::PendingTooLong => Some(STAGE_SHARE_PENDING),
            Self::Unverified => Some(STAGE_SHARE_UNVERIFIED),
            Self::NotShared => Some(STAGE_NOT_SHARED),
            Self::Pending | Self::NoAnchor | Self::Undecided | Self::Shared => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PendingTooLong => "pending_too_long",
            Self::NoAnchor => "no_anchor",
            Self::Unverified => "unverified",
            Self::NotShared => "not_shared",
            Self::Undecided => "undecided",
            Self::Shared => "shared",
        }
    }
}

/// A check that the stage tree is still the one pinned at open: the root
/// path names the pinned root, and its `staged` and `liveness`, opened with
/// no symlink and no mount point, are the pinned directories. Blocking;
/// called on the probe or marker thread only. See the module docs ("Drain
/// guard").
pub type RootCheck = Arc<dyn Fn() -> bool + Send + Sync>;

/// The absence guard's state on a reader (the drain worker, or a guarded web
/// replica). See the module docs ("Drain guard").
#[derive(Debug, Default)]
struct GuardState {
    /// Every fresh `stage` row of the last successful view: the sequence
    /// number of the first current challenge of this reader that its echo
    /// file showed, if any. A later current challenge confirms it.
    candidates: BTreeMap<StagerIdentity, Option<u64>>,
    /// Stagers this reader process confirmed in its own stage. Kept for the
    /// life of this incarnation (a process never changes its directory),
    /// never stored, at most [`MAX_CONFIRMED_STAGERS`].
    confirmed: BTreeSet<StagerIdentity>,
    /// `confirmed` in the order it grew, to drop the oldest first.
    confirmed_order: VecDeque<StagerIdentity>,
    /// The other processes of the last view whose challenges a web stage
    /// replica echoes, as (replica id, incarnation): fresh rows only, drain
    /// rows first, at most [`MAX_CHALLENGE_ECHOES`].
    checkers: Vec<(String, String)>,
}

impl GuardState {
    /// Web replicas of the last view not confirmed by this reader.
    fn unconfirmed(&self) -> impl Iterator<Item = &StagerIdentity> {
        self.candidates
            .keys()
            .filter(|stager| !self.confirmed.contains(stager))
    }

    fn confirm(&mut self, stager: StagerIdentity) {
        if self.confirmed.insert(stager.clone()) {
            self.confirmed_order.push_back(stager);
        }
        while self.confirmed_order.len() > MAX_CONFIRMED_STAGERS {
            if let Some(oldest) = self.confirmed_order.pop_front() {
                self.confirmed.remove(&oldest);
            }
        }
    }
}

/// A reader's own challenge (module docs, "Drain guard").
#[derive(Debug, Default)]
struct ChallengeState {
    /// Challenge steps so far.
    steps: u64,
    /// The sequence number of the last challenge written.
    seq: u64,
    /// The current challenge: the last one whose write completed while the
    /// root path named the pinned root. `None` before the first, and after a
    /// root check fails.
    current: Option<(u64, String)>,
}
/// What [`StageLiveness::report_absence`] logged on one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsenceLog {
    /// Nothing new.
    None,
    /// The first report, while something is unproven (info).
    StartHeld,
    /// Proven before, unproven now (warn).
    Held,
    /// Unproven before, proven now (info).
    Proven,
    /// Unproven for [`SHARE_GRACE`] (error, once per hold).
    Escalated,
}

/// The drain guard's last reported state, for its log lines.
#[derive(Debug, Clone, Copy)]
struct AbsenceReport {
    held: bool,
    since: Instant,
    escalated: bool,
}

/// The shared-stage check's state. See the module docs.
#[derive(Debug, Default)]
struct ShareState {
    /// Whether an exchange has succeeded.
    exchanged: bool,
    /// The fresh drain anchors the last view named: replica id to
    /// incarnation. Empty when no `drain` row is fresh.
    required: BTreeMap<String, String>,
    /// (replica id, incarnation) pairs whose marker this replica has seen.
    confirmed: HashSet<(String, String)>,
    /// When each required, unconfirmed pair was first required.
    since: HashMap<(String, String), Instant>,
    /// Required, unconfirmed pairs whose last marker read failed with an I/O
    /// error other than "not found": this replica cannot decide them.
    unreadable: HashSet<(String, String)>,
    /// Required, unconfirmed pairs whose last marker read completed without
    /// the marker (no file, or another incarnation). A hung step does not
    /// undo this: the last completed read stands.
    absent: HashSet<(String, String)>,
    /// Latched once every fresh drain anchor's marker was seen. Only this
    /// opens staging, and nothing closes it again.
    proven: bool,
}

impl ShareState {
    fn unconfirmed(&self) -> impl Iterator<Item = (&String, &String)> {
        self.required.iter().filter(|(id, incarnation)| {
            !self
                .confirmed
                .contains(&((*id).clone(), (*incarnation).clone()))
        })
    }

    /// Whether the last view proves the share: at least one fresh drain
    /// anchor, and every one of them confirmed.
    fn anchor_proof(&self) -> bool {
        self.exchanged && !self.required.is_empty() && self.unconfirmed().next().is_none()
    }

    /// The verdict at `now`. `stuck` is whether the probe-thread step has
    /// hung for `marker_stuck_after`: then no new marker read can complete,
    /// so a pair not yet read is not decided. A pair that a completed read
    /// already found absent still counts: the last completed read stands.
    fn verdict(&self, now: Instant, grace: Duration, born: Instant, stuck: bool) -> ShareVerdict {
        if self.proven {
            return ShareVerdict::Shared;
        }
        if !self.exchanged {
            return if now.saturating_duration_since(born) >= grace {
                ShareVerdict::PendingTooLong
            } else {
                ShareVerdict::Pending
            };
        }
        if self.required.is_empty() {
            return ShareVerdict::NoAnchor;
        }
        // Only an unseen marker that was not last read with an I/O error
        // counts toward the 503 words. A marker not read yet counts (the
        // start-up 503, RV3-C in the module docs), unless the step is hung:
        // then only a marker a completed read found absent counts.
        let mut decided = self
            .unconfirmed()
            .filter(|(id, incarnation)| {
                let key = ((*id).clone(), (*incarnation).clone());
                !self.unreadable.contains(&key) && (!stuck || self.absent.contains(&key))
            })
            .peekable();
        if decided.peek().is_none() {
            // Every anchor confirmed latches `proven` in the same lock
            // (`sync_gate`), so an unproven state always has one unseen;
            // here every unseen one was unreadable, or not read before the
            // step hung.
            return ShareVerdict::Undecided;
        }
        let oldest = decided
            .filter_map(|(id, incarnation)| {
                self.since.get(&(id.clone(), incarnation.clone())).copied()
            })
            .min();
        match oldest {
            Some(since) if now.saturating_duration_since(since) >= grace => ShareVerdict::NotShared,
            _ => ShareVerdict::Unverified,
        }
    }
}

/// Whether `id` is a replica id this build could have written: safe as a
/// file name. An id that is not is never confirmed.
pub fn is_marker_safe_id(id: &str) -> bool {
    sanitize_replica_id(id) == id
}

/// The marker, challenge and echo files under `<stage>/liveness/`. Blocking;
/// used only on the probe or marker thread.
///
/// A replica's stage liveness uses [`Self::pinned`]: every file goes through
/// the `liveness/` directory the stage pinned at open (a held descriptor,
/// confined: no symlink, no mount point), never through a path, so a file it
/// reads or writes is in its own pinned stage tree (review B1 of round 4).
/// [`Self::new`] works on a plain path; tests and tools only.
#[derive(Debug, Clone)]
pub struct ShareMarkers {
    directory: MarkerDirectory,
}

#[derive(Debug, Clone)]
enum MarkerDirectory {
    /// `<root>/liveness` by path, created on demand.
    Path(PathBuf),
    /// The stage's pinned `liveness/` directory.
    Pinned(lore_postgres::store::write_behind::StageLivenessDir),
}

impl MarkerDirectory {
    /// The trimmed content of `name`, at most `limit` bytes, or `None` when
    /// there is no such file.
    fn read(&self, name: &str, limit: u64) -> std::io::Result<Option<String>> {
        match self {
            Self::Path(directory) => read_limited(&directory.join(name), limit),
            Self::Pinned(directory) => match directory.read(name, limit)? {
                None => Ok(None),
                Some(bytes) => String::from_utf8(bytes)
                    .map(|content| Some(content.trim().to_owned()))
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            },
        }
    }

    /// Replace `name` with `content` through `temporary` (write, fsync,
    /// rename), so a reader never sees a partial file.
    fn replace(&self, name: &str, temporary: &str, content: &str) -> std::io::Result<()> {
        match self {
            Self::Path(directory) => write_atomic(
                directory,
                &directory.join(temporary),
                &directory.join(name),
                content,
            ),
            Self::Pinned(directory) => directory.replace(name, temporary, content.as_bytes()),
        }
    }

    /// Remove `name`. An absent file is a success.
    fn remove(&self, name: &str) -> std::io::Result<()> {
        match self {
            Self::Path(directory) => match std::fs::remove_file(directory.join(name)) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
            Self::Pinned(directory) => directory.remove(name),
        }
    }

    /// Remove `name` if its first word is `incarnation`. A file of another
    /// process under the same name is kept.
    fn remove_if_named(&self, name: &str, incarnation: &str, limit: u64) -> std::io::Result<()> {
        let held = self.read(name, limit)?;
        if held
            .as_deref()
            .and_then(|content| content.split_whitespace().next())
            != Some(incarnation)
        {
            return Ok(());
        }
        self.remove(name)
    }
}

/// Split marker or challenge content into its incarnation and the word after
/// it (a challenge file's challenge), if any. `None` for empty content or
/// more than two words.
pub fn parse_marker(content: &str) -> Option<(&str, Option<&str>)> {
    let mut words = content.split_whitespace();
    let incarnation = words.next()?;
    let word = words.next();
    if words.next().is_some() {
        return None;
    }
    Some((incarnation, word))
}

/// A new random challenge (and the random part of a replica id).
fn new_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// The challenge `reader_incarnation` is echoed with in the content of an
/// echo file (`content`) written by the process `stager_incarnation`, if
/// any. The first line must name exactly that incarnation; each later line
/// is `<reader incarnation> <challenge>`. Only an exact incarnation match
/// counts: an echo of another reader's challenge, or a file another process
/// wrote under the same replica id, is never this reader's echo.
pub fn echoed_challenge<'a>(
    content: &'a str,
    stager_incarnation: &str,
    reader_incarnation: &str,
) -> Option<&'a str> {
    let mut lines = content.lines();
    if lines.next()?.trim() != stager_incarnation {
        return None;
    }
    lines
        .filter_map(parse_marker)
        .find(|(incarnation, _)| *incarnation == reader_incarnation)
        .and_then(|(_, challenge)| challenge)
}

/// The trimmed content of the file at `path`, at most `limit` bytes, or
/// `None` when there is no file.
fn read_limited(path: &std::path::Path, limit: u64) -> std::io::Result<Option<String>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut content = String::new();
    file.take(limit).read_to_string(&mut content)?;
    Ok(Some(content.trim().to_owned()))
}

/// Replace `path` with `content` through `temporary` in `directory`
/// (created on demand): write, fsync, then rename, so a reader never sees a
/// partial file.
fn write_atomic(
    directory: &std::path::Path,
    temporary: &std::path::Path,
    path: &std::path::Path,
    content: &str,
) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    {
        let mut handle = std::fs::File::create(temporary)?;
        handle.write_all(content.as_bytes())?;
        handle.sync_all()?;
    }
    std::fs::rename(temporary, path)
}

/// `replica_id` followed by `suffix`, if the id is safe as a file name.
fn file_name(replica_id: &str, suffix: &str) -> Option<String> {
    is_marker_safe_id(replica_id).then(|| format!("{replica_id}{suffix}"))
}

/// The error for a write under a replica id that is not safe as a file name.
fn unsafe_name(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("replica id is not safe as a {what} file name"),
    )
}

impl ShareMarkers {
    /// The files under `<root>/liveness` by path, created on demand. Tests
    /// and tools only: a replica's stage liveness uses [`Self::pinned`].
    pub fn new(root: &std::path::Path) -> Self {
        Self {
            directory: MarkerDirectory::Path(
                root.join(lore_postgres::store::write_behind::root::LIVENESS_DIR),
            ),
        }
    }

    /// The files in the stage's pinned `liveness/` directory.
    pub fn pinned(directory: lore_postgres::store::write_behind::StageLivenessDir) -> Self {
        Self {
            directory: MarkerDirectory::Pinned(directory),
        }
    }

    /// Whether this goes through a stage's pinned `liveness/` directory.
    pub fn is_pinned(&self) -> bool {
        matches!(self.directory, MarkerDirectory::Pinned(_))
    }

    /// The content of `replica_id`'s challenge file (`<incarnation>
    /// <challenge>`), or `None` when there is none (or the id is not safe as
    /// a file name).
    pub fn read_challenge(&self, replica_id: &str) -> std::io::Result<Option<String>> {
        match file_name(replica_id, CHALLENGE_SUFFIX) {
            Some(name) => self.directory.read(&name, MARKER_READ_LIMIT),
            None => Ok(None),
        }
    }

    /// Replace `replica_id`'s challenge file with `content`: a temporary
    /// file, fsync, then rename, so a reader never sees a partial challenge.
    pub fn write_challenge(&self, replica_id: &str, content: &str) -> std::io::Result<()> {
        let Some(name) = file_name(replica_id, CHALLENGE_SUFFIX) else {
            return Err(unsafe_name("challenge"));
        };
        self.directory
            .replace(&name, &format!("{name}.tmp"), content)
    }

    /// Remove `replica_id`'s challenge file if it still names `incarnation`,
    /// so a stopped reader leaves nothing behind. A newer process's file
    /// under the same id is kept.
    pub fn remove_challenge_if(&self, replica_id: &str, incarnation: &str) -> std::io::Result<()> {
        match file_name(replica_id, CHALLENGE_SUFFIX) {
            Some(name) => self
                .directory
                .remove_if_named(&name, incarnation, MARKER_READ_LIMIT),
            None => Ok(()),
        }
    }

    /// The content of `replica_id`'s echo file, or `None` when there is none
    /// (or the id is not safe as a file name). See [`echoed_challenge`].
    pub fn read_echo(&self, replica_id: &str) -> std::io::Result<Option<String>> {
        match file_name(replica_id, ECHO_SUFFIX) {
            Some(name) => self.directory.read(&name, ECHO_READ_LIMIT),
            None => Ok(None),
        }
    }

    /// Replace `replica_id`'s echo file with `content` (temporary file,
    /// fsync, rename).
    pub fn write_echo(&self, replica_id: &str, content: &str) -> std::io::Result<()> {
        let Some(name) = file_name(replica_id, ECHO_SUFFIX) else {
            return Err(unsafe_name("echo"));
        };
        self.directory
            .replace(&name, &format!("{name}.tmp"), content)
    }

    /// Remove `replica_id`'s echo file if it still names `incarnation`. A
    /// newer process's file under the same id is kept.
    pub fn remove_echo_if(&self, replica_id: &str, incarnation: &str) -> std::io::Result<()> {
        match file_name(replica_id, ECHO_SUFFIX) {
            Some(name) => self
                .directory
                .remove_if_named(&name, incarnation, ECHO_READ_LIMIT),
            None => Ok(()),
        }
    }

    /// The incarnation in `replica_id`'s marker, or `None` when there is no
    /// marker (or the id is not safe as a file name).
    pub fn read(&self, replica_id: &str) -> std::io::Result<Option<String>> {
        match file_name(replica_id, SHARE_MARKER_SUFFIX) {
            Some(name) => self.directory.read(&name, MARKER_READ_LIMIT),
            None => Ok(None),
        }
    }

    /// Make `replica_id`'s marker hold `incarnation`. Writes only when it is
    /// missing or holds another value: a temporary file, fsync, then rename,
    /// so a reader never sees a partial marker. Returns whether it wrote.
    pub fn ensure(&self, replica_id: &str, incarnation: &str) -> std::io::Result<bool> {
        if self.read(replica_id)?.as_deref() == Some(incarnation) {
            return Ok(false);
        }
        let Some(name) = file_name(replica_id, SHARE_MARKER_SUFFIX) else {
            return Err(unsafe_name("marker"));
        };
        self.directory
            .replace(&name, &format!("{name}.tmp"), incarnation)?;
        Ok(true)
    }

    /// Remove `replica_id`'s marker if it still holds `incarnation`, so a
    /// stopped replica leaves nothing behind.
    /// A newer process's marker under the same id is kept.
    pub fn remove_if(&self, replica_id: &str, incarnation: &str) -> std::io::Result<()> {
        let held = self.read(replica_id)?;
        if held
            .as_deref()
            .and_then(parse_marker)
            .map(|(found, _)| found)
            != Some(incarnation)
        {
            return Ok(());
        }
        let Some(name) = file_name(replica_id, SHARE_MARKER_SUFFIX) else {
            return Ok(());
        };
        self.directory.remove(&name)
    }
}

/// One probe of the stage. Blocking; runs only on the probe thread.
pub type ProbeFn = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

/// The probe: write, fsync and remove `<root>/liveness/<replica>.probe`.
///
/// The directory is created on demand, so a purge of it, or a fresh stage,
/// heals by itself. A file already gone at remove is still a success: the
/// write and fsync reached the server, which is what the probe tests.
pub fn file_probe(root: PathBuf, replica_id: &str) -> ProbeFn {
    let directory = root.join(lore_postgres::store::write_behind::root::LIVENESS_DIR);
    let file = directory.join(format!("{replica_id}.probe"));
    Arc::new(move || {
        use std::io::Write as _;
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        {
            let mut handle = std::fs::File::create(&file)?;
            handle.write_all(b"lore-stage-liveness")?;
            handle.sync_all()?;
        }
        match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    })
}

/// This replica's identity in the liveness table: host, process id, and a
/// random part.
///
/// Stable for the life of the process and unique per process (assumption
/// A3). Host and process id alone are not: two containers given the same
/// host name both run as process 1 and would share one row, so their
/// incarnations would replace each other and the K11 baseline and the
/// shared-stage checks would flap (review S2). The random part ends that.
/// A restarted process gets a new id; its old row is withdrawn at drain, or
/// pruned after [`RETAIN`]. The host part is cut first if the id is too
/// long, so the random part always survives.
pub fn default_replica_id() -> String {
    replica_id_for(&default_host(), std::process::id(), &new_nonce()[..8])
}

/// [`default_replica_id`] from its parts. The suffix `-<pid>-<random>` is
/// always kept whole; only the host is cut to fit.
pub fn replica_id_for(host: &str, pid: u32, random: &str) -> String {
    let suffix = sanitize_replica_id(&format!("{pid}-{random}"));
    let room = MAX_STAGE_LIVENESS_ID_BYTES.saturating_sub(suffix.len() + 1);
    let host: String = sanitize_replica_id(host).chars().take(room).collect();
    sanitize_replica_id(&format!("{host}-{suffix}"))
}

/// The host part of [`default_replica_id`].
fn default_host() -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".to_owned())
}

/// Keep `[A-Za-z0-9._-]`, map anything else to `_`, and bound the length, so
/// the id is safe as a file name and fits the table.
pub fn sanitize_replica_id(raw: &str) -> String {
    let mut id: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    id.truncate(MAX_STAGE_LIVENESS_ID_BYTES);
    if id.is_empty() || id.chars().all(|c| c == '.') {
        id = "replica".to_owned();
    }
    id
}

/// What `/health_check` reports about the probe, so an operator sees why a
/// host was ejected without reading the log.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StageLivenessSnapshot {
    pub replica_id: String,
    pub incarnation: String,
    pub progress: u64,
    pub probe_age_millis: u64,
    pub probe_in_flight: bool,
    pub probe_failures: u64,
    pub peer_view_age_millis: Option<u64>,
    pub progressing_peers: Option<u64>,
    pub peers: Option<u64>,
    pub fault: Option<&'static str>,
    /// The shared-stage check: `pending`, `pending_too_long`, `no_anchor`,
    /// `unverified`, `not_shared`, `undecided` or `shared`
    /// ([`ShareVerdict::name`]).
    /// `None` when the guard is off.
    pub share: Option<&'static str>,
    /// Fresh drains whose marker this replica has not seen.
    pub share_unconfirmed: Vec<String>,
    /// The absence guard (the drain, and a web replica with the guard
    /// attached): `guarded`, or [`ABSENCE_NO_CHALLENGE`] while this replica
    /// has no current challenge. `None` without the guard.
    pub absence: Option<&'static str>,
    /// Web stage replicas of the last view not yet confirmed by this
    /// process.
    pub absence_unconfirmed: Vec<String>,
    /// Web stage replica processes this process confirmed (also ones that
    /// have left). `None` without the guard.
    pub absence_confirmed: Option<u64>,
    /// What the guard decided for staged files this replica could not find,
    /// since boot. Decisions, not files: a kept file adds one per retry.
    pub absence_counts: Option<AbsenceCounts>,
}

/// The drain guard's decision counts, for `/health_check`.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbsenceCounts {
    /// Read as absent (the stager was confirmed here).
    pub proven: u64,
    /// Kept `Staged`: this process has not confirmed the stager.
    pub unconfirmed: u64,
    /// Kept `Staged`: no stager is recorded.
    pub no_stager: u64,
    /// Kept `Staged`: the stager is confirmed, but the representation is
    /// younger than `MIN_STAGED_ABSENCE_AGE`.
    pub too_recent: u64,
    /// Kept `Staged`: the stager read failed.
    pub failed: u64,
}

impl AbsenceCounts {
    /// Files kept `Staged`, for every cause.
    pub fn kept(&self) -> u64 {
        self.unconfirmed
            .saturating_add(self.no_stager)
            .saturating_add(self.too_recent)
            .saturating_add(self.failed)
    }
}

impl From<DrainAbsenceSnapshot> for AbsenceCounts {
    fn from(snapshot: DrainAbsenceSnapshot) -> Self {
        Self {
            proven: snapshot.proven,
            unconfirmed: snapshot.unconfirmed,
            no_stager: snapshot.no_stager,
            too_recent: snapshot.too_recent,
            failed: snapshot.failed,
        }
    }
}

/// A peer as the baseline holds it: its incarnation, its count, and the
/// database time after which an increase must have run to count.
#[derive(Debug, Clone)]
struct PeerBaseline {
    incarnation: String,
    progress: i64,
    after_micros: i64,
}

/// The first view taken after this replica went stale, per peer.
#[derive(Debug, Clone)]
struct Baseline {
    /// `last_good` (nanos after origin) when the baseline was taken. A new
    /// own success changes it, which ends this stale period.
    epoch: u64,
    peers: HashMap<String, PeerBaseline>,
}

#[derive(Debug, Clone, Copy)]
struct LatestView {
    /// When the exchange that read it STARTED. That is no later than the
    /// database read, so the view's age and the "taken after self went
    /// stale" test both err toward "cannot decide".
    at: Instant,
    epoch: u64,
    after_stale: bool,
    peers: u64,
    progressing: u64,
}

#[derive(Debug, Default)]
struct PeerState {
    latest: Option<LatestView>,
    baseline: Option<Baseline>,
}

/// This process's own probe progress. Updated together so a publication
/// never pairs a count with a newer success time.
#[derive(Debug, Default, Clone, Copy)]
struct OwnProgress {
    count: u64,
}

/// One replica's stage liveness: its own progress, the peer views, and the
/// verdict over both.
pub struct StageLiveness {
    replica_id: String,
    incarnation: String,
    origin: Instant,
    /// Nanoseconds after `origin` of the last good probe. Starts at 0: the
    /// stage was proven writable at boot by `WriteBehindStage::open`.
    last_good: AtomicU64,
    own: Mutex<OwnProgress>,
    probes_started: AtomicU64,
    probe_failures: AtomicU64,
    in_flight: AtomicBool,
    /// Probe threads ever started for this replica. Never above 1.
    threads_started: AtomicUsize,
    peers: Mutex<PeerState>,
    /// The last successful exchange's database clock, for the next deadline.
    clock: Mutex<Option<StageLivenessClock>>,
    /// This process's own row as its last exchange left it. `None` until an
    /// exchange succeeds, and again after one fails, because a failed
    /// exchange may still have written the row.
    last_published: Mutex<Option<StageProgressRecord>>,
    /// The last duplicate-identity sighting: when it was last logged, and
    /// the (published, found) pair that disagreed.
    duplicate_warned: Mutex<Option<(Instant, StageProgressRecord, StageProgressRecord)>>,
    /// The last verdict, for one log line per transition.
    ejected: AtomicBool,
    thresholds: LivenessThresholds,
    /// Whether the shared-stage guard answers `/lb_health`. Off in a
    /// replica built for K11 alone (tests); on in production.
    share_guard: bool,
    share: Mutex<ShareState>,
    /// When the probe thread's current step (probe plus marker reads)
    /// started, or `None` between steps. A step that runs longer than
    /// `marker_stuck_after` is hung.
    step_started: Mutex<Option<Instant>>,
    /// `true` while staging is held. Shared with the stage; see
    /// [`Self::share_gate`].
    share_gate: Arc<AtomicBool>,
    /// The last reported share verdict, for one log line per transition.
    share_reported: Mutex<Option<ShareVerdict>>,
    /// `Stage`, or `Drain` for the drain worker: it publishes a row and a
    /// marker as the shared-stage anchor, and is never ejected or held.
    role: StageLivenessRole,
    /// The drain worker only: when a read-back of its own marker last showed
    /// its incarnation. `None` until one does, and again after one fails.
    anchor_verified: Mutex<Option<Instant>>,
    /// The drain worker only: the last reported anchor state, for one log
    /// line per transition.
    anchor_reported: Mutex<Option<bool>>,
    /// A reader (the drain worker, or a guarded web replica): the absence
    /// guard's confirmations (module docs, "Drain guard").
    guard: Mutex<GuardState>,
    /// A reader: the stage's decision counts, once attached.
    absence_counts: OnceLock<Arc<DrainAbsenceCounts>>,
    /// A reader: the last reported drain guard state.
    absence_reported: Mutex<Option<AbsenceReport>>,
    /// A reader: its own challenge. Written on the probe or marker thread,
    /// read by the exchange task; never held across file I/O.
    challenge: Mutex<ChallengeState>,
    /// A web stage replica: the echo file content its last step wrote (and
    /// the root check confirmed), so an unchanged echo is not written again.
    /// `None` before the first, and after a failed write or root check.
    echo_written: Mutex<Option<String>>,
    /// Whether the configured root path still names the pinned stage root.
    /// `None` (tests): always.
    root_check: Option<RootCheck>,
}

impl StageLiveness {
    pub fn new(replica_id: String) -> Self {
        Self::with_thresholds(replica_id, LivenessThresholds::default())
    }

    pub fn with_thresholds(replica_id: String, thresholds: LivenessThresholds) -> Self {
        Self::with_incarnation(
            replica_id,
            uuid::Uuid::new_v4().simple().to_string(),
            thresholds,
        )
    }

    /// As [`Self::with_thresholds`], with a chosen incarnation id. A test
    /// uses it to stand in for one process across a restart.
    pub fn with_incarnation(
        replica_id: String,
        incarnation: String,
        thresholds: LivenessThresholds,
    ) -> Self {
        Self {
            replica_id,
            incarnation,
            origin: Instant::now(),
            last_good: AtomicU64::new(0),
            own: Mutex::new(OwnProgress::default()),
            probes_started: AtomicU64::new(0),
            probe_failures: AtomicU64::new(0),
            in_flight: AtomicBool::new(false),
            threads_started: AtomicUsize::new(0),
            peers: Mutex::new(PeerState::default()),
            clock: Mutex::new(None),
            last_published: Mutex::new(None),
            duplicate_warned: Mutex::new(None),
            ejected: AtomicBool::new(false),
            thresholds,
            share_guard: false,
            share: Mutex::new(ShareState::default()),
            step_started: Mutex::new(None),
            share_gate: Arc::new(AtomicBool::new(true)),
            share_reported: Mutex::new(None),
            role: StageLivenessRole::Stage,
            anchor_verified: Mutex::new(None),
            anchor_reported: Mutex::new(None),
            guard: Mutex::new(GuardState::default()),
            absence_counts: OnceLock::new(),
            absence_reported: Mutex::new(None),
            challenge: Mutex::new(ChallengeState::default()),
            echo_written: Mutex::new(None),
            root_check: None,
        }
    }

    /// Publish as `role`. A `Drain` replica anchors the shared-stage check
    /// and is never held, ejected, or counted as a K11 peer.
    #[must_use]
    pub fn with_role(mut self, role: StageLivenessRole) -> Self {
        self.role = role;
        self
    }

    pub fn role(&self) -> StageLivenessRole {
        self.role
    }

    /// Turn the shared-stage guard on: its verdict joins `/lb_health`.
    #[must_use]
    pub fn with_share_guard(mut self) -> Self {
        self.share_guard = true;
        self
    }

    pub fn share_guard(&self) -> bool {
        self.share_guard
    }

    /// The "staging is off" flag to attach to the stage. Starts `true`:
    /// nothing is proven before the first exchange. It only ever goes from
    /// `true` to `false`, once, when an anchor proof latches.
    pub fn share_gate(&self) -> Arc<AtomicBool> {
        self.share_gate.clone()
    }

    /// Check, around every challenge write and read, that the stage tree is
    /// still the one pinned at open ([`RootCheck`]). Without one (tests), the
    /// tree always counts as pinned.
    #[must_use]
    pub fn with_root_check(mut self, check: RootCheck) -> Self {
        self.root_check = Some(check);
        self
    }

    fn root_ok(&self) -> bool {
        self.root_check.as_ref().is_none_or(|check| check())
    }

    /// A reader: the stage's absence guard counters, once
    /// [`FragmentWriteBehindHandle::attach_drain_absence_guard`] returned
    /// them. `false` if they were already set.
    ///
    /// [`FragmentWriteBehindHandle::attach_drain_absence_guard`]:
    ///     lore_postgres::store::fragment_write_behind::FragmentWriteBehindHandle::attach_drain_absence_guard
    pub fn set_absence_counts(&self, counts: Arc<DrainAbsenceCounts>) -> bool {
        self.absence_counts.set(counts).is_ok()
    }

    /// A reader: whether `stager` is proven, to this process, to stage into
    /// this process's own stage directory. A web stage replica always
    /// confirms itself: its own files are in its own pinned root. Any other
    /// stager only after its echo file, read in this process's own stage,
    /// showed two of this process's current challenges
    /// ([`Self::confirm_step`]). The absence guard asks this for each staged
    /// file the stage cannot find.
    pub fn confirms(&self, stager: &StagerIdentity) -> bool {
        if self.role == StageLivenessRole::Stage
            && stager.replica_id == self.replica_id
            && stager.incarnation == self.incarnation
        {
            return true;
        }
        lock(&self.guard).confirmed.contains(stager)
    }

    /// A reader: its current challenge, as (sequence number, challenge), or
    /// `None`. The challenge is a secret of this process's stage directory:
    /// never log it.
    #[lore_macro::test_pub]
    pub(crate) fn current_challenge(&self) -> Option<(u64, String)> {
        lock(&self.challenge).current.clone()
    }

    /// A reader: record the absence guard's part of a view. Only rows
    /// published within `share_peer_fresh` count (review A1/A2 and S1 of
    /// round 3): a crashed or departed process's row stays in the table for
    /// [`RETAIN`], and must neither hold the "not confirmed yet" signal nor
    /// take an echo slot.
    ///
    /// Every fresh `stage` row is a candidate, which [`Self::confirm_step`]
    /// may confirm from its echo file. A candidate whose row is gone or stale
    /// is dropped, but a confirmation never is: it is a fact about a process
    /// that never changes its directory. A stager this process never
    /// confirmed stays unconfirmed whatever its row does, so its staged files
    /// are never read as absent here.
    ///
    /// Every other fresh process of the view is also a checker whose
    /// challenge a web stage replica echoes: drain rows first, then the
    /// others in replica-id order, at most [`MAX_CHALLENGE_ECHOES`].
    #[lore_macro::test_pub]
    pub(crate) fn note_guard_view(&self, view: &StagePeerLiveness) {
        let fresh_micros =
            i64::try_from(self.thresholds.share_peer_fresh.as_micros()).unwrap_or(i64::MAX);
        let fresh = |peer: &StagePeerProgress| {
            view.db_clock_micros.saturating_sub(peer.published_micros) <= fresh_micros
        };
        // This process itself is neither a checker nor a candidate (review A
        // nit of round 4): echoing its own challenge proves nothing, and a
        // web replica confirms itself anyway (`confirms`).
        let other = |peer: &StagePeerProgress| {
            peer.replica_id != self.replica_id || peer.record.incarnation != self.incarnation
        };
        let mut checkers: Vec<&StagePeerProgress> = view
            .peers
            .iter()
            .filter(|peer| {
                fresh(peer)
                    && other(peer)
                    && is_marker_safe_id(&peer.replica_id)
                    && !peer.record.incarnation.is_empty()
            })
            .collect();
        // A stable sort: drain rows (any drain role) first, each group in
        // view (replica id) order.
        checkers.sort_by_key(|peer| peer.role == StageLivenessRole::Stage);
        let mut guard = lock(&self.guard);
        let state = &mut *guard;
        state.checkers = checkers
            .into_iter()
            .take(MAX_CHALLENGE_ECHOES)
            .map(|peer| (peer.replica_id.clone(), peer.record.incarnation.clone()))
            .collect();
        let mut next = BTreeMap::new();
        for peer in &view.peers {
            if peer.role != StageLivenessRole::Stage || !fresh(peer) || !other(peer) {
                continue;
            }
            let Some(stager) = StagerIdentity::new(&peer.replica_id, &peer.record.incarnation)
            else {
                continue;
            };
            let first = state.candidates.remove(&stager).flatten();
            next.insert(stager, first);
        }
        state.candidates = next;
    }

    /// A reader, on the probe or marker thread: read the echo file of each
    /// candidate not confirmed yet (at most [`MAX_ECHO_READS`]) in this
    /// process's own stage. A file that names the candidate's incarnation and
    /// echoes this reader's CURRENT challenge under this reader's incarnation
    /// notes that challenge's sequence number; a later current challenge
    /// confirms the candidate. Only while the root path names the pinned root
    /// before and after the reads; else nothing read counts.
    #[lore_macro::test_pub]
    pub(crate) fn confirm_step(&self, markers: &ShareMarkers) {
        let Some((seq, challenge)) = lock(&self.challenge).current.clone() else {
            return;
        };
        let candidates: Vec<StagerIdentity> = {
            let guard = lock(&self.guard);
            guard.unconfirmed().take(MAX_ECHO_READS).cloned().collect()
        };
        if candidates.is_empty() || !self.root_ok() {
            return;
        }
        let echoed: Vec<StagerIdentity> = candidates
            .into_iter()
            .filter(|stager| {
                markers
                    .read_echo(&stager.replica_id)
                    .ok()
                    .flatten()
                    .is_some_and(|content| {
                        echoed_challenge(&content, &stager.incarnation, &self.incarnation)
                            == Some(challenge.as_str())
                    })
            })
            .collect();
        if !self.root_ok() {
            return;
        }
        let mut guard = lock(&self.guard);
        for stager in echoed {
            let confirm = match guard.candidates.get_mut(&stager) {
                Some(slot @ None) => {
                    *slot = Some(seq);
                    false
                }
                Some(Some(earlier)) => *earlier < seq,
                None => false,
            };
            if confirm {
                guard.confirm(stager);
            }
        }
    }

    /// A reader, on the probe or marker thread: write a new challenge every
    /// [`CHALLENGE_EVERY_STEPS`] steps (and on every step while there is
    /// none). It becomes current only after its write completed, with the
    /// root path naming the pinned root before and after. A failed root
    /// check clears the current challenge. A failed write keeps the last
    /// one: the file still holds it, or the new one that nobody counts.
    #[lore_macro::test_pub]
    pub(crate) fn challenge_step(&self, markers: &ShareMarkers) {
        let due = {
            let mut state = lock(&self.challenge);
            let due = state.current.is_none() || state.steps.is_multiple_of(CHALLENGE_EVERY_STEPS);
            state.steps = state.steps.wrapping_add(1);
            due
        };
        if !self.root_ok() {
            lock(&self.challenge).current = None;
            return;
        }
        if !due {
            return;
        }
        let challenge = new_nonce();
        let written = markers
            .write_challenge(
                &self.replica_id,
                &format!("{} {challenge}", self.incarnation),
            )
            .is_ok();
        let rooted = self.root_ok();
        let mut state = lock(&self.challenge);
        if !rooted {
            state.current = None;
        } else if written {
            state.seq = state.seq.saturating_add(1);
            state.current = Some((state.seq, challenge));
        }
    }

    /// A web stage replica, on the probe thread: read the challenge file of
    /// each checker of the last view in this replica's own stage, keep those
    /// that name the checker's current incarnation, and write them as this
    /// replica's echo file in the same directory (module docs, "Drain guard",
    /// step 3). An unchanged echo is not written again.
    ///
    /// Only while the root path names the pinned root before the reads and
    /// after the write. If it no longer does after the write, the echo may
    /// sit in another directory, so the echo file the path names now is
    /// removed (if it holds this process's incarnation) and nothing counts as
    /// written.
    #[lore_macro::test_pub]
    pub(crate) fn echo_step(&self, markers: &ShareMarkers) {
        let checkers = lock(&self.guard).checkers.clone();
        if !self.root_ok() {
            *lock(&self.echo_written) = None;
            return;
        }
        let mut content = self.incarnation.clone();
        for (id, incarnation) in &checkers {
            if let Ok(Some(found)) = markers.read_challenge(id)
                && let Some((named, Some(challenge))) = parse_marker(&found)
                && named == incarnation
            {
                content.push('\n');
                content.push_str(incarnation);
                content.push(' ');
                content.push_str(challenge);
            }
        }
        let unchanged = lock(&self.echo_written).as_deref() == Some(content.as_str());
        let written = unchanged || markers.write_echo(&self.replica_id, &content).is_ok();
        if !self.root_ok() {
            *lock(&self.echo_written) = None;
            if let Err(error) = markers.remove_echo_if(&self.replica_id, &self.incarnation) {
                warn!(%error, "stage echo file could not be removed after the root path moved");
            }
            return;
        }
        *lock(&self.echo_written) = written.then_some(content);
    }

    /// A reader: whether something is not proven: this process has no
    /// current challenge, or a web replica in the last view is not confirmed
    /// by it yet.
    pub fn absence_unproven(&self) -> bool {
        if lock(&self.challenge).current.is_none() {
            return true;
        }
        lock(&self.guard).unconfirmed().next().is_some()
    }
    /// The shared-stage verdict at `now`.
    pub fn share_verdict(&self, now: Instant) -> ShareVerdict {
        let stuck = self.step_stuck(now);
        lock(&self.share).verdict(now, self.thresholds.share_grace, self.origin, stuck)
    }

    /// Whether the probe thread's current step has run for at least
    /// `marker_stuck_after` at `now`.
    pub fn step_stuck(&self, now: Instant) -> bool {
        lock(&self.step_started).is_some_and(|started| {
            now.saturating_duration_since(started) >= self.thresholds.marker_stuck_after
        })
    }

    /// Mark the start (`Some`) or the end (`None`) of a probe-thread step.
    fn note_step(&self, started: Option<Instant>) {
        *lock(&self.step_started) = started;
    }

    /// Latch `proven` when the last view's drain anchors are all confirmed,
    /// and store it in the gate. Only an anchor proof opens staging; nothing
    /// closes it again. Called with the state lock held, so gate writes
    /// follow state changes in order.
    fn sync_gate(&self, state: &mut ShareState) {
        if !state.proven && state.anchor_proof() {
            state.proven = true;
            state.required.clear();
            state.since.clear();
            state.unreadable.clear();
            state.absent.clear();
        }
        self.share_gate.store(!state.proven, Ordering::Release);
    }

    /// Record the shared-stage part of a peer view.
    ///
    /// A drain worker is never held. For a stage replica the required set is
    /// every `drain` row published within [`SHARE_PEER_FRESH`], with its
    /// current incarnation. It is computed again on every view until an
    /// anchor proof latches; after that nothing is required again. With no
    /// fresh `drain` row nothing is required and nothing is proven: staging
    /// stays off and `/lb_health` stays 200.
    pub fn note_share(&self, now: Instant, view: &StagePeerLiveness) {
        self.note_guard_view(view);
        let mut state = lock(&self.share);
        state.exchanged = true;
        if self.role != StageLivenessRole::Stage {
            state.proven = true;
        }
        if state.proven {
            state.required.clear();
            self.sync_gate(&mut state);
            return;
        }
        let fresh_micros =
            i64::try_from(self.thresholds.share_peer_fresh.as_micros()).unwrap_or(i64::MAX);
        let fresh = |peer: &StagePeerProgress| {
            view.db_clock_micros.saturating_sub(peer.published_micros) <= fresh_micros
        };
        let required: BTreeMap<String, String> = view
            .peers
            .iter()
            .filter(|peer| peer.role == StageLivenessRole::Drain && fresh(peer))
            .map(|peer| (peer.replica_id.clone(), peer.record.incarnation.clone()))
            .collect();
        let seen: HashSet<&str> = view
            .peers
            .iter()
            .map(|peer| peer.replica_id.as_str())
            .collect();
        state.confirmed.retain(|(id, _)| seen.contains(id.as_str()));
        state
            .since
            .retain(|key, _| required.get(&key.0) == Some(&key.1));
        state
            .unreadable
            .retain(|key| required.get(&key.0) == Some(&key.1));
        state
            .absent
            .retain(|key| required.get(&key.0) == Some(&key.1));
        for (id, incarnation) in &required {
            let key = (id.clone(), incarnation.clone());
            if !state.confirmed.contains(&key) {
                state.since.entry(key).or_insert(now);
            }
        }
        state.required = required;
        self.sync_gate(&mut state);
    }

    /// The (peer, incarnation) pairs whose marker the probe thread should
    /// look for.
    pub fn share_checks(&self) -> Vec<(String, String)> {
        lock(&self.share)
            .unconfirmed()
            .map(|(id, incarnation)| (id.clone(), incarnation.clone()))
            .collect()
    }

    /// Record that `id`'s marker holds `incarnation`. Once seen, the pair
    /// stays confirmed while the peer keeps its row.
    pub fn note_marker_seen(&self, id: &str, incarnation: &str) {
        let mut state = lock(&self.share);
        let key = (id.to_owned(), incarnation.to_owned());
        state.since.remove(&key);
        state.unreadable.remove(&key);
        state.absent.remove(&key);
        state.confirmed.insert(key);
        self.sync_gate(&mut state);
    }

    /// Record the outcome of a marker read that did not show `incarnation`:
    /// `readable` when the read completed (no file, or another value), so it
    /// counts toward the 503 words; else an I/O error, "cannot decide".
    pub fn note_marker_unseen(&self, id: &str, incarnation: &str, readable: bool) {
        let mut state = lock(&self.share);
        if state.required.get(id).map(String::as_str) != Some(incarnation) {
            return;
        }
        let key = (id.to_owned(), incarnation.to_owned());
        if readable {
            state.unreadable.remove(&key);
            state.absent.insert(key);
        } else {
            state.absent.remove(&key);
            state.unreadable.insert(key);
        }
    }

    /// One marker step, on the probe or marker thread: keep this replica's
    /// own marker. A stage replica then looks for each required drain's
    /// marker. A completed read without it is "not seen"; a read that fails
    /// with an I/O error is "cannot decide" (module docs, step 6). The drain
    /// worker reads its own marker back and records whether it shows its
    /// current incarnation: only then does it publish as an anchor. Every
    /// reader also keeps its challenge and reads its candidates' echo files,
    /// and a stage replica reads the other processes' challenges and writes
    /// its own echo file (module docs, "Drain guard").
    /// Returns the own marker's write result.
    pub fn share_step(&self, markers: &ShareMarkers) -> std::io::Result<()> {
        if self.role != StageLivenessRole::Stage {
            let own = markers
                .ensure(&self.replica_id, &self.incarnation)
                .map(|_| ());
            let read_back = own.is_ok()
                && markers.read(&self.replica_id).ok().flatten().as_deref()
                    == Some(self.incarnation.as_str());
            *lock(&self.anchor_verified) = read_back.then(Instant::now);
            self.challenge_step(markers);
            self.confirm_step(markers);
            return own;
        }
        let own = markers
            .ensure(&self.replica_id, &self.incarnation)
            .map(|_| ());
        self.challenge_step(markers);
        self.confirm_step(markers);
        self.echo_step(markers);
        for (id, incarnation) in self.share_checks() {
            match markers.read(&id) {
                Ok(Some(found)) if found == incarnation => {
                    self.note_marker_seen(&id, &incarnation);
                }
                Ok(_) => self.note_marker_unseen(&id, &incarnation, true),
                Err(_) => self.note_marker_unseen(&id, &incarnation, false),
            }
        }
        own
    }
    /// The drain worker only: whether its last marker read-back showed its
    /// incarnation and is at most `anchor_verify_max_age` old at `now`.
    /// `true` for a stage replica, which anchors nobody.
    pub fn anchor_verified(&self, now: Instant) -> bool {
        if self.role == StageLivenessRole::Stage {
            return true;
        }
        lock(&self.anchor_verified).is_some_and(|at| {
            now.saturating_duration_since(at) <= self.thresholds.anchor_verify_max_age
        })
    }

    pub fn thresholds(&self) -> LivenessThresholds {
        self.thresholds
    }

    /// The bounds an exchange passes to the store.
    pub fn limits(&self) -> StageLivenessLimits {
        StageLivenessLimits {
            fresh_within: self.thresholds.publish_fresh,
            deadline: self.thresholds.publish_deadline,
            statement_timeout: self.thresholds.statement_timeout,
            retain: RETAIN,
        }
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    pub fn stale_after(&self) -> Duration {
        self.thresholds.stale_after
    }

    /// Fully successful probes so far.
    pub fn progress(&self) -> u64 {
        lock(&self.own).count
    }

    fn nanos_since_origin(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.origin).as_nanos()).unwrap_or(u64::MAX)
    }

    fn instant_of(&self, nanos: u64) -> Instant {
        self.origin
            .checked_add(Duration::from_nanos(nanos))
            .unwrap_or(self.origin)
    }

    /// Record a good probe at `at`: one more success. The success time never
    /// moves back.
    pub fn note_good(&self, at: Instant) {
        let mut own = lock(&self.own);
        own.count = own.count.saturating_add(1);
        self.last_good
            .fetch_max(self.nanos_since_origin(at), Ordering::Relaxed);
    }

    /// What the next exchange publishes.
    pub fn publication(&self) -> StageLivenessPublication {
        let (count, last_good) = {
            let own = lock(&self.own);
            (own.count, self.last_good.load(Ordering::Relaxed))
        };
        StageLivenessPublication {
            incarnation: self.incarnation.clone(),
            progress: count,
            last_good: self.instant_of(last_good),
            clock: *lock(&self.clock),
            role: self.published_role(Instant::now()),
        }
    }

    /// The role the next exchange publishes: the drain worker publishes
    /// `drain` (an anchor) only while its marker read-back is verified.
    fn published_role(&self, now: Instant) -> StageLivenessRole {
        if self.role == StageLivenessRole::Drain && !self.anchor_verified(now) {
            StageLivenessRole::DrainUnverified
        } else {
            self.role
        }
    }

    /// How long before `now` the last good probe was.
    pub fn last_good_age(&self, now: Instant) -> Duration {
        let last = Duration::from_nanos(self.last_good.load(Ordering::Relaxed));
        now.saturating_duration_since(self.origin)
            .saturating_sub(last)
    }

    fn is_stale_at(&self, at: Instant) -> bool {
        self.last_good_age(at) >= self.thresholds.stale_after
    }

    /// Record a peer view whose exchange started at `at`.
    ///
    /// The first view taken after this replica went stale becomes the
    /// baseline. A later view counts a peer as progressing only if it has the
    /// same incarnation as in the baseline, a higher count, and that count
    /// was accepted after the view the baseline holds for it, and within
    /// [`PROGRESS_WINDOW`] of this view. A peer that is
    /// new, restarted (another incarnation) or reappears after a gap gets a
    /// fresh baseline entry from this view. A peer absent from this view is
    /// dropped from the baseline.
    pub fn note_peers(&self, at: Instant, view: &StagePeerLiveness) {
        // A drain row is never a K11 peer: its count never rises, and its
        // stage is the reference, not a web replica's evidence.
        let stage_peers: Vec<&StagePeerProgress> = view
            .peers
            .iter()
            .filter(|peer| peer.role == StageLivenessRole::Stage)
            .collect();
        let epoch = self.last_good.load(Ordering::Relaxed);
        let after_stale = self.is_stale_at(at);
        let mut state = lock(&self.peers);
        let mut progressing = 0;
        let window_start = view.db_clock_micros.saturating_sub(
            i64::try_from(self.thresholds.progress_window.as_micros()).unwrap_or(i64::MAX),
        );
        if !after_stale {
            state.baseline = None;
        } else {
            let entry = |record: &StageProgressRecord| PeerBaseline {
                incarnation: record.incarnation.clone(),
                progress: record.progress,
                after_micros: view.db_clock_micros,
            };
            match state.baseline.as_mut() {
                Some(baseline) if baseline.epoch == epoch => {
                    let mut next = HashMap::with_capacity(stage_peers.len());
                    for peer in &stage_peers {
                        let record = &peer.record;
                        let kept = match baseline.peers.remove(&peer.replica_id) {
                            Some(base) if base.incarnation == record.incarnation => {
                                if record.progress > base.progress
                                    && record.progressed_micros > base.after_micros
                                    && record.progressed_micros > window_start
                                {
                                    progressing += 1;
                                }
                                base
                            }
                            _ => entry(record),
                        };
                        next.insert(peer.replica_id.clone(), kept);
                    }
                    baseline.peers = next;
                }
                _ => {
                    state.baseline = Some(Baseline {
                        epoch,
                        peers: stage_peers
                            .iter()
                            .map(|peer| (peer.replica_id.clone(), entry(&peer.record)))
                            .collect(),
                    });
                }
            }
        }
        state.latest = Some(LatestView {
            at,
            epoch,
            after_stale,
            peers: u64::try_from(stage_peers.len()).unwrap_or(u64::MAX),
            progressing,
        });
    }

    /// The peer evidence at `now`.
    pub fn peer_evidence(&self, now: Instant) -> PeerEvidence {
        let Some(latest) = lock(&self.peers).latest else {
            return PeerEvidence::Unknown;
        };
        if now.saturating_duration_since(latest.at) >= self.thresholds.peer_view_max_age
            || !latest.after_stale
            || latest.epoch != self.last_good.load(Ordering::Relaxed)
        {
            return PeerEvidence::Unknown;
        }
        if latest.progressing > 0 {
            PeerEvidence::ProgressingPeer
        } else {
            PeerEvidence::NoProgress
        }
    }

    /// Compare this replica's row as the exchange found it with what this
    /// process last wrote. A difference means another process publishes
    /// under the same `replica_id`, and its progress can hide this replica's
    /// stale mount (or the reverse). Warns, at most every [`WARN_EVERY`].
    pub fn note_publication(&self, now: Instant, view: &StagePeerLiveness) {
        let mut last = lock(&self.last_published);
        if let (Some(mine), Some(found)) = (last.as_ref(), view.prior.as_ref())
            && mine != found
        {
            let mut warned = lock(&self.duplicate_warned);
            let logged_at = warned
                .as_ref()
                .map(|(at, _, _)| *at)
                .filter(|at| now.saturating_duration_since(*at) < WARN_EVERY);
            let due = logged_at.is_none();
            *warned = Some((logged_at.unwrap_or(now), mine.clone(), found.clone()));
            if due {
                warn!(
                    replica_id = %self.replica_id,
                    last_published = ?mine,
                    found = ?found,
                    "another process publishes stage liveness under this replica id; \
                     give each replica a distinct id"
                );
            }
        }
        *last = view.published.clone();
    }

    /// The last duplicate-identity sighting, as (what this process last
    /// published, what the exchange found), or `None`.
    pub fn duplicate_identity_seen(&self) -> Option<(StageProgressRecord, StageProgressRecord)> {
        lock(&self.duplicate_warned)
            .as_ref()
            .map(|(_, mine, found)| (mine.clone(), found.clone()))
    }

    /// Forget what this process last wrote: a failed exchange may still have
    /// committed, so the next comparison would be a false alarm.
    fn forget_publication(&self) {
        *lock(&self.last_published) = None;
    }

    fn note_clock(&self, db_micros: i64, received: Instant) {
        *lock(&self.clock) = Some(StageLivenessClock {
            db_micros,
            received,
        });
    }

    /// The `/lb_health` fault at `now`, or `None`. A shared-stage fault comes
    /// first: a replica on the wrong stage must not serve even if its own
    /// probe is fine.
    pub fn fault(&self, now: Instant) -> Option<&'static str> {
        if self.role != StageLivenessRole::Stage {
            // The drain answers `drain_role` on `/lb_health` anyway; it has no
            // own K11 verdict and is never held. Its one fault is an anchor it
            // cannot verify, for `/health_check`.
            return (!self.anchor_verified(now)).then_some(STAGE_ANCHOR_UNVERIFIED);
        }
        self.share_fault(now)
            .or_else(|| decide(self.is_stale_at(now), self.peer_evidence(now)))
    }

    /// The shared-stage part of [`Self::fault`]. `None` when the guard is off.
    pub fn share_fault(&self, now: Instant) -> Option<&'static str> {
        if !self.share_guard {
            return None;
        }
        self.share_verdict(now).fault()
    }

    /// Probe threads started so far.
    pub fn threads_started(&self) -> usize {
        self.threads_started.load(Ordering::Relaxed)
    }

    /// Probes started so far.
    pub fn probes_started(&self) -> u64 {
        self.probes_started.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self, now: Instant) -> StageLivenessSnapshot {
        let latest = lock(&self.peers).latest;
        let (share, share_unconfirmed) = if self.share_guard {
            let stuck = self.step_stuck(now);
            let state = lock(&self.share);
            (
                Some(
                    state
                        .verdict(now, self.thresholds.share_grace, self.origin, stuck)
                        .name(),
                ),
                state.unconfirmed().map(|(id, _)| id.clone()).collect(),
            )
        } else {
            (None, Vec::new())
        };
        let (absence, absence_unconfirmed, absence_confirmed, absence_counts) =
            if self.role == StageLivenessRole::Drain || self.absence_counts.get().is_some() {
                let challenged = lock(&self.challenge).current.is_some();
                let state = lock(&self.guard);
                (
                    Some(if challenged {
                        "guarded"
                    } else {
                        ABSENCE_NO_CHALLENGE
                    }),
                    state
                        .unconfirmed()
                        .map(|stager| stager.replica_id.clone())
                        .collect(),
                    Some(u64::try_from(state.confirmed.len()).unwrap_or(u64::MAX)),
                    self.absence_counts
                        .get()
                        .map(|counts| AbsenceCounts::from(counts.snapshot())),
                )
            } else {
                (None, Vec::new(), None, None)
            };
        StageLivenessSnapshot {
            share,
            share_unconfirmed,
            absence,
            absence_unconfirmed,
            absence_confirmed,
            absence_counts,
            replica_id: self.replica_id.clone(),
            incarnation: self.incarnation.clone(),
            progress: self.progress(),
            probe_age_millis: millis(self.last_good_age(now)),
            probe_in_flight: self.in_flight.load(Ordering::Relaxed),
            probe_failures: self.probe_failures.load(Ordering::Relaxed),
            peer_view_age_millis: latest.map(|view| millis(now.saturating_duration_since(view.at))),
            progressing_peers: latest.map(|view| view.progressing),
            peers: latest.map(|view| view.peers),
            fault: self.fault(now),
        }
    }

    /// Record the verdict in the gauges, and log a transition once.
    pub fn report(&self, now: Instant) {
        let snapshot = self.snapshot(now);
        if self.role != StageLivenessRole::Stage {
            self.report_anchor(now, &snapshot);
            self.report_absence(now, &snapshot);
            return;
        }
        instruments()
            .ejected
            .record(u64::from(snapshot.fault.is_some()), &[]);
        // The transition log below is K11's own; the share guard logs its
        // own transitions in `report_share`.
        let ejected = decide(self.is_stale_at(now), self.peer_evidence(now)).is_some();
        instruments()
            .probe_age
            .record(snapshot.probe_age_millis / 1000, &[]);
        if let Some(progressing) = snapshot.progressing_peers {
            instruments().progressing_peers.record(progressing, &[]);
        }
        if self.share_guard {
            self.report_share(now, &snapshot);
        }
        // A web stage replica with the absence guard is a reader too: the
        // same local gauges and state log as the drain (review S3, round 3).
        if self.absence_counts.get().is_some() {
            self.report_absence(now, &snapshot);
        }
        if self.ejected.swap(ejected, Ordering::Relaxed) != ejected {
            if ejected {
                warn!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    probe_in_flight = snapshot.probe_in_flight,
                    progressing_peers = snapshot.progressing_peers,
                    peers = snapshot.peers,
                    "stage mount is stale here while a peer keeps writing it; /lb_health answers stage_unavailable_local"
                );
            } else {
                info!(
                    replica_id = %snapshot.replica_id,
                    probe_age_millis = snapshot.probe_age_millis,
                    progressing_peers = snapshot.progressing_peers,
                    "stage liveness no longer ejects this replica"
                );
            }
        }
    }

    /// The drain worker's anchor gauge, and one log line per change.
    fn report_anchor(&self, now: Instant, snapshot: &StageLivenessSnapshot) {
        let verified = self.anchor_verified(now);
        instruments()
            .share_anchor_unverified
            .record(u64::from(!verified), &[]);
        let mut reported = lock(&self.anchor_reported);
        if *reported == Some(verified) {
            return;
        }
        let first = reported.is_none();
        *reported = Some(verified);
        if !verified {
            error!(
                replica_id = %snapshot.replica_id,
                "the drain cannot read back its own stage marker; it publishes \
                 drain_unverified and anchors no web replica, so unproven web replicas \
                 write directly. Check the stage mount on this host"
            );
        } else if !first {
            info!(
                replica_id = %snapshot.replica_id,
                "the drain reads back its own stage marker again; it anchors the shared-stage check"
            );
        }
    }

    /// A reader's drain guard gauges (the drain, or a web stage replica with
    /// the guard), one log line per change, and one error line when
    /// something has been unproven for [`SHARE_GRACE`]. Unproven at boot (no
    /// view or marker step yet) is logged at info: a healthy cell leaves it
    /// within a few exchanges. Returns the log line it wrote. The gauges are
    /// this process's own; nothing exports them to Lorehub.
    #[lore_macro::test_pub]
    pub(crate) fn report_absence(
        &self,
        now: Instant,
        snapshot: &StageLivenessSnapshot,
    ) -> AbsenceLog {
        let held = self.absence_unproven();
        instruments()
            .share_absence_unproven
            .record(u64::from(held), &[]);
        if let Some(counts) = snapshot.absence_counts {
            instruments().drain_absence_kept.record(counts.kept(), &[]);
        }
        let unconfirmed = &snapshot.absence_unconfirmed;
        let mut reported = lock(&self.absence_reported);
        let logged = match reported.as_mut() {
            Some(report) if report.held == held => {
                if held
                    && !report.escalated
                    && now.saturating_duration_since(report.since) >= self.thresholds.share_grace
                {
                    report.escalated = true;
                    error!(
                        replica_id = %snapshot.replica_id,
                        role = self.role.as_str(),
                        ?unconfirmed,
                        "this reader has not confirmed every web stage replica in its own stage \
                         for a long time; a staged file such a replica wrote that this reader \
                         cannot find is retried, never marked Missing. Check the stage mount on \
                         this host and on the listed web hosts"
                    );
                    return AbsenceLog::Escalated;
                }
                return AbsenceLog::None;
            }
            Some(_) if held => {
                warn!(
                    replica_id = %snapshot.replica_id,
                    role = self.role.as_str(),
                    ?unconfirmed,
                    "this reader has a web stage replica it has not confirmed in its own stage; \
                     a staged file that replica wrote that this reader cannot find is retried, \
                     never marked Missing"
                );
                AbsenceLog::Held
            }
            Some(_) => {
                info!(
                    replica_id = %snapshot.replica_id,
                    role = self.role.as_str(),
                    "this reader has confirmed every fresh web stage replica in its view in its \
                     own stage"
                );
                AbsenceLog::Proven
            }
            None if held => {
                info!(
                    replica_id = %snapshot.replica_id,
                    role = self.role.as_str(),
                    "until this reader confirms a web stage replica in its own stage, a staged \
                     file that replica wrote that this reader cannot find is retried, never \
                     marked Missing"
                );
                AbsenceLog::StartHeld
            }
            None => AbsenceLog::None,
        };
        *reported = Some(AbsenceReport {
            held,
            since: now,
            escalated: false,
        });
        logged
    }

    /// The share gauge and one log line per share verdict change.
    fn report_share(&self, now: Instant, snapshot: &StageLivenessSnapshot) {
        let verdict = self.share_verdict(now);
        instruments()
            .share_unproven
            .record(u64::from(verdict.holds_staging()), &[]);
        instruments()
            .share_undecided
            .record(u64::from(verdict == ShareVerdict::Undecided), &[]);
        let mut reported = lock(&self.share_reported);
        if *reported == Some(verdict) {
            return;
        }
        *reported = Some(verdict);
        let unconfirmed = &snapshot.share_unconfirmed;
        match verdict {
            ShareVerdict::Pending => {}
            ShareVerdict::PendingTooLong => error!(
                replica_id = %snapshot.replica_id,
                "no stage liveness exchange has succeeded since boot; staging is off and \
                 /lb_health answers stage_share_pending. Check this host's Postgres access"
            ),
            ShareVerdict::NoAnchor => info!(
                replica_id = %snapshot.replica_id,
                "no fresh drain row proves this stage is the drain's; staging is off and new \
                 fragments are written directly until the drain's marker is seen"
            ),
            ShareVerdict::Shared => info!(
                replica_id = %snapshot.replica_id,
                "the drain's stage marker is visible; staging is open"
            ),
            ShareVerdict::Unverified => warn!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "the drain's stage marker is not visible yet; staging is off and \
                 /lb_health answers stage_share_unverified"
            ),
            ShareVerdict::NotShared => error!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "this replica's stage is not the drain's stage; staging is off and \
                 /lb_health answers stage_not_shared. Check the stage mount on this host"
            ),
            ShareVerdict::Undecided => warn!(
                replica_id = %snapshot.replica_id,
                ?unconfirmed,
                "the drain's stage marker cannot be read here (an I/O error or a hung stage \
                 step); staging is off, new fragments are written directly, and /lb_health \
                 stays 200. Check the stage mount on this host"
            ),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// At most one warning per `every`.
#[derive(Default)]
struct WarnEvery {
    last: Option<Instant>,
}

impl WarnEvery {
    fn allow(&mut self, now: Instant, every: Duration) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < every)
        {
            return false;
        }
        self.last = Some(now);
        true
    }
}

/// Start the one probe thread for `liveness`. A second call starts nothing.
///
/// The thread runs `probe` every `interval` until `stop` is set. A probe that
/// never returns keeps the thread, and so all probing, parked in it: the
/// replica then ages to stale, which is the signal. Nothing replaces the
/// thread, so a hung mount costs exactly one thread.
pub fn spawn_probe_thread(
    liveness: &Arc<StageLiveness>,
    probe: ProbeFn,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    spawn_probe_thread_with_markers(liveness, probe, None, interval, stop)
}

/// [`spawn_probe_thread`], plus the shared-stage marker step after each
/// probe when `markers` is set. A hung probe parks the marker step too, so
/// nothing new is confirmed while the mount hangs. When the thread stops, it
/// removes this replica's own marker.
pub fn spawn_probe_thread_with_markers(
    liveness: &Arc<StageLiveness>,
    probe: ProbeFn,
    markers: Option<ShareMarkers>,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    if liveness
        .threads_started
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(false);
    }
    let liveness = liveness.clone();
    std::thread::Builder::new()
        .name("stage-liveness-probe".to_owned())
        .spawn(move || probe_loop(&liveness, &probe, markers.as_ref(), interval, &stop))
        .map(|_detached| true)
}

/// The drain worker's thread: keep this replica's marker and read it back,
/// every `interval`, and remove it at stop. A hung step stops the read-backs,
/// so the drain falls back to `drain_unverified` after
/// [`ANCHOR_VERIFY_MAX_AGE`]. It runs no probe and counts no progress, so the
/// drain's row never looks like K11 progress, even to an older binary.
pub fn spawn_marker_thread(
    liveness: &Arc<StageLiveness>,
    markers: ShareMarkers,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<bool> {
    if liveness
        .threads_started
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(false);
    }
    let liveness = liveness.clone();
    std::thread::Builder::new()
        .name("stage-share-marker".to_owned())
        .spawn(move || marker_loop(&liveness, &markers, interval, &stop))
        .map(|_detached| true)
}

fn marker_loop(
    liveness: &StageLiveness,
    markers: &ShareMarkers,
    interval: Duration,
    stop: &AtomicBool,
) {
    let mut warn_every = WarnEvery::default();
    while !stop.load(Ordering::Relaxed) {
        // Write the marker and read it back: the drain publishes `drain` only
        // while the read-back shows its incarnation.
        if let Err(error) = liveness.share_step(markers)
            && warn_every.allow(Instant::now(), WARN_EVERY)
        {
            warn!(%error, "stage share marker could not be written");
        }
        let wake = Instant::now() + interval;
        while !stop.load(Ordering::Relaxed) {
            let left = wake.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    if let Err(error) = markers.remove_if(liveness.replica_id(), liveness.incarnation()) {
        warn!(%error, "stage share marker could not be removed at stop");
    }
    if let Err(error) = markers.remove_challenge_if(liveness.replica_id(), liveness.incarnation()) {
        warn!(%error, "stage challenge file could not be removed at stop");
    }
}

fn probe_loop(
    liveness: &StageLiveness,
    probe: &ProbeFn,
    markers: Option<&ShareMarkers>,
    interval: Duration,
    stop: &AtomicBool,
) {
    let mut warn_every = WarnEvery::default();
    let mut marker_warn_every = WarnEvery::default();
    while !stop.load(Ordering::Relaxed) {
        // The step (probe plus marker reads) is timed: one that hangs makes
        // the shared-stage check "cannot decide" (module docs, step 6).
        liveness.note_step(Some(Instant::now()));
        liveness.probes_started.fetch_add(1, Ordering::Relaxed);
        liveness.in_flight.store(true, Ordering::Relaxed);
        let result = probe();
        liveness.in_flight.store(false, Ordering::Relaxed);
        let now = Instant::now();
        match result {
            Ok(()) => liveness.note_good(now),
            Err(error) => {
                let failures = liveness.probe_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if warn_every.allow(now, WARN_EVERY) {
                    warn!(%error, failures, "stage liveness probe failed");
                }
            }
        }
        if let Some(markers) = markers
            && let Err(error) = liveness.share_step(markers)
            && marker_warn_every.allow(Instant::now(), WARN_EVERY)
        {
            warn!(%error, "stage share marker could not be written");
        }
        liveness.note_step(None);
        // Sleep in short steps so `stop` is seen promptly.
        let wake = Instant::now() + interval;
        while !stop.load(Ordering::Relaxed) {
            let left = wake.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }
    if let Some(markers) = markers {
        if let Err(error) = markers.remove_if(liveness.replica_id(), liveness.incarnation()) {
            warn!(%error, "stage share marker could not be removed at stop");
        }
        if let Err(error) =
            markers.remove_challenge_if(liveness.replica_id(), liveness.incarnation())
        {
            warn!(%error, "stage challenge file could not be removed at stop");
        }
        if let Err(error) = markers.remove_echo_if(liveness.replica_id(), liveness.incarnation()) {
            warn!(%error, "stage echo file could not be removed at stop");
        }
    }
}

/// What one tick of the exchange task did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessTick {
    /// Published and read peers.
    Exchanged,
    /// The exchange failed or timed out.
    ExchangeFailed,
    /// Draining: this tick deleted the row.
    Withdrew,
    /// Draining: the delete failed or timed out; the next tick retries.
    WithdrawFailed,
    /// Draining and already withdrawn: nothing to do.
    Withdrawn,
}

/// One tick of the exchange task.
///
/// A draining replica (lame duck or SIGTERM) never publishes again, so its
/// count stops moving and no peer can count it as progressing. It also
/// deletes its row once, so it leaves the peers' baselines.
pub async fn liveness_tick<X, XFut, W, WFut, E>(
    liveness: &StageLiveness,
    draining: bool,
    withdrawn: &mut bool,
    exchange: X,
    withdraw: W,
    timeout: Duration,
    warn_every: &mut Option<Instant>,
) -> LivenessTick
where
    X: FnOnce(StageLivenessPublication) -> XFut,
    XFut: std::future::Future<Output = Result<StagePeerLiveness, E>>,
    W: FnOnce() -> WFut,
    WFut: std::future::Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
{
    if !draining {
        return if exchange_once(liveness, exchange, timeout, warn_every).await {
            LivenessTick::Exchanged
        } else {
            LivenessTick::ExchangeFailed
        };
    }
    if *withdrawn {
        return LivenessTick::Withdrawn;
    }
    match tokio::time::timeout(timeout, withdraw()).await {
        Ok(Ok(_deleted)) => {
            *withdrawn = true;
            info!(
                replica_id = %liveness.replica_id(),
                "stage liveness withdrawn for drain; peers no longer count this replica"
            );
            LivenessTick::Withdrew
        }
        Ok(Err(error)) => {
            warn!(%error, "stage liveness withdraw failed; the next tick retries");
            LivenessTick::WithdrawFailed
        }
        Err(_elapsed) => {
            warn!("stage liveness withdraw timed out; the next tick retries");
            LivenessTick::WithdrawFailed
        }
    }
}

/// One exchange: publish, read peers, record the view. A failure or a timeout
/// records nothing, so the last view ages to [`PeerEvidence::Unknown`].
///
/// The view is recorded at the instant the exchange started: no later than
/// the read it reflects. The reply's database clock becomes the anchor for
/// the next publication's deadline.
///
/// Returns whether the exchange succeeded.
pub async fn exchange_once<F, Fut, E>(
    liveness: &StageLiveness,
    exchange: F,
    timeout: Duration,
    warn_every: &mut Option<Instant>,
) -> bool
where
    F: FnOnce(StageLivenessPublication) -> Fut,
    Fut: std::future::Future<Output = Result<StagePeerLiveness, E>>,
    E: std::fmt::Display,
{
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, exchange(liveness.publication())).await;
    let now = Instant::now();
    let warn = |message: String, warn_every: &mut Option<Instant>| {
        if warn_every.is_none_or(|last| now.saturating_duration_since(last) >= WARN_EVERY) {
            *warn_every = Some(now);
            warn!(error = %message, "stage liveness exchange failed; this signal cannot eject until it succeeds");
        }
    };
    match result {
        Ok(Ok(view)) => {
            liveness.note_clock(view.db_clock_micros, now);
            liveness.note_publication(now, &view);
            liveness.note_peers(started, &view);
            liveness.note_share(now, &view);
            true
        }
        Ok(Err(error)) => {
            liveness.forget_publication();
            warn(error.to_string(), warn_every);
            false
        }
        Err(_elapsed) => {
            liveness.forget_publication();
            warn(format!("timed out after {timeout:?}"), warn_every);
            false
        }
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031/WP-118 Phase 9 deterministic failpoints for the fragment coordinator.
//!
//! **This whole module is compiled out of every default build.** `mod.rs`
//! declares it under `#[cfg(feature = "failure_generator")]`, so in a default
//! build [`hit`] is not merely unreachable, it is *unnameable* — an edit in
//! `coordinator.rs` that tried to call it would be `E0433`, not a review catch.
//! The `failpoint!` macro's default-build arm expands to a typed `Ok`, so no
//! environment variable is read, no file is stat'd, and no anchor exists in a
//! shipped binary. See [`super::failpoints_compiled`] for the always-present
//! probe the cross-crate feature guard uses.
//!
//! # Why this exists
//!
//! WP-109 (shared-backend multi-instance proof) has to drive races between two
//! loreserver processes against one Postgres database and one bucket, and its
//! Phase 2 requires "deterministic barriers and failpoints, not task
//! scheduling". Task scheduling cannot produce a repeatable interleaving across
//! two OS processes; a barrier can.
//!
//! # The three windows
//!
//! Every mutating coordinator method has one shape: `checkout()` ->
//! `client.transaction()` -> `LockSequence` + row locks -> work ->
//! `classify_commit(tx.commit())`. That gives exactly three windows worth
//! naming, and they are the same three at every site:
//!
//! - `.entry` — before `checkout()`. Holds nothing. Lets two processes arrive
//!   at the same method together without either holding a database resource.
//! - `.locked` — the transaction is open and its rows are locked, and nothing
//!   is committed. This is the only window in which one process can be *made*
//!   to contend with another deterministically, and it is also "before COMMIT"
//!   for the kill tests. Placed once, immediately after the method's locks are
//!   taken, so it covers every exit past that point rather than needing one
//!   anchor per `tx.commit()` call (`begin_obliterate` alone has eight).
//! - `.settled` — the commit returned and the value has not yet gone back to
//!   the caller. This is "after COMMIT", and the only place a lost commit
//!   acknowledgement can be injected.
//!
//! `enable_lifecycle` is a single autocommit `UPDATE` rather than a
//! transaction, so its two anchors are `.pre_write`/`.post_write` instead.
//!
//! # Environment contract
//!
//! Read once, when the first anchor in this process is reached, and never
//! re-read — the same discipline as `lore-storage`'s `LORE_MISS_FRAGMENT_WRITES`.
//!
//! - `LORE_FRAGMENT_FAILPOINTS` — comma-separated `anchor=action`, for example
//!   `publication.commit.locked=pause,obliterate.payload.settled=abort`. An
//!   entry naming an unknown anchor or an unknown action is reported and
//!   dropped rather than being fatal, so a stale harness config degrades to
//!   "no failpoint" instead of refusing to boot.
//! - `LORE_FRAGMENT_FAILPOINT_DIR` — the rendezvous directory `pause` uses.
//!   A `pause` configured with no directory is a no-op, so a half-configured
//!   harness cannot wedge a server.
//!
//! # How a `pause` rendezvous works
//!
//! WP-109 Phase 3 races two *processes*, so an in-process signal cannot line
//! them up and a second pooled connection taking `pg_advisory_lock` would
//! acquire a database resource inside the very window being instrumented. The
//! rendezvous is therefore a filesystem gate, which takes no database resource
//! and needs no new dependency:
//!
//! 1. the harness creates `<dir>/<anchor>.hold` **before** starting operation A;
//! 2. process A reaches the anchor, writes `<dir>/<anchor>.reached` with its
//!    pid, and blocks while the hold file exists;
//! 3. the harness waits for `.reached`, then runs operation B and observes it
//!    contending against A's held locks;
//! 4. the harness deletes `.hold`; A proceeds and removes `.reached`.
//!
//! A pause gives up after [`PAUSE_CEILING`] and proceeds, so a mis-driven test
//! times out visibly instead of pinning a pool connection for the life of the
//! process.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use crate::domain::errors::DomainError;

/// How long a `pause` waits for its hold file to disappear before giving up and
/// proceeding. A barrier that never releases must fail as a visible timeout,
/// not as a hung connection.
pub(crate) const PAUSE_CEILING: Duration = Duration::from_secs(60);

/// Poll interval for the rendezvous file. Short enough that a barrier does not
/// materially widen the window it is measuring.
const PAUSE_POLL: Duration = Duration::from_millis(5);

/// Every anchor the coordinator can hit, with the WP-109 race each one exists
/// to serve.
///
/// The set is **derived from WP-109's written race lists**
/// (`lorehub/docs/work-packages/wp-109-shared-backend-multi-instance-proof.md`,
/// Phase 2 at `:157-171` and Phase 3 at `:180-196`), not invented. WP-109 is
/// `Planned` and unowned, so these will sit unexercised for a while: this table
/// is what lets a later reader tell "derived and waiting for its harness" from
/// "left over". An anchor with no entry here is not reachable through
/// [`hit`] — the configuration parser drops it.
const ANCHORS: &[(&str, &str)] = &[
    // ---- publication ---------------------------------------------------
    (
        "publication.begin.entry",
        "P2 fragment put: line two processes up on one hash before either takes a lock",
    ),
    (
        "publication.begin.locked",
        "P2 fragment put: two processes racing one hash into Preparing*, and the dedup \
         short-circuit that must win over a second admission",
    ),
    (
        "publication.begin.settled",
        "P3 kill after COMMIT: an intent and write claim exist but no bytes were sent, so \
         restart must recover from the claim rather than from the head alone",
    ),
    (
        "publication.commit.locked",
        "P2 push/push and every lifecycle crash point; P3 process kill before COMMIT",
    ),
    (
        "publication.commit.settled",
        "P3 process kill after COMMIT, and P2 commit-acknowledgement loss (see the `unknown` \
         action) with its outcome-unknown reconciliation read",
    ),
    (
        "promotion.begin.locked",
        "P2 fragment copy/repair: a Staged->Remote promotion against a concurrent push that \
         requires the same hash at its staged epoch",
    ),
    (
        "promotion.begin.settled",
        "P3 kill after COMMIT with a new remote epoch allocated and the staged predecessor \
         quarantined but not yet uploaded",
    ),
    (
        "lifecycle.mark_missing.locked",
        "P2 fragment repair: a readable->Missing transition against a concurrent read or \
         association bind on the same hash",
    ),
    (
        "lifecycle.mark_missing.settled",
        "P3 kill after COMMIT with the head demoted and the lifecycle generation moved",
    ),
    // ---- associations ----------------------------------------------------
    (
        "association.create.entry",
        "P2 association race: line two processes up on one (hash, repository, context)",
    ),
    (
        "association.create.locked",
        "P2 association race, and push/obliterate ordering when the bind and the obliterate \
         request reach the same repository row together",
    ),
    (
        "association.create.settled",
        "P3 kill after COMMIT with the association live and the repository association \
         scalar moved",
    ),
    (
        "association.create_guarded.locked",
        "P2 fragment copy/dedup: the guarded bind against a concurrent obliterate or \
         mark-missing that moves the witnessed head under it",
    ),
    (
        "association.create_guarded.settled",
        "P3 kill after COMMIT on the copy/dedup publication path",
    ),
    (
        "association.tombstone.entry",
        "P2 push/delete: line a retire up against a concurrent bind of the same association",
    ),
    (
        "association.tombstone.locked",
        "P2 push/delete, and the transfer of obliterate ownership when this is the last live \
         association",
    ),
    (
        "association.tombstone.settled",
        "P3 kill after COMMIT with the association retired and ownership transferred",
    ),
    // ---- obliterate ------------------------------------------------------
    (
        "obliterate.begin.entry",
        "P2 push/obliterate and obliterate/obliterate: line two deletions up on one hash",
    ),
    (
        "obliterate.begin.locked",
        "P2 push/obliterate: the exact-association ownership claim against a concurrent \
         publication or bind on the same fanout",
    ),
    (
        "obliterate.begin.settled",
        "P3 kill after COMMIT with DeletingChildren published and no cleanup performed",
    ),
    (
        "obliterate.children.locked",
        "P2 obliterate lifecycle crash point: DeletingChildren against a concurrent reader \
         lease over the same hash",
    ),
    (
        "obliterate.children.settled",
        "P3 kill after COMMIT between DeletingChildren and DeletingPayload",
    ),
    (
        "obliterate.payload.locked",
        "P2 obliterate: Tombstoned publication against a concurrent staged reader lease, and \
         the decisive-cleanup-proof requirement",
    ),
    (
        "obliterate.payload.settled",
        "P3 kill after COMMIT with Tombstoned published",
    ),
    // ---- write claims ----------------------------------------------------
    (
        "claim.authorize.locked",
        "P2 'stale uploads cannot publish': the lineage/fence check against a concurrent \
         obliterate or repair that moves the head under an authorized send",
    ),
    (
        "claim.authorize.settled",
        "P3 kill after COMMIT with a claim in Sending and no upload issued",
    ),
    (
        "claim.settle.locked",
        "P2 stale claim completion and duplicate counting against a concurrent settlement",
    ),
    (
        "claim.settle.settled",
        "P2 commit-acknowledgement loss: the Ambiguous-claim reconciliation read (use the \
         `unknown` action here)",
    ),
    // ---- metering --------------------------------------------------------
    (
        "metering.rebuild.locked",
        "P2 fragment metering: the rebuild's lifecycle EXCLUSIVE table lock against a \
         concurrent publication, proving the Phase 6 lock order rather than asserting it",
    ),
    (
        "metering.rebuild.settled",
        "P3 kill after COMMIT with the projection rebuilt",
    ),
    // ---- staged reader leases -------------------------------------------
    (
        "lease.acquire.locked",
        "P2 fragment get: a lease acquisition against a concurrent obliterate, which is the \
         race lock_lease_member_heads was added to close",
    ),
    (
        "lease.acquire.settled",
        "P3 kill after COMMIT with a lease granted and no reader attached",
    ),
    // ---- backfill cursor -------------------------------------------------
    //
    // Read the method's own documentation before reading these three as
    // progress. They instrument a cursor mechanism built so WP-109's schema
    // backfill race has a site; this is not Phase 8, which remains stopped on
    // a real staging cell. Each description repeats that because an anchor
    // table is read in isolation, which is exactly when the wrong inference
    // gets made.
    (
        "backfill.advance.entry",
        "P2 schema backfill: line two replicas up on one durable cursor before either locks \
         the schema-state row. This is not Phase 8, which remains stopped on a staging cell",
    ),
    (
        "backfill.advance.locked",
        "P2 schema backfill: the FOR UPDATE on the singleton cursor row, which serialises two \
         replicas rather than excluding one. Both advance, in turn, each resuming from the \
         position the other committed. This is not Phase 8, which remains stopped on a \
         staging cell",
    ),
    (
        "backfill.advance.settled",
        "P3 restart: the cursor advanced and the caller has not seen it, so restart must \
         resume from the durable position rather than rescan. This is not Phase 8, which \
         remains stopped on a staging cell",
    ),
    // ---- cutover ---------------------------------------------------------
    (
        "cutover.require_claims.locked",
        "P2 cutover marker: the write-claims-v1 requirement against a concurrent publication \
         from a replica that has not seen it",
    ),
    (
        "cutover.require_claims.settled",
        "P2 mixed-version refusal: the window in which one replica has the marker and the \
         other has not yet read it",
    ),
    (
        "cutover.enable_lifecycle.pre_write",
        "P2 schema/readiness refusal: readiness passed and the enable has not landed",
    ),
    (
        "cutover.enable_lifecycle.post_write",
        "P3 restart: lifecycle routing enabled, against a concurrent boot readiness check",
    ),
];

/// What a configured anchor does when reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// Block until the harness releases the rendezvous. The barrier.
    Pause,
    /// `std::process::abort()`. Serves WP-109 Phase 3's "process kill before
    /// and after COMMIT" without the harness having to win a `taskkill` race
    /// against a window measured in microseconds.
    Abort,
    /// Return [`DomainError::OutcomeUnknown`] from a commit that actually
    /// succeeded — WP-109's "commit-acknowledgement loss". Accepted **only** on
    /// a `.settled`/`.post_write` anchor: before the commit there is no
    /// unknown outcome to report, so configuring it earlier would inject a lie
    /// rather than a race.
    Unknown,
}

impl Action {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "pause" => Some(Self::Pause),
            "abort" => Some(Self::Abort),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Whether an anchor names a window that is past its commit, and so can carry
/// [`Action::Unknown`].
fn is_post_commit(anchor: &str) -> bool {
    anchor.ends_with(".settled") || anchor.ends_with(".post_write")
}

struct Config {
    actions: HashMap<&'static str, Action>,
    dir: Option<PathBuf>,
}

impl Config {
    fn load() -> Self {
        let dir = std::env::var("LORE_FRAGMENT_FAILPOINT_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        Self::from_parts(
            std::env::var("LORE_FRAGMENT_FAILPOINTS").ok().as_deref(),
            dir,
        )
    }

    /// The parser, separated from the environment so it can be tested.
    ///
    /// [`Self::load`] is the only caller that touches `std::env`, and it does
    /// nothing but read the two variables. Everything that can be got wrong —
    /// the malformed-entry drop, the unknown-anchor drop, and above all the
    /// refusal of `unknown` on a pre-commit anchor — lives here, where a test
    /// can reach it without a `LazyLock` and a process-global environment.
    fn from_parts(spec: Option<&str>, dir: Option<PathBuf>) -> Self {
        let mut actions = HashMap::new();
        let Some(spec) = spec else {
            return Self { actions, dir };
        };
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let Some((name, action)) = entry.split_once('=') else {
                tracing::warn!(entry, "fragment failpoint entry is not `anchor=action`");
                continue;
            };
            let name = name.trim();
            // Resolve against the table rather than storing the caller's
            // string, so a typo is dropped here instead of silently never
            // matching, and so the map key is the same `&'static str` the call
            // site passes.
            let Some((anchor, _)) = ANCHORS.iter().find(|(anchor, _)| *anchor == name) else {
                tracing::warn!(name, "unknown fragment failpoint anchor; entry ignored");
                continue;
            };
            let Some(action) = Action::parse(action.trim()) else {
                tracing::warn!(
                    anchor,
                    action = action.trim(),
                    "unknown fragment failpoint action; entry ignored"
                );
                continue;
            };
            if action == Action::Unknown && !is_post_commit(anchor) {
                tracing::warn!(
                    anchor,
                    "the `unknown` action needs a post-commit anchor; entry ignored"
                );
                continue;
            }
            actions.insert(*anchor, action);
        }
        if !actions.is_empty() {
            tracing::warn!(
                count = actions.len(),
                "fragment failpoints are ARMED; this build carries the failure_generator feature \
                 and must not be a production binary"
            );
        }
        Self { actions, dir }
    }
}

static CONFIG: LazyLock<Config> = LazyLock::new(Config::load);

/// Reach a named failpoint.
///
/// Returns `Ok(())` for every anchor that is not configured, which is every
/// anchor unless `LORE_FRAGMENT_FAILPOINTS` names it — so even a
/// `failure_generator` build with no environment set behaves exactly like a
/// default build.
pub(crate) async fn hit(anchor: &'static str) -> Result<(), DomainError> {
    debug_assert!(
        ANCHORS.iter().any(|(known, _)| *known == anchor),
        "fragment failpoint anchor is not in the ANCHORS table: {anchor}"
    );
    hit_with(&CONFIG, anchor, PAUSE_CEILING).await
}

/// [`hit`] against an explicit configuration and ceiling, so the dispatch can be
/// tested without the process-global `CONFIG` and without a 60-second wait.
async fn hit_with(config: &Config, anchor: &str, ceiling: Duration) -> Result<(), DomainError> {
    let Some(action) = config.actions.get(anchor).copied() else {
        return Ok(());
    };
    match action {
        Action::Pause => {
            pause_with(config, anchor, ceiling).await;
            Ok(())
        }
        Action::Abort => {
            // `abort` skips destructors and unwinding by design — that is what
            // makes it a faithful stand-in for a killed process. Announce on
            // stderr as well as through tracing, because a tracing subscriber
            // may still be holding the line in a buffer when the process dies.
            tracing::error!(anchor, "fragment failpoint aborting this process");
            eprintln!("fragment failpoint {anchor}: aborting this process");
            std::process::abort();
        }
        Action::Unknown => Err(DomainError::OutcomeUnknown(format!(
            "fragment failpoint {anchor} withheld a successful commit acknowledgement"
        ))),
    }
}

/// Whether a rendezvous probe means "the harness is still holding this anchor".
///
/// **An IO error counts as still held, and that asymmetry is the whole point.**
/// `Path::exists()` folds every error into `false`, so a transient failure
/// inside the wait loop would end the barrier early — *after* `.reached` was
/// written, so the harness would go on believing its barrier was held and would
/// report a race it never ran. A barrier that fails open is worse than one that
/// fails closed, because only the second is visible: an anchor stuck held hits
/// the ceiling and says so.
fn still_held(probe: std::io::Result<bool>) -> bool {
    probe.unwrap_or(true)
}

/// Whether a rendezvous probe means "the harness armed this anchor before the
/// operation started".
///
/// **The opposite polarity to [`still_held`], deliberately, and the two are not
/// interchangeable.** Nothing has been announced at the entry check, so an IO
/// error that proceeds loses no evidence — and the harness, which waits for
/// `.reached`, times out visibly rather than believing a barrier it does not
/// have. Treating an entry error as *armed* would be worse: it would block an
/// anchor the harness never armed, on a filesystem hiccup, for the ceiling.
///
/// An edit "harmonising" this with [`still_held`] is caught by
/// `an_io_error_at_the_entry_check_leaves_the_anchor_unarmed` and
/// `the_entry_check_announces_no_arrival_on_an_io_error`.
fn armed_at_entry(probe: std::io::Result<bool>) -> bool {
    probe.unwrap_or(false)
}

/// Block at `anchor` while the harness holds the rendezvous file.
///
/// The `try_exists()` stat is a blocking filesystem call on an async task. That
/// is acceptable here and only here: this code cannot exist in a default build,
/// the call is a single sub-millisecond `stat`, and the alternative — spawning
/// a blocking task — would add a task-scheduling dependency to the one
/// mechanism WP-109 asked for *because* it must not depend on task scheduling.
async fn pause_with(config: &Config, anchor: &str, ceiling: Duration) {
    let Some(dir) = config.dir.as_ref() else {
        tracing::warn!(
            anchor,
            "fragment failpoint pause has no LORE_FRAGMENT_FAILPOINT_DIR; proceeding"
        );
        return;
    };
    let hold = dir.join(format!("{anchor}.hold"));
    let reached = dir.join(format!("{anchor}.reached"));
    pause_at(anchor, ceiling, &reached, || hold.try_exists()).await;
}

/// The rendezvous itself, over an injected probe and an explicit arrival-marker
/// path, so both polarity decisions are reachable from a test without having to
/// manufacture a filesystem failure.
///
/// The harness must arm the hold file before starting the operation. Arriving at
/// an unarmed pause is not an error: it is how a case that arms only some of its
/// anchors runs the rest at full speed.
async fn pause_at<P>(anchor: &str, ceiling: Duration, reached: &std::path::Path, mut probe: P)
where
    P: FnMut() -> std::io::Result<bool>,
{
    if !armed_at_entry(probe()) {
        return;
    }
    if let Err(error) = std::fs::write(reached, std::process::id().to_string()) {
        tracing::warn!(
            anchor,
            ?error,
            "could not write the fragment failpoint arrival marker"
        );
    }
    tracing::warn!(anchor, "fragment failpoint paused");
    wait_while_held(anchor, ceiling, probe).await;
    let _ = std::fs::remove_file(reached);
    tracing::warn!(anchor, "fragment failpoint released");
}

/// The wait loop, over an injected probe so the error branch is reachable from a
/// test without having to manufacture a filesystem failure.
async fn wait_while_held<P>(anchor: &str, ceiling: Duration, mut probe: P)
where
    P: FnMut() -> std::io::Result<bool>,
{
    let started = Instant::now();
    while still_held(probe()) {
        if started.elapsed() >= ceiling {
            tracing::error!(
                anchor,
                ceiling_millis = ceiling.as_millis(),
                "fragment failpoint pause hit its ceiling and is proceeding; the harness never \
                 released the hold file"
            );
            break;
        }
        tokio::time::sleep(PAUSE_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_anchor_names_one_of_the_four_windows() {
        for (anchor, _) in ANCHORS {
            assert!(
                anchor.ends_with(".entry")
                    || anchor.ends_with(".locked")
                    || anchor.ends_with(".settled")
                    || anchor.ends_with(".pre_write")
                    || anchor.ends_with(".post_write"),
                "{anchor} does not name one of the documented windows"
            );
        }
    }

    #[test]
    fn every_anchor_is_unique_and_carries_its_wp109_race() {
        let mut seen = std::collections::HashSet::new();
        for (anchor, race) in ANCHORS {
            assert!(seen.insert(*anchor), "duplicate anchor {anchor}");
            assert!(
                !race.trim().is_empty(),
                "{anchor} has no WP-109 race recorded; an anchor nothing exercises must be \
                 visibly unused for a named reason, not mystery surface"
            );
        }
    }

    #[test]
    fn the_unknown_action_is_refused_before_a_commit() {
        assert!(is_post_commit("publication.commit.settled"));
        assert!(is_post_commit("cutover.enable_lifecycle.post_write"));
        assert!(!is_post_commit("publication.commit.locked"));
        assert!(!is_post_commit("publication.begin.entry"));
        assert!(!is_post_commit("cutover.enable_lifecycle.pre_write"));
    }

    /// Every `.rs` file under `lore-postgres/src/`, recursively.
    ///
    /// The scan must cover the whole crate, not just `coordinator.rs`:
    /// `mod.rs` does `pub(crate) use failpoint;`, so the macro is callable from
    /// any file in `lore-postgres`. A scan scoped to one file would let an
    /// anchor added anywhere else escape the table entirely.
    fn crate_source_files() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            let entries = std::fs::read_dir(dir).expect("src/ must be readable");
            for entry in entries {
                let path = entry.expect("a readable directory entry").path();
                if path.is_dir() {
                    walk(&path, found);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        found.sort();
        found
    }

    /// Drop comment text before scanning for call sites.
    ///
    /// Necessary, not cosmetic: `mod.rs`'s own doc comment shows the macro's
    /// usage as `failpoint!("anchor.name")`, and a doc comment is exactly where
    /// an example anchor gets written. Without this the scan reports a call site
    /// that does not exist.
    ///
    /// Whole-line `//` comments go, which covers every doc comment; a trailing
    /// `//` after real code is left alone because a call site sits before it.
    /// `/* */` regions go too, so a commented-out call site is not counted as
    /// live. Both directions here only ever remove text, so the worst case is a
    /// missed call site rather than a phantom one — and a missed call site is
    /// itself caught, because its anchor then has no caller and the table
    /// comparison fails.
    fn strip_comments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            match rest[start..].find("*/") {
                Some(end) => rest = &rest[start + end + 2..],
                None => {
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_scan_ignores_an_anchor_written_in_prose() {
        let code = "        failpoint!(\"real.anchor.locked\")?;";
        assert!(strip_comments(code).contains("real.anchor.locked"));
        assert!(
            !strip_comments("/// Call sites write `failpoint!(\"doc.example.locked\")?;`")
                .contains("doc.example.locked"),
            "a doc comment's example anchor must not count as a call site"
        );
        assert!(
            !strip_comments("/* failpoint!(\"removed.anchor.locked\")?; */")
                .contains("removed.anchor.locked"),
            "a commented-out call site must not count as live"
        );
    }

    /// The table and the call sites must name exactly the same set.
    ///
    /// Both directions matter and they fail differently. A call site missing
    /// from the table is an anchor the configuration parser silently drops, so
    /// a harness arming it gets a no-op barrier and a proof that raced nothing.
    /// A table entry with no call site is an anchor a harness can arm and wait
    /// on forever.
    ///
    /// # This is one of two scans, and neither is the sole authority
    ///
    /// `tests/fragment_provider_source_pins.rs` holds a twin,
    /// `every_failpoint_anchor_is_declared_even_in_a_default_build`. They are
    /// deliberately kept rather than deduplicated, because each is stronger on a
    /// different side:
    ///
    /// - **Declared side: this one is stronger.** It compares against the
    ///   compiled [`ANCHORS`] constant, so it cannot desync from what the code
    ///   actually holds. The twin parses the table out of this file's text, and
    ///   a text parse of a Rust constant can drift from the constant.
    /// - **Tier: the twin is stronger.** This module is compiled only under
    ///   `failure_generator`, and CI builds with that feature but never runs
    ///   `cargo test` with it — so this test executes essentially only when
    ///   someone works the feature tier locally. The twin runs on every default
    ///   `cargo test -p lore-postgres`, which is what a pull request actually
    ///   runs.
    ///
    /// **The called sides must stay identical**, and that is the reason this one
    /// reads the anchor rather than matching the bytes `failpoint!("`. A scan
    /// that is weaker than its twin is worse than no second scan, because it
    /// passes where the real check fails and a later reader cites it as
    /// authority.
    #[test]
    fn the_anchor_table_and_the_call_sites_name_the_same_set() {
        let files = crate_source_files();
        assert!(
            files.len() > 1,
            "the crate walk found {} file(s); the scan is broken, not the code",
            files.len()
        );

        let mut called: Vec<String> = Vec::new();
        for file in &files {
            let raw = std::fs::read_to_string(file)
                .unwrap_or_else(|error| panic!("{} must be readable: {error}", file.display()));
            let source = strip_comments(&raw);
            let name = file.display();
            for (offset, _) in source.match_indices("failpoint!") {
                let rest = source[offset + "failpoint!".len()..].trim_start();
                let Some(after_delimiter) = rest.strip_prefix('(') else {
                    // `failpoint!{..}` and `failpoint![..]` are legal macro
                    // invocations that this scan cannot read, so they are
                    // refused rather than skipped.
                    assert!(
                        !rest.starts_with('{') && !rest.starts_with('['),
                        "{name} invokes failpoint! with a non-parenthesised delimiter, which \
                         this scan cannot read; use failpoint!(\"anchor\")"
                    );
                    // Otherwise this is prose inside a string literal naming the
                    // macro — this module's own assertion messages do that.
                    continue;
                };
                let anchor_start = after_delimiter.trim_start();
                if anchor_start.starts_with('\\') {
                    // `failpoint!(\"` appears only inside a string literal that
                    // quotes the scan token itself. A real invocation cannot
                    // have an escaped quote here.
                    continue;
                }
                let Some(literal) = anchor_start.strip_prefix('"') else {
                    panic!(
                        "{name} invokes failpoint! with a non-literal anchor; this scan can only \
                         verify a string literal"
                    );
                };
                let end = literal
                    .find('"')
                    .unwrap_or_else(|| panic!("an unterminated failpoint! anchor in {name}"));
                called.push(literal[..end].to_owned());
            }
        }
        assert!(
            !called.is_empty(),
            "no failpoint! call sites found anywhere in src/; the scan is broken, not the code"
        );

        called.sort_unstable();
        called.dedup();
        let mut declared: Vec<String> = ANCHORS
            .iter()
            .map(|(anchor, _)| (*anchor).to_owned())
            .collect();
        declared.sort_unstable();

        assert_eq!(
            called, declared,
            "every failpoint! anchor anywhere in lore-postgres/src/ must be declared in ANCHORS \
             with the WP-109 race it serves, and every declared anchor must have a call site"
        );
    }

    // ---- the parser (Config::from_parts) ---------------------------------

    fn parse(spec: &str) -> HashMap<&'static str, Action> {
        Config::from_parts(Some(spec), None).actions
    }

    #[test]
    fn the_parser_accepts_a_well_formed_spec() {
        let actions = parse(
            " publication.commit.locked = pause ,obliterate.payload.settled=abort,\
             claim.settle.settled=unknown ",
        );
        assert_eq!(actions.len(), 3);
        assert_eq!(actions["publication.commit.locked"], Action::Pause);
        assert_eq!(actions["obliterate.payload.settled"], Action::Abort);
        assert_eq!(actions["claim.settle.settled"], Action::Unknown);
    }

    /// The one that would be serious if it regressed.
    ///
    /// `unknown` reports a successful commit as unacknowledged. At a `.settled`
    /// anchor that is WP-109's commit-acknowledgement-loss race. At a `.locked`
    /// or `.entry` anchor there is no commit yet, so the same action would
    /// report an outcome-unknown for a transaction that provably did not
    /// commit — injecting a lie into the exact reconciliation path
    /// `DomainError::OutcomeUnknown` exists to make trustworthy.
    #[test]
    fn the_parser_refuses_unknown_on_a_pre_commit_anchor() {
        assert!(parse("publication.commit.locked=unknown").is_empty());
        assert!(parse("publication.begin.entry=unknown").is_empty());
        assert!(parse("cutover.enable_lifecycle.pre_write=unknown").is_empty());
        // ... and accepts it on both post-commit window names.
        assert_eq!(parse("publication.commit.settled=unknown").len(), 1);
        assert_eq!(
            parse("cutover.enable_lifecycle.post_write=unknown").len(),
            1
        );
    }

    #[test]
    fn the_parser_drops_malformed_unknown_and_empty_entries() {
        // No `=` at all.
        assert!(parse("publication.commit.locked").is_empty());
        // An anchor that is not in the table (a typo of a real one).
        assert!(parse("publication.commit.lockd=pause").is_empty());
        // An action that is not one of the three.
        assert!(parse("publication.commit.locked=panic").is_empty());
        // Empty entries and stray separators are skipped, not fatal.
        assert!(parse("").is_empty());
        assert!(parse(",, ,").is_empty());
        // A bad entry does not discard the good ones beside it.
        let actions = parse("nonsense,publication.commit.locked=pause,another=bogus");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions["publication.commit.locked"], Action::Pause);
    }

    #[test]
    fn an_absent_spec_arms_nothing() {
        assert!(Config::from_parts(None, None).actions.is_empty());
    }

    // ---- the rendezvous --------------------------------------------------

    /// An IO error must mean "still held", not "released".
    ///
    /// This is the discriminating test for `still_held`. Reverting it to
    /// `Path::exists()` semantics — folding `Err` into `false` — fails the
    /// third assertion.
    #[test]
    fn an_io_error_on_the_rendezvous_probe_counts_as_still_held() {
        assert!(still_held(Ok(true)), "a present hold file is held");
        assert!(!still_held(Ok(false)), "an absent hold file is released");
        assert!(
            still_held(Err(std::io::Error::other("transient"))),
            "an IO error must keep the barrier held; failing open here ends the barrier while \
             the harness still believes it is holding, and the race is never run"
        );
    }

    /// The entry check is the opposite polarity, and that is load-bearing too.
    ///
    /// This is the discriminating test for `armed_at_entry`. "Harmonising" it
    /// with `still_held` — the edit the doc comments warn against — fails the
    /// third assertion.
    #[test]
    fn an_io_error_at_the_entry_check_leaves_the_anchor_unarmed() {
        assert!(armed_at_entry(Ok(true)), "a present hold file is armed");
        assert!(!armed_at_entry(Ok(false)), "an absent hold file is unarmed");
        assert!(
            !armed_at_entry(Err(std::io::Error::other("transient"))),
            "an IO error before anything is announced must proceed, not block: treating it as \
             armed would stall an anchor the harness never armed, for the whole ceiling, on a \
             filesystem hiccup"
        );
    }

    /// The entry polarity, driven through the real rendezvous rather than the
    /// predicate alone.
    ///
    /// A probe that only ever errors must produce no arrival marker and must
    /// return well inside the ceiling. Swapping the entry check to `still_held`
    /// makes this block for the full ceiling and announce an arrival, failing
    /// both assertions.
    #[tokio::test]
    async fn the_entry_check_announces_no_arrival_on_an_io_error() {
        let dir = TempRendezvous::new();
        let reached = dir.path().join("test.anchor.reached");
        let started = Instant::now();
        pause_at("test.anchor", Duration::from_millis(500), &reached, || {
            Err(std::io::Error::other("transient"))
        })
        .await;
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "an entry-check error must proceed immediately, not wait out the ceiling"
        );
        assert!(
            !reached.exists(),
            "an anchor that was never armed must not announce an arrival the harness would \
             read as a held barrier"
        );
    }

    /// Removing the hold file must actually release a pause.
    ///
    /// The armed cases elsewhere wait out their ceiling, which proves the
    /// ceiling rather than the release. This one proves the release: the probe
    /// reports held twice and then gone, and the pause must return well inside
    /// its ceiling with the arrival marker cleaned up.
    #[tokio::test]
    async fn a_pause_releases_when_the_hold_file_goes_away() {
        use std::cell::Cell;

        let dir = TempRendezvous::new();
        let reached = dir.path().join("test.anchor.reached");
        let calls = Cell::new(0usize);
        let started = Instant::now();
        pause_at("test.anchor", Duration::from_secs(30), &reached, || {
            let seen = calls.get();
            calls.set(seen + 1);
            Ok(seen < 3)
        })
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the pause must end when the hold file goes away, not at its ceiling"
        );
        assert!(
            calls.get() >= 4,
            "the pause must have observed the hold file present before it went away"
        );
        assert!(
            !reached.exists(),
            "the arrival marker must be removed once the pause is released"
        );
    }

    /// The same asymmetry, driven through the real wait loop.
    ///
    /// The probe errors twice before reporting the file gone. The loop must
    /// still be waiting after both errors, so it must observe all three
    /// answers. With `Err` folded into `false` it would stop after one.
    #[tokio::test]
    async fn the_wait_loop_keeps_waiting_across_a_transient_probe_error() {
        use std::cell::Cell;

        let calls = Cell::new(0usize);
        wait_while_held("test.anchor", Duration::from_secs(5), || {
            let seen = calls.get();
            calls.set(seen + 1);
            match seen {
                0 | 1 => Err(std::io::Error::other("transient")),
                _ => Ok(false),
            }
        })
        .await;
        assert_eq!(
            calls.get(),
            3,
            "the loop must survive both probe errors and stop only on a clean Ok(false)"
        );
    }

    #[tokio::test]
    async fn the_wait_loop_gives_up_at_its_ceiling_rather_than_waiting_forever() {
        let started = Instant::now();
        // A probe that is held forever. The loop must exit on the ceiling.
        wait_while_held("test.anchor", Duration::from_millis(50), || Ok(true)).await;
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "the loop must actually wait out its ceiling"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the loop must give up at its ceiling rather than block forever"
        );
    }

    // ---- end-to-end dispatch --------------------------------------------

    #[tokio::test]
    async fn hit_is_a_no_op_for_an_anchor_that_is_not_configured() {
        let config = Config::from_parts(Some("publication.commit.locked=pause"), None);
        // A different anchor: nothing configured, so no rendezvous is consulted
        // even though this config does arm one.
        hit_with(
            &config,
            "obliterate.payload.settled",
            Duration::from_millis(50),
        )
        .await
        .expect("an unconfigured anchor must be a no-op");
    }

    #[tokio::test]
    async fn hit_returns_outcome_unknown_for_a_configured_unknown_anchor() {
        let config = Config::from_parts(Some("publication.commit.settled=unknown"), None);
        let error = hit_with(
            &config,
            "publication.commit.settled",
            Duration::from_millis(50),
        )
        .await
        .expect_err("a configured `unknown` anchor must return an error");
        assert!(
            matches!(error, DomainError::OutcomeUnknown(_)),
            "the injected error must be OutcomeUnknown, not some other variant: {error:?}"
        );
    }

    /// `hit` -> `pause_with` -> `pause_at` end to end against a real directory
    /// and real `try_exists` probes, with nothing injected.
    ///
    /// Three halves, because the release is the one a ceiling test cannot
    /// prove: unarmed returns promptly, armed-and-released ends when the hold
    /// file goes away, and armed-and-never-released ends at the ceiling.
    #[tokio::test]
    async fn hit_pauses_only_while_the_hold_file_is_present() {
        let dir = TempRendezvous::new();
        let config = Config::from_parts(
            Some("publication.commit.locked=pause"),
            Some(dir.path().to_path_buf()),
        );
        let anchor = "publication.commit.locked";
        let hold = dir.path().join(format!("{anchor}.hold"));
        let reached = dir.path().join(format!("{anchor}.reached"));

        // Unarmed: no hold file, so this must return without waiting and must
        // leave no arrival marker behind.
        let started = Instant::now();
        hit_with(&config, anchor, Duration::from_millis(500))
            .await
            .expect("a pause anchor never returns an error");
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "an unarmed pause must not wait"
        );
        assert!(
            !reached.exists(),
            "an unarmed pause must not announce arrival"
        );

        // Armed and then released. A second task removes the hold file shortly
        // after the pause announces its arrival, which is exactly the sequence
        // a WP-109 harness performs. The ceiling is far larger than the release
        // delay, so reaching it would mean the release did not work.
        std::fs::write(&hold, b"held").expect("arm the rendezvous");
        let releaser = {
            let hold = hold.clone();
            let reached = reached.clone();
            lore_base::lore_spawn!(async move {
                // Wait until the pause has actually announced, so this proves a
                // release rather than racing the entry check.
                while !reached.exists() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                std::fs::remove_file(&hold).expect("release the rendezvous");
            })
        };
        let started = Instant::now();
        hit_with(&config, anchor, Duration::from_secs(30))
            .await
            .expect("a pause anchor never returns an error");
        releaser.await.expect("the releaser task must finish");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "removing the hold file must release the pause, not leave it to the ceiling"
        );
        assert!(
            !reached.exists(),
            "the arrival marker must be removed once the pause is released"
        );

        // Armed and never released: the pause must end at its ceiling rather
        // than blocking a coordinator transaction for the life of the process.
        std::fs::write(&hold, b"held").expect("re-arm the rendezvous");
        let started = Instant::now();
        hit_with(&config, anchor, Duration::from_millis(150))
            .await
            .expect("a pause anchor never returns an error");
        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "an armed pause must block until its ceiling when nothing releases it"
        );
        assert!(
            !reached.exists(),
            "the arrival marker must be removed once the pause ends"
        );
    }

    /// A uniquely named temporary directory that removes itself, including on
    /// panic.
    ///
    /// The name carries a real random token. An earlier version used
    /// `Instant::now().elapsed()`, which is always about zero — so the name was
    /// effectively just the pid, and the isolation the code claimed was not the
    /// isolation it had. Two cases in one process would have shared a
    /// directory, and a panic leaked it.
    struct TempRendezvous(std::path::PathBuf);

    impl TempRendezvous {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lore-failpoint-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).expect("temp rendezvous directory");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempRendezvous {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn actions_parse_exactly_three_names() {
        assert_eq!(Action::parse("pause"), Some(Action::Pause));
        assert_eq!(Action::parse("abort"), Some(Action::Abort));
        assert_eq!(Action::parse("unknown"), Some(Action::Unknown));
        assert_eq!(Action::parse("panic"), None);
        assert_eq!(Action::parse(""), None);
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `stage resolve-lost` at the drain: the drain carries out an operator loss
//! ruling only with its own pinned miss, a healthy guard, and echo evidence
//! or the ruling's attestation. End to end through the real stage,
//! coordinator, ruling SQL and a drain pass. Linux only (the pinned tree).
use std::sync::atomic::AtomicBool;

use super::*;
use crate::domain::fragments::StagerIdentity;
use crate::domain::fragments::stage_loss::LossApply;
use crate::domain::fragments::stage_loss::LossApplyOutcome;
use crate::domain::fragments::stage_loss::LossFilter;
use crate::domain::fragments::stage_loss::LossRulingReader;

/// The fixture's cell. No liveness row is published, so every stager is
/// "not fresh" to the selection.
const CELL: &str = "adapter-cell";

/// What the test controls about the drain process.
#[derive(Clone)]
struct Drain {
    healthy: Arc<AtomicBool>,
    echo: Arc<std::sync::Mutex<Option<bool>>>,
    echo_calls: Arc<AtomicUsize>,
}

impl Drain {
    fn new() -> Self {
        Self {
            healthy: Arc::new(AtomicBool::new(false)),
            echo: Arc::new(std::sync::Mutex::new(Some(false))),
            echo_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn hooks(&self) -> LossRulingHooks {
        let healthy = self.healthy.clone();
        let echo = self.echo.clone();
        let calls = self.echo_calls.clone();
        LossRulingHooks {
            guard_healthy: Arc::new(move || healthy.load(Ordering::SeqCst)),
            stager_echo: Arc::new(move |stager: &StagerIdentity| {
                assert_eq!(
                    stager.replica_id, "web-a",
                    "the ruling's own stager is checked"
                );
                calls.fetch_add(1, Ordering::SeqCst);
                *echo.lock().unwrap()
            }),
            reader: LossRulingReader {
                replica_id: "drain-1".to_owned(),
                incarnation: "drain-inc".to_owned(),
            },
        }
    }
}

/// Where [`lost_file_with`] leaves the staged file.
enum Placement {
    /// In the drain's stage: the mount was fixed after all.
    Keep,
    /// Gone.
    Delete,
    /// Moved to this other stage root, at the same relative path: the stager
    /// wrote another directory (a split mount).
    MoveTo(PathBuf),
}

/// Stage one fragment as web replica `web-a`, attach the drain's guard (it
/// confirmed nobody) and the ruling hooks, delete the file, and age the
/// epoch past the floor. Returns `(hash, epoch)`.
async fn lost_file(fixture: &Fixture, drain: &Drain, tag: &str, delete: bool) -> (Vec<u8>, i64) {
    let placement = if delete {
        Placement::Delete
    } else {
        Placement::Keep
    };
    lost_file_with(fixture, drain.hooks(), tag, placement).await
}

/// [`lost_file`] with the drain's own hooks and any placement.
async fn lost_file_with(
    fixture: &Fixture,
    hooks: LossRulingHooks,
    tag: &str,
    placement: Placement,
) -> (Vec<u8>, i64) {
    assert!(
        fixture
            .handle
            .attach_stager(StagerIdentity::new("web-a", "inc-a").unwrap())
    );
    let bytes = Bytes::from(format!("loss ruling {tag} payload repeated ").repeat(512));
    let address = Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(&bytes).as_bytes().as_slice()),
    };
    fixture
        .port
        .extra_bodies
        .lock()
        .unwrap()
        .push(bytes.clone());
    let staged = fixture
        .store
        .put_staged(
            &fixture.handle.coordinator,
            &fixture.stage,
            address,
            raw_fragment(&bytes),
            bytes,
        )
        .await
        .unwrap();
    let hash = address.hash.data().to_vec();
    let stager: String = fixture
        .admin
        .query_one(
            "SELECT replica_id FROM lore_domain_write_behind_stagers WHERE hash=$1 AND epoch=$2",
            &[&hash, &staged.epoch],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stager, "web-a");
    fixture
        .handle
        .attach_drain_absence_guard(Arc::new(|_| false), MIN_STAGED_ABSENCE_AGE)
        .expect("the drain guard attaches");
    assert!(fixture.handle.attach_loss_rulings(hooks.clone()));
    assert!(
        !fixture.handle.attach_loss_rulings(hooks),
        "a second set of hooks is refused"
    );
    let file = staged_file(fixture, &address.hash, staged.epoch);
    match placement {
        Placement::Keep => {}
        Placement::Delete => std::fs::remove_file(&file).unwrap(),
        Placement::MoveTo(other) => {
            let relative = file.strip_prefix(fixture.root.join("stage")).unwrap();
            let moved = other.join(relative);
            std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
            std::fs::rename(&file, &moved).unwrap();
        }
    }
    // The fixture's own fragment has no stager and no ruling: it must stay.
    std::fs::remove_file(staged_file(
        fixture,
        &fixture.address.hash,
        fixture.source_epoch,
    ))
    .unwrap();
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_epochs SET created_at = created_at - interval '2 hours' \
             WHERE hash = $1",
            &[&hash],
        )
        .await
        .unwrap();
    (hash, staged.epoch)
}

fn staged_file(fixture: &Fixture, hash: &Hash, epoch: i64) -> PathBuf {
    let key = format!("{hash}.s{epoch}");
    fixture
        .root
        .join("stage/staged")
        .join(&key[..2])
        .join(&key[2..4])
        .join(&key)
}

/// Record a ruling for `hash` through the real `list` + `apply`.
async fn rule(hash: &[u8], attested: bool) {
    let url = std::env::var("LORE_TEST_PG_URL").unwrap();
    let pool = crate::pool::build_pool(&url, 1, &TlsConfig::default()).unwrap();
    let mut client = pool.get().await.unwrap();
    let filter = LossFilter {
        hash: Some(hash.to_vec()),
        stager: None,
        repository: None,
        min_age: Duration::from_secs(3_600),
        limit: 10,
    };
    let fresh = Duration::from_secs(10);
    let listing = crate::domain::fragments::stage_loss::list_lost_staged(
        &***client, CELL, fresh, &filter, None,
    )
    .await
    .unwrap();
    assert_eq!(listing.files.len(), 1, "the kept file is listed");
    let token = crate::domain::fragments::stage_loss::confirm_token(
        listing.as_of_ms,
        CELL,
        &filter,
        &listing.files,
    );
    let outcome = crate::domain::fragments::stage_loss::apply_loss_rulings(
        &mut client,
        CELL,
        fresh,
        &filter,
        &LossApply {
            actor: "kv",
            reason: "test",
            attested,
            multi_repository: false,
            token: &token,
        },
    )
    .await
    .unwrap();
    assert!(matches!(outcome, LossApplyOutcome::Applied { ref rulings, .. } if rulings.len() == 1));
}

async fn state(fixture: &Fixture, hash: &[u8]) -> i16 {
    fixture
        .admin
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash=$1",
            &[&hash],
        )
        .await
        .unwrap()
        .get(0)
}

/// The newest ruling of `hash`: `(outcome, evidence, drain incarnation)`.
async fn ruling(
    fixture: &Fixture,
    hash: &[u8],
) -> (Option<String>, Option<String>, Option<String>) {
    let row = fixture
        .admin
        .query_one(
            "SELECT outcome, evidence, drain_incarnation FROM lore_domain_stage_loss_rulings \
             WHERE hash=$1 ORDER BY ruling_id DESC LIMIT 1",
            &[&hash],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

/// What [`drain_until`] waits for.
#[derive(Clone, Copy)]
enum Until {
    /// The head of the hash is in this state.
    State(FragmentLifecycleState),
    /// The newest ruling of the hash is decided.
    Decided,
}

/// Drain until `until` holds for `hash`, or fail after 60 s. A kept
/// fragment waits out its cool-down, so a pass may not read it.
async fn drain_until(fixture: &Fixture, hash: &[u8], until: Until, why: &str) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let done = match until {
                Until::State(wanted) => state(fixture, hash).await == wanted.bits(),
                Until::Decided => ruling(fixture, hash).await.0.is_some(),
            };
            if done {
                return;
            }
            let _ = fixture.handle.drain_pass(8).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{why}"));
}

/// A departed stager's lost file: kept `Staged` while the guard is unhealthy
/// (the ruling stays open), then marked `Missing` once the guard is healthy
/// and the stager's echo is in the drain's own stage, with the ruling closed
/// `marked_missing`, evidence `echo`, in the same transaction. The fixture's
/// own lost file, with no stager and no ruling, stays `Staged`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_ruling_marks_a_pinned_miss_missing_only_with_a_healthy_guard_and_echo_evidence() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let drain = Drain::new();
    let (hash, _epoch) = lost_file(&fixture, &drain, "echo", true).await;
    rule(&hash, false).await;

    for _ in 0..4 {
        let _ = fixture.handle.drain_pass(8).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        state(&fixture, &hash).await,
        FragmentLifecycleState::Staged.bits()
    );
    assert_eq!(
        ruling(&fixture, &hash).await.0,
        None,
        "an unhealthy guard keeps it open"
    );
    assert_eq!(
        drain.echo_calls.load(Ordering::SeqCst),
        0,
        "nothing past the guard check runs while it is unhealthy"
    );

    *drain.echo.lock().unwrap() = Some(true);
    drain.healthy.store(true, Ordering::SeqCst);
    drain_until(
        &fixture,
        &hash,
        Until::State(FragmentLifecycleState::Missing),
        "a healthy guard with echo evidence marks it",
    )
    .await;
    assert_eq!(
        ruling(&fixture, &hash).await,
        (
            Some("marked_missing".to_owned()),
            Some("echo".to_owned()),
            Some("drain-inc".to_owned())
        )
    );
    assert_eq!(
        state(&fixture, fixture.address.hash.data()).await,
        FragmentLifecycleState::Staged.bits(),
        "a file with no stager and no ruling is never marked"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
}

/// A stager that stopped cleanly left no echo: an unattested ruling closes
/// `no_evidence` and the file stays `Staged`. An attested ruling then marks
/// it `Missing` with evidence `none`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_clean_stop_without_attestation_is_refused_and_an_attested_ruling_marks_it() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let drain = Drain::new();
    drain.healthy.store(true, Ordering::SeqCst);
    let (hash, _epoch) = lost_file(&fixture, &drain, "clean-stop", true).await;
    rule(&hash, false).await;
    drain_until(
        &fixture,
        &hash,
        Until::Decided,
        "no evidence closes the ruling",
    )
    .await;
    assert_eq!(
        ruling(&fixture, &hash).await.0.as_deref(),
        Some("no_evidence")
    );
    assert_eq!(
        state(&fixture, &hash).await,
        FragmentLifecycleState::Staged.bits()
    );
    assert!(drain.echo_calls.load(Ordering::SeqCst) >= 1);

    // A refresh is due only every 10 s; the new ruling waits for it.
    rule(&hash, true).await;
    drain_until(
        &fixture,
        &hash,
        Until::State(FragmentLifecycleState::Missing),
        "an attested ruling marks it",
    )
    .await;
    assert_eq!(
        ruling(&fixture, &hash).await,
        (
            Some("marked_missing".to_owned()),
            Some("none".to_owned()),
            Some("drain-inc".to_owned())
        )
    );
}

/// The file is there after all (the mount was fixed): the drain's read
/// finds it, closes the ruling `found`, and promotes it as usual.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_found_file_closes_its_ruling_and_is_promoted() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let drain = Drain::new();
    drain.healthy.store(true, Ordering::SeqCst);
    let (hash, _epoch) = lost_file(&fixture, &drain, "found", false).await;
    rule(&hash, true).await;
    drain_until(
        &fixture,
        &hash,
        Until::State(FragmentLifecycleState::Remote),
        "the found file is promoted",
    )
    .await;
    assert_eq!(ruling(&fixture, &hash).await.0.as_deref(), Some("found"));
    assert_eq!(drain.echo_calls.load(Ordering::SeqCst), 0);
}

/// The drain's real echo check, through its own pinned `liveness/`: the
/// stager's echo file there, first line its incarnation.
fn pinned_echo(fixture: &Fixture) -> StagerEcho {
    let liveness = fixture.handle.stage_liveness_dir();
    Arc::new(move |stager: &StagerIdentity| {
        match liveness.read(&format!("{}.echo", stager.replica_id), 4_096) {
            Ok(None) => Some(false),
            Ok(Some(bytes)) => Some(
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .next()
                    .is_some_and(|first| first.trim() == stager.incarnation),
            ),
            Err(_) => None,
        }
    })
}

/// When `LORE_TEST_REQUIRE_NFS` is set (the loopback NFS harness), the
/// fixture's stage must be on an NFS mount, so a pass on local disk can never
/// stand in for the NFS run.
fn require_nfs_if_asked(fixture: &Fixture) {
    if std::env::var_os("LORE_TEST_REQUIRE_NFS").is_none() {
        return;
    }
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap();
    let root = fixture.root.to_string_lossy().into_owned();
    let on_nfs = mounts.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() > 2 && fields[2].starts_with("nfs") && root.starts_with(fields[1])
    });
    assert!(
        on_nfs,
        "LORE_TEST_REQUIRE_NFS: {root} is not on an NFS mount"
    );
    eprintln!("stage root {root} is on NFS");
}

/// Split directory (design section 7): the stager `web-a` wrote stage B and
/// left; the drain reads stage A. The file is absent in A and present in B,
/// and `web-a`'s echo is in B's `liveness/`, not A's. With a healthy guard
/// (every LIVE replica proven in A) but no evidence and no attestation, the
/// ruling closes `no_evidence` and the fragment stays `Staged`; B's file is
/// untouched. Control: had `web-a` echoed into A, the drain's own pinned
/// echo read is evidence and the ruling is carried out.
///
/// The loopback NFS harness runs this same case with both stages on one NFS
/// export (`LORE_TEST_REQUIRE_NFS`).
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_split_directory_stager_without_evidence_or_attestation_stays_staged() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    require_nfs_if_asked(&fixture);
    let other = fixture.root.join("stage-b");
    std::fs::create_dir_all(other.join("liveness")).unwrap();
    std::fs::write(other.join("liveness/web-a.echo"), "inc-a\ndrain-b nonce").unwrap();
    let healthy = Arc::new(AtomicBool::new(true));
    let probe = healthy.clone();
    let hooks = LossRulingHooks {
        guard_healthy: Arc::new(move || probe.load(Ordering::SeqCst)),
        stager_echo: pinned_echo(&fixture),
        reader: LossRulingReader {
            replica_id: "drain-1".to_owned(),
            incarnation: "drain-inc".to_owned(),
        },
    };
    let (hash, epoch) =
        lost_file_with(&fixture, hooks, "split", Placement::MoveTo(other.clone())).await;
    let in_b = {
        let key = format!("{}.s{epoch}", Hash::from(hash.as_slice()));
        other
            .join("staged")
            .join(&key[..2])
            .join(&key[2..4])
            .join(&key)
    };
    assert!(in_b.exists(), "the stager's copy is in B");
    rule(&hash, false).await;
    drain_until(
        &fixture,
        &hash,
        Until::Decided,
        "no evidence closes the ruling",
    )
    .await;
    assert_eq!(
        ruling(&fixture, &hash).await.0.as_deref(),
        Some("no_evidence")
    );
    assert_eq!(
        state(&fixture, &hash).await,
        FragmentLifecycleState::Staged.bits()
    );
    assert!(in_b.exists(), "B's file is untouched");

    // Control: the stager's echo in the drain's own stage is evidence.
    std::fs::write(
        fixture.root.join("stage/liveness/web-a.echo"),
        "inc-a\ndrain-1 nonce",
    )
    .unwrap();
    rule(&hash, false).await;
    drain_until(
        &fixture,
        &hash,
        Until::State(FragmentLifecycleState::Missing),
        "echo evidence in A carries the ruling out",
    )
    .await;
    assert_eq!(
        ruling(&fixture, &hash).await,
        (
            Some("marked_missing".to_owned()),
            Some("echo".to_owned()),
            Some("drain-inc".to_owned())
        )
    );
}
/// The drain's own read before it carries a ruling out: found is
/// `Some(false)`, a miss under the intact pinned tree is `Some(true)`, and a
/// miss after the stage root path was replaced decides nothing (`None`).
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn the_ruling_read_misses_only_under_the_intact_pinned_tree() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let hash = fixture.address.hash.data().to_vec();
    let epoch = fixture.source_epoch;
    let key: String = fixture
        .admin
        .query_one(
            "SELECT object_key FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2",
            &[&hash, &epoch],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        fixture.stage.ruling_read(&hash, epoch, &key).await,
        Some(false)
    );
    std::fs::remove_file(staged_file(&fixture, &fixture.address.hash, epoch)).unwrap();
    assert_eq!(
        fixture.stage.ruling_read(&hash, epoch, &key).await,
        Some(true)
    );
    assert_eq!(
        fixture
            .stage
            .ruling_read(&hash, epoch, "not-the-derived-key")
            .await,
        None,
        "a key the stage does not derive is refused, never absent"
    );
    // Replace the stage root path: the pinned tree is no longer what the
    // path names, so a miss proves nothing.
    let stage = fixture.root.join("stage");
    std::fs::rename(&stage, fixture.root.join("stage-moved")).unwrap();
    std::fs::create_dir_all(stage.join("staged")).unwrap();
    std::fs::create_dir_all(stage.join("liveness")).unwrap();
    assert_eq!(fixture.stage.ruling_read(&hash, epoch, &key).await, None);
}

/// Run drain passes until `done` holds (fail after 60 s), then three more, so
/// a decision a later pass would take has the chance to happen.
async fn drain_until_then_three<F: Fn() -> bool>(fixture: &Fixture, done: F, why: &str) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !done() {
            let _ = fixture.handle.drain_pass(8).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{why}"));
    for _ in 0..3 {
        let _ = fixture.handle.drain_pass(8).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Review D1: the guard is checked again after the evidence and just before
/// the mark. A guard healthy at the first check and unhealthy at the second
/// keeps the fragment `Staged` and the ruling open, although every other
/// condition (pinned miss, echo evidence) holds. Without the second check the
/// first pass marks it `Missing`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_guard_that_turns_unhealthy_before_the_mark_keeps_the_ruling_open() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let echo_calls = Arc::new(AtomicUsize::new(0));
    let (guard_probe, echo_probe) = (guard_calls.clone(), echo_calls.clone());
    let hooks = LossRulingHooks {
        // Healthy on the first call only.
        guard_healthy: Arc::new(move || guard_probe.fetch_add(1, Ordering::SeqCst) == 0),
        stager_echo: Arc::new(move |_stager: &StagerIdentity| {
            echo_probe.fetch_add(1, Ordering::SeqCst);
            Some(true)
        }),
        reader: LossRulingReader {
            replica_id: "drain-1".to_owned(),
            incarnation: "drain-inc".to_owned(),
        },
    };
    let (hash, _epoch) = lost_file_with(&fixture, hooks, "guard-flip", Placement::Delete).await;
    rule(&hash, false).await;
    drain_until_then_three(
        &fixture,
        || echo_calls.load(Ordering::SeqCst) >= 1,
        "the first guard check passes and the evidence is read",
    )
    .await;
    assert!(
        guard_calls.load(Ordering::SeqCst) >= 2,
        "the guard was checked again after the evidence"
    );
    assert_eq!(
        state(&fixture, &hash).await,
        FragmentLifecycleState::Staged.bits(),
        "an unhealthy guard at the second check marks nothing"
    );
    assert_eq!(
        ruling(&fixture, &hash).await.0,
        None,
        "the ruling stays open"
    );
}

/// Review D2: an ESTALE or EIO at the drain's own ruling read decides
/// nothing. The ruling stays open and nothing is marked, with a healthy
/// guard and echo evidence ready. Control: once the read can decide again,
/// the same ruling is carried out.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_ruling_read_estale_keeps_the_ruling_open_and_marks_nothing() {
    ruling_read_error_keeps_the_ruling_open(rustix::io::Errno::STALE).await;
}

/// [`a_ruling_read_estale_keeps_the_ruling_open_and_marks_nothing`] with EIO.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn a_ruling_read_eio_keeps_the_ruling_open_and_marks_nothing() {
    ruling_read_error_keeps_the_ruling_open(rustix::io::Errno::IO).await;
}

async fn ruling_read_error_keeps_the_ruling_open(errno: rustix::io::Errno) {
    use crate::store::write_behind::root::durability_tests::InjectedErrno;
    {
        let fixture =
            Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
        let drain = Drain::new();
        drain.healthy.store(true, Ordering::SeqCst);
        *drain.echo.lock().unwrap() = Some(true);
        let (hash, epoch) = lost_file(&fixture, &drain, &format!("read-{errno:?}"), true).await;
        rule(&hash, false).await;
        let relative = staged_file(&fixture, &Hash::from(hash.as_slice()), epoch)
            .strip_prefix(fixture.root.join("stage/staged"))
            .unwrap()
            .to_path_buf();
        // The guarded read of the first pass is a real ENOENT the guard keeps;
        // the ruling read right after it is the next open of this path.
        let injected = InjectedErrno::after("staged open", relative, 1, usize::MAX, errno);
        drain_until_then_three(
            &fixture,
            || injected.hits() >= 2,
            "the drain reaches its ruling read",
        )
        .await;
        assert_eq!(
            state(&fixture, &hash).await,
            FragmentLifecycleState::Staged.bits(),
            "{errno:?}: nothing is marked"
        );
        assert_eq!(
            ruling(&fixture, &hash).await.0,
            None,
            "{errno:?}: the ruling stays open"
        );
        assert_eq!(
            drain.echo_calls.load(Ordering::SeqCst),
            0,
            "{errno:?}: nothing past the read ran"
        );
        drop(injected);
        drain_until(
            &fixture,
            &hash,
            Until::State(FragmentLifecycleState::Missing),
            "control: a decidable read carries the same ruling out",
        )
        .await;
    }
}

/// Review D3: an echo check that cannot decide (`None`: a root check or the
/// read failed) defers even on an attested ruling. The attestation stands in
/// for missing evidence, never for a check that did not run.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn an_undecided_echo_defers_even_an_attested_ruling() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let drain = Drain::new();
    drain.healthy.store(true, Ordering::SeqCst);
    *drain.echo.lock().unwrap() = None;
    let (hash, _epoch) = lost_file(&fixture, &drain, "echo-undecided", true).await;
    rule(&hash, true).await;
    drain_until_then_three(
        &fixture,
        || drain.echo_calls.load(Ordering::SeqCst) >= 1,
        "the drain reaches the echo check",
    )
    .await;
    assert_eq!(
        state(&fixture, &hash).await,
        FragmentLifecycleState::Staged.bits()
    );
    assert_eq!(
        ruling(&fixture, &hash).await.0,
        None,
        "the ruling stays open"
    );
    // Control: a decided "no echo" on the attested ruling carries it out.
    *drain.echo.lock().unwrap() = Some(false);
    drain_until(
        &fixture,
        &hash,
        Until::State(FragmentLifecycleState::Missing),
        "an attested ruling with a decided echo is carried out",
    )
    .await;
    assert_eq!(ruling(&fixture, &hash).await.1.as_deref(), Some("none"));
}

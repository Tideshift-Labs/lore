// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-115 row 80, idea 1: the lease-free optimistic staged GET.
//!
//! Real coordinator, real SQL, real confined staging root; only the provider
//! transport is scripted. The observable is the coordinator pool's per-site
//! checkout tally: a staged GET that takes no reader lease records no checkout
//! at `acquire_staged_leases` or `release_staged_lease`, and a fallback onto a
//! leased pass records exactly one of each.
//!
//! The race cases pause the GET at `staged_read.unleased.resolved` (after its
//! first resolve, before its staged read), move the head and purge the staged
//! file, then release it. The failpoint config is read once per process, so the
//! runner must start each race case in its own process with
//! `LORE_FRAGMENT_FAILPOINTS=staged_read.unleased.resolved=pause` and
//! `LORE_FRAGMENT_FAILPOINT_DIR=<writable dir>`; see
//! `tests/run-write-behind-linux.ps1`.
use super::*;
use crate::domain::fragments::PostgresFragmentCoordinator;
use crate::store::immutable_store::CoordinatedLoad;
use crate::store::immutable_store::StagedReadMode;

/// The repository every case binds its fragment to.
const REPOSITORY: [u8; 16] = [0x5a; 16];

const COORDINATOR_SOURCE: &str = include_str!("../domain/fragments/coordinator.rs");
const COORDINATOR_FILE_SUFFIX: &str = "domain/fragments/coordinator.rs";

/// The 1-based line of the first `self.checkout()` inside `async fn <function>(`.
///
/// Pool checkouts are attributed to the source line that asked for one, so the
/// lease sites cannot be named; they are found. Failing here, loudly, when a
/// refactor moves or duplicates the function is the point: a stale line would
/// read as "no lease taken" and pass the very property under test.
fn checkout_line(function: &str) -> u32 {
    let header = format!("async fn {function}(");
    let lines: Vec<&str> = COORDINATOR_SOURCE.lines().collect();
    let headers: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(&header))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        headers.len(),
        1,
        "`{header}` must appear exactly once in coordinator.rs"
    );
    let Some(index) = lines
        .iter()
        .skip(headers[0])
        .position(|line| line.contains("self.checkout()"))
    else {
        panic!("`{function}` has no `self.checkout()`");
    };
    u32::try_from(headers[0] + index + 1).unwrap()
}

fn acquired_at(coordinator: &PostgresFragmentCoordinator, line: u32) -> u64 {
    coordinator
        .pool_checkout_sites()
        .iter()
        .filter(|site| {
            site.site()
                .file()
                .replace('\\', "/")
                .ends_with(COORDINATOR_FILE_SUFFIX)
                && site.site().line() == line
        })
        .map(|site| site.acquired())
        .sum()
}

/// Checkouts at the three coordinator sites the staged read cares about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Checkouts {
    lease_acquire: u64,
    lease_release: u64,
    mark_missing: u64,
}

impl Checkouts {
    fn take(coordinator: &PostgresFragmentCoordinator) -> Self {
        Self {
            lease_acquire: acquired_at(coordinator, checkout_line("acquire_staged_leases")),
            lease_release: acquired_at(coordinator, checkout_line("release_staged_lease")),
            mark_missing: acquired_at(coordinator, checkout_line("mark_missing")),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            lease_acquire: self.lease_acquire - before.lease_acquire,
            lease_release: self.lease_release - before.lease_release,
            mark_missing: self.mark_missing - before.mark_missing,
        }
    }
}

fn route(store: &PostgresImmutableStore) -> (&PostgresFragmentCoordinator, &FragmentProviderEntry) {
    match &store.fragment_route {
        FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            ..
        } => (coordinator, provider.as_ref()),
        FragmentLifecycleRoute::Legacy => panic!("the fixture store is coordinated"),
    }
}

/// The GET entry under test, with the fixture's own address and repository.
async fn optimistic_get(fixture: &Fixture) -> Result<(Fragment, Bytes), StoreError> {
    let (coordinator, provider) = route(&fixture.store);
    fixture
        .store
        .load_coordinated_optimistic(
            coordinator,
            provider,
            Context::from(REPOSITORY),
            fixture.address,
        )
        .await
}

/// Give the fixture's fragment a live repository and association, so a GET
/// resolves it as `Readable`.
async fn bind_association(fixture: &Fixture) {
    fixture
        .admin
        .execute(
            "INSERT INTO lore_domain_repositories(repository_id,state,generation,name,\
             metadata_hash,default_branch_id,creation_fingerprint_version,\
             creation_fingerprint,created_at) \
             VALUES($1,0,1,'staged-read',$2,$3,1,$2,clock_timestamp())",
            &[&&REPOSITORY[..], &&[0x78u8; 32][..], &&[0x79u8; 16][..]],
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .handle
            .coordinator
            .create_association(
                fixture.address.hash.data(),
                &REPOSITORY,
                fixture.address.context.data(),
            )
            .await
            .unwrap(),
        CommitVerdict::Published
    );
}

async fn head_state(fixture: &Fixture) -> i16 {
    fixture
        .admin
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash=$1",
            &[&fixture.address.hash.data().as_slice()],
        )
        .await
        .unwrap()
        .get(0)
}

fn assert_no_lease(delta: Checkouts) {
    assert_eq!(
        (delta.lease_acquire, delta.lease_release),
        (0, 0),
        "no reader lease was taken: {delta:?}"
    );
}

/// Row 80 idea 1, case (d) plus the positive control for the checkout probe.
///
/// A happy staged GET takes no lease. The same probe then sees a leased pass
/// take exactly one pair, so a zero above is a measurement and not a probe that
/// silently reads nothing.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn unleased_staged_get_takes_no_reader_lease_and_a_leased_pass_still_does() {
    let body = payload();
    let fixture = Fixture::open(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        body.clone(),
    )
    .await;
    bind_association(&fixture).await;
    let (coordinator, provider) = route(&fixture.store);

    let before = Checkouts::take(coordinator);
    let (_, loaded) = optimistic_get(&fixture).await.expect("happy staged GET");
    let unleased = Checkouts::take(coordinator).since(before);
    assert_eq!(loaded, body, "the GET returns the staged bytes");
    assert_no_lease(unleased);
    assert_eq!(unleased.mark_missing, 0, "a clean read publishes nothing");
    assert_eq!(
        head_state(&fixture).await,
        FragmentLifecycleState::Staged.bits()
    );

    let before = Checkouts::take(coordinator);
    let CoordinatedLoad::Loaded((_, leased_bytes)) = fixture
        .store
        .load_coordinated(
            coordinator,
            provider,
            Context::from(REPOSITORY),
            fixture.address,
            StagedReadMode::Leased,
        )
        .await
        .expect("leased staged GET")
    else {
        panic!("a leased pass never asks for a leased retry");
    };
    let leased = Checkouts::take(coordinator).since(before);
    assert_eq!(leased_bytes, body);
    assert_eq!(
        (leased.lease_acquire, leased.lease_release),
        (1, 1),
        "control: a leased pass takes exactly one acquire and one release"
    );
}

/// Case (e): a `Remote` head never touches the staged tier or a lease.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn remote_head_get_is_unaffected_by_the_unleased_path() {
    let body = payload();
    let fixture = Fixture::open(
        PutResult::Created,
        remote(raw_fragment(&body), &body),
        body.clone(),
    )
    .await;
    bind_association(&fixture).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
    let (coordinator, _) = route(&fixture.store);

    let before = Checkouts::take(coordinator);
    let (_, loaded) = optimistic_get(&fixture).await.expect("remote GET");
    let delta = Checkouts::take(coordinator).since(before);
    assert_eq!(loaded, body);
    assert_no_lease(delta);
    assert_eq!(delta.mark_missing, 0);
    assert_eq!(
        fixture.port.gets.load(Ordering::SeqCst),
        1,
        "served by exactly one provider GET"
    );
}

#[cfg(feature = "failure_generator")]
mod race {
    use std::path::Path;

    use super::*;
    use crate::domain::fragments::FragmentObliterateBegin;
    use crate::domain::fragments::FragmentPurgeProof;
    use crate::domain::fragments::FragmentWriteCapabilityCutover;
    use crate::domain::fragments::MissingDiagnostic;
    use crate::domain::fragments::schema;
    use crate::store::write_behind::StagedRead;

    const ANCHOR: &str = "staged_read.unleased.resolved";

    fn stage_root(fixture: &Fixture) -> PathBuf {
        fixture.root.join("stage")
    }

    /// Every regular file under `root` whose name contains `needle`.
    fn files_named(root: &Path, needle: &str) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    pending.push(path);
                } else if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(needle))
                {
                    found.push(path);
                }
            }
        }
        found
    }

    /// Delete one staged epoch's file straight off disk: a loss with no head move.
    fn delete_staged_file(fixture: &Fixture, epoch: i64) {
        let needle = format!("{}.s{epoch}", hex::encode(fixture.address.hash.data()));
        let found = files_named(&stage_root(fixture), &needle);
        assert_eq!(
            found.len(),
            1,
            "exactly one staged file for {needle}: {found:?}"
        );
        std::fs::remove_file(&found[0]).unwrap();
    }

    async fn assert_staged_absent(fixture: &Fixture, epoch: i64, object_key: &str) {
        assert!(
            matches!(
                fixture
                    .stage
                    .read_staged(fixture.address.hash.data(), epoch, object_key)
                    .await,
                StagedRead::Absent
            ),
            "the staged file of epoch {epoch} must be gone"
        );
    }

    /// The rendezvous for `staged_read.unleased.resolved`: arm before the GET
    /// starts, wait for the GET to announce arrival, release when done.
    struct Gate {
        hold: PathBuf,
        reached: PathBuf,
    }

    impl Gate {
        fn arm() -> Self {
            assert!(crate::domain::fragments::failpoints_compiled());
            assert_eq!(
                std::env::var("LORE_FRAGMENT_FAILPOINTS").unwrap(),
                format!("{ANCHOR}=pause"),
                "runner must set the process-wide failpoint before startup"
            );
            let directory = PathBuf::from(
                std::env::var("LORE_FRAGMENT_FAILPOINT_DIR")
                    .expect("runner must set LORE_FRAGMENT_FAILPOINT_DIR"),
            );
            std::fs::create_dir_all(&directory).unwrap();
            let gate = Self {
                hold: directory.join(format!("{ANCHOR}.hold")),
                reached: directory.join(format!("{ANCHOR}.reached")),
            };
            let _ = std::fs::remove_file(&gate.reached);
            std::fs::write(&gate.hold, b"hold").unwrap();
            gate
        }

        async fn reached(&self) {
            tokio::time::timeout(Duration::from_secs(20), async {
                while !self.reached.exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect(
                "the GET never reached staged_read.unleased.resolved: it did not take the \
                 unleased staged path",
            );
        }

        fn release(&self) {
            std::fs::remove_file(&self.hold).unwrap();
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.hold);
        }
    }

    /// Case (a): a promotion plus stage cleanup purges the epoch under a
    /// paused unleased GET. The GET must fall back, resolve the new `Remote`
    /// head and return the right bytes, and must never demote the fragment.
    ///
    /// The leased pass resolves a `Remote` head, so it takes no reader lease
    /// here; the fallback is evidenced by the fenced `mark_missing` and the one
    /// provider GET. The lease pair on a fallback is pinned by
    /// `fenced_fallback_onto_a_restaged_epoch_takes_exactly_one_lease_pair`.
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL BLAKE3 fixture, Linux roots and staged_read.unleased.resolved=pause"]
    async fn promote_then_cleanup_under_a_paused_unleased_get_falls_back_to_the_remote_epoch() {
        let body = payload();
        let fixture = Fixture::open(
            PutResult::Created,
            remote(raw_fragment(&body), &body),
            body.clone(),
        )
        .await;
        bind_association(&fixture).await;
        let coordinator = &fixture.handle.coordinator;
        let hash = fixture.address.hash.data();
        let gate = Gate::arm();
        let before = Checkouts::take(coordinator);

        let (got, ()) = tokio::join!(optimistic_get(&fixture), async {
            gate.reached().await;
            assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
            assert_eq!(
                fixture.current().await.state,
                FragmentLifecycleState::Remote
            );
            let cleanup = coordinator
                .begin_stage_cleanup(hash, fixture.source_epoch)
                .await
                .unwrap()
                .expect("the promoted predecessor can be reclaimed: nothing leases it");
            fixture
                .handle
                .stage
                .purge_placement(cleanup.target())
                .unwrap();
            coordinator.commit_stage_cleanup(&cleanup).await.unwrap();
            assert_staged_absent(
                &fixture,
                fixture.source_epoch,
                cleanup.target().object_key(),
            )
            .await;
            gate.release();
        });

        let (_, loaded) = got.expect("the GET falls back and succeeds");
        assert_eq!(loaded, body, "correct bytes, from the promoted epoch");
        let delta = Checkouts::take(coordinator).since(before);
        assert_eq!(
            delta.mark_missing, 1,
            "the unleased miss reached mark_missing once, and it was fenced: {delta:?}"
        );
        assert_no_lease(delta);
        assert_eq!(
            fixture.port.gets.load(Ordering::SeqCst),
            1,
            "one remote read"
        );
        assert_eq!(
            head_state(&fixture).await,
            FragmentLifecycleState::Remote.bits(),
            "the fragment was never demoted to Missing"
        );
    }

    /// Case (b): an obliterate purges the epoch under a paused unleased GET.
    /// The fenced miss falls back, the fresh resolve finds nothing readable,
    /// and the client sees `NotFound` with the head left deleting or
    /// tombstoned, never `Missing`.
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL BLAKE3 fixture, Linux roots and staged_read.unleased.resolved=pause"]
    async fn obliterate_under_a_paused_unleased_get_is_not_found_and_never_missing() {
        let body = payload();
        let fixture = Fixture::open(
            PutResult::Created,
            FragmentGetResponse::NotFound,
            body.clone(),
        )
        .await;
        bind_association(&fixture).await;
        let coordinator = &fixture.handle.coordinator;
        let hash = fixture.address.hash.data();
        fixture
            .admin
            .execute(
                "UPDATE lore_fragment_schema_state SET backfill_state=$1,\
                 cutover_at=clock_timestamp(),residue_classified=true,\
                 sequence_headroom_fence=1 WHERE id=1",
                &[&schema::BACKFILL_CUTOVER],
            )
            .await
            .unwrap();
        coordinator.enable_lifecycle().await.unwrap();
        coordinator
            .require_write_claims(&FragmentWriteCapabilityCutover::new("staged-read-v1").unwrap())
            .await
            .unwrap();
        let gate = Gate::arm();
        let before = Checkouts::take(coordinator);

        let (got, ()) = tokio::join!(optimistic_get(&fixture), async {
            gate.reached().await;
            let FragmentObliterateBegin::Ready(deleting) = coordinator
                .begin_obliterate(
                    hash,
                    &REPOSITORY,
                    fixture.address.context.data(),
                    "staged-read-v1",
                )
                .await
                .unwrap()
            else {
                panic!("an unleased staged fragment with no claims is immediately deletable");
            };
            coordinator
                .commit_obliterate_children(&deleting)
                .await
                .unwrap();
            let FragmentObliterateBegin::Ready(deleting) = coordinator
                .begin_obliterate(
                    hash,
                    &REPOSITORY,
                    fixture.address.context.data(),
                    "staged-read-v1",
                )
                .await
                .unwrap()
            else {
                panic!("the payload phase resumes as ready");
            };
            assert!(!deleting.purge_targets().is_empty());
            for target in deleting.purge_targets() {
                assert_eq!(target.authority(), EpochAuthority::Staged);
                fixture.handle.stage.purge_placement(target).unwrap();
                assert_staged_absent(&fixture, target.epoch(), target.object_key()).await;
            }
            let proofs = deleting
                .purge_targets()
                .iter()
                .cloned()
                .map(FragmentPurgeProof::new)
                .collect::<Vec<_>>();
            assert_eq!(
                coordinator
                    .commit_obliterate_payload(&deleting, &proofs)
                    .await
                    .unwrap(),
                CommitVerdict::Published
            );
            gate.release();
        });

        let error = got.expect_err("an obliterated fragment is not readable");
        assert!(
            error.is_address_not_found(),
            "NotFound, not a retry or internal error: {error:?}"
        );
        let delta = Checkouts::take(coordinator).since(before);
        assert_eq!(
            delta.mark_missing, 1,
            "the unleased miss reached mark_missing once, and it was fenced: {delta:?}"
        );
        assert_no_lease(delta);
        let state = head_state(&fixture).await;
        assert_ne!(
            state,
            FragmentLifecycleState::Missing.bits(),
            "an obliterated fragment is never published as Missing"
        );
        assert!(
            [
                FragmentLifecycleState::DeletingChildren.bits(),
                FragmentLifecycleState::DeletingPayload.bits(),
                FragmentLifecycleState::Tombstoned.bits(),
            ]
            .contains(&state),
            "head state {state} must be deleting or tombstoned"
        );
    }

    /// Case (c), the control: a genuine loss with no head move. `mark_missing`
    /// publishes, the client sees `NotFound`, and no lease is ever taken.
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL BLAKE3 fixture, Linux roots and staged_read.unleased.resolved=pause"]
    async fn genuinely_lost_staged_file_is_not_found_and_published_missing_without_a_lease() {
        let body = payload();
        let fixture = Fixture::open(
            PutResult::Created,
            FragmentGetResponse::NotFound,
            body.clone(),
        )
        .await;
        bind_association(&fixture).await;
        let (coordinator, _) = route(&fixture.store);
        let gate = Gate::arm();
        let before = Checkouts::take(coordinator);

        let (got, ()) = tokio::join!(optimistic_get(&fixture), async {
            gate.reached().await;
            delete_staged_file(&fixture, fixture.source_epoch);
            gate.release();
        });

        let error = got.expect_err("a lost staged file is not readable");
        assert!(error.is_address_not_found(), "NotFound: {error:?}");
        let delta = Checkouts::take(coordinator).since(before);
        assert_eq!(
            delta.mark_missing, 1,
            "the miss was published, not fenced: {delta:?}"
        );
        assert_no_lease(delta);
        assert_eq!(
            head_state(&fixture).await,
            FragmentLifecycleState::Missing.bits(),
            "a genuine loss is published as Missing"
        );
    }

    /// A fenced miss whose fresh resolve is still `Staged`, at a new epoch,
    /// is the one fallback that takes a lease: exactly one acquire and one
    /// release, and the bytes come from the new epoch.
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL BLAKE3 fixture, Linux roots and staged_read.unleased.resolved=pause"]
    async fn fenced_fallback_onto_a_restaged_epoch_takes_exactly_one_lease_pair() {
        let body = payload();
        let fixture = Fixture::open(
            PutResult::Created,
            FragmentGetResponse::NotFound,
            body.clone(),
        )
        .await;
        bind_association(&fixture).await;
        let (coordinator, _) = route(&fixture.store);
        let gate = Gate::arm();
        let before = Checkouts::take(coordinator);
        let first_epoch = fixture.source_epoch;

        let (got, restaged_epoch) = tokio::join!(optimistic_get(&fixture), async {
            gate.reached().await;
            let witness = fixture.current().await;
            assert_eq!(witness.epoch, first_epoch);
            assert_eq!(
                coordinator
                    .mark_missing(&witness, MissingDiagnostic::Absent)
                    .await
                    .unwrap(),
                CommitVerdict::Published
            );
            delete_staged_file(&fixture, first_epoch);
            let restaged = fixture
                .store
                .put_staged(
                    coordinator,
                    &fixture.stage,
                    fixture.address,
                    raw_fragment(&body),
                    body.clone(),
                )
                .await
                .unwrap();
            assert!(restaged.epoch > first_epoch, "a fresh epoch");
            assert_eq!(restaged.state, FragmentLifecycleState::Staged);
            gate.release();
            restaged.epoch
        });

        let (_, loaded) = got.expect("the GET falls back onto the restaged epoch");
        assert_eq!(loaded, body);
        let delta = Checkouts::take(coordinator).since(before);
        assert_eq!(
            (delta.lease_acquire, delta.lease_release),
            (1, 1),
            "the fallback took exactly one lease pair: {delta:?}"
        );
        assert_eq!(
            delta.mark_missing, 2,
            "one from this test's own demotion, one fenced miss from the GET: {delta:?}"
        );
        assert_eq!(fixture.current().await.epoch, restaged_epoch);
        assert_eq!(
            head_state(&fixture).await,
            FragmentLifecycleState::Staged.bits()
        );
    }
}

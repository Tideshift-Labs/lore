// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-109 Phase 3: two real loreserver PROCESSES over one cell Postgres database
// and one MinIO bucket, with the CR-029/030/031/032 coordinators, the WP-119
// outbox relay, and the CR-027 remote notification plugin enabled, driven by
// real gRPC clients, with kills and restarts.
//
// Every case is `#[ignore]` and is meant to be run one at a time by
// `tests/run-active-active-two-process-live.ps1`, which gives each case its own
// disposable database and its own MinIO bucket, provisions the gateway, and
// reports PASS / FAIL / NOT RUN against an expected inventory. Running these by
// hand against a shared database is not a proof: see
// `a-cargo-test-run-against-a-shared-database-or-that-never-compiled-is-not-proof.md`.
//
// The support module's own documentation carries the design: which of the three
// roles the harness is playing at each step, why the harness mints its own
// governed carriage, and why no single cell configuration can exercise both the
// public lock path and the governed outbox path today.
#[cfg(all(test, feature = "integration_tests"))]
mod active_active_two_process_tests {
    use std::time::Duration;
    use std::time::Instant;

    use lore_base::types::Hash;
    use lore_base::types::RepositoryId;
    use tonic::Code;

    use crate::active_active_two_process_support::Arming;
    use crate::active_active_two_process_support::Env;
    use crate::active_active_two_process_support::backend::OutboxRow;
    use crate::active_active_two_process_support::backend::SharedBackend;
    use crate::active_active_two_process_support::carriage;
    use crate::active_active_two_process_support::cell::BootOptions;
    use crate::active_active_two_process_support::cell::Cell;
    use crate::active_active_two_process_support::client;
    use crate::active_active_two_process_support::jwks::JwksServer;
    use crate::active_active_two_process_support::jwks::TokenMinter;

    /// The `event_kind` a governed branch push appends
    /// (`lore-postgres/src/domain/outbox/builders.rs`).
    const BRANCH_PUSHED: &str = "branch.pushed";

    /// Ceiling on any "the relay should have got to it by now" wait.
    ///
    /// Generous relative to the 200 ms idle interval, because the first publish
    /// of a process also pays for the lazy gateway channel's first connect.
    const RELAY_DEADLINE: Duration = Duration::from_secs(60);

    /// Ceiling on any "the durable receiver should have got there by now" wait.
    ///
    /// A receiver's bootstrap is a round trip more than a publish: it joins,
    /// opens a `Consume` stream, drains to the captured position, writes a
    /// checkpoint, and only then passes its readiness compare-and-set. The
    /// first of those also pays for the lazy gateway channel's first connect,
    /// which is why this is not tighter than the relay's own bound.
    const RECEIVER_DEADLINE: Duration = Duration::from_secs(60);

    /// Everything a case shares before it decides how many processes to start.
    struct Fixture {
        env: Env,
        /// Held for its `Drop`: both processes fetch keys from it, so it has to
        /// outlive them.
        _jwks: JwksServer,
        minter: TokenMinter,
        backend: SharedBackend,
    }

    impl Fixture {
        /// Read the runner's contract, serve the keys, and prepare the shared
        /// backend for `arming`.
        async fn open(arming: Arming) -> Self {
            let env = Env::from_process();
            std::fs::create_dir_all(&env.work_dir).expect("create the case work directory");
            let jwks = JwksServer::start(env.jwks_port(), &env.jwks_json).await;
            let minter = TokenMinter::from_env(&env);
            let backend = SharedBackend::open(&env, arming).await;
            assert!(
                backend.cutover_stamped().await,
                "the outbox cutover marker must be stamped before any process boots; \
                 the relay's startup gate is fail-closed on it"
            );
            Self {
                env,
                _jwks: jwks,
                minter,
                backend,
            }
        }

        async fn start(&self, name: &'static str, options: BootOptions<'_>) -> Cell {
            let (grpc, http) = match name {
                "a" => self.env.a_ports(),
                "b" => self.env.b_ports(),
                other => panic!("unknown cell name {other}"),
            };
            Cell::start(&self.env, name, grpc, http, &self.env.jwks_url(), options).await
        }
    }

    /// A fresh 16-byte identity.
    ///
    /// UUIDv7 rather than a counter so two cases that somehow shared a database
    /// could not collide silently, and so a repository id read out of a failure
    /// message is traceable to when it was minted.
    fn id16() -> [u8; 16] {
        *uuid::Uuid::now_v7().as_bytes()
    }

    fn repository_id(bytes: [u8; 16]) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = bytes;
        id
    }

    /// Poll `probe` until it reports true, or fail naming what never happened.
    ///
    /// Deliberately not a sleep-then-assert: a fixed sleep either flakes on a
    /// slow machine or wastes the same wall-clock on a fast one, and the
    /// failure message from a bare assertion after a sleep says nothing about
    /// how close it came.
    macro_rules! wait_until {
        ($label:expr, $deadline:expr, $probe:expr) => {{
            let start = Instant::now();
            loop {
                if $probe {
                    break;
                }
                assert!(
                    start.elapsed() < $deadline,
                    "timed out after {:?} waiting for: {}",
                    start.elapsed(),
                    $label
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }};
    }

    /// Create a repository and its default branch through the GOVERNED path.
    ///
    /// Returns the repository id, the default branch id, and the branch name.
    async fn governed_repository(
        fixture: &Fixture,
        through: &Cell,
        token: &str,
        subject: &str,
        label: &str,
    ) -> ([u8; 16], [u8; 16], String) {
        let repository = id16();
        let branch = id16();
        let name = format!("wp109-{label}-{}", hex(&repository[..6]));
        let description = "WP-109 Phase 3 two-process proof";
        let branch_name = "main".to_owned();
        let creator = Some("wp109-harness");

        let prepared = carriage::prepare_repository_create(
            &fixture.backend,
            fixture.minter.issuer(),
            subject,
            &repository,
            &name,
            description,
            &branch,
            &branch_name,
            creator,
            0x11,
        )
        .await;
        let request = carriage::create_request(
            token,
            &repository,
            &name,
            description,
            &branch,
            &branch_name,
            creator,
            &prepared,
        );
        carriage::repository_create(through.grpc_endpoint(), request)
            .await
            .unwrap_or_else(|status| {
                panic!("the governed repository create must succeed, got {status:?}")
            });
        (repository, branch, branch_name)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// True once the broker has accepted this row.
    ///
    /// **Not** `state == "broker_accepted"`, and the difference is load-bearing
    /// now that a durable receiver runs. `broker_accepted` used to be terminal
    /// only because nothing in the tree ever advanced it; the consumer-safety
    /// evaluator moves an accepted row to `consumer_safe` as soon as the
    /// required membership's checkpoints cover its sequence, which on this
    /// two-process cell happens within a probe interval or two of the publish.
    /// A poll comparing against the single string therefore loses the race
    /// roughly whenever the receiver is healthy, and reports it as a
    /// sixty-second timeout on the relay.
    ///
    /// Both states mean the broker accepted the row and only `pending` means it
    /// did not, so this is the whole accepted set rather than a tolerance.
    fn broker_accepted(row: &OutboxRow) -> bool {
        row.state == "broker_accepted" || row.state == "consumer_safe"
    }

    /// The outbox rows a governed push produced, for a message.
    fn describe(rows: &[OutboxRow]) -> String {
        rows.iter()
            .map(|row| {
                format!(
                    "{} kind={} state={} attempts={} owner={:?} seq={:?}",
                    row.event_id,
                    row.event_kind,
                    row.state,
                    row.attempt_count,
                    row.claim_owner,
                    row.broker_sequence
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    // -----------------------------------------------------------------------
    // Case A — both processes serve reads of a repository created through A
    // -----------------------------------------------------------------------

    /// The baseline shared-backend fact, and the one every later case assumes:
    /// a repository created through one process is a repository the other
    /// process can serve, with no replication, no affinity, and no cache
    /// warming between them.
    ///
    /// Run on the public-lock arming because nothing here is governed; the
    /// create takes the legacy path, whose authority is `lore_mutable` rather
    /// than the domain projection.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_a_both_processes_serve_reads_of_a_repository_created_through_a() {
        let fixture = Fixture::open(Arming::PublicLocks).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        let token = fixture.minter.mint("case-a-writer");

        let repository = id16();
        let branch = id16();
        let name = format!("wp109-a-{}", hex(&repository[..6]));

        client::repository_create(
            a.grpc_endpoint(),
            &token,
            &repository,
            &name,
            &branch,
            "main",
        )
        .await
        .unwrap_or_else(|status| panic!("create through process A: {status:?}"));

        // The authority, before either server is asked anything: the create
        // reached the ONE shared database.
        assert!(
            fixture.backend.mutable_key_count(&repository).await > 0,
            "the create must have written the shared mutable store"
        );

        // Both processes serve it. B has never seen a write for this
        // repository and holds no state that A put there.
        for (label, cell) in [("A", &a), ("B", &b)] {
            let response = client::repository_get(cell.grpc_endpoint(), &token, &repository)
                .await
                .unwrap_or_else(|status| panic!("read through process {label}: {status:?}"));
            let served = response
                .repository
                .unwrap_or_else(|| panic!("process {label} returned no repository"));
            assert_eq!(
                served.id.as_ref(),
                &repository[..],
                "process {label} served a different repository id"
            );
            assert_eq!(
                served.name, name,
                "process {label} served a different repository name"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Case B — simultaneous pushes to one branch
    // -----------------------------------------------------------------------

    /// Two governed pushes, one through each process, racing for the same
    /// branch from the same parent. Exactly one advances; the loser is refused;
    /// the branch does not split; and exactly one `branch.pushed` outbox row
    /// exists afterwards.
    ///
    /// The two candidates carry distinctly named nodes on purpose. Revisions
    /// are content-addressed, so two empty revisions off one parent ARE the
    /// same revision and a race between them would prove nothing.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_b_simultaneous_pushes_leave_one_winner_one_branch_and_one_outbox_row() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        let token_a = fixture.minter.mint("case-b-writer-a");
        let token_b = fixture.minter.mint("case-b-writer-b");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token_a, "case-b-writer-a", "b").await;

        let candidate_a = fixture
            .backend
            .serialize_revision(
                repository_id(repository),
                Hash::default(),
                1,
                Some("from-a.txt"),
            )
            .await;
        let candidate_b = fixture
            .backend
            .serialize_revision(
                repository_id(repository),
                Hash::default(),
                1,
                Some("from-b.txt"),
            )
            .await;
        assert_ne!(
            candidate_a, candidate_b,
            "the two racing candidates must be different revisions"
        );

        let carriage_a = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-b-writer-a",
            &repository,
            &branch,
            candidate_a.as_ref(),
            false,
            false,
            0x21,
        )
        .await;
        let carriage_b = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-b-writer-b",
            &repository,
            &branch,
            candidate_b.as_ref(),
            false,
            false,
            0x22,
        )
        .await;

        // Both clients are CONNECTED and both requests fully built before
        // either is sent, so the overlap is the two RPCs and nothing else — not
        // one client still doing TCP and HTTP/2 setup while the other is
        // already committing.
        let mut client_a = carriage::connect_revision(a.grpc_endpoint()).await;
        let mut client_b = carriage::connect_revision(b.grpc_endpoint()).await;
        let request_a = carriage::push_request(
            &token_a,
            &repository,
            &branch,
            candidate_a.as_ref(),
            false,
            false,
            Some(&carriage_a),
        );
        let request_b = carriage::push_request(
            &token_b,
            &repository,
            &branch,
            candidate_b.as_ref(),
            false,
            false,
            Some(&carriage_b),
        );
        let (outcome_a, outcome_b) = tokio::join!(
            carriage::branch_push_on(&mut client_a, request_a),
            carriage::branch_push_on(&mut client_b, request_b),
        );

        let winners = [&outcome_a, &outcome_b]
            .iter()
            .filter(|outcome| outcome.is_ok())
            .count();
        assert_eq!(
            winners, 1,
            "exactly one racing push may advance the branch; A={outcome_a:?} B={outcome_b:?}"
        );

        // The loser must lose for the RIGHT reason. Counting any error as the
        // refusal would let a dead process, a dropped connection, or a bad
        // token stand in for the CAS outcome and the case would still pass.
        // `FAILED_PRECONDITION` is what a non-fast-forward push returns
        // (`lore-server/src/grpc/revision/v1/branch_push.rs:218-233`), and
        // `ABORTED` is the lost-CAS shape the coordinator reports.
        let loser = match (&outcome_a, &outcome_b) {
            (Err(status), Ok(_)) | (Ok(_), Err(status)) => status,
            _ => unreachable!("exactly one winner was already asserted"),
        };
        assert!(
            matches!(loser.code(), Code::FailedPrecondition | Code::Aborted),
            "the losing writer must be refused by the branch CAS, not by transport or auth; \
             got {loser:?}"
        );

        let expected_tip = if outcome_a.is_ok() {
            candidate_a
        } else {
            candidate_b
        };

        // Authority, read over the harness's own connection: one branch row,
        // holding the winner's revision and nothing else.
        assert_eq!(
            fixture.backend.branch_row_count(&repository, &branch).await,
            1,
            "the race must leave exactly one branch row"
        );
        let tip = fixture
            .backend
            .branch_latest_hash(&repository, &branch)
            .await
            .expect("the domain projection must carry the branch");
        assert_eq!(
            tip.as_slice(),
            expected_tip.as_ref(),
            "the authoritative branch tip must be the winner's revision"
        );

        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "a race with one winner must leave exactly one branch.pushed row, got [{}]",
            describe(&rows)
        );
        assert_eq!(
            rows[0].aggregate_kind, "branch",
            "a branch push must be keyed on the branch aggregate"
        );
        assert_eq!(
            rows[0].idempotency_key.len(),
            32,
            "every outbox row carries a 32-byte BLAKE3 idempotency key"
        );
        assert_eq!(
            fixture.backend.dead_letter_count().await,
            0,
            "no row may be dead-lettered by a clean race"
        );
    }

    // -----------------------------------------------------------------------
    // Case C — lock ownership across two processes
    // -----------------------------------------------------------------------

    /// A lock taken through one process is refused through the other, and
    /// becomes available to the other only once the holder releases it.
    ///
    /// This case runs UNARMED. Arming fenced routing makes the public lock
    /// mutation RPCs refuse outright until WP-120's public mutation contract
    /// exists (`lore-server/src/grpc/lock_service.rs:291`, gated by
    /// `PUBLIC_MUTATION_CONTRACT_AVAILABLE`), so the fenced coordinator's
    /// cross-process ownership cannot be exercised through a client at all
    /// today. What is proved here is the shipped path: two processes over one
    /// lock store.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_c_a_lock_held_through_one_process_is_refused_through_the_other() {
        let fixture = Fixture::open(Arming::PublicLocks).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        let token_a = fixture.minter.mint("case-c-holder");
        let token_b = fixture.minter.mint("case-c-contender");

        let repository = id16();
        let branch = id16();
        let name = format!("wp109-c-{}", hex(&repository[..6]));
        client::repository_create(
            a.grpc_endpoint(),
            &token_a,
            &repository,
            &name,
            &branch,
            "main",
        )
        .await
        .unwrap_or_else(|status| panic!("create through process A: {status:?}"));

        let resource = [0x5au8; 32];

        client::lock_acquire(
            a.grpc_endpoint(),
            &token_a,
            &repository,
            &branch,
            &resource,
            "wp109/case-c",
        )
        .await
        .unwrap_or_else(|status| panic!("the first acquire through A must succeed: {status:?}"));

        let held = fixture.backend.lock_owners(&repository).await;
        assert_eq!(
            held.len(),
            1,
            "exactly one lock row after the first acquire"
        );
        let holder = held[0].1.clone();

        let refused = client::lock_acquire(
            b.grpc_endpoint(),
            &token_b,
            &repository,
            &branch,
            &resource,
            "wp109/case-c",
        )
        .await
        .expect_err("a lock held by another owner must be refused through the other process");
        assert_eq!(
            refused.code(),
            Code::FailedPrecondition,
            "a contended lock is refused as FAILED_PRECONDITION, got {refused:?}"
        );
        let after_refusal = fixture.backend.lock_owners(&repository).await;
        assert_eq!(
            after_refusal, held,
            "a refused acquire must not disturb the authoritative lock row"
        );

        client::lock_release(
            a.grpc_endpoint(),
            &token_a,
            &repository,
            &branch,
            &resource,
            &[],
        )
        .await
        .unwrap_or_else(|status| panic!("release through A: {status:?}"));
        assert!(
            fixture.backend.lock_owners(&repository).await.is_empty(),
            "the release must remove the authoritative lock row"
        );

        client::lock_acquire(
            b.grpc_endpoint(),
            &token_b,
            &repository,
            &branch,
            &resource,
            "wp109/case-c",
        )
        .await
        .unwrap_or_else(|status| panic!("acquire through B after release: {status:?}"));

        let successor = fixture.backend.lock_owners(&repository).await;
        assert_eq!(
            successor.len(),
            1,
            "exactly one lock row after the successor"
        );
        assert_ne!(
            successor[0].1, holder,
            "the successor must own the lock, not the released holder"
        );
    }

    // -----------------------------------------------------------------------
    // Case D — kill between COMMIT and the relay claim
    // -----------------------------------------------------------------------

    /// A governed push commits its outbox row; the process that wrote it is
    /// then killed inside the very transaction that was going to claim that row
    /// for publication; after a restart the row is relayed, once.
    ///
    /// The kill is `outbox.claim.before_commit=abort`, which calls
    /// `std::process::abort()` at the anchor
    /// (`lore-postgres/src/domain/fragments/failpoints.rs:343-346`, added for
    /// exactly this case). It is deterministic in a way an external `taskkill`
    /// could not be, and it is reached only when the claim actually selected a
    /// row (`relay.rs:523-527` returns early on an empty selection), so it
    /// cannot fire on an idle tick before the push has even happened.
    ///
    /// Process B is quiet for the first half so the observation "nothing has
    /// claimed this row" is a fact rather than a race; both processes relay for
    /// the recovery half, which is where exactly-once has to hold.
    ///
    /// The fault is armed only AFTER the create's own backlog has drained. A
    /// governed create appends two outbox rows of its own, and an abort armed
    /// from boot would fire on those instead of on the push — a case that says
    /// "killed between a push's COMMIT and its claim" while actually killing on
    /// a repository create is worse than no case at all.
    ///
    /// The case then carries the CONSUMER half, because this is the only case
    /// that already has both processes relaying after a recovery: it waits for
    /// process B's durable receiver to report ready, takes its checkpoint
    /// frontier as a baseline, publishes one more governed push, and requires
    /// that frontier to advance within the same membership generation. The
    /// recovered row above is deliberately not the subject — it may be
    /// published before either receiver has captured a position, so an
    /// assertion on it would be a race between two background loops rather than
    /// a proof.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_d_a_kill_before_the_relay_claim_relays_the_row_exactly_once_after_restart() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let mut a = fixture.start("a", BootOptions::relaying()).await;
        let mut b = fixture.start("b", BootOptions::quiet()).await;
        let token = fixture.minter.mint("case-d-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-d-writer", "d").await;
        // A governed create appends exactly two rows of its own,
        // `repository.published` and `branch.created`
        // (`lore-server/src/domain.rs:811-830`). Asserting they EXIST before
        // waiting for them to drain is what stops the drain from being
        // vacuously satisfied: a create that appended nothing would make both
        // the wait and the fault-arming that follows it meaningless.
        assert_eq!(
            fixture.backend.outbox_rows().await.len(),
            2,
            "a governed create must append its two outbox rows, got [{}]",
            describe(&fixture.backend.outbox_rows().await)
        );
        wait_until!(
            "the governed create's own outbox rows to drain before the fault is armed",
            RELAY_DEADLINE,
            fixture.backend.pending_count().await == 0
        );

        a.restart_with(BootOptions {
            relay_enabled: true,
            failpoints: Some("outbox.claim.before_commit=abort"),
        })
        .await;

        let revision = fixture
            .backend
            .serialize_revision(repository_id(repository), Hash::default(), 1, None)
            .await;
        let prepared = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-d-writer",
            &repository,
            &branch,
            revision.as_ref(),
            false,
            false,
            0x31,
        )
        .await;
        let request = carriage::push_request(
            &token,
            &repository,
            &branch,
            revision.as_ref(),
            false,
            false,
            Some(&prepared),
        );

        // The push itself may or may not get its response back: A is about to
        // abort inside its own relay loop, which is a different task from the
        // one serving this RPC, but the process dies for both. Either outcome
        // is admissible; what matters is the authority afterwards.
        let outcome = carriage::branch_push(a.grpc_endpoint(), request).await;

        a.wait_exit(Duration::from_secs(30)).await;
        assert!(
            a.has_exited(),
            "the failpoint must end process A at its first claim of this row"
        );

        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "the push must have committed exactly one outbox row before the kill \
             (push outcome was {outcome:?}); rows: [{}]",
            describe(&rows)
        );
        assert_eq!(
            rows[0].state, "pending",
            "the killed claim must not have committed"
        );
        assert_eq!(
            rows[0].claim_generation, 0,
            "an aborted claim transaction rolls back its generation bump"
        );
        assert!(
            rows[0].claim_owner.is_none(),
            "no owner may be recorded for a claim that never committed"
        );

        // Recovery: both processes now relay. Exactly one publication may
        // result, whichever of them wins the claim.
        a.restart_with(BootOptions::relaying()).await;
        b.restart_with(BootOptions::relaying()).await;

        wait_until!(
            format!(
                "the recovered row to be accepted by the broker; last seen [{}]",
                describe(&fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await)
            ),
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows_of_kind(BRANCH_PUSHED)
                .await
                .first()
                .is_some_and(broker_accepted)
        );

        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "two relaying processes must not turn one intent into two rows: [{}]",
            describe(&rows)
        );
        assert!(
            rows[0].broker_sequence.is_some(),
            "an accepted row carries the broker sequence its acceptance evidence named"
        );
        assert!(
            rows[0].stream_identity.is_some(),
            "an accepted row records the stream it was accepted on"
        );
        // Kept so the receiver half below can tell the recovered row apart from
        // the push it makes for itself. Without it, "the frontier advanced"
        // could be satisfied by this row, which may be published before either
        // receiver captured a position.
        let recovered_event_id = rows[0].event_id;
        assert_eq!(
            fixture.backend.dead_letter_count().await,
            0,
            "recovery must not dead-letter the row"
        );
        assert_eq!(
            fixture
                .backend
                .branch_latest_hash(&repository, &branch)
                .await,
            Some(revision.as_ref().to_vec()),
            "the branch the killed process advanced must still hold that revision"
        );

        // -- the durable receiver half -----------------------------------
        //
        // Both processes now run one, because both are relaying and the
        // template renders `[plugins.remote.receiver]` with the relay switch.
        //
        // Waiting for B's receiver to report READY is what makes the frontier
        // assertion below discriminating rather than lucky. Ready means it has
        // joined a generation, captured a stream position, taken its
        // authoritative baseline, drained to that position, and written a
        // checkpoint at the cell's current placement. Anything published AFTER
        // that is something it provably had to consume.
        //
        // The recovered row above is deliberately NOT that event: A restarts
        // relaying first and may well publish it before either receiver
        // captures, so an assertion built on it would pass or hang depending on
        // a race between two background loops.
        wait_until!(
            format!(
                "process B's durable receiver to report itself ready; last seen {:?}",
                b.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            b.event_readiness().await.receiver_ready == Some(true)
        );
        let identity = b.receiver_identity();
        let (generation, baseline) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "receiver {identity} reported itself ready, so it must have written a \
                     checkpoint at the current placement: the readiness compare-and-set refuses \
                     without one"
                )
            });

        // A SECOND governed push, so the event whose consumption is asserted
        // provably did not exist when B's receiver captured its position.
        let second = fixture
            .backend
            .serialize_revision(repository_id(repository), revision, 2, None)
            .await;
        let prepared = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-d-writer",
            &repository,
            &branch,
            second.as_ref(),
            false,
            false,
            0x32,
        )
        .await;
        let request = carriage::push_request(
            &token,
            &repository,
            &branch,
            second.as_ref(),
            false,
            false,
            Some(&prepared),
        );
        carriage::branch_push(a.grpc_endpoint(), request)
            .await
            .unwrap_or_else(|status| {
                panic!("the second governed push must succeed, got {status:?}")
            });

        wait_until!(
            format!(
                "the second push's row to be accepted by the broker; last seen [{}]",
                describe(&fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await)
            ),
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows_of_kind(BRANCH_PUSHED)
                .await
                .iter()
                .filter(|row| broker_accepted(row))
                .count()
                == 2
        );

        // The exact sequence the second push was accepted at. Asserting the
        // frontier reaches THIS number, rather than merely that it moved, is
        // what stops the recovered row from satisfying the case: both rows
        // travel the same stream, so "the frontier advanced" alone is true as
        // soon as the receiver consumes either one.
        let second_row = fixture
            .backend
            .outbox_rows_of_kind(BRANCH_PUSHED)
            .await
            .into_iter()
            .find(|row| row.event_id != recovered_event_id)
            .expect("the second governed push must have appended its own outbox row");
        let second_sequence = second_row
            .broker_sequence
            .expect("an accepted row carries the broker sequence its acceptance evidence named");
        assert!(
            second_sequence > baseline,
            "the second push was accepted at sequence {second_sequence}, which is not above the \
             frontier {baseline} the receiver had already proved; the case cannot discriminate"
        );

        wait_until!(
            format!(
                "receiver {identity} to carry its contiguous frontier to at least the second \
                 push's sequence {second_sequence} on generation {generation}; last seen {:?} \
                 with readiness {:?}",
                fixture.backend.checkpoint_frontier_of(&identity).await,
                b.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            fixture
                .backend
                .checkpoint_frontier_of(&identity)
                .await
                .is_some_and(|(seen, frontier)| seen == generation && frontier >= second_sequence)
        );

        // The generation must be the SAME one that was ready. A frontier that
        // "advanced" by retiring and re-capturing at a later position would be
        // a receiver that skipped the event, not one that consumed it.
        let (final_generation, final_frontier) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("the frontier that just advanced must still be readable");
        assert_eq!(
            final_generation, generation,
            "the frontier must advance within the generation that was ready; a new generation \
             captures at a later position and would advance without consuming anything"
        );
        assert!(final_frontier >= second_sequence);
        assert_eq!(
            b.event_readiness().await.receiver_ready,
            Some(true),
            "consuming the event must leave the receiver ready, not blocked on a gap or a \
             parked poison event"
        );
    }

    // -----------------------------------------------------------------------
    // Case E — relay failover after a lease expires
    // -----------------------------------------------------------------------

    /// One process dies holding a live claim; the other takes the row over
    /// under a NEW claim generation and publishes it.
    ///
    /// `outbox.accept.before_update=abort` ends process A after it has claimed
    /// AND published but before it records the acceptance, which is exactly the
    /// window the lease exists for: the row is unreachable to any other worker
    /// until that lease runs out. The gateway may therefore see this event
    /// twice, once from each process — with the same `event_id`, which the
    /// broker's own duplicate window collapses. That duplicate is the expected
    /// shape, not a defect.
    ///
    /// B relays only after A is gone. Leaving both relaying from the start
    /// would make it a coin flip which process claimed first, and a failover
    /// case that half the time never loses a claim-holder proves nothing. For
    /// the same reason the fault is armed only after the governed create's own
    /// two outbox rows have drained.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_e_a_lost_relay_worker_is_reclaimed_by_the_other_process() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let mut a = fixture.start("a", BootOptions::relaying()).await;
        let mut b = fixture.start("b", BootOptions::quiet()).await;
        let token = fixture.minter.mint("case-e-writer");
        let owner_a = a.relay_owner();
        let owner_b = b.relay_owner();
        assert_ne!(
            owner_a, owner_b,
            "the two processes must claim under different owners or a failover is unobservable"
        );

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-e-writer", "e").await;
        // A governed create appends exactly two rows of its own,
        // `repository.published` and `branch.created`
        // (`lore-server/src/domain.rs:811-830`). Asserting they EXIST before
        // waiting for them to drain is what stops the drain from being
        // vacuously satisfied: a create that appended nothing would make both
        // the wait and the fault-arming that follows it meaningless.
        assert_eq!(
            fixture.backend.outbox_rows().await.len(),
            2,
            "a governed create must append its two outbox rows, got [{}]",
            describe(&fixture.backend.outbox_rows().await)
        );
        wait_until!(
            "the governed create's own outbox rows to drain before the fault is armed",
            RELAY_DEADLINE,
            fixture.backend.pending_count().await == 0
        );

        a.restart_with(BootOptions {
            relay_enabled: true,
            failpoints: Some("outbox.accept.before_update=abort"),
        })
        .await;

        let revision = fixture
            .backend
            .serialize_revision(repository_id(repository), Hash::default(), 1, None)
            .await;
        let prepared = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-e-writer",
            &repository,
            &branch,
            revision.as_ref(),
            false,
            false,
            0x41,
        )
        .await;
        let request = carriage::push_request(
            &token,
            &repository,
            &branch,
            revision.as_ref(),
            false,
            false,
            Some(&prepared),
        );
        let outcome = carriage::branch_push(a.grpc_endpoint(), request).await;

        a.wait_exit(Duration::from_secs(60)).await;

        // A died holding the claim, and left a lease behind: at this instant
        // the row belongs to a process that no longer exists, and no other
        // worker may touch it.
        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "one push, one row (push outcome was {outcome:?}); rows: [{}]",
            describe(&rows)
        );
        assert_eq!(
            rows[0].claim_owner.as_deref(),
            Some(owner_a.as_str()),
            "the dead process must still hold the claim it committed"
        );
        assert_eq!(
            rows[0].claim_generation, 1,
            "exactly one claim has been committed so far"
        );
        // Not evidence on its own — every claim writes a lease — but it is
        // what bounds how long a dead owner blocks a successor, so its absence
        // here would mean the claim never really happened.
        assert!(
            rows[0].claim_expires_at.is_some(),
            "a committed claim must carry the lease that bounds how long it blocks a successor"
        );
        assert_eq!(rows[0].state, "pending", "acceptance was never recorded");
        assert!(
            a.has_exited(),
            "process A must be gone before the survivor is allowed to relay, or the takeover \
             below could be A finishing its own work"
        );

        // Only now does the survivor start relaying. It has to take the row
        // over from a lease it did not write.
        b.restart_with(BootOptions::relaying()).await;

        wait_until!(
            format!(
                "process B to take over the abandoned row and publish it; last seen [{}]",
                describe(&fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await)
            ),
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows_of_kind(BRANCH_PUSHED)
                .await
                .first()
                .is_some_and(broker_accepted)
        );

        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "a failover must not duplicate the row: [{}]",
            describe(&rows)
        );
        // Exactly two, not "at least two". A only ever committed one claim and
        // is dead; the survivor took exactly one more. A larger number would
        // mean some third claim happened that this case cannot account for,
        // and `>=` would hide it.
        assert_eq!(
            rows[0].claim_generation, 2,
            "the surviving process must have taken exactly ONE new claim generation, fencing \
             the dead owner out"
        );
        assert!(
            a.has_exited(),
            "the takeover must have been performed by the survivor, with A still gone"
        );
        assert!(
            rows[0].broker_sequence.is_some(),
            "the reclaimed row must carry the acceptance evidence of the publish that stuck"
        );
        assert_eq!(
            fixture.backend.dead_letter_count().await,
            0,
            "a failover is not a poison condition"
        );
    }

    // -----------------------------------------------------------------------
    // Case F — obliterate through one process, observed through the other
    // -----------------------------------------------------------------------

    /// A fragment obliterated through one process stops being readable through
    /// the other, with no restart and no invalidation message in between.
    ///
    /// The obliterated revision is the SECOND one, not the branch tip, and the
    /// refusal asserted is a push OF that revision. That matters for
    /// attribution: obliterating an ancestor walks and deletes its child
    /// fragments, so refusing a push of a descendant could be "the descendant's
    /// own fragments are gone" rather than "the parent is unreadable", and the
    /// case would be claiming something it had not shown. Obliterating exactly
    /// the revision whose push is then refused leaves one explanation.
    ///
    /// The observation from process B is `State::deserialize` on the requested
    /// revision (`lore-server/src/grpc/handlers/branch_push.rs:682`) — a
    /// genuine read of the shared immutable store through B's own code path,
    /// observable through a client, which a direct store query would not be.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_f_an_obliterate_through_one_process_is_seen_by_the_other() {
        let fixture = Fixture::open(Arming::PublicLocks).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;

        let repository = id16();
        let branch = id16();
        // Obliterate is the one path whose permission check does not honour the
        // wildcard resource, so this case needs a token naming the repository
        // exactly. See `TokenMinter::mint_for_repository`.
        let token = fixture
            .minter
            .mint_for_repository("case-f-writer", &repository);
        let name = format!("wp109-f-{}", hex(&repository[..6]));
        client::repository_create(
            a.grpc_endpoint(),
            &token,
            &repository,
            &name,
            &branch,
            "main",
        )
        .await
        .unwrap_or_else(|status| panic!("create through process A: {status:?}"));

        let first = fixture
            .backend
            .serialize_revision(repository_id(repository), Hash::default(), 1, None)
            .await;
        let second = fixture
            .backend
            .serialize_revision(repository_id(repository), first, 2, Some("second.txt"))
            .await;
        for (label, hash) in [("first", &first), ("second", &second)] {
            assert!(
                fixture
                    .backend
                    .fragment_exists(hash.as_ref(), &repository)
                    .await,
                "the fixture must have written the {label} revision into the shared store"
            );
        }

        // Control: before any obliterate, process B can read the shared store
        // and accept a push, which also puts the branch tip at `first` so that
        // `second` is a legitimate fast-forward candidate.
        let request = carriage::push_request(
            &token,
            &repository,
            &branch,
            first.as_ref(),
            false,
            false,
            None,
        );
        carriage::branch_push(b.grpc_endpoint(), request)
            .await
            .unwrap_or_else(|status| {
                panic!("process B must be able to read the revision before it is obliterated: {status:?}")
            });
        assert_eq!(
            fixture
                .backend
                .branch_latest_hash(&repository, &branch)
                .await,
            None,
            "an ungoverned push writes the generic store, not the domain projection"
        );

        // Obliterate the SECOND revision through A. The address of a revision's
        // state fragment is its signature under the zero context.
        client::obliterate(
            a.grpc_endpoint(),
            &token,
            &repository,
            second.as_ref(),
            &[0u8; 16],
        )
        .await
        .unwrap_or_else(|status| panic!("obliterate through process A: {status:?}"));

        // Authority: the tombstone is in the shared database, not in a cache
        // belonging to whichever process performed it.
        wait_until!(
            "the obliterated fragment to stop being readable in the shared database",
            Duration::from_secs(30),
            fixture
                .backend
                .fragment_unreadable(second.as_ref(), &repository)
                .await
        );

        // Process B, which did not perform the obliterate and was not told
        // about it, can no longer read the revision that was obliterated.
        // `NOT_FOUND` exactly: that is the status the push handler returns when
        // `State::deserialize` cannot find the requested revision
        // (`branch_push.rs:682`). Accepting `FAILED_PRECONDITION` too would
        // also accept a non-fast-forward refusal, which would mean the tip had
        // moved rather than that the revision was gone.
        let request = carriage::push_request(
            &token,
            &repository,
            &branch,
            second.as_ref(),
            false,
            false,
            None,
        );
        let refused = carriage::branch_push(b.grpc_endpoint(), request)
            .await
            .expect_err("process B must not serve a push of an obliterated revision");
        assert_eq!(
            refused.code(),
            Code::NotFound,
            "an obliterated revision must read as absent through the other process, got \
             {refused:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Case G — the event-plane readiness facets, at rest
    // -----------------------------------------------------------------------

    /// Both processes report their relay AND durable-receiver facets true with
    /// no work outstanding.
    ///
    /// The receiver facet is a per-PROCESS fact, which is why it is asserted on
    /// each process separately rather than once for the cell: the two
    /// loreservers join the membership under different identities, run
    /// independent generations, and consume through separate durable consumers.
    /// One of them being caught up says nothing about the other.
    ///
    /// A true facet here is not merely "a receiver task exists". The readiness
    /// compare-and-set behind it refuses without a checkpoint at the cell's
    /// current placement, so `receiver_ready == Some(true)` means this process
    /// joined, captured, baselined, drained, and durably reported a frontier —
    /// which is also why the checkpoint row is read back from the database
    /// afterwards rather than trusted from the HTTP body.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_g_both_processes_report_their_event_plane_facets_at_rest() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        let token = fixture.minter.mint("case-g-writer");

        // Give the cell real work first. "At rest" on a database nothing ever
        // wrote to is a state both processes would report without a relay
        // running at all, so a zero backlog would prove nothing. A governed
        // create appends two rows; draining them is what makes the zero
        // meaningful, and it is the SHARED backlog that both processes are
        // then reporting on.
        let (_repository, _branch, _) =
            governed_repository(&fixture, &a, &token, "case-g-writer", "g").await;
        assert_eq!(
            fixture.backend.outbox_rows().await.len(),
            2,
            "a governed create must append its two outbox rows, got [{}]",
            describe(&fixture.backend.outbox_rows().await)
        );
        wait_until!(
            "the cell's outbox backlog to drain through one of the two relays",
            RELAY_DEADLINE,
            fixture.backend.pending_count().await == 0
        );

        for (label, cell) in [("A", &a), ("B", &b)] {
            // The facets are a BOUNDED-STALENESS observation, refreshed on the
            // relay's own probe interval, not a live read of the database.
            // Waiting on the facet rather than asserting it immediately after
            // the SQL backlog cleared is therefore the correct shape: right
            // after the drain, a process can still be reporting the snapshot it
            // took a second earlier, and `relay_ready` does not disambiguate
            // because it is decided on the oldest row's AGE, which is still
            // small while a row is pending.
            wait_until!(
                format!(
                    "process {label}'s relay to report itself running, caught up, and with the \
                     drained backlog reflected in its own snapshot"
                ),
                Duration::from_secs(30),
                {
                    let readiness = cell.event_readiness().await;
                    readiness.configured
                        && readiness.loop_running
                        && readiness.relay_ready
                        && readiness.pending_count == 0
                }
            );
            let readiness = cell.event_readiness().await;
            assert!(
                readiness.configured,
                "process {label} must report a configured relay"
            );
            assert!(
                readiness.loop_running,
                "process {label} must report its relay loop running"
            );
            assert!(
                readiness.relay_ready,
                "process {label} must report the relay facet ready at rest"
            );
            assert!(
                readiness.event_ready,
                "process {label} must report the event facet ready with no parked row"
            );
            assert_eq!(
                readiness.pending_count, 0,
                "process {label} must see the shared backlog drained, not merely empty"
            );
            assert_eq!(
                readiness.dead_letter_count, 0,
                "process {label} must see no dead letters at rest"
            );
            // The receiver facet is on its own clock: it is written by the
            // receiver task, not by the relay's probe, and its bootstrap is a
            // round trip more than a publish. Waiting on it separately keeps a
            // slow first gateway connect from reading as a failed facet.
            wait_until!(
                format!(
                    "process {label}'s durable receiver to report itself ready; last seen {:?}",
                    cell.event_readiness().await
                ),
                RECEIVER_DEADLINE,
                cell.event_readiness().await.receiver_ready == Some(true)
            );
            let readiness = cell.event_readiness().await;
            assert_eq!(
                readiness.receiver_ready,
                Some(true),
                "process {label} must report its durable receiver ready at rest; reason was {:?}",
                readiness.receiver_reason
            );
            assert_eq!(
                readiness.receiver_reason, None,
                "a ready receiver carries no reason"
            );

            // And the facet is backed by a durable checkpoint, read from the
            // database rather than believed from the process reporting on
            // itself. The generation is compared against the one the process
            // reports, so a checkpoint left behind by an earlier generation
            // cannot stand in for this one.
            let identity = cell.receiver_identity();
            let (generation, _) = fixture
                .backend
                .checkpoint_frontier_of(&identity)
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "process {label} reports receiver {identity} ready, so a checkpoint row \
                         must exist: the readiness compare-and-set refuses without one at the \
                         current placement"
                    )
                });
            assert_eq!(
                Some(generation),
                readiness.receiver_generation,
                "process {label}'s checkpoint must belong to the generation it reports running"
            );

            // The frontier has to reach the highest sequence this cell was told
            // one of its own rows was accepted at. That number is the
            // discriminating one: a frontier compared against zero, or against
            // itself, is satisfied by the database CHECK constraint alone and
            // proves nothing about consumption.
            let accepted =
                fixture.backend.max_broker_sequence().await.expect(
                    "the governed create's rows drained, so the cell has accepted sequences",
                );
            wait_until!(
                format!(
                    "process {label}'s receiver {identity} to carry its frontier to the cell's \
                     highest accepted sequence {accepted}; last seen {:?}",
                    fixture.backend.checkpoint_frontier_of(&identity).await
                ),
                RECEIVER_DEADLINE,
                fixture
                    .backend
                    .checkpoint_frontier_of(&identity)
                    .await
                    .is_some_and(|(seen, frontier)| seen == generation && frontier >= accepted)
            );
        }

        assert_ne!(
            a.receiver_identity(),
            b.receiver_identity(),
            "the two processes must join the membership under different identities, or one \
             process's receiver could satisfy an assertion about the other's"
        );
    }

    // -----------------------------------------------------------------------
    // Case H — cross-process fenced lock ownership (CR-030, WP-120)
    // -----------------------------------------------------------------------

    /// A lock acquired through one process is releasable through the other ONLY by presenting
    /// the ownership token the acquire returned. This is Case C's proof one layer further in:
    /// Case C shows the legacy, unfenced lock store agreeing across two processes; this shows the
    /// fenced coordinator's per-resource token agreeing across two processes too, over real gRPC,
    /// each server reaching the coordinator through its own `DomainContext` but the same
    /// database row.
    ///
    /// `Arming::GovernedOutbox` arms fenced lock routing through the same test-only
    /// `enable_fencing_for_component_fixture` bypass `p12_lock_service_fenced_routing.rs` uses
    /// (`active_active_two_process_support::backend::SharedBackend::open`) -- independent of
    /// whether production's `PUBLIC_MUTATION_CONTRACT_AVAILABLE` has flipped, because this case
    /// drives the server's fenced `Lock`/`Unlock` RPCs directly with an explicit token rather
    /// than through the `lore` CLI's own client-side token store.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_h_a_lock_acquired_through_one_process_is_released_through_the_other_only_with_its_token()
     {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        let token = fixture.minter.mint("case-h-owner");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-h-owner", "h").await;
        let resource = [0x8au8; 32];

        let acquired = client::lock_acquire(
            a.grpc_endpoint(),
            &token,
            &repository,
            &branch,
            &resource,
            "wp109/case-h",
        )
        .await
        .unwrap_or_else(|status| panic!("acquire through A must succeed: {status:?}"));
        let ownership_token = acquired
            .locks
            .first()
            .unwrap_or_else(|| panic!("one resource requested, one lock expected: {acquired:?}"))
            .ownership_token
            .to_vec();
        assert_eq!(
            ownership_token.len(),
            32,
            "a fenced acquire must mint a real 32-byte ownership token, got {ownership_token:?}"
        );

        let refused = client::lock_release(
            b.grpc_endpoint(),
            &token,
            &repository,
            &branch,
            &resource,
            &[],
        )
        .await
        .expect_err(
            "releasing a fenced lock through the other process with no token must be refused",
        );
        assert_eq!(
            refused.code(),
            Code::InvalidArgument,
            "a tokenless release of a fenced lock must be INVALID_ARGUMENT, got {refused:?}"
        );
        assert_eq!(
            fixture.backend.lock_owners(&repository).await.len(),
            1,
            "a refused release must not disturb the authoritative lock row"
        );

        client::lock_release(
            b.grpc_endpoint(),
            &token,
            &repository,
            &branch,
            &resource,
            &ownership_token,
        )
        .await
        .unwrap_or_else(|status| {
            panic!(
                "releasing through the OTHER process with the stored token must succeed: {status:?}"
            )
        });
        assert!(
            fixture.backend.lock_owners(&repository).await.is_empty(),
            "the token-bearing release through process B must remove the authoritative lock row"
        );
    }
}

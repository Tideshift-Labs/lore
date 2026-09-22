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
    use lore_postgres::domain::outbox::CheckpointOutcome;
    use lore_proto::lore::domain::v1::DomainOperationOutcome;
    use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
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
    use crate::active_active_two_process_support::rebac_stub::RebacStub;
    use crate::active_active_two_process_support::rebac_stub::policy::Role;

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
        /// The rebac/auth-grpc stand-in both processes point `auth_url` at.
        ///
        /// Held rather than detached because a case asserts against it: how
        /// many direct authorizations it issued, and for whom. It also has to
        /// outlive both processes, which dial it lazily on every governed
        /// mutation and every repository read.
        stub: RebacStub,
        minter: TokenMinter,
        backend: SharedBackend,
    }

    impl Fixture {
        /// Read the runner's contract, serve the keys and the authorizer, and
        /// prepare the shared backend for `arming`.
        async fn open(arming: Arming) -> Self {
            let env = Env::from_process();
            std::fs::create_dir_all(&env.work_dir).expect("create the case work directory");
            let jwks = JwksServer::start(env.jwks_port(), &env.jwks_json).await;
            let stub = RebacStub::start(&env, env.rebac_stub_port()).await;
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
                stub,
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
            Cell::start(
                &self.env,
                name,
                grpc,
                http,
                &self.env.jwks_url(),
                self.stub.url(),
                options,
            )
            .await
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

    /// A subject the DIRECT authorization rail will accept.
    ///
    /// auth-grpc derives the initiating principal namespace as
    /// `"principal-v1\0" || Principal.userId` and denies unless the result is
    /// exactly 49 bytes, which admits only a canonical lowercase UUID. Nothing
    /// in Lore enforces that, so a case using a readable label like
    /// `case-h-owner` would pass against this harness and be refused by the
    /// real platform — the most valuable kind of harness lie to prevent. The
    /// mediated cases keep their readable subjects, which never reach that
    /// gate.
    fn direct_subject() -> String {
        uuid::Uuid::now_v7().to_string()
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

        // Those reads went through the auth-grpc repository-query authorizer,
        // which exists on this cell only because WP-120 wired `auth_url`.
        // Asserted so the new coupling is visible rather than implicit: this
        // case now depends on the harness's stub answering `CheckUserPermission`
        // — permissively, on purpose, so nothing here is evidence about read
        // authorization.
        assert!(
            fixture.stub.permission_checks() >= 2,
            "each process's RepositoryGet must have consulted the authorizer; it saw {} checks",
            fixture.stub.permission_checks()
        );
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
            None,
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
            None,
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
            None,
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
            None,
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

        a.restart_with(BootOptions::with_failpoints(
            "outbox.claim.before_commit=abort",
        ))
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

        a.restart_with(BootOptions::with_failpoints(
            "outbox.accept.before_update=abort",
        ))
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
    ///
    /// `Arming::PublicLocks` is load-bearing here now that WP-120 has wired a
    /// verifier. It leaves domain enforcement OFF, so the carriage-free pushes
    /// this case makes take the legacy path. On an ENFORCING cell they would
    /// take the direct rail instead and be denied for want of a role grant,
    /// which would look like an obliterate that had not worked. A case moved to
    /// `GovernedOutbox` must grant its subject a role and mint a UUID subject.
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
        // A canonical UUID subject, not a readable label, and that is a
        // contract requirement rather than a style choice. auth-grpc derives the
        // initiating principal namespace as `"principal-v1\0" || userId` and
        // denies unless it comes to exactly 49 bytes, which admits only a
        // 36-character lowercase UUID. A case run under `case-h-owner` would
        // pass against this harness and be refused by the real platform.
        let owner = direct_subject();
        let token = fixture.minter.mint(&owner);
        // `lore-authn-bearer` -- the human's own authn JWT, distinct from
        // `token`'s exchanged multiresource shape. WP-120's direct rail
        // requires this on every governed lock RPC; the tightened rebac stub
        // refuses `token` alone for that purpose.
        let authn_token = fixture.minter.mint_authn(&owner);

        let (repository, branch, _) = governed_repository(&fixture, &a, &token, &owner, "h").await;
        // The floor, not a blanket owner. `lock.acquire` and `lock.release` are
        // what any contributor does with their own lock, so `developer` is what
        // the platform's table requires; granting `owner` here would make the
        // case pass without the role check ever being at its boundary.
        fixture.stub.grant(&repository, &owner, Role::Developer);
        let resource = [0x8au8; 32];

        let acquired = client::lock_acquire(
            a.grpc_endpoint(),
            &token,
            Some(&authn_token),
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
            Some(&authn_token),
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
            Some(&authn_token),
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

        // The case must have gone through the direct rail, not around it. A
        // fenced acquire that somehow reached the coordinator without an
        // authorization would satisfy every assertion above and prove nothing
        // about WP-120.
        assert_eq!(
            fixture
                .stub
                .authorized_count(&owner, "lock.acquire", &repository),
            1,
            "the acquire must have been authorized exactly once through the direct rail; \
             the stub issued {:?}",
            fixture.stub.authorized()
        );
        // Exactly one, not "at least one". The tokenless release is refused by
        // the lock service's own argument check before it reaches the rail, so a
        // second authorization here would mean that ordering had changed and a
        // refused release had begun consuming an authorization it never used.
        assert_eq!(
            fixture
                .stub
                .authorized_count(&owner, "lock.release", &repository),
            1,
            "exactly the token-bearing release must have been authorized; the stub issued {:?}",
            fixture.stub.authorized()
        );
        // The lock families are the only ones that supply the BRANCH half of
        // the platform's binding — the five mutation families send it empty —
        // so a case that never looked at it would leave that half unproven.
        for entry in fixture.stub.authorized() {
            assert_eq!(
                entry.branch_id.as_slice(),
                &branch[..],
                "a lock-family authorization must carry the branch it is scoped to, got {entry:?}"
            );
        }
        // And the tokenless refusal must have come from Lore's fenced
        // coordinator, not from the authorizer. `developer` clears every lock
        // family this case uses, so a refusal here would mean the case proved
        // the stub's policy rather than the fence.
        assert!(
            fixture.stub.refusals().is_empty(),
            "the authorizer must refuse nothing in this case; it refused {:?}",
            fixture.stub.refusals()
        );
    }

    // -----------------------------------------------------------------------
    // Case I — a released client's push, reconciled through the other process
    // -----------------------------------------------------------------------

    /// The whole WP-120 released-client round trip, across two processes.
    ///
    /// A human with no carriage pushes through process A. loreserver mints the
    /// operation identity itself, asks the authorizer whether this human may
    /// perform this mutation, runs the ordinary prepare-then-consume rail, and
    /// appends the governed outbox row. The client then asks process B — which
    /// served none of that — what happened to the attempt id it minted before
    /// dispatch, and gets the receipt.
    ///
    /// Three things make this more than case B with the carriage removed:
    ///
    /// * The push is a call a **released client can actually make**. Case B's
    ///   pushes carry carriage this harness minted against the coordinator,
    ///   which no shipped client can produce.
    /// * The receipt is read through the **other process**, so the answer comes
    ///   from the shared coordinator rather than from process A's memory of its
    ///   own write.
    /// * A different principal reading the same attempt id gets `NOT_FOUND`,
    ///   which is the property that makes this RPC safe to expose to a caller
    ///   that is not the control plane: the namespace comes from the verified
    ///   token, so a caller cannot name someone else's.
    ///
    /// The role granted is `developer`, the exact floor `branch.push` requires,
    /// so the gate is exercised at its boundary rather than waved through by an
    /// owner grant.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_i_a_released_client_push_through_a_is_reconciled_through_b_by_attempt_id() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::relaying()).await;
        // Canonical UUID subjects, for the reason case H spells out: auth-grpc
        // denies any subject that cannot key a 49-byte principal namespace.
        let writer = direct_subject();
        let outsider = direct_subject();
        let token = fixture.minter.mint(&writer);
        // The human's own authn JWT for `lore-authn-bearer` -- distinct from
        // `token`'s exchanged multiresource shape, which the tightened rebac
        // stub now refuses as the direct-rail bearer.
        let authn_token = fixture.minter.mint_authn(&writer);
        let stranger = fixture.minter.mint(&outsider);

        // The repository itself still comes through the mediated rail: a
        // direct-human `repository.create` does not exist, on either side. The
        // platform refuses it by name and loreserver's own admission gate
        // returns `Ok(None)` for a create scope, so the create here is
        // deliberately the one governed step this case does NOT prove.
        let (repository, branch, _) = governed_repository(&fixture, &a, &token, &writer, "i").await;
        fixture.stub.grant(&repository, &writer, Role::Developer);

        let candidate = fixture
            .backend
            .serialize_revision(
                repository_id(repository),
                Hash::default(),
                1,
                Some("from-a-released-client.txt"),
            )
            .await;

        // Minted by the CLIENT, before dispatch. That is the whole point of the
        // identity: it is the only thing a client that lost its response still
        // holds.
        let attempt = uuid::Uuid::now_v7();
        client::branch_push_no_carriage(
            a.grpc_endpoint(),
            &token,
            Some(&authn_token),
            &repository,
            &branch,
            candidate.as_ref(),
            attempt,
        )
        .await
        .unwrap_or_else(|status| {
            panic!(
                "a released client's push through process A must succeed: {status:?}; \
                 the authorizer refused {:?}",
                fixture.stub.refusals()
            )
        });

        // The direct rail was actually used. Without this, a cell that had
        // quietly fallen back to the legacy unfenced path would satisfy every
        // assertion below.
        assert_eq!(
            fixture
                .stub
                .authorized_count(&writer, "branch.push", &repository),
            1,
            "the push must have been authorized exactly once through the direct rail; \
             the stub issued {:?}",
            fixture.stub.authorized()
        );
        // A mutation family sends the branch EMPTY, unlike the lock families
        // case H covers. That is loreserver's deliberate deferral, not an
        // absence, and pinning it here keeps a future change that starts
        // sending it from passing unnoticed.
        for entry in fixture.stub.authorized() {
            assert!(
                entry.branch_id.is_empty(),
                "branch.push binds the repository only; loreserver defers the branch half, \
                 got {entry:?}"
            );
        }
        assert!(
            fixture.stub.refusals().is_empty(),
            "the authorizer must refuse nothing in this case; it refused {:?}",
            fixture.stub.refusals()
        );

        // Authority, over the harness's own connection.
        let tip = fixture
            .backend
            .branch_latest_hash(&repository, &branch)
            .await
            .expect("the domain projection must carry the branch after a governed push");
        assert_eq!(
            tip.as_slice(),
            candidate.as_ref(),
            "the authoritative branch tip must be the released client's revision"
        );
        let rows = fixture.backend.outbox_rows_of_kind(BRANCH_PUSHED).await;
        assert_eq!(
            rows.len(),
            1,
            "a carriage-free governed push must append exactly one branch.pushed row, got [{}]",
            describe(&rows)
        );
        assert_eq!(
            rows[0].aggregate_kind, "branch",
            "a branch push must be keyed on the branch aggregate"
        );

        // The reconciliation, through the process that served none of it.
        let receipt = client::attempt_receipt_get(b.grpc_endpoint(), &token, attempt)
            .await
            .unwrap_or_else(|status| {
                panic!("process B must serve the attempt receipt to its own principal: {status:?}")
            });
        assert_eq!(
            receipt.status,
            DomainOperationReceiptStatus::Committed as i32,
            "an applied push must read back COMMITTED through the other process, got {receipt:?}"
        );
        assert_eq!(
            receipt.outcome,
            DomainOperationOutcome::Applied as i32,
            "the committed receipt must report the mutation as applied, got {receipt:?}"
        );
        assert_eq!(
            receipt.method, "branch.push",
            "the receipt must name the family it was filed under, got {receipt:?}"
        );

        // A different subject reads absent. Not an error, and not someone
        // else's receipt: an attempt id belonging to another principal answers
        // exactly as one that never existed.
        let absent = client::attempt_receipt_get(b.grpc_endpoint(), &stranger, attempt)
            .await
            .unwrap_or_else(|status| {
                panic!("a stranger's receipt lookup must be answered, not refused: {status:?}")
            });
        assert_eq!(
            absent.status,
            DomainOperationReceiptStatus::NotFound as i32,
            "another principal must not reach this attempt's receipt, got {absent:?}"
        );
        assert!(
            absent.method.is_empty(),
            "an absent receipt must leak no method, got {absent:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Case J — WP-109 Phase 5: Postgres and relay capacity
    // -----------------------------------------------------------------------

    /// How many governed creates the driven-peak burst issues concurrently.
    ///
    /// Split evenly across both processes, so the peak is a two-replica figure
    /// rather than one process measured twice.
    const BURST: usize = 16;

    /// How long the sampler watches during the burst.
    ///
    /// The case asserts the burst finished inside this window. A burst that
    /// outran the sampler would report a peak from a partial overlap, which is
    /// an understatement that looks like a result — so it fails instead.
    const SAMPLE_WINDOW: Duration = Duration::from_secs(20);

    /// How many kill/restart rounds the leak check runs.
    const RESTART_ROUNDS: usize = 3;

    /// Connections `max_connections` is sized for, for the replica arithmetic.
    ///
    /// Staging's live ceiling, confirmed by direct query in
    /// `lorehub/docs/learnings/do-managed-pg-connection-budget.md` (the
    /// instance was resized `db-s-1vcpu-1gb` -> `db-s-2vcpu-4gb`, 25 -> 100).
    /// The disposable Postgres this case runs on is deliberately sized higher,
    /// so the arithmetic is reported against the real target rather than
    /// against the fixture.
    const STAGING_MAX_CONNECTIONS: f64 = 100.0;

    /// ADR-00025:418-419: planned use stays below 70% of `max_connections`
    /// while retaining one-replica-loss headroom.
    const HEADROOM_FRACTION: f64 = 0.70;

    /// WP-109 Phase 5: idle and peak connections for every pool a loreserver
    /// opens, transaction duration, outbox overhead, restart behavior, and the
    /// safe replica count that follows.
    ///
    /// # Why this is measured from `pg_stat_activity` and not from the server
    ///
    /// A loreserver process opens SIX Postgres pools against its cell database
    /// — immutable, mutable, lock, domain, dispatch, and the outbox relay — and
    /// only four of them report anything. `pool_waiting`/`pool_available`
    /// (`lore-postgres/src/metrics.rs:41-42`) cover the store and domain pools
    /// over OTLP; the relay pool exposes backlog and lag only
    /// (`lore-server/src/event_relay/metrics.rs`) and the dispatch pool exposes
    /// no metric at all. No RPC or HTTP surface reports pool utilisation. The
    /// database is the only vantage point that sees all six, which is why the
    /// whole measurement is taken over the harness's authority connection.
    ///
    /// # What this case deliberately does NOT report
    ///
    /// WP-121 gates placement on "p95 pool acquisition exceeds 100 ms / 250 ms
    /// for 15 minutes". **There is no acquisition-latency emitter anywhere in
    /// the fork** — `latency_ms` (`lore-postgres/src/metrics.rs:50`) is
    /// whole-operation duration, not checkout wait — and adding one would be a
    /// production change WP-109 forbids. So this case reports the
    /// `idle in transaction` and open-transaction-age figures it can actually
    /// see, and reports NO p95 acquisition number. A proof must not quote a
    /// gate it did not measure.
    #[tokio::test]
    #[ignore = "WP-109 Phase 5: needs the runner's disposable Postgres, bucket, gateway and certificates"]
    async fn case_j_two_processes_report_their_connection_and_relay_capacity() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;

        // (1) The harness's own connections, before either process exists.
        // Everything below subtracts this, because nothing in this stack sets
        // `application_name` and a harness connection is otherwise
        // indistinguishable from a server's.
        let (harness, harness_samples) = fixture
            .backend
            .peak_over(Duration::from_secs(2), Duration::from_millis(100))
            .await;
        println!(
            "PHASE5 harness-baseline total={} active={} idle={} in_tx={} samples={}",
            harness.total,
            harness.active,
            harness.idle,
            harness.idle_in_transaction,
            harness_samples
        );

        let mut a = fixture.start("a", BootOptions::relaying()).await;
        let mut b = fixture.start("b", BootOptions::relaying()).await;
        a.wait_ready().await;
        b.wait_ready().await;

        // (2) Idle, both processes up and serving nothing. Pools are lazy
        // (`lore-postgres/src/pool.rs` sets max size only — no min, no idle
        // timeout), so this is expected to sit far below the configured maxima
        // and is the number that makes "peak" the meaningful one.
        let (idle, idle_samples) = fixture
            .backend
            .peak_over(Duration::from_secs(5), Duration::from_millis(100))
            .await;
        let idle_servers = idle.total - harness.total;
        println!(
            "PHASE5 idle-two-processes total={} minus-harness={} active={} idle={} in_tx={} \
             samples={}",
            idle.total,
            idle_servers,
            idle.active,
            idle.idle,
            idle.idle_in_transaction,
            idle_samples
        );

        // (3) Driven peak. Carriage is prepared up front and sequentially, on
        // purpose: preparation runs through the HARNESS's own domain pool, so
        // preparing inside the burst would measure the harness queueing on
        // itself rather than two servers queueing on their pools.
        // One subject, used for BOTH the bearer and the carriage. The
        // coordinator checks the receipt key's `authenticated_subject` against
        // the authenticated bearer, so minting for one subject and preparing
        // under another is refused `ADMISSION_REJECTED_V1`
        // (`lore-postgres/src/domain/postgres_coordinator.rs:570`) — which
        // looks like a capacity failure and is not one. A readable subject
        // rather than `direct_subject()`: this is the governed create rail,
        // which never reaches auth-grpc's 49-byte principal-namespace gate.
        let subject = "case-j-capacity";
        let token = fixture.minter.mint(subject);
        let mut requests = Vec::with_capacity(BURST);
        for index in 0..BURST {
            let repository = id16();
            let branch = id16();
            let name = format!("wp109-j-{index}-{}", hex(&repository[..6]));
            let description = "WP-109 Phase 5 capacity burst";
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
                &token,
                &repository,
                &name,
                description,
                &branch,
                &branch_name,
                creator,
                &prepared,
            );
            requests.push(request);
        }

        let outbox_before = fixture.backend.outbox_rows().await.len();

        // Re-baseline immediately before the burst, and subtract THIS rather
        // than the pre-boot reading. The eight preparations above ran on the
        // harness's own domain pool, which is lazy: connections it opened
        // persist, and counting them as a server's would inflate the peak by
        // up to one pool's worth with no way to tell from the result.
        let pre_burst = fixture.backend.connection_sample().await;
        println!(
            "PHASE5 pre-burst-baseline total={} drift_from_harness_baseline={}",
            pre_burst.total,
            pre_burst.total - harness.total
        );

        // Half through each process. `join_all` would be tidier, but this crate
        // has no `futures` dependency and `tokio::spawn` is out (Lore spawns
        // only through `lore_spawn!`), so the burst is an explicit join of
        // futures — concurrency without tasks, which is all this needs.
        let mut sends = Vec::with_capacity(BURST);
        for (index, request) in requests.into_iter().enumerate() {
            let endpoint = if index % 2 == 0 {
                a.grpc_endpoint()
            } else {
                b.grpc_endpoint()
            };
            sends.push(carriage::repository_create(endpoint, request));
        }
        // The burst times ITSELF, inside its own future. Timing it around the
        // `join!` would time the join — which never returns before the sampler's
        // whole window — and the guard below would then fire on every run
        // regardless of how fast the burst actually was.
        let drive = async {
            let started = Instant::now();
            // Polled together rather than awaited in turn: awaiting each in
            // sequence would issue one request at a time and measure no
            // concurrency at all.
            let outcomes = futures_join(sends).await;
            (outcomes, started.elapsed())
        };
        // 5 ms, not 25: the burst lands in roughly a tenth of a second, so a
        // coarse interval takes only a handful of readings inside the load and
        // reports whichever of them happened to catch the most. The sample
        // count is printed so the reported peak can be read as "the highest of
        // N in-burst readings" rather than as the true maximum.
        let watch = fixture
            .backend
            .peak_over(SAMPLE_WINDOW, Duration::from_millis(5));
        let ((outcomes, burst_elapsed), (peak, peak_samples)) = tokio::join!(drive, watch);

        for (index, outcome) in outcomes.iter().enumerate() {
            outcome.as_ref().unwrap_or_else(|status| {
                panic!("governed create {index} in the capacity burst must succeed: {status:?}")
            });
        }
        assert!(
            burst_elapsed < SAMPLE_WINDOW,
            "the burst ({burst_elapsed:?}) outran the sampling window ({SAMPLE_WINDOW:?}); the \
             peak below would be an understatement taken from a partial overlap"
        );

        let peak_servers = peak.total - pre_burst.total;
        // Readings that actually landed inside the load, at the 5 ms interval.
        // The peak is the highest of THESE, and no more than that.
        let in_burst_samples = (burst_elapsed.as_millis() / 5).max(1);
        println!(
            "PHASE5 driven-peak total={} minus-pre-burst={} active={} idle={} in_tx={} \
             max_xact_ms={:.1} samples={} in_burst_samples≈{} concurrency={} elapsed_ms={}",
            peak.total,
            peak_servers,
            peak.active,
            peak.idle,
            peak.idle_in_transaction,
            peak.max_xact_ms,
            peak_samples,
            in_burst_samples,
            BURST,
            burst_elapsed.as_millis()
        );

        // (4) Outbox overhead. A governed repository create appends exactly two
        // rows — `repository.published` and `branch.created`
        // (`lore-postgres/src/domain/postgres_coordinator.rs:747`) — so the
        // per-mutation cost is a count, not an estimate.
        wait_until!(
            "every burst row to reach the broker",
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows()
                .await
                .iter()
                .all(broker_accepted)
        );
        let rows = fixture.backend.outbox_rows().await;
        let appended = rows.len() - outbox_before;
        let attempts: i32 = rows.iter().map(|row| row.attempt_count).sum();
        println!(
            "PHASE5 outbox-overhead mutations={} rows_appended={} rows_per_mutation={:.2} \
             total_attempts={} dead_letters={}",
            BURST,
            appended,
            appended as f64 / BURST as f64,
            attempts,
            fixture.backend.dead_letter_count().await
        );
        assert_eq!(
            appended,
            BURST * 2,
            "a governed repository create appends exactly two outbox rows; {BURST} creates must \
             append {} and appended {appended}: {}",
            BURST * 2,
            describe(&rows)
        );

        // (5) Repeated restart. The question is whether a process that comes
        // back reopens its pools and settles, or whether each cycle leaves
        // connections behind — the failure mode that exhausts a shared instance
        // after a rolling deploy rather than during one.
        let mut after_restart = peak;
        for round in 1..=RESTART_ROUNDS {
            for (label, cell) in [("a", &mut a), ("b", &mut b)] {
                cell.kill();
                cell.wait_exit(Duration::from_secs(30)).await;
                cell.restart_with(BootOptions::relaying()).await;
                cell.wait_ready().await;
                let sample = fixture
                    .backend
                    .peak_over(Duration::from_secs(3), Duration::from_millis(100))
                    .await
                    .0;
                after_restart = sample;
                println!(
                    "PHASE5 restart round={round} process={label} total={} minus-pre-burst={} \
                     active={} idle={}",
                    sample.total,
                    sample.total - pre_burst.total,
                    sample.active,
                    sample.idle
                );
            }
        }
        let settled_servers = after_restart.total - pre_burst.total;
        // Compared against IDLE, not against the peak. Against the peak this
        // would pass while a process leaked an entire pool every cycle, which
        // is exactly the failure a rolling deploy produces. The tolerance is
        // one replica's idle share: a just-restarted process can still overlap
        // the departing one's connections for a moment.
        let restart_tolerance = idle_servers / 2;
        assert!(
            settled_servers <= idle_servers + restart_tolerance,
            "after {RESTART_ROUNDS} restart rounds the settled connection count \
             ({settled_servers}) exceeded idle ({idle_servers}) by more than one replica's \
             share ({restart_tolerance}); connections are leaking across restarts"
        );

        // (6) The replica arithmetic. Reported against staging's real ceiling,
        // not this fixture's, and stated as what it is: derived from a measured
        // two-process peak on one machine under a burst of `BURST`, not a
        // production load model.
        let per_replica = (peak_servers as f64 / 2.0).ceil();
        let budget = HEADROOM_FRACTION * STAGING_MAX_CONNECTIONS;
        let safe_replicas = (budget / per_replica).floor() - 1.0;
        println!(
            "PHASE5 replica-arithmetic measured_peak_two_processes={peak_servers} \
             measured_per_replica={per_replica} staging_configured_per_replica=24 \
             max_connections={STAGING_MAX_CONNECTIONS} budget_at_70pct={budget} \
             safe_replicas_with_one_loss={safe_replicas}"
        );
        assert!(
            per_replica > 0.0,
            "the burst drove no measurable server connection at all; the peak sampler saw \
             nothing above the harness baseline, so this case measured nothing"
        );
    }

    // -----------------------------------------------------------------------
    // Case K — receiver death and replacement inherits nothing
    // -----------------------------------------------------------------------

    /// A durable receiver generation dies holding an unresolved blocker; its
    /// replacement captures its own position, takes its own baseline, and
    /// drains before it may report ready — and the dead generation can never
    /// again touch a checkpoint once its successor exists.
    ///
    /// Contract: `lorehub/docs/contracts/lore-notification-plane.md`,
    /// "DURABLE_INVALIDATION" ("A hard-dead member may be retired only by
    /// compare-and-set after a replacement with a newer generation proves an
    /// authoritative baseline and persisted checkpoint. Name reuse never
    /// inherits an old checkpoint.") and `report_checkpoint`'s own fenced
    /// contract (`lore-postgres/src/domain/outbox/checkpoint.rs:24-29`): "a
    /// stale generation therefore cannot advance its successor's frontier or
    /// clear a blocker it did not resolve".
    ///
    /// # What is real and what this case injects
    ///
    /// Process B's FIRST generation is entirely real: it boots, joins,
    /// captures, baselines, drains, and passes its readiness CAS exactly as
    /// case G's does, and this case waits on the same `/event_readiness`
    /// facet every other case does before touching anything. The kill is
    /// real too (`Cell::kill`, a hard `SIGKILL`).
    ///
    /// What this case cannot get the harness to do on its own is make a real
    /// process die HOLDING an unresolved blocker: `receiver.rs`'s own resume
    /// rule means an ordinary clean kill-and-restart of a generation with no
    /// blocker RESUMES that same generation, which would prove nothing about
    /// replacement. Nothing in the shipped client surface lets this harness
    /// hand a live receiver a message it cannot apply, and the harness cannot
    /// keep a receiver task alive independently of its whole process. So the
    /// harness stands in for the dying generation's own last gasp
    /// (`receiver.rs`'s `final_checkpoint`, which a hard kill never runs) by
    /// calling the exact function a real generation calls,
    /// [`SharedBackend::report_synthetic_checkpoint`], under generation 1's
    /// own real identity, membership version, and last real frontier, adding
    /// one poison entry. This is the harness playing the role of the dead
    /// process's own shutdown handler with the same write path, schema, and
    /// generation the real process was just running — not a fabricated row.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_k_a_replacement_receiver_generation_inherits_nothing_from_its_dead_predecessor() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let mut b = fixture.start("b", BootOptions::relaying()).await;
        let token = fixture.minter.mint("case-k-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-k-writer", "k").await;

        // Real generation 1: real capture, real baseline, real drain, real
        // readiness CAS.
        wait_until!(
            format!(
                "process B's durable receiver to report itself ready; last seen {:?}",
                b.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            b.event_readiness().await.receiver_ready == Some(true)
        );
        let identity = b.receiver_identity();
        let readiness = b.event_readiness().await;
        let first_generation = readiness
            .receiver_generation
            .expect("a ready receiver reports the generation it is running");
        let (checkpointed_generation, first_frontier) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("a ready receiver has a persisted checkpoint at the current placement");
        assert_eq!(
            checkpointed_generation, first_generation,
            "the checkpoint just read must belong to the generation that reported ready"
        );

        // The real kill. Not a graceful stop: a graceful stop drains and
        // checkpoints on its way out, which is precisely the standing this
        // case must NOT let the dead generation keep.
        b.kill();
        b.wait_exit(Duration::from_secs(30)).await;
        assert!(b.has_exited(), "process B must actually be gone");

        // The harness stands in for generation 1's own dying gasp: the exact
        // write path a real generation uses, under its own identity,
        // membership version, and last proven frontier, now carrying one
        // poison entry. See the case doc comment for why this, and not a
        // live-induced poison, is what the harness can produce here.
        let poisoned_at = first_frontier + 1;
        let outcome = fixture
            .backend
            .report_synthetic_checkpoint(
                &fixture.env,
                &identity,
                first_generation,
                first_frontier,
                Vec::new(),
                vec![(poisoned_at, "SIMULATED_RECEIVER_DEATH")],
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "generation {first_generation} is still current; its own last report must \
                     be accepted: {error:?}"
                )
            });
        assert_eq!(
            outcome,
            CheckpointOutcome::Applied {
                contiguous_frontier: first_frontier
            },
            "the dying generation's own last report is legitimate and must be accepted verbatim"
        );

        // Restart under the SAME receiver identity. Per the resume rule this
        // is not a fresh generation for free: it is refused resumption only
        // because the persisted checkpoint now carries a blocker.
        b.restart_with(BootOptions::relaying()).await;
        wait_until!(
            format!(
                "process B's replacement receiver generation to report itself ready; last seen \
                 {:?}",
                b.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            b.event_readiness().await.receiver_ready == Some(true)
        );
        assert_eq!(
            b.receiver_identity(),
            identity,
            "the replacement must run under the SAME receiver identity; name reuse is the case"
        );
        let readiness = b.event_readiness().await;
        let second_generation = readiness
            .receiver_generation
            .expect("a ready receiver reports the generation it is running");
        assert!(
            second_generation > first_generation,
            "a persisted blocker must force a NEW generation, not a resume of generation \
             {first_generation}; got {second_generation}"
        );

        // The replacement's own checkpoint: a fresh generation, freshly
        // captured and baselined, at or ahead of what the dead generation
        // last proved — not a copy of it.
        let (reported_generation, second_frontier) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("the replacement's own readiness compare-and-set refuses without a checkpoint");
        assert_eq!(reported_generation, second_generation);
        assert!(
            second_frontier >= first_frontier,
            "the replacement's fresh baseline must cover at least what the dead generation \
             already proved; got {second_frontier} against {first_frontier}"
        );

        // The dead generation's OWN row must be exactly what the harness left
        // it at: nobody may have advanced or cleared it on its behalf.
        let (retired_frontier, retired_gaps) = fixture
            .backend
            .checkpoint_row(&identity, first_generation)
            .await
            .expect("the retired generation's own row must still exist");
        assert_eq!(
            retired_frontier, first_frontier,
            "the retired generation's frontier must never move again"
        );
        assert!(
            retired_gaps.is_empty(),
            "this row's blocker was a poison entry, not a gap; a gap here would mean something \
             wrote to this row after retirement"
        );

        // The direct proof: the dead generation itself can never again touch
        // a checkpoint now that a successor exists. Submitted under its own
        // real identity, version, and generation, attempting to advance PAST
        // what the live successor has already proved.
        let forged = fixture
            .backend
            .report_synthetic_checkpoint(
                &fixture.env,
                &identity,
                first_generation,
                second_frontier + 100,
                Vec::new(),
                Vec::new(),
            )
            .await
            .expect("the fence is a normal outcome, not a database error");
        assert_eq!(
            forged,
            CheckpointOutcome::StaleGeneration {
                current_membership_generation: second_generation
            },
            "generation {first_generation} must be refused as stale once generation \
             {second_generation} exists; got {forged:?}"
        );

        // And the refusal must have left the successor's own row untouched.
        let (still_second, _) = fixture
            .backend
            .checkpoint_row(&identity, second_generation)
            .await
            .expect("the successor's row must still exist");
        assert_eq!(
            still_second, second_frontier,
            "a stale generation's refused report must not have moved the successor's frontier"
        );

        // No retained row is stranded or silently credited: the replacement
        // must actually go on to drain NEW work, not merely report a number.
        let revision = fixture
            .backend
            .serialize_revision(repository_id(repository), Hash::default(), 1, None)
            .await;
        let prepared = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            "case-k-writer",
            &repository,
            &branch,
            revision.as_ref(),
            false,
            false,
            0x51,
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
        carriage::branch_push(a.grpc_endpoint(), request)
            .await
            .unwrap_or_else(|status| panic!("the post-replacement push must succeed: {status:?}"));

        let accepted = fixture.backend.max_broker_sequence().await.expect(
            "the post-replacement push must have been accepted by the broker to have a sequence",
        );
        wait_until!(
            format!(
                "the replacement generation {second_generation} to drain the post-replacement \
                 push to sequence {accepted}; last seen {:?}",
                fixture.backend.checkpoint_frontier_of(&identity).await
            ),
            RECEIVER_DEADLINE,
            fixture
                .backend
                .checkpoint_frontier_of(&identity)
                .await
                .is_some_and(|(generation, frontier)| {
                    generation == second_generation && frontier >= accepted
                })
        );
    }

    // -----------------------------------------------------------------------
    // Case L — an unresolved gap blocks the frontier and cannot be skipped
    // -----------------------------------------------------------------------

    /// The contiguous-frontier rule, driven through the real production write
    /// path a live receiver reports through:
    /// [`SharedBackend::report_synthetic_checkpoint`] (over
    /// `lore_postgres::domain::outbox::report_checkpoint`) refuses a
    /// checkpoint report that claims a frontier at or above a gap it still
    /// lists as open, and an unresolved gap sits there even though a later
    /// sequence could otherwise have been acknowledged.
    ///
    /// Contract: `lorehub/docs/contracts/lore-notification-plane.md`,
    /// "DURABLE_INVALIDATION" ("Each receiver frontier is contiguous: an
    /// unresolved gap ... blocks advancement even when a later event was
    /// acknowledged") and `report_checkpoint`'s own doc comment
    /// (`lore-postgres/src/domain/outbox/checkpoint.rs:14-20`): "A receiver
    /// that acknowledged 900-916 and 919-930 with 917-918 unresolved has a
    /// frontier of 916, not 930 — and `report_checkpoint` refuses the report
    /// that says otherwise rather than trusting the reporter to have computed
    /// it correctly."
    ///
    /// # What is real, what this case injects, and why a live broker gap is
    /// out of reach here
    ///
    /// Process A's receiver generation is entirely real: real join, real
    /// capture, real baseline, real drain, real readiness CAS, waited on
    /// through the same `/event_readiness` facet every other case uses.
    ///
    /// A genuine broker-sequence gap in `receiver.rs`'s own tracking
    /// (`frontier.rs`'s `AckFrontier`) requires the broker to actually skip a
    /// delivery to this consumer while delivering a later one — something a
    /// single JetStream durable consumer does not do under ordinary
    /// operation, and which this crate exposes no failpoint to force:
    /// `LORE_FRAGMENT_FAILPOINTS` only reaches the outbox claim/accept sites
    /// cases D and E use, and there is no receiver-side equivalent. **This
    /// case does not claim to have made a live receiver observe a real
    /// gap.** What it proves instead, honestly: the checkpoint PROJECTION
    /// itself — the thing the retention reaper and every future generation's
    /// resume decision reads — refuses a self-contradictory report under this
    /// receiver's own real, live, still-current generation, exactly as its
    /// own doc comment claims. A report is submitted through the exact
    /// function and identity a real receiver would use, first with a
    /// self-consistent unresolved gap (accepted, and provably does not move
    /// the frontier), then a second time under the SAME generation claiming a
    /// higher frontier while still listing that exact gap as open (refused,
    /// pre-database, by the store's own validation, never applied).
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_l_the_checkpoint_projection_refuses_a_frontier_that_skips_an_unresolved_gap() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;

        wait_until!(
            format!(
                "process A's durable receiver to report itself ready; last seen {:?}",
                a.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            a.event_readiness().await.receiver_ready == Some(true)
        );
        let identity = a.receiver_identity();
        let readiness = a.event_readiness().await;
        let generation = readiness
            .receiver_generation
            .expect("a ready receiver reports the generation it is running");
        let (checkpointed_generation, baseline_frontier) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("a ready receiver has a persisted checkpoint at the current placement");
        assert_eq!(
            checkpointed_generation, generation,
            "the checkpoint just read must belong to the generation that reported ready"
        );

        // A self-consistent report: an unresolved gap strictly above the
        // frontier, the frontier itself unmoved. This is the legitimate shape
        // a real receiver's `AckFrontier` produces once it observes a hole;
        // see the case doc comment for why this harness injects it rather
        // than a live broker skip.
        let gap = (baseline_frontier + 2, baseline_frontier + 2);
        let with_gap = fixture
            .backend
            .report_synthetic_checkpoint(
                &fixture.env,
                &identity,
                generation,
                baseline_frontier,
                vec![gap],
                Vec::new(),
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "a self-consistent report from the still-current generation must be \
                     accepted: {error:?}"
                )
            });
        assert_eq!(
            with_gap,
            CheckpointOutcome::Applied {
                contiguous_frontier: baseline_frontier
            },
            "a report naming a gap strictly above its own frontier is legitimate and must be \
             accepted as reported"
        );
        let (_, stored_frontier) = fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("the checkpoint just accepted must be readable");
        assert_eq!(
            stored_frontier, baseline_frontier,
            "an unresolved gap must leave the persisted frontier exactly where it was"
        );
        let (_, stored_gaps) = fixture
            .backend
            .checkpoint_row(&identity, generation)
            .await
            .expect("the row this generation just wrote must exist");
        assert_eq!(
            stored_gaps,
            vec![gap],
            "the projection must carry the exact gap this generation reported"
        );

        // The forged report: the SAME still-current generation now claims a
        // frontier past that gap while still listing it as open — exactly
        // the "a later acknowledgement skips the gap" shape the contract
        // forbids. The store's own input validation must refuse this before
        // any write, per its doc comment.
        let skip_attempt = fixture
            .backend
            .report_synthetic_checkpoint(
                &fixture.env,
                &identity,
                generation,
                gap.1 + 3,
                vec![gap],
                Vec::new(),
            )
            .await;
        let error = skip_attempt.expect_err(
            "a report claiming a frontier at or above its own unresolved gap must be refused, \
             not accepted",
        );
        let message = error.to_string();
        assert!(
            message.contains("unresolved gap"),
            "the refusal must be the frontier-versus-gap rule, not some other rejection: \
             {message}"
        );

        // The refused report must not have touched the projection: the gap
        // and the frontier are exactly what the first, legitimate report
        // left them at.
        let (unmoved_frontier, unmoved_gaps) = fixture
            .backend
            .checkpoint_row(&identity, generation)
            .await
            .expect("the row must still exist");
        assert_eq!(
            unmoved_frontier, baseline_frontier,
            "a refused report must never move the frontier, forged or not"
        );
        assert_eq!(
            unmoved_gaps,
            vec![gap],
            "a refused report must leave the previously reported gap exactly as it was"
        );
        assert_eq!(
            a.event_readiness().await.receiver_ready,
            Some(true),
            "this harness-injected report never reached the live receiver's own in-memory \
             session, so its facet is unaffected; asserted so a reader does not mistake this for \
             a live-receiver gap"
        );
    }

    // -----------------------------------------------------------------------
    // Cases M..Q — the receiver-side fault tier (WP-119 Phase 10, WP-111 P5)
    // -----------------------------------------------------------------------
    //
    // Everything below runs against the REAL plane end to end: a governed
    // mutation committed on one loreserver, its CR-032 outbox row, a real
    // relay claim, a real mTLS Publish into the real notification gateway, real
    // JetStream, the other process's real `Consume` stream, its real receiver,
    // and its real Postgres checkpoint projection. Nothing is stood in for.
    //
    // What makes that possible is `lore-server`'s receiver-side fault seam
    // (`plugins::remote_notification::faults`), which cases K and L could not
    // use because it did not exist: their doc comments record that
    // `LORE_FRAGMENT_FAILPOINTS` reaches only the producer half, so a genuine
    // broker-sequence gap was out of reach and case L wrote the projection
    // directly instead. Case N below is the live version of what case L could
    // only assert about the projection, and the two are kept apart on purpose —
    // L still proves the projection refuses a bad report from ANY reporter,
    // which is a claim about the store, not about a receiver.
    //
    // The fault is armed at RUNTIME through a rendezvous file rather than by an
    // ordinal chosen up front, and every case waits for the process's own
    // `.fired` marker before asserting. An assertion made without that wait
    // cannot distinguish "the receiver handled the injected fault" from "the
    // fault never fired", which is the difference these cases exist to make.

    /// Anchor spellings, so a case names a fault the same way the server parses
    /// it. A typo here would arm nothing and the `.fired` wait would time out,
    /// which is the failure mode to prefer over a silent pass.
    const FAULT_DROP: &str = "receiver.stream.drop";
    const FAULT_DUPLICATE: &str = "receiver.stream.duplicate";
    const FAULT_STREAM_TRANSIENT: &str = "receiver.stream.transient";
    const FAULT_ACK_TRANSIENT: &str = "receiver.ack.transient";

    /// Ceiling on a wait that depends on the broker redelivering an unacked
    /// message.
    ///
    /// Deliberately far above [`RECEIVER_DEADLINE`]: redelivery is gated on
    /// JetStream's own `ack_wait`, which the gateway provisions at 30 seconds,
    /// and a bound under that would report a correct receiver as a failure.
    const REDELIVERY_DEADLINE: Duration = Duration::from_secs(150);

    /// Push one revision through `through` and return the branch tip it left.
    ///
    /// `previous` is the parent revision and `number` its revision number, so a
    /// case can chain pushes and give ONE aggregate key a rising ordinal
    /// sequence — which is what a gap has to be a gap in. A gap needs a skip
    /// within a sequence this generation was already following, so a case that
    /// pushed to three different branches would produce three unrelated
    /// aggregates and no gap at all.
    async fn governed_push(
        fixture: &Fixture,
        through: &Cell,
        token: &str,
        subject: &str,
        repository: &[u8; 16],
        branch: &[u8; 16],
        previous: Hash,
        number: u64,
        nonce: u8,
    ) -> Hash {
        let revision = fixture
            .backend
            .serialize_revision(
                repository_id(*repository),
                previous,
                number,
                Some(&format!("push-{number}.txt")),
            )
            .await;
        let prepared = carriage::prepare_push(
            &fixture.backend,
            fixture.minter.issuer(),
            subject,
            repository,
            branch,
            revision.as_ref(),
            false,
            false,
            nonce,
        )
        .await;
        let request = carriage::push_request(
            token,
            repository,
            branch,
            revision.as_ref(),
            false,
            false,
            Some(&prepared),
        );
        carriage::branch_push(through.grpc_endpoint(), request)
            .await
            .unwrap_or_else(|status| {
                panic!("the governed push at revision {number} must succeed: {status:?}")
            });
        revision
    }

    /// The evidence line one FIRING of `anchor` writes.
    ///
    /// Matches `anchor=`, not the bare anchor name: the server logs an
    /// `armed=<...>` banner at startup naming every armed anchor, and counting
    /// the bare name would score that banner as a firing.
    fn fired_line(anchor: &str) -> String {
        format!("RECEIVER_FAULT anchor={anchor}")
    }

    /// The traced-apply evidence line for ONE event kind of one repository.
    ///
    /// Necessary rather than decorative: a governed repository create appends
    /// `repository.published` and `branch.created` before any push appends
    /// `branch.pushed`, so a count matched on the repository alone answers
    /// three for a repository whose push was applied exactly once. An
    /// exactly-once assertion has to name the aggregate it is counting.
    fn applied_event_line(repository: &[u8; 16], event_kind: &str) -> String {
        format!(
            "RECEIVER_FAULT target=apply repository={} event_kind={event_kind}",
            hex(repository)
        )
    }

    /// The traced-refetch evidence line.
    fn refetch_line(repository: &[u8; 16]) -> String {
        format!(
            "RECEIVER_FAULT target=refetch repository={}",
            hex(repository)
        )
    }

    /// Wait until process `cell`'s current receiver generation has a checkpoint
    /// covering `sequence`, and return that generation.
    async fn wait_for_frontier(fixture: &Fixture, cell: &Cell, sequence: i64, label: &str) -> i64 {
        let identity = cell.receiver_identity();
        wait_until!(
            format!(
                "{label}: {}'s receiver frontier to cover sequence {sequence}; last seen {:?}",
                cell.name,
                fixture.backend.checkpoint_frontier_of(&identity).await
            ),
            RECEIVER_DEADLINE,
            fixture
                .backend
                .checkpoint_frontier_of(&identity)
                .await
                .is_some_and(|(_, frontier)| frontier >= sequence)
        );
        fixture
            .backend
            .checkpoint_frontier_of(&identity)
            .await
            .expect("the frontier just observed must still be readable")
            .0
    }

    /// Wait until every relayed event has reached `cell`'s receiver and its
    /// frontier covers all of them.
    ///
    /// Arming a delivery fault needs this, and skipping it is how case O first
    /// failed: a governed repository create appends its own events, and a fault
    /// armed while those are still in flight lands on one of THEM rather than
    /// on the push the case is about. The fault still fires and the assertion
    /// still reads a real log, so the failure looks like a receiver defect
    /// rather than a setup race.
    async fn wait_for_quiescence(fixture: &Fixture, cell: &Cell, label: &str) {
        let identity = cell.receiver_identity();
        wait_until!(
            format!(
                "{label}: {}'s receiver to drain the setup events; pending={:?} max_seq={:?} \
                 frontier={:?}",
                cell.name,
                fixture.backend.pending_count().await,
                fixture.backend.max_broker_sequence().await,
                fixture.backend.checkpoint_frontier_of(&identity).await
            ),
            RECEIVER_DEADLINE,
            fixture.backend.pending_count().await == 0
                && match fixture.backend.max_broker_sequence().await {
                    None => false,
                    Some(max) => fixture
                        .backend
                        .checkpoint_frontier_of(&identity)
                        .await
                        .is_some_and(|(_, frontier)| frontier >= max),
                }
        );
    }

    /// Wait until `cell` reports its durable receiver ready.
    async fn wait_for_receiver(cell: &Cell) {
        wait_until!(
            format!(
                "process {}'s durable receiver to report itself ready; last seen {:?}",
                cell.name,
                cell.event_readiness().await
            ),
            RECEIVER_DEADLINE,
            cell.event_readiness().await.receiver_ready == Some(true)
        );
    }

    // -----------------------------------------------------------------------
    // Case M — a mutation committed on A is applied by B's durable receiver
    // -----------------------------------------------------------------------

    /// The completion criterion of the local event plane, end to end, with no
    /// component stood in for: a governed push committed through process A
    /// becomes an invalidation process B's receiver **applies**, named by
    /// repository and aggregate ordinal.
    ///
    /// Contract: `lorehub/docs/contracts/lore-notification-plane.md`,
    /// "DURABLE_INVALIDATION".
    ///
    /// # Why the traced target, and not just the frontier
    ///
    /// Every earlier case in this file proves B's receiver *advanced* — that
    /// its contiguous frontier covered a broker sequence. That is a real fact
    /// and an insufficient one for this claim: a frontier advances for a
    /// duplicate, a stale no-op, and a refetch exactly as it does for an apply,
    /// so "the frontier moved past A's push" is consistent with B never having
    /// applied anything. `LORE_RECEIVER_FAULT_TRACE` makes the apply itself an
    /// artifact carrying the repository, the event kind, and the ordinal, so
    /// the assertion is about the event rather than about a number.
    ///
    /// The target it traces is still `NoopInvalidationTarget`'s behaviour — a
    /// `remote`-mode cell has no repository-scoped derived state to evict — so
    /// this changes what is *visible*, not what the receiver *does*.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_m_a_mutation_committed_on_a_is_applied_by_bs_durable_receiver() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture.start("b", BootOptions::traced()).await;
        let token = fixture.minter.mint("case-m-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-m-writer", "m").await;
        wait_for_receiver(&b).await;

        // The mutation. Committed on A, and A is the only process it touches.
        let revision = governed_push(
            &fixture,
            &a,
            &token,
            "case-m-writer",
            &repository,
            &branch,
            Hash::default(),
            1,
            0x61,
        )
        .await;

        // One durable outbox intent, of the expected kind, accepted by the
        // real broker. Asserted before the receiver half so a failure
        // downstream cannot be misread as a producer fault.
        wait_until!(
            format!(
                "A's governed push to reach the broker; rows: {}",
                describe(&fixture.backend.outbox_rows().await)
            ),
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows_of_kind(BRANCH_PUSHED)
                .await
                .iter()
                .any(broker_accepted)
        );
        let accepted = fixture
            .backend
            .max_broker_sequence()
            .await
            .expect("an accepted row carries the sequence the broker assigned it");

        // The receiver half, on the OTHER process.
        wait_for_frontier(&fixture, &b, accepted, "case M").await;
        wait_until!(
            format!(
                "process B to apply repository {}'s invalidation; log tail: {}",
                hex(&repository),
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)) >= 1
        );

        // The branch tip A wrote is the one B's own reads answer with, which is
        // the data-plane half of the same visibility claim. Case A proves this
        // for a repository create; asserted here too so this case stands alone
        // as "the mutation is visible through B", not only "an event was".
        assert_eq!(
            fixture
                .backend
                .branch_latest_hash(&repository, &branch)
                .await,
            Some(revision.as_ref().to_vec()),
            "the committed branch tip must be the revision A pushed"
        );
        assert_eq!(
            b.log_lines_containing(&refetch_line(&repository)),
            0,
            "an ordinary delivery must be applied, never refetched; a refetch here would mean \
             the receiver could not order the event"
        );
    }

    // -----------------------------------------------------------------------
    // Case N — a live receiver observes a REAL gap, refetches, and recovers
    // -----------------------------------------------------------------------

    /// WP-119 Phase 10's gap/refetch row, closed: a live durable receiver, on a
    /// live broker, never receives one delivery, observes the resulting
    /// version gap, issues an authoritative refetch **before** acknowledging,
    /// persists a real gap blocker that stalls its contiguous frontier, and
    /// then recovers when the broker redelivers the missing message.
    ///
    /// Contract: `lorehub/docs/contracts/lore-notification-plane.md`,
    /// "DURABLE_INVALIDATION" ("Each receiver frontier is contiguous: an
    /// unresolved gap ... blocks advancement even when a later event was
    /// acknowledged"), and the receiver's own rule
    /// (`plugins/remote_notification/receiver.rs`): "a gap or an incomparable
    /// version is resolved by authoritative refetch BEFORE the acknowledgement,
    /// never by picking an order."
    ///
    /// # What is real
    ///
    /// All of it, which is the point. The three pushes are real governed
    /// mutations on process A; the events reach process B through the real
    /// relay, the real gateway, and real JetStream; B's receiver is the shipped
    /// one, unmodified. The single injected fact is that B's durable stream
    /// never hands ONE delivery to the receiver — the shape a lost delivery
    /// has from inside a consumer — and because that message is therefore never
    /// acknowledged, the BROKER's own `ack_wait` redelivers it, which is what
    /// the recovery half then rides.
    ///
    /// # Why three pushes to one branch
    ///
    /// A gap is a skip within a sequence this generation was already
    /// following. `AppliedVersions::verdict` answers `NextOrdinal` for an
    /// aggregate with nothing applied yet, deliberately, so dropping the FIRST
    /// event a receiver ever sees for a branch produces no gap at all. Push one
    /// establishes the applied ordinal, push two is dropped, push three is the
    /// skip.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_n_a_dropped_delivery_makes_a_live_receiver_refetch_and_then_recover() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture
            .start(
                "b",
                BootOptions::receiver_faults("receiver.stream.drop=next"),
            )
            .await;
        let token = fixture.minter.mint("case-n-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-n-writer", "n").await;
        wait_for_receiver(&b).await;

        // Push 1: establishes the applied ordinal for this aggregate. Nothing
        // is armed yet, so this delivery is ordinary.
        let first = governed_push(
            &fixture,
            &a,
            &token,
            "case-n-writer",
            &repository,
            &branch,
            Hash::default(),
            1,
            0x71,
        )
        .await;
        let first_sequence = wait_for_accepted_pushes(&fixture, 1, "case N push 1").await;
        let generation = wait_for_frontier(&fixture, &b, first_sequence, "case N push 1").await;
        assert!(
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)) >= 1,
            "push 1 must be APPLIED, not merely acknowledged; without an applied ordinal for \
             this aggregate a later skip is not a gap. Log tail: {}",
            b.log_tail()
        );

        // Arm, then push 2. The arm is deliberately after push 1's frontier is
        // proven, so the fault cannot land on a bootstrap drain delivery.
        b.arm_receiver_fault(FAULT_DROP);
        let second = governed_push(
            &fixture,
            &a,
            &token,
            "case-n-writer",
            &repository,
            &branch,
            first,
            2,
            0x72,
        )
        .await;
        let dropped_sequence = wait_for_accepted_pushes(&fixture, 2, "case N push 2").await;
        wait_until!(
            format!(
                "process B's durable stream to drop one delivery; log tail: {}",
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.fault_fired(FAULT_DROP)
        );

        // Push 3: the skip. B has applied ordinal 1, never saw ordinal 2, and
        // now sees ordinal 3 for the same aggregate key.
        governed_push(
            &fixture,
            &a,
            &token,
            "case-n-writer",
            &repository,
            &branch,
            second,
            3,
            0x73,
        )
        .await;
        let third_sequence = wait_for_accepted_pushes(&fixture, 3, "case N push 3").await;

        wait_until!(
            format!(
                "process B's receiver to refetch repository {} after the gap; log tail: {}",
                hex(&repository),
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.log_lines_containing(&refetch_line(&repository)) >= 1
        );

        // The persisted blocker, from a live receiver's own projection. This is
        // exactly the fact case L had to write by hand.
        wait_until!(
            format!(
                "process B's checkpoint to carry the gap at {dropped_sequence}; last seen {:?}",
                fixture
                    .backend
                    .checkpoint_row(&b.receiver_identity(), generation)
                    .await
            ),
            RECEIVER_DEADLINE,
            fixture
                .backend
                .checkpoint_row(&b.receiver_identity(), generation)
                .await
                .is_some_and(|(_, gaps)| gaps
                    .iter()
                    .any(|(from, to)| *from <= dropped_sequence && dropped_sequence <= *to))
        );
        let (blocked_frontier, gaps) = fixture
            .backend
            .checkpoint_row(&b.receiver_identity(), generation)
            .await
            .expect("the generation that just reported a gap must have a row");
        assert!(
            blocked_frontier < third_sequence,
            "an unresolved gap at {dropped_sequence} must block the frontier below the later \
             acknowledged sequence {third_sequence}; got {blocked_frontier} with gaps {gaps:?}"
        );

        // Recovery. The dropped message was never acknowledged, so the broker's
        // own ack_wait redelivers it; the fault is one-shot and spent, so this
        // time the receiver sees it. The refetch already forgot this
        // repository's applied versions, so the redelivery is applied rather
        // than refused, and the frontier closes over the whole run.
        wait_until!(
            format!(
                "the broker to redeliver sequence {dropped_sequence} and process B to close its \
                 frontier past {third_sequence}; last seen {:?}",
                fixture
                    .backend
                    .checkpoint_row(&b.receiver_identity(), generation)
                    .await
            ),
            REDELIVERY_DEADLINE,
            fixture
                .backend
                .checkpoint_row(&b.receiver_identity(), generation)
                .await
                .is_some_and(|(frontier, gaps)| frontier >= third_sequence && gaps.is_empty())
        );

        // Recovery must not have cost a generation: a gap is resolved in place,
        // not by retiring and rebootstrapping.
        assert_eq!(
            b.event_readiness().await.receiver_generation,
            Some(generation),
            "a resolved gap must not retire the generation that observed it"
        );
        assert_eq!(
            b.log_lines_containing(&fired_line(FAULT_DROP)),
            1,
            "the drop anchor is one-shot; a second firing would have swallowed the redelivery \
             too and made the recovery half vacuous. Log tail: {}",
            b.log_tail()
        );
    }

    // -----------------------------------------------------------------------
    // Case O — a duplicated delivery is an acknowledged no-op, applied once
    // -----------------------------------------------------------------------

    /// At-least-once delivery, absorbed: the same durable invalidation arrives
    /// twice at a live receiver and is applied exactly once, acknowledged both
    /// times, and advances the frontier without a blocker.
    ///
    /// Contract: the outcome matrix's "duplicate" row, and
    /// `AppliedVersions::verdict` answering `VersionOrder::Equal`.
    ///
    /// The exactly-once assertion is a COUNT, not a presence check. "At least
    /// one apply" is satisfied by the double apply this case exists to refuse,
    /// which is why the traced line is counted rather than searched for.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_o_a_duplicated_delivery_is_applied_once_and_acknowledged_twice() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture
            .start(
                "b",
                BootOptions::receiver_faults("receiver.stream.duplicate=next"),
            )
            .await;
        let token = fixture.minter.mint("case-o-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-o-writer", "o").await;
        wait_for_receiver(&b).await;
        // The create's own events must land BEFORE the fault is armed, or the
        // duplicate fires on one of them and this case silently stops being
        // about the push.
        wait_for_quiescence(&fixture, &b, "case O setup").await;
        let generation = b
            .event_readiness()
            .await
            .receiver_generation
            .expect("a ready receiver reports its generation");

        b.arm_receiver_fault(FAULT_DUPLICATE);
        governed_push(
            &fixture,
            &a,
            &token,
            "case-o-writer",
            &repository,
            &branch,
            Hash::default(),
            1,
            0x81,
        )
        .await;
        let accepted = wait_for_accepted_pushes(&fixture, 1, "case O push").await;
        wait_until!(
            format!(
                "process B's durable stream to replay one delivery; log tail: {}",
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.fault_fired(FAULT_DUPLICATE)
        );
        wait_for_frontier(&fixture, &b, accepted, "case O").await;

        // The duplicate is acknowledged, so nothing blocks; and the whole point
        // is that the SECOND copy changed no derived state.
        let (frontier, gaps) = fixture
            .backend
            .checkpoint_row(&b.receiver_identity(), generation)
            .await
            .expect("the ready generation must have a checkpoint row");
        assert!(
            gaps.is_empty(),
            "a duplicate is an acknowledged no-op and must leave no blocker; got {gaps:?}"
        );
        assert!(
            frontier >= accepted,
            "the duplicate was acknowledged twice, so the frontier must still cover \
             {accepted}; got {frontier}"
        );
        assert_eq!(
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)),
            1,
            "the repeated stable event must be ONE invalidation, applied once. Log tail: {}",
            b.log_tail()
        );
        assert_eq!(
            b.log_lines_containing(&fired_line(FAULT_DUPLICATE)),
            1,
            "the duplicate anchor is one-shot; a second firing would mean the count above is \
             about a different delivery than the case thinks"
        );
        // Without this the case is satisfiable with no duplicate ever
        // delivered: "applied exactly once" is trivially true of a stream that
        // carried the event once. The replay line is the only proof the
        // receiver was actually handed the same event twice.
        assert_eq!(
            b.log_lines_containing(&format!("RECEIVER_FAULT replay anchor={FAULT_DUPLICATE}")),
            1,
            "the stashed copy must actually have been REPLAYED to the receiver, not merely \
             stashed. Log tail: {}",
            b.log_tail()
        );
        assert_eq!(
            b.log_lines_containing(&refetch_line(&repository)),
            0,
            "a duplicate is orderable and must never trigger an authoritative refetch"
        );
    }

    // -----------------------------------------------------------------------
    // Case P — a transient read failure reconnects without costing a generation
    // -----------------------------------------------------------------------

    /// A durable-stream read fails transiently under a live receiver. The
    /// receiver acknowledges nothing, backs off, resumes on the SAME
    /// generation, and goes on to drain the event it was reaching for.
    ///
    /// Contract: `StreamError::Transient`'s own rule — "the receiver backs off,
    /// leaves everything unacknowledged, and fails its lag readiness facet. It
    /// never acknowledges to clear a transient failure" — and the asymmetry
    /// amendment A-26 records, under which only a `FAILED_PRECONDITION` class
    /// retires a generation.
    ///
    /// The sharp assertion is the generation. A receiver that treated a
    /// transient read as fatal would still end up ready, still end up with a
    /// covering frontier, and still look entirely healthy in every check except
    /// this one — it would simply have paid a full rebootstrap for a blip.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_p_a_transient_read_failure_reconnects_without_costing_a_generation() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture
            .start(
                "b",
                BootOptions::receiver_faults("receiver.stream.transient=next"),
            )
            .await;
        let token = fixture.minter.mint("case-p-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-p-writer", "p").await;
        wait_for_receiver(&b).await;
        wait_for_quiescence(&fixture, &b, "case P setup").await;
        let generation = b
            .event_readiness()
            .await
            .receiver_generation
            .expect("a ready receiver reports its generation");

        // Arm FIRST, then push. The order is not cosmetic and the reverse does
        // not work: a `receiver.stream.transient` trigger is evaluated at the
        // start of a `next` call, and an idle receiver is BLOCKED inside a
        // `next` that the gateway's `Consume` stream has not answered. Arming a
        // quiet receiver therefore fires nothing until traffic wakes that call,
        // which is how this case first failed — a sixty-second timeout that
        // reads like a broken decorator and is really a long-poll.
        b.arm_receiver_fault(FAULT_STREAM_TRANSIENT);
        let first = governed_push(
            &fixture,
            &a,
            &token,
            "case-p-writer",
            &repository,
            &branch,
            Hash::default(),
            1,
            0x91,
        )
        .await;
        let first_sequence = wait_for_accepted_pushes(&fixture, 1, "case P push 1").await;
        wait_until!(
            format!(
                "process B's durable stream to fail one read transiently; log tail: {}",
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.fault_fired(FAULT_STREAM_TRANSIENT)
        );
        wait_for_frontier(&fixture, &b, first_sequence, "case P push 1").await;

        // The recovery half. A second push AFTER the transient read proves the
        // receiver is still consuming rather than merely still alive: the
        // failure left everything unacknowledged, the receiver backed off, and
        // it is now draining new work on the SAME generation.
        governed_push(
            &fixture,
            &a,
            &token,
            "case-p-writer",
            &repository,
            &branch,
            first,
            2,
            0x92,
        )
        .await;
        let accepted = wait_for_accepted_pushes(&fixture, 2, "case P push 2").await;
        let after = wait_for_frontier(&fixture, &b, accepted, "case P push 2").await;

        assert_eq!(
            after, generation,
            "a transient read is not a placement move; generation {generation} must survive it \
             rather than being retired and replaced by {after}"
        );
        assert_eq!(
            b.log_lines_containing(&fired_line(FAULT_STREAM_TRANSIENT)),
            1,
            "the transient anchor is one-shot; a second firing would mean the recovery above \
             was never actually tested"
        );
        wait_until!(
            format!(
                "process B to apply both of repository {}'s pushes after reconnecting; log \
                 tail: {}",
                hex(&repository),
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)) >= 2
        );
        let (_, gaps) = fixture
            .backend
            .checkpoint_row(&b.receiver_identity(), generation)
            .await
            .expect("the surviving generation must still have its own row");
        assert!(
            gaps.is_empty(),
            "a transient read acknowledges nothing and therefore skips nothing; a gap here \
             would mean the receiver advanced past a delivery it never saw. Got {gaps:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Case Q — a failed acknowledgement does not undo the apply
    // -----------------------------------------------------------------------

    /// The acknowledgement is last and its failure is not a rollback: the
    /// invalidation has already been applied, the broker redelivers the
    /// unacknowledged message, and the redelivery is absorbed as a duplicate
    /// rather than applied a second time.
    ///
    /// Contract: the receiver's own rule — "the acknowledgement is last, and
    /// its failure does not undo the application: applying is idempotent, so a
    /// redelivery of an applied event is a duplicate, which is an acknowledged
    /// no-op."
    ///
    /// This is the one case where the injected fault and the real broker do
    /// half the work each: the ack failure is injected, and the redelivery that
    /// follows is JetStream's own, on its own `ack_wait`. Nothing in the
    /// harness replays the message.
    #[tokio::test]
    #[ignore = "two live loreserver processes; run tests/run-active-active-two-process-live.ps1"]
    async fn case_q_a_failed_acknowledgement_does_not_undo_the_apply() {
        let fixture = Fixture::open(Arming::GovernedOutbox).await;
        let a = fixture.start("a", BootOptions::relaying()).await;
        let b = fixture
            .start(
                "b",
                BootOptions::receiver_faults("receiver.ack.transient=next"),
            )
            .await;
        let token = fixture.minter.mint("case-q-writer");

        let (repository, branch, _) =
            governed_repository(&fixture, &a, &token, "case-q-writer", "q").await;
        wait_for_receiver(&b).await;
        // Same reason as case O: an ack fault armed while the create's events
        // are in flight fails the acknowledgement of one of THOSE.
        wait_for_quiescence(&fixture, &b, "case Q setup").await;
        let generation = b
            .event_readiness()
            .await
            .receiver_generation
            .expect("a ready receiver reports its generation");

        b.arm_receiver_fault(FAULT_ACK_TRANSIENT);
        governed_push(
            &fixture,
            &a,
            &token,
            "case-q-writer",
            &repository,
            &branch,
            Hash::default(),
            1,
            0xa1,
        )
        .await;
        let accepted = wait_for_accepted_pushes(&fixture, 1, "case Q push").await;
        wait_until!(
            format!(
                "process B's acknowledgement to fail once; log tail: {}",
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.fault_fired(FAULT_ACK_TRANSIENT)
        );

        // The apply happened before the failed acknowledgement, so it is
        // already visible even though the frontier cannot be.
        wait_until!(
            format!(
                "process B to have applied repository {}'s push before its acknowledgement \
                 failed; log tail: {}",
                hex(&repository),
                b.log_tail()
            ),
            RECEIVER_DEADLINE,
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)) >= 1
        );

        // The broker's own redelivery closes the frontier, on the same
        // generation: a failed ack is transient, not a placement move.
        wait_until!(
            format!(
                "the broker to redeliver sequence {accepted} and process B to acknowledge it; \
                 last seen {:?}",
                fixture
                    .backend
                    .checkpoint_row(&b.receiver_identity(), generation)
                    .await
            ),
            REDELIVERY_DEADLINE,
            fixture
                .backend
                .checkpoint_row(&b.receiver_identity(), generation)
                .await
                .is_some_and(|(frontier, gaps)| frontier >= accepted && gaps.is_empty())
        );
        assert_eq!(
            b.event_readiness().await.receiver_generation,
            Some(generation),
            "a failed acknowledgement must not retire the generation"
        );
        assert_eq!(
            b.log_lines_containing(&applied_event_line(&repository, BRANCH_PUSHED)),
            1,
            "the redelivery must be absorbed as a duplicate, not applied a second time. Log \
             tail: {}",
            b.log_tail()
        );
        assert_eq!(
            b.log_lines_containing(&fired_line(FAULT_ACK_TRANSIENT)),
            1,
            "the ack anchor is one-shot; a second firing would have blocked the redelivery's \
             own acknowledgement and made the recovery half vacuous"
        );
    }

    /// Wait until `expected` `branch.pushed` rows have reached the broker, and
    /// answer with the highest sequence the broker has assigned.
    ///
    /// The COUNT is load-bearing and an `any(broker_accepted)` here would be a
    /// vacuous wait in any case that pushes more than once: the previous
    /// push's row already satisfies it, so the wait returns immediately and
    /// `max_broker_sequence` answers with the PREVIOUS push's sequence. Every
    /// later assertion would then be about the wrong event while looking
    /// exactly as healthy.
    async fn wait_for_accepted_pushes(fixture: &Fixture, expected: usize, label: &str) -> i64 {
        wait_until!(
            format!(
                "{label}: {expected} governed push(es) to be accepted by the broker; rows: {}",
                describe(&fixture.backend.outbox_rows().await)
            ),
            RELAY_DEADLINE,
            fixture
                .backend
                .outbox_rows_of_kind(BRANCH_PUSHED)
                .await
                .iter()
                .filter(|row| broker_accepted(row))
                .count()
                >= expected
        );
        fixture
            .backend
            .max_broker_sequence()
            .await
            .expect("an accepted row carries the sequence the broker assigned it")
    }

    /// Poll a set of futures to completion together.
    ///
    /// This crate has no `futures` dependency, and Lore's task rule
    /// (`lore-base/src/runtime.rs`) forbids a bare `tokio::spawn`, so the
    /// burst needs a join that spawns nothing. Boxing keeps the future type
    /// uniform across the vector.
    ///
    /// Every unfinished future is re-polled on every wake, so no wakeup is
    /// lost to a future that was not the one woken. Polling the returned
    /// future again after it is `Ready` would panic on the drained slots;
    /// unreachable through the single `.await` here, and noted rather than
    /// guarded because a guard would hide the misuse instead of ending it.
    async fn futures_join<T>(futures: Vec<impl std::future::Future<Output = T>>) -> Vec<T> {
        use std::pin::Pin;
        use std::task::Poll;

        let mut pinned: Vec<Pin<Box<_>>> = futures.into_iter().map(Box::pin).collect();
        let mut results: Vec<Option<T>> = (0..pinned.len()).map(|_| None).collect();
        std::future::poll_fn(move |context| {
            let mut pending = false;
            for (slot, future) in pinned.iter_mut().enumerate() {
                if results[slot].is_some() {
                    continue;
                }
                match future.as_mut().poll(context) {
                    Poll::Ready(value) => results[slot] = Some(value),
                    Poll::Pending => pending = true,
                }
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(
                    results
                        .iter_mut()
                        .map(|slot| slot.take().expect("every future resolved"))
                        .collect(),
                )
            }
        })
        .await
    }
}

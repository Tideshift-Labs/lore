// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real handler publication against PostgreSQL membership authority. Payload I/O
//! uses the real local store; these cases do not claim provider transport proof.

use std::time::Duration;

use lore_postgres::domain::fragments::*;
use lore_storage::ImmutableStore;

use super::*;

mod admission_tests;
mod membership_store;
mod paused_store;
use membership_store::MembershipStore;
use paused_store::PausedStore;

struct Fixture {
    store: Arc<PausedStore>,
    domain: Arc<DomainContext>,
    immutable: Arc<MembershipStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
    repository: [u8; 16],
    branch: [u8; 16],
    revision: Hash,
    token: AuthorizationToken,
    merge: bool,
}

impl Fixture {
    async fn new(url: &str) -> Self {
        Self::with_files(url, 1).await
    }

    async fn with_files(url: &str, count: usize) -> Self {
        Self::with_number(url, count, 1).await
    }

    async fn with_number(url: &str, count: usize, number: u64) -> Self {
        let (inner, _, mutable, repository, branch) = fenced_domain_context(url).await;
        let pg = PostgresDomainStore::connect(url, 8, &TlsConfig::default())
            .await
            .unwrap();
        let fragments = Arc::new(pg.fragment_coordinator());
        let (policy_client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .unwrap();
        lore_base::lore_spawn!(async move {
            connection.await.unwrap();
        });
        policy_client.batch_execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$").await.unwrap();
        fragments.bootstrap().await.unwrap();
        policy_client
            .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance")
            .await
            .unwrap();
        policy_client.execute("SELECT stage_policy_publish_v1('membership-tests','fixture-policy-v1',decode(repeat('aa',32),'hex'),1073741824,100000,1073741824,100000,60000,4102444800000)", &[]).await.unwrap();
        policy_client
            .batch_execute("RESET SESSION AUTHORIZATION")
            .await
            .unwrap();
        let locks = Arc::new(pg.lock_coordinator());
        let store = Arc::new(PausedStore {
            inner,
            reached: Default::default(),
            resume: Default::default(),
            captured: Default::default(),
            pause: std::sync::atomic::AtomicBool::new(true),
        });
        let domain = Arc::new(
            DomainContext::new_with_lock_coordinator(store.clone(), true, locks)
                .with_fragment_coordinator(fragments.clone())
                .with_cell_id(Some("membership-tests".into())),
        );
        let (payload, _, _, execution) =
            local_repository_with_zero_head(repository.into(), branch.into(), mutable.clone())
                .await;
        let immutable = Arc::new(MembershipStore {
            inner: payload,
            coordinator: fragments,
            repository,
            addresses: Default::default(),
            queried: Default::default(),
            pause_read: std::sync::atomic::AtomicBool::new(false),
            read_reached: Default::default(),
            read_resume: Default::default(),
        });
        let context = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            repository.into(),
        ));
        let revision = LORE_CONTEXT
            .scope(execution, async {
                let state = state::State::new();
                state.set_revision_number(number);
                for index in 0..count {
                    let bytes = bytes::Bytes::copy_from_slice(&(index as u64).to_le_bytes());
                    let fragment = lore_storage::Fragment {
                        flags: 0,
                        size_payload: 8,
                        size_content: 8,
                    };
                    let hash = lore_storage::hash::hash_fragment(fragment, &bytes).unwrap();
                    let address = Address {
                        hash,
                        context: rand::random(),
                    };
                    immutable
                        .clone()
                        .put(repository.into(), address, fragment, Some(bytes), false)
                        .await
                        .unwrap();
                    let name = format!("required-{index}.uasset");
                    let node = Node {
                        flags: NodeFlags::File.bits(),
                        name_hash: hash_string(&name),
                        address,
                        ..Default::default()
                    };
                    state
                        .node_add(context.clone(), ROOT_NODE, node, &name)
                        .await
                        .unwrap();
                }
                state
                    .serialize(context.clone(), &get_write_token())
                    .await
                    .unwrap()
            })
            .await;
        Self {
            store,
            domain,
            immutable,
            mutable,
            repository,
            branch,
            revision,
            merge: false,
            token: AuthorizationToken {
                issuer: "https://issuer.example/membership".into(),
                user_id: "membership-pusher".into(),
                ..Default::default()
            },
        }
    }

    async fn push(&self, v1: bool) -> Result<Hash, Status> {
        let store: Arc<dyn DomainTransactionStore> = self.store.clone();
        let request = prepare_and_build_push_request_with_options(
            &store,
            self.repository,
            self.branch,
            self.revision,
            &self.token,
            self.merge,
        )
        .await;
        let mut notifications = MockNotificationSender::new();
        notifications
            .expect_branch_pushed()
            .returning(|_, _, _, _, _| ());
        let notifications: Arc<dyn NotificationSender> = Arc::new(notifications);
        let hooks = HookDispatcher::from_hooks_default(Vec::new());
        if v1 {
            let (metadata, extensions, body) = request.into_parts();
            let request = Request::from_parts(
                metadata,
                extensions,
                lore_proto::lore::revision::v1::BranchPushRequest {
                    id: body.branch,
                    revision_signature: body.revision,
                    force: body.force,
                    fast_forward_merge: body.fast_forward_merge,
                },
            );
            crate::grpc::revision::v1::branch_push::handler(
                request,
                self.immutable.clone(),
                self.mutable.clone(),
                notifications,
                &hooks,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&self.domain),
            )
            .await?;
        } else {
            let response = handler(
                request,
                self.immutable.clone(),
                self.mutable.clone(),
                notifications,
                &hooks,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&self.domain),
            )
            .await?;
            assert!(response.into_inner().success);
        }
        let snapshot = self
            .store
            .inner
            .branch_snapshot(&self.repository, &self.branch)
            .await
            .unwrap()
            .unwrap();
        Ok(Hash::from(snapshot.latest_hash.as_slice()))
    }

    async fn assert_result(&self, url: &str, applied: bool) {
        let snapshot = self
            .store
            .inner
            .branch_snapshot(&self.repository, &self.branch)
            .await
            .unwrap()
            .unwrap();
        let expected = if applied {
            self.revision
        } else {
            Hash::default()
        };
        assert_eq!(snapshot.latest_hash, expected.as_ref());
        let context = Arc::new(RepositoryContext::new_server_context(
            self.immutable.clone(),
            self.mutable.clone(),
            self.repository.into(),
        ));
        let projected = branch::load_latest(context, self.branch.into())
            .await
            .unwrap();
        assert_eq!(projected, expected, "projection agrees with domain tip");
        let direct = direct_client(url).await;
        let rows = direct.query("SELECT outcome FROM lore_domain_operation_receipts WHERE authenticated_subject = $1 AND method = 'branch.push'", &[&self.token.user_id]).await.unwrap();
        assert_eq!(rows.len(), 1, "one terminal push receipt");
        assert_eq!(rows[0].get::<_, i16>(0), if applied { 0 } else { 1 });
        let count: i64 = direct.query_one("SELECT count(*) FROM lore_outbox_events WHERE event_kind = 'branch.pushed' AND repository_id = $1", &[&self.repository.as_slice()]).await.unwrap().get(0);
        assert_eq!(count, i64::from(applied));
    }
}

#[derive(Clone, Copy, Debug)]
enum Change {
    Fresh,
    Retire,
    Rebind,
    Recreate,
    Missing,
}

async fn wait_for_blocked_backend(observer: &Client, blocker: i32) -> i32 {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(row) = observer.query_opt("SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1", &[&blocker]).await.unwrap() {
                return row.get(0);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("PostgreSQL must report the intended blocking edge")
}

async fn mutation_first(url: &str, v1: bool, change: Change, required: bool) {
    mutation_first_count(url, v1, change, required, 1).await;
}

async fn mutation_first_count(url: &str, v1: bool, change: Change, required: bool, count: usize) {
    let setup_started = std::time::Instant::now();
    let fixture = Fixture::with_files(url, count).await;
    let setup_elapsed = setup_started.elapsed();
    let publication_started = std::time::Instant::now();
    let address = if required {
        *fixture.immutable.addresses.lock().unwrap().first().unwrap()
    } else {
        let address = Address {
            hash: rand::random(),
            context: rand::random(),
        };
        fixture.immutable.record(address).await.unwrap();
        address
    };
    let retained_context: Context = rand::random();
    fixture
        .immutable
        .coordinator
        .create_association(
            address.hash.as_ref(),
            &fixture.repository,
            retained_context.as_ref(),
        )
        .await
        .unwrap();
    let before = fixture
        .immutable
        .coordinator
        .capture_push_witness(&fixture.repository)
        .await
        .unwrap()
        .unwrap();
    let holder = direct_client(url).await;
    let observer = direct_client(url).await;
    let holder_pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    if !matches!(change, Change::Fresh) {
        holder.batch_execute("BEGIN").await.unwrap();
        if matches!(change, Change::Retire | Change::Recreate) {
            holder.query_one("SELECT association_epoch FROM lore_fragment_associations WHERE hash=$1 AND repository_id=$2 AND context=$3 FOR UPDATE", &[&address.hash.as_ref(), &fixture.repository.as_slice(), &address.context.as_ref()]).await.unwrap();
        } else {
            holder
                .query_one(
                    "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash=$1 FOR UPDATE",
                    &[&address.hash.as_ref()],
                )
                .await
                .unwrap();
        }
    }
    fixture.immutable.queried.lock().unwrap().clear();
    let push = fixture.push(v1);
    let mutate = async {
        fixture.store.reached.notified().await;
        let coordinator = &fixture.immutable.coordinator;
        let mutation = async {
            match change {
                Change::Fresh => fixture
                    .immutable
                    .record(Address {
                        hash: rand::random(),
                        context: rand::random(),
                    })
                    .await
                    .unwrap(),
                Change::Retire => {
                    assert_eq!(
                        coordinator
                            .tombstone_association(
                                address.hash.as_ref(),
                                &fixture.repository,
                                address.context.as_ref()
                            )
                            .await
                            .unwrap(),
                        CommitVerdict::Published
                    );
                }
                Change::Rebind => {
                    assert_eq!(
                        coordinator
                            .create_association(
                                address.hash.as_ref(),
                                &fixture.repository,
                                address.context.as_ref()
                            )
                            .await
                            .unwrap(),
                        CommitVerdict::Published
                    );
                }
                Change::Recreate => {
                    coordinator
                        .tombstone_association(
                            address.hash.as_ref(),
                            &fixture.repository,
                            address.context.as_ref(),
                        )
                        .await
                        .unwrap();
                    coordinator
                        .create_association(
                            address.hash.as_ref(),
                            &fixture.repository,
                            address.context.as_ref(),
                        )
                        .await
                        .unwrap();
                }
                Change::Missing => {
                    let resolutions = coordinator
                        .resolve(
                            &fixture.repository,
                            address.context.as_ref(),
                            &[address.hash.as_ref().to_vec()],
                        )
                        .await
                        .unwrap();
                    let FragmentVerdict::Readable { witness, .. } = &resolutions[0].verdict else {
                        panic!("required readable fixture")
                    };
                    assert_eq!(
                        coordinator
                            .mark_missing(witness, MissingDiagnostic::Absent)
                            .await
                            .unwrap(),
                        CommitVerdict::Published
                    );
                }
            }
        };
        if matches!(change, Change::Fresh) {
            mutation.await;
            fixture.store.resume.notify_one();
        } else {
            let release = async {
                let mutation_pid = wait_for_blocked_backend(&observer, holder_pid).await;
                // The coordinator now owns Repository and waits for the held
                // fragment/association row. Start real final publication and
                // require its database backend to wait behind that writer.
                fixture.store.resume.notify_one();
                let publication_pid = wait_for_blocked_backend(&observer, mutation_pid).await;
                assert_ne!(publication_pid, mutation_pid);
                holder.batch_execute("COMMIT").await.unwrap();
            };
            tokio::join!(mutation, release);
        }
        let captured = fixture
            .store
            .captured
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .fragment_witness
            .unwrap();
        assert_eq!(
            captured, before,
            "publication carries original preflight witness"
        );
        if !matches!(change, Change::Missing) {
            let retained = coordinator
                .resolve(
                    &fixture.repository,
                    retained_context.as_ref(),
                    &[address.hash.as_ref().to_vec()],
                )
                .await
                .unwrap();
            assert!(
                matches!(retained[0].verdict, FragmentVerdict::Readable { .. }),
                "other context retains the physical payload"
            );
        }
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(push, mutate)
    })
    .await
    .expect("handler watchdog");
    let applied = matches!(change, Change::Fresh);
    if applied {
        assert_eq!(result.unwrap(), fixture.revision);
    } else {
        let error = result.unwrap_err();
        assert_eq!(error.code(), Code::Aborted);
        assert!(
            error
                .message()
                .contains(if matches!(change, Change::Missing) {
                    "required_fragment_proof_unavailable"
                } else {
                    "required_fragment_changed"
                }),
            "{error}"
        );
    }
    fixture.assert_result(url, applied).await;
    assert_file_queries(&fixture, count);
    if count > 4096 {
        println!(
            "{count} handler dependencies; setup {setup_elapsed:?}; publication {:?}",
            publication_started.elapsed()
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_fresh_addition_after_preflight_publishes_on_first_attempt() {
    mutation_first(&pg_url().unwrap(), false, Change::Fresh, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_fresh_addition_after_preflight_publishes_on_first_attempt() {
    mutation_first(&pg_url().unwrap(), true, Change::Fresh, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_required_retirement_after_preflight_refuses() {
    mutation_first(&pg_url().unwrap(), false, Change::Retire, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_unrelated_retirement_after_preflight_refuses() {
    mutation_first(&pg_url().unwrap(), true, Change::Retire, false).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_required_rebind_after_preflight_refuses() {
    mutation_first(&pg_url().unwrap(), false, Change::Rebind, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_unrelated_rebind_after_preflight_refuses() {
    mutation_first(&pg_url().unwrap(), true, Change::Rebind, false).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_tombstone_recreate_after_preflight_refuses() {
    mutation_first(&pg_url().unwrap(), true, Change::Recreate, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_lifecycle_move_without_complete_proof_refuses() {
    mutation_first(&pg_url().unwrap(), false, Change::Missing, true).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_more_than_4096_real_dependencies_allow_fresh_addition() {
    mutation_first_count(&pg_url().unwrap(), true, Change::Fresh, true, 4097).await;
}

async fn push_first(url: &str, v1: bool, change: Change, required: bool) {
    push_first_count(url, v1, change, required, 1).await;
}

async fn push_first_count(url: &str, v1: bool, change: Change, required: bool, count: usize) {
    let setup_started = std::time::Instant::now();
    let fixture = Fixture::with_files(url, count).await;
    let setup_elapsed = setup_started.elapsed();
    let publication_started = std::time::Instant::now();
    let address = if required {
        *fixture.immutable.addresses.lock().unwrap().first().unwrap()
    } else {
        let address = Address {
            hash: rand::random(),
            context: rand::random(),
        };
        fixture.immutable.record(address).await.unwrap();
        address
    };
    let holder = direct_client(url).await;
    let observer = direct_client(url).await;
    let holder_pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    holder.batch_execute("BEGIN").await.unwrap();
    holder.query_one("SELECT branch_id FROM lore_domain_branches WHERE repository_id = $1 AND branch_id = $2 FOR UPDATE", &[&fixture.repository.as_slice(), &fixture.branch.as_slice()]).await.unwrap();
    fixture.immutable.queried.lock().unwrap().clear();
    let publication = fixture.push(v1);
    let race = async {
        fixture.store.reached.notified().await;
        fixture.store.resume.notify_one();
        // The actual publication transaction has Repository and is now waiting
        // on our Branch lock. Its backend ID comes from PostgreSQL, not timing.
        let publication_pid = wait_for_blocked_backend(&observer, holder_pid).await;
        let mutation = async {
            let coordinator = &fixture.immutable.coordinator;
            match change {
                Change::Fresh => fixture
                    .immutable
                    .record(Address {
                        hash: rand::random(),
                        context: rand::random(),
                    })
                    .await
                    .unwrap(),
                Change::Retire => {
                    assert_eq!(
                        coordinator
                            .tombstone_association(
                                address.hash.as_ref(),
                                &fixture.repository,
                                address.context.as_ref()
                            )
                            .await
                            .unwrap(),
                        CommitVerdict::Published
                    );
                }
                Change::Rebind => {
                    assert_eq!(
                        coordinator
                            .create_association(
                                address.hash.as_ref(),
                                &fixture.repository,
                                address.context.as_ref()
                            )
                            .await
                            .unwrap(),
                        CommitVerdict::Published
                    );
                }
                Change::Recreate => {
                    coordinator
                        .tombstone_association(
                            address.hash.as_ref(),
                            &fixture.repository,
                            address.context.as_ref(),
                        )
                        .await
                        .unwrap();
                    coordinator
                        .create_association(
                            address.hash.as_ref(),
                            &fixture.repository,
                            address.context.as_ref(),
                        )
                        .await
                        .unwrap();
                }
                Change::Missing => unreachable!(),
            }
        };
        let release = async {
            let mutation_pid = wait_for_blocked_backend(&observer, publication_pid).await;
            assert_ne!(mutation_pid, publication_pid);
            let tip = fixture
                .store
                .inner
                .branch_snapshot(&fixture.repository, &fixture.branch)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                tip.latest_hash,
                vec![0; 32],
                "publication has not committed while Branch is held"
            );
            holder.batch_execute("COMMIT").await.unwrap();
        };
        tokio::join!(mutation, release);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(publication, race)
    })
    .await
    .expect("push-first watchdog");
    assert_eq!(result.unwrap(), fixture.revision);
    fixture.assert_result(url, true).await;
    assert_file_queries(&fixture, count);
    if count > 4096 {
        println!(
            "{count} handler dependencies; setup {setup_elapsed:?}; publication {:?}",
            publication_started.elapsed()
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_publication_blocks_required_retirement_until_commit() {
    push_first(&pg_url().unwrap(), false, Change::Retire, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_publication_blocks_unrelated_rebind_until_commit() {
    push_first(&pg_url().unwrap(), true, Change::Rebind, false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_publication_blocks_unrelated_retirement_until_commit() {
    push_first(&pg_url().unwrap(), false, Change::Retire, false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_publication_blocks_required_rebind_until_commit() {
    push_first(&pg_url().unwrap(), true, Change::Rebind, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_publication_blocks_required_recreation_until_commit() {
    push_first(&pg_url().unwrap(), true, Change::Recreate, true).await;
}
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_publication_allows_fresh_addition_after_commit() {
    push_first(&pg_url().unwrap(), false, Change::Fresh, false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn same_repo_bulk_upload_does_not_starve_real_branch_push() {
    sustained_upload(false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn cross_repo_bulk_upload_does_not_abort_real_branch_push() {
    sustained_upload(true).await;
}

async fn sustained_upload(cross_repository: bool) {
    let url = pg_url().unwrap();
    let mut fixture = Fixture::new(&url).await;
    fixture
        .store
        .pause
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (_, _, execution) = crate::store::test_store_create().await.unwrap();
    let context = Arc::new(RepositoryContext::new_server_context(
        fixture.immutable.clone(),
        fixture.mutable.clone(),
        fixture.repository.into(),
    ));
    let mut uploaders = Vec::new();
    for _ in 0..3 {
        uploaders.push(if cross_repository {
            let pg = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
                .await
                .unwrap();
            let (other_repository, _) = create_repository_with_zero_head(&pg).await;
            assert_ne!(other_repository, fixture.repository);
            Arc::new(fixture.immutable.for_repository(other_repository))
        } else {
            fixture.immutable.clone()
        });
    }
    let started = std::time::Instant::now();
    let pushes_done = std::sync::atomic::AtomicBool::new(false);
    let upload = |index: usize| {
        let pushes_done = &pushes_done;
        let immutable = uploaders[index].clone();
        async move {
            let mut added = 0;
            while started.elapsed() < Duration::from_secs(10)
                || !pushes_done.load(std::sync::atomic::Ordering::SeqCst)
            {
                immutable.clone().upload_fresh().await;
                added += 1;
            }
            assert!(added >= 2);
            added
        }
    };
    let pushes = async {
        for index in 0..100 {
            let published = fixture
                .push(index % 2 == 1)
                .await
                .expect("first-attempt publication under fresh uploads");
            assert_eq!(published, fixture.revision);
            if index != 99 {
                fixture.revision = serialize_file_revision(
                    &context,
                    published,
                    index + 2,
                    &format!("fresh-{index}.uasset"),
                )
                .await;
            }
        }
    };
    let pushes = async {
        pushes.await;
        pushes_done.store(true, std::sync::atomic::Ordering::SeqCst);
    };
    // The property here is that a bulk upload never *starves* a real branch
    // push: the failure this guards is unbounded blocking, not a few seconds of
    // slowdown. A watchdog close to the observed runtime therefore reports load
    // rather than starvation.
    //
    // At 30 seconds it did exactly that. Six runs of the two cases on an idle
    // rig, against a disposable PostgreSQL 16 with a fresh database per case:
    // three tripped the watchdog, and the three that passed reported 25.88 s,
    // 27.84 s and 28.53 s, so 1.5 to 4 seconds of margin with nothing else
    // competing.
    //
    // Under load it is worse. A full-registry run failed `same_repo` on the
    // 30-second budget while the sibling `cross_repo` passed at 26.87 s of it.
    //
    // 60 seconds keeps the watchdog well inside "this never finished" while
    // leaving the workload untouched, so the case still proves what it claims
    // on a loaded machine.
    let ((), first, second, third) = tokio::time::timeout(
        Duration::from_secs(60),
        LORE_CONTEXT.scope(execution, async {
            tokio::join!(pushes, upload(0), upload(1), upload(2))
        }),
    )
    .await
    .expect("100 pushes and ten-second upload window fit the watchdog");
    assert!(started.elapsed() >= Duration::from_secs(10));
    let direct = direct_client(&url).await;
    let committed: i64 = direct.query_one("SELECT count(*) FROM lore_domain_operation_receipts WHERE authenticated_subject = $1 AND method = 'branch.push' AND outcome = 0", &[&fixture.token.user_id]).await.unwrap().get(0);
    assert_eq!(committed, 100);
    let events: i64 = direct.query_one("SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1 AND event_kind = 'branch.pushed'", &[&fixture.repository.as_slice()]).await.unwrap().get(0);
    assert_eq!(events, 100);
    println!(
        "100 first-attempt real-handler publications; fresh additions by uploader: {first}, {second}, {third}; elapsed {:?}",
        started.elapsed()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_more_than_4096_real_dependencies_publish_before_fresh_addition() {
    push_first_count(&pg_url().unwrap(), false, Change::Fresh, false, 4097).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn unchanged_fast_path_publishes_while_fragment_and_association_tables_are_locked() {
    let url = pg_url().unwrap();
    let fixture = Fixture::new(&url).await;
    let holder = direct_client(&url).await;
    let observer = direct_client(&url).await;
    let operation = fixture.push(false);
    let gate = async {
        fixture.store.reached.notified().await;
        holder.batch_execute("BEGIN; LOCK TABLE lore_fragment_lifecycle, lore_fragment_associations IN ACCESS EXCLUSIVE MODE").await.unwrap();
        observer
            .batch_execute("SET lock_timeout = '100ms'")
            .await
            .unwrap();
        for table in ["lore_fragment_lifecycle", "lore_fragment_associations"] {
            let error = observer
                .query(&format!("SELECT 1 FROM {table} LIMIT 1"), &[])
                .await
                .expect_err("control read must actually be blocked");
            assert_eq!(
                error.code(),
                Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
            );
        }
        fixture.store.resume.notify_one();
    };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(operation, gate)
    })
    .await
    .expect("scalar final publication takes no fragment or association table read")
    .0;
    holder.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(result.unwrap(), fixture.revision);
    fixture.assert_result(&url, true).await;
}

async fn rewritten_publication_retains_original_witness(merge: bool) {
    let url = pg_url().unwrap();
    let mut fixture = Fixture::with_number(&url, 1, if merge { 1 } else { 42 }).await;
    let initial_tip = if merge {
        fixture
            .store
            .pause
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let initial_tip = fixture.push(false).await.unwrap();
        fixture
            .store
            .pause
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let context = Arc::new(RepositoryContext::new_server_context(
            fixture.immutable.clone(),
            fixture.mutable.clone(),
            fixture.repository.into(),
        ));
        let (_, _, execution) = crate::store::test_store_create().await.unwrap();
        fixture.revision = LORE_CONTEXT
            .scope(execution, async {
                serialize_file_revision(
                    &context,
                    Hash::default(),
                    1,
                    "independent-merge-file.uasset",
                )
                .await
            })
            .await;
        fixture.merge = true;
        initial_tip
    } else {
        Hash::default()
    };
    let unrelated = Address {
        hash: rand::random(),
        context: rand::random(),
    };
    fixture.immutable.record(unrelated).await.unwrap();
    let before = fixture
        .immutable
        .coordinator
        .capture_push_witness(&fixture.repository)
        .await
        .unwrap()
        .unwrap();
    fixture
        .immutable
        .pause_read
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let push = fixture.push(merge);
    let race = async {
        fixture.immutable.read_reached.notified().await;
        fixture
            .immutable
            .coordinator
            .tombstone_association(
                unrelated.hash.as_ref(),
                &fixture.repository,
                unrelated.context.as_ref(),
            )
            .await
            .unwrap();
        fixture.immutable.read_resume.notify_one();
        fixture.store.reached.notified().await;
        let input = fixture.store.captured.lock().unwrap().clone().unwrap();
        assert_eq!(
            input.fragment_witness,
            Some(before),
            "serialization must retain witness captured before the intervening retirement"
        );
        assert_ne!(
            input.new_latest_hash,
            fixture.revision.as_ref(),
            "the handler actually generated a different head"
        );
        fixture.store.resume.notify_one();
    };
    let (result, ()) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(push, race) })
            .await
            .expect("rewrite/merge reaches actual publication");
    let error = result.unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
    assert!(error.message().contains("required_fragment_changed"));
    let tip = fixture
        .store
        .inner
        .branch_snapshot(&fixture.repository, &fixture.branch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tip.latest_hash, initial_tip.as_ref());
    let direct = direct_client(&url).await;
    let refused: i64 = direct.query_one("SELECT count(*) FROM lore_domain_operation_receipts WHERE authenticated_subject = $1 AND method = 'branch.push' AND outcome = 1", &[&fixture.token.user_id]).await.unwrap().get(0);
    assert_eq!(refused, 1);
    let events: i64 = direct.query_one("SELECT count(*) FROM lore_outbox_events WHERE repository_id = $1 AND event_kind = 'branch.pushed'", &[&fixture.repository.as_slice()]).await.unwrap().get(0);
    assert_eq!(events, i64::from(merge));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn revision_number_rewrite_keeps_the_witness_from_before_preflight() {
    rewritten_publication_retains_original_witness(false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn server_merge_keeps_the_witness_from_before_preflight() {
    rewritten_publication_retains_original_witness(true).await;
}

fn assert_file_queries(fixture: &Fixture, count: usize) {
    let addresses = fixture.immutable.addresses.lock().unwrap();
    let queried = fixture.immutable.queried.lock().unwrap();
    for address in addresses.iter().take(count) {
        assert!(
            queried.contains(address),
            "handler preflight did not query file dependency {address:?}"
        );
    }
}

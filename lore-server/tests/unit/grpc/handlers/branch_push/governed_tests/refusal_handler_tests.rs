// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_storage::KeyType;
use lore_storage::KeyValueStream;
use lore_storage::MutableStore;
use lore_storage::Partition;

use super::*;

struct OverloadedMutable {
    inner: Arc<dyn MutableStore>,
    metadata_key: Mutex<Option<Hash>>,
    metadata_reads: AtomicUsize,
    successful_metadata_reads: AtomicUsize,
    overloads: AtomicUsize,
    allow_first_metadata: bool,
}

#[async_trait]
impl MutableStore for OverloadedMutable {
    /// Nothing on disk to claim.
    async fn hold_for_command(
        self: std::sync::Arc<Self>,
    ) -> std::result::Result<
        Option<lore_storage::local::store_lock::StoreGuard>,
        lore_storage::StoreError,
    > {
        Ok(None)
    }

    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        let metadata_key = *self.metadata_key.lock().unwrap().get_or_insert(key);
        if key == metadata_key {
            let previous_reads = self.metadata_reads.fetch_add(1, Ordering::SeqCst);
            if !self.allow_first_metadata || previous_reads > 0 {
                self.overloads.fetch_add(1, Ordering::SeqCst);
                return Err(StoreError::from(lore_storage::SlowDown));
            }
        }
        let result = self.inner.clone().load(partition, key, key_type).await;
        if key == metadata_key && result.is_ok() {
            self.successful_metadata_reads
                .fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    async fn store(
        self: Arc<Self>,
        _: Partition,
        _: Hash,
        _: Hash,
        _: KeyType,
    ) -> Result<(), StoreError> {
        panic!("refused push must not write")
    }
    async fn compare_and_swap(
        self: Arc<Self>,
        _: Partition,
        _: Hash,
        _: Hash,
        _: Hash,
        _: KeyType,
    ) -> Result<Hash, StoreError> {
        panic!("refused push must not CAS")
    }
    async fn list(self: Arc<Self>, _: Partition, _: KeyType) -> Result<KeyValueStream, StoreError> {
        panic!("unused list")
    }
    async fn flush(self: Arc<Self>, _: lore_storage::FlushOptions) -> Result<(), StoreError> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; LORE_TEST_PG_URL"]
async fn both_push_handlers_terminalize_actual_early_store_slowdown_without_publication() {
    let url = pg_url().expect("PostgreSQL required");
    for v1 in [false, true] {
        let (store, domain, real_mutable, repo, branch) = fenced_domain_context(&url).await;
        let token = AuthorizationToken {
            issuer: "https://early-overload.test".into(),
            user_id: "writer".into(),
            ..Default::default()
        };
        let request = prepare_and_build_push_request(
            &store,
            repo,
            branch,
            Hash::hash_buffer(b"never-published"),
            &token,
        )
        .await;
        let operation_id = request
            .metadata()
            .get_bin(OPERATION_ID_KEY)
            .unwrap()
            .to_bytes()
            .unwrap();
        let (immutable, real_mutable, _, _execution) = local_repository_with_zero_head(
            RepositoryId::from(repo),
            BranchId::from(branch),
            real_mutable,
        )
        .await;
        let mutable = Arc::new(OverloadedMutable {
            inner: real_mutable,
            metadata_key: Mutex::new(None),
            metadata_reads: AtomicUsize::new(0),
            successful_metadata_reads: AtomicUsize::new(0),
            overloads: AtomicUsize::new(0),
            // Upstream v0.13 dropped v1's separate branch-exists pre-read: both
            // handlers load the branch metadata once, in the shared push path,
            // so the first metadata read is the one to fault for v0 and v1.
            allow_first_metadata: false,
        });
        let notification: Arc<dyn NotificationSender> = Arc::new(MockNotificationSender::new());
        let result = if v1 {
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
            lore_server::grpc::revision::v1::branch_push::handler(
                request,
                crate::grpc::push_protected::allow_all(),
                immutable,
                None,
                mutable.clone(),
                notification,
                &HookDispatcher::empty(),
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&domain),
            )
            .await
            .map(|_| ())
        } else {
            handler(
                request,
                crate::grpc::push_protected::allow_all(),
                immutable,
                None,
                mutable.clone(),
                notification,
                &HookDispatcher::empty(),
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&domain),
            )
            .await
            .map(|_| ())
        };
        // The first mutable read loads metadata. Upstream fa606b08 maps its
        // SlowDown to ResourceExhausted, like the fork's later push-store
        // refusals (state_load, parent_load). That is safe: settle_governed_push
        // settles the receipt NotApplied before any error returns, whatever its
        // code, so this attempt can never later become Applied.
        let status = result.unwrap_err();
        assert_eq!(status.code(), Code::ResourceExhausted, "v1={v1}: {status}");
        assert!(
            status.message().contains("Store overloaded, slow down"),
            "missing injected SlowDown cause: {status}"
        );
        assert_eq!(mutable.overloads.load(Ordering::SeqCst), 1, "v1={v1}");
        assert_eq!(
            mutable.successful_metadata_reads.load(Ordering::SeqCst),
            0,
            "v1={v1}: the only metadata read is the injected failure"
        );
        assert_eq!(
            mutable.metadata_reads.load(Ordering::SeqCst),
            1,
            "v1={v1}: the push path reads the branch metadata exactly once"
        );
        let db = direct_client(&url).await;
        let row = db.query_one("SELECT state, outcome, not_applied_reason FROM lore_domain_operation_receipts WHERE operation_id=$1", &[&operation_id.as_ref()]).await.unwrap();
        assert_eq!(row.get::<_, i16>(0), 1);
        assert_eq!(row.get::<_, i16>(1), 1);
        assert_eq!(row.get::<_, String>(2), "BRANCH_PUSH_REFUSED_V1");
        assert_eq!(
            store
                .branch_snapshot(&repo, &branch)
                .await
                .unwrap()
                .unwrap()
                .latest_hash,
            vec![0; 32]
        );
        let count: i64 = db
            .query_one(
                "SELECT count(*) FROM lore_outbox_events WHERE repository_id=$1",
                &[&repo.as_slice()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
    }
}

/// FORK-LOCAL (Tideshift, A6): the client resends a `BranchPush` refused as `ABORTED` with this
/// reason, and matches it by a wire string it restates because it cannot name this crate's
/// constant. This pins the two together: the server's reason, sent as the handler sends it, must
/// reach the client classified as a required-fragment change.
#[test]
fn required_fragment_changed_reason_reaches_the_client_classified() {
    let reason = lore_postgres::domain::fragments::REQUIRED_FRAGMENT_CHANGED;
    assert_eq!(reason, lore_transport::REQUIRED_FRAGMENT_CHANGED_REASON);
    assert!(lore_transport::is_required_fragment_changed(
        &lore_transport::ProtocolError::from(Status::aborted(reason))
    ));
}

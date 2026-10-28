// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! [CLIENT] The QUIC twin of `put_fence.rs` (WP-124 slice 4): a fragment write inside a managed
//! parent writes no journal child, so a lost answer to one never holds the repository fence, and
//! the push never answers a lost `Copy` with an upload.
//!
//! The real QUIC `StorageClient` runs against the scripted `lore-storage/0.4` peer that
//! `lore-transport`'s own send-bound tests use (included by path, so the two cannot drift), with a
//! durable `RepositoryAttemptStore` and the real `RepositoryMutationGuard`. A lost answer comes
//! two ways, and both are exercised: the peer closes the connection after reading the request
//! (`Reply::Disconnect`), or it reads the request and never answers while the connection lives
//! (`Reply::Silent`, ended by the managed answer bound).
//!
//! This is also the QUIC twin of `tests/unit/branch/push.rs`'s `copy_fallback` module: the error
//! `copy_failure_allows_upload` judges is the one the QUIC transport itself produced, because the
//! lost-answer mapping is private to `lore-transport` and only a real send can reach it. That
//! needs a peer, which the unit binary does not carry.
//!
//! What it does not cover: the push's own `duplicate_association` loop, which needs a resolved
//! `StorageSession` (see `put_fence.rs`); `lore-integration-tests` runs the full push over QUIC.

use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::RepositoryId;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptStore;
use lore_transport::MutableOutcome;
use lore_transport::Storage;
use lore_transport::SuppliedCredentials;
use lore_transport::caller_operation::CallerOperationContext;
use lore_transport::caller_operation::with_caller_operation;
use lore_transport::error::ProtocolError;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::client::ServiceClient;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::client::StorageClient;
use uuid::Uuid;

// The peer is `lore-transport`'s. Not every helper is used here.
#[allow(dead_code)]
#[path = "../../lore-transport/tests/unit/quic/scripted_storage_peer.rs"]
mod scripted_storage_peer;

use scripted_storage_peer::Peer;
use scripted_storage_peer::Reply;

const PUT: u8 = Command::Put as u8;
const COPY: u8 = Command::Copy as u8;
const PUT_RESOLVED: u8 = Command::PutResolved as u8;

/// Short enough to keep the silent cases fast. The managed answer bound counts answers on the
/// connection, and keep-alive PINGs are not answers.
const ANSWER_BOUND: Duration = Duration::from_millis(400);

fn partition() -> Partition {
    Partition::from(Context::from([0x11u8; 16]))
}

/// How the peer loses the answer to a request it has fully read.
#[derive(Clone, Copy, Debug)]
enum Lost {
    /// The connection closes. The answer can never come.
    Disconnect,
    /// The connection stays and nothing is answered. The managed answer bound ends it.
    Silent,
}

impl Lost {
    const ALL: [Lost; 2] = [Lost::Disconnect, Lost::Silent];

    fn reply(self) -> Reply {
        match self {
            Lost::Disconnect => Reply::Disconnect,
            Lost::Silent => Reply::Silent,
        }
    }
}

/// A managed write must either be applied or fail: an unknown outcome handed back as `Ok` is the
/// wedge this suite exists to keep out, so it fails the test rather than reading as success.
fn applied(outcome: MutableOutcome<()>) -> Result<(), ProtocolError> {
    match outcome {
        MutableOutcome::Applied(()) => Ok(()),
        MutableOutcome::Unknown(unknown) => {
            panic!("a managed write handed back an unknown outcome as Ok: {unknown:?}")
        }
    }
}

/// A peer, a QUIC client on it, and a declared session, as a managed push holds them.
struct Fixture {
    peer: Peer,
    client: StorageClient,
    session: u32,
}

impl Fixture {
    /// A peer that loses the answer to each of `Put`, `Copy` and `PutResolved` in the given way.
    async fn lossy(lost: Lost) -> Self {
        let fixture = Self::healthy().await;
        for opcode in [PUT, COPY, PUT_RESOLVED] {
            fixture.peer.rule(opcode, lost.reply());
        }
        fixture
    }

    /// A peer that answers everything.
    async fn healthy() -> Self {
        let peer = Peer::start();
        let client = StorageClient::connect(
            Weak::new(),
            &peer.url(),
            "127.0.0.1".to_string(),
            "",
            "put-fence-quic",
            partition(),
            &Arc::new(SuppliedCredentials::default()),
            None,
        )
        .await
        .expect("connect to the scripted peer");
        client.quic().set_managed_idle_for_test(ANSWER_BOUND);
        let session = client
            .session_start_declared(partition(), "put-fence-quic", "outcome_unknown_v1")
            .await
            .expect("a declared session")
            .0;
        Self {
            peer,
            client,
            session,
        }
    }

    /// Wait long enough for a stray resend to show up on the wire.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    async fn put(&self, tag: u8) -> Result<(), ProtocolError> {
        let address = Address::zero_context_hash(Hash::from([tag; 32]));
        let fragment = Fragment {
            flags: 0,
            size_payload: 1,
            size_content: 1,
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            self.client.put_outcome(
                self.session,
                address,
                fragment,
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put")
        .and_then(applied)
    }

    async fn put_resolved(&self, tag: u8) -> Result<(), ProtocolError> {
        let fragment = Fragment {
            flags: 0,
            size_payload: 1,
            size_content: 1,
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            self.client.put_resolved_outcome(
                self.session,
                &Hash::from([tag; 32]),
                Address::zero_context_hash(Hash::from([tag.wrapping_add(1); 32])),
                fragment,
                Some(Bytes::from_static(b"x")),
            ),
        )
        .await
        .expect("bounded put_resolved")
        .and_then(applied)
    }

    async fn copy(&self, tag: u8) -> Result<(), ProtocolError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.client.copy_outcome(
                self.session,
                partition(),
                Address::zero_context_hash(Hash::from([tag; 32])),
                Context::from([0x12u8; 16]),
            ),
        )
        .await
        .expect("bounded copy")
        .and_then(applied)
    }

    fn seen(&self, opcode: u8) -> usize {
        self.peer.seen_opcode(opcode).len()
    }
}

// The workspace bans direct filesystem and temp-dir calls; this fixture alone needs a real
// directory for the repository fence's lock file.
#[allow(clippy::disallowed_methods)]
fn worktree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lore")).unwrap();
    dir
}

/// A managed parent with a durable journal and the real fence.
struct Managed {
    dir: tempfile::TempDir,
    guard: RepositoryMutationGuard,
    store: Arc<lore_revision::attempt_store::RepositoryAttemptStore>,
    parent: Uuid,
    operation: CallerOperationContext,
}

async fn managed() -> Managed {
    let dir = worktree();
    let guard = RepositoryMutationGuard::acquire(dir.path()).await.unwrap();
    let parent = Uuid::now_v7();
    let store = guard
        .begin(parent, "push".into(), "branch".into())
        .await
        .unwrap();
    let operation = CallerOperationContext::new(
        parent,
        RepositoryId::from([0x11; 16]),
        store.clone() as Arc<dyn AttemptStore>,
    );
    Managed {
        dir,
        guard,
        store,
        parent,
        operation,
    }
}

impl Managed {
    /// The parent completes and the next write is admitted: nothing holds the fence.
    async fn assert_fence_reopens(self) {
        assert!(self.store.unresolved().await.unwrap().is_empty());
        self.store.complete_parent_body(self.parent).await.unwrap();
        self.guard.finish(self.parent).await.unwrap();
        assert!(self.store.managed_parents().await.unwrap()[0].complete);
        let dir = self.dir;
        drop(self.store);
        drop(self.guard);
        RepositoryMutationGuard::acquire(dir.path())
            .await
            .expect("a lost managed answer must not hold the repository fence");
    }
}

/// What a lost managed fragment write must look like to its caller, on either way of losing it.
fn assert_lost_unjournaled(error: &ProtocolError, verb: &str, how: Lost) {
    assert!(
        matches!(error, ProtocolError::Internal(_)),
        "{how:?}: {error:?}"
    );
    assert!(!error.is_outcome_unknown(), "{how:?}: {error:?}");
    assert!(!error.is_disconnected(), "{how:?}: {error:?}");
    assert!(
        lore_transport::is_unjournaled_answer_lost(error),
        "{how:?}: {error:?}"
    );
    assert!(
        error.to_string().contains(verb) && error.to_string().contains("lost its answer"),
        "{how:?}: {error}"
    );
}

/// A lost Put answer, either way, leaves `unresolved()` empty, so the parent finishes and the next
/// mutation is admitted. Each Put is sent once and none is recorded.
#[tokio::test]
async fn a_lost_put_answer_over_quic_leaves_no_blocker_and_the_fence_reopens() {
    let m = managed().await;

    for (tag, how) in [(1u8, Lost::Disconnect), (2, Lost::Silent)] {
        let f = Fixture::lossy(how).await;
        let error = with_caller_operation(m.operation.clone(), f.put(tag))
            .await
            .unwrap_err();
        assert_lost_unjournaled(&error, "put", how);
        Fixture::settle().await;
        assert_eq!(f.seen(PUT), 1, "{how:?}: one wire request per Put");
    }

    m.assert_fence_reopens().await;
}

/// A lost managed `PutResolved` answer, either way, fails its caller retryably, is sent once, and
/// leaves no journal child and no fence block.
#[tokio::test]
async fn a_lost_put_resolved_answer_over_quic_leaves_no_blocker_and_the_fence_reopens() {
    let m = managed().await;

    for (tag, how) in [(7u8, Lost::Disconnect), (8, Lost::Silent)] {
        let f = Fixture::lossy(how).await;
        let error = with_caller_operation(m.operation.clone(), f.put_resolved(tag))
            .await
            .unwrap_err();
        assert_lost_unjournaled(&error, "put_resolved", how);
        Fixture::settle().await;
        assert_eq!(f.seen(PUT_RESOLVED), 1, "{how:?}: one wire request each");
    }

    m.assert_fence_reopens().await;
}

/// What `duplicate_association` does with a failed Copy: upload the payload with a Put only when
/// `copy_failure_allows_upload`. Returns whether it fell back.
async fn copy_then_fall_back(f: &Fixture, operation: &CallerOperationContext, tag: u8) -> bool {
    let error = with_caller_operation(operation.clone(), f.copy(tag))
        .await
        .unwrap_err();
    if !lore_revision::branch::push::copy_failure_allows_upload(&error) {
        return false;
    }
    let _ = with_caller_operation(operation.clone(), f.put(tag)).await;
    true
}

/// A lost managed Copy answer, either way, fails the push retryably, is not an unknown outcome, is
/// sent once, writes no child, and the push may not fall back to a Put for that address.
#[tokio::test]
async fn a_lost_copy_answer_over_quic_fails_the_push_without_a_fallback_put() {
    for how in Lost::ALL {
        let f = Fixture::lossy(how).await;
        let m = managed().await;

        let error = with_caller_operation(m.operation.clone(), f.copy(3))
            .await
            .unwrap_err();
        assert_lost_unjournaled(&error, "copy", how);
        assert!(
            !lore_revision::branch::push::copy_failure_allows_upload(&error),
            "{how:?}: {error:?}"
        );
        Fixture::settle().await;
        assert_eq!(f.seen(COPY), 1, "{how:?}: sent exactly once");

        // The push's decision, on a fresh peer that loses the same way: no fallback Put.
        let g = Fixture::lossy(how).await;
        assert!(
            !copy_then_fall_back(&g, &m.operation, 4).await,
            "{how:?}: the push must not upload after a lost Copy"
        );
        Fixture::settle().await;
        assert_eq!(g.seen(COPY), 1, "{how:?}");
        assert_eq!(g.seen(PUT), 0, "{how:?}: no fallback Put was sent");

        m.assert_fence_reopens().await;
    }
}

/// A decisive Copy refusal (the source is not held) still falls back to uploading the payload.
#[tokio::test]
async fn a_decisive_copy_refusal_over_quic_still_falls_back_to_a_put() {
    let f = Fixture::healthy().await;
    f.peer
        .rule(COPY, Reply::Status(QuicServiceError::NotFound as u32));
    let m = managed().await;

    let error = with_caller_operation(m.operation.clone(), f.copy(5))
        .await
        .unwrap_err();
    assert!(
        !lore_transport::is_unjournaled_answer_lost(&error),
        "{error:?}"
    );
    assert!(!error.is_outcome_unknown(), "{error:?}");
    assert!(lore_revision::branch::push::copy_failure_allows_upload(
        &error
    ));

    assert!(copy_then_fall_back(&f, &m.operation, 6).await);
    assert_eq!(f.seen(COPY), 2);
    assert_eq!(f.seen(PUT), 1, "the fallback Put was sent");

    m.assert_fence_reopens().await;
}

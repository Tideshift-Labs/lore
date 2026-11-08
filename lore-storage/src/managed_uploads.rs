// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 K10): a commit's fragment uploads as declared, best-effort
//! writes.
//!
//! A commit uploads each fragment as it writes it. Unmanaged, those uploads carry no caller
//! declaration, and a strict cell (`require_outcome_unknown_v1`) refuses every one. In a
//! [`ManagedUploads`] scope the same uploads run inside a caller operation, so they go out on a
//! declared session (QUIC) or with the caller-capabilities header (gRPC), exactly as a managed
//! push's do, and a strict cell accepts them.
//!
//! What stays as it was: an upload is best effort for the commit. A failure, a refusal or a lost
//! answer leaves the fragment local and not durable, the commit succeeds, and the next push
//! uploads it under managed rules. The replay contract is untouched: a dispatched write whose
//! answer is lost is never sent again (all three verbs stay `MutableNoReplay`), and a `Copy` whose
//! answer is lost is not followed by a fallback `Put`.
//!
//! Shape: one scope per command, entered per upload. The scope holds one
//! [`CallerOperationContext`] per partition, so a declared session is opened once per connection
//! and partition and stopped when the command drops the scope. Only the remote legs of
//! [`crate::write`]'s leader enter it. The rest of the command (its reads, its local writes, the
//! write tracker, in-flight dedup) runs exactly as an unmanaged command does. Each context's
//! journal refuses every record, so a journaled verb that ever ran in the scope would fail before
//! dispatch rather than write a recovery record nothing reads.
//!
//! Cost on a dead path is one managed bound for the whole command:
//! - `ready` resolves when the command's connect has, and answers whether uploads may start. The
//!   connect's session-pool pre-warm already ran inside the managed bound; when it expired, every
//!   upload is skipped.
//! - Otherwise the first upload whose QUIC path cannot be replaced within the bound (or that the
//!   server cannot declare, or refuses as an unsupported client, or that reports a disconnect
//!   before sending, or whose answer is lost) latches the scope, and later uploads skip.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use futures::FutureExt;
use futures::future::BoxFuture;
use futures::future::Shared;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptStore;
use lore_transport::CallerOperationContext;
use lore_transport::LockOwnership;
use lore_transport::ProtocolError;
use lore_transport::StorageSession;

use crate::types::Partition;

tokio::task_local! {
    /// The leg running now, for the failure sites below it to report into.
    static CURRENT: Arc<Leg>;
}

/// One upload leg in flight: its scope, and whether the server refused it outright.
struct Leg {
    uploads: Arc<ManagedUploads>,
    refused: AtomicBool,
}

/// A command's declared, best-effort upload scope. See the module docs.
pub struct ManagedUploads {
    contexts: parking_lot::Mutex<HashMap<Partition, CallerOperationContext>>,
    journal: Arc<dyn AttemptStore>,
    latched: AtomicBool,
    ready: Shared<BoxFuture<'static, bool>>,
}

/// What became of one upload leg run in a [`ManagedUploads`] scope.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UploadLeg<T> {
    /// Not started: the scope is latched, or the command's connect said no.
    Skipped,
    /// The leg returned this value.
    Done(T),
    /// The leg failed. The fragment stays local and not durable. `refused` when the server
    /// refused it outright (not authorized, not found): such a leg never applied, so a Copy may
    /// fall back to a Put. Any other failure, a lost answer among them, may have applied.
    Failed { refused: bool },
}

impl ManagedUploads {
    /// A scope whose uploads wait for `ready` and start only if it answers `true`.
    ///
    /// `ready` is awaited once, by the first upload, and shared by every later one.
    pub fn new(ready: impl Future<Output = bool> + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            contexts: parking_lot::Mutex::new(HashMap::new()),
            journal: Arc::new(UploadOnlyJournal),
            latched: AtomicBool::new(false),
            ready: ready.boxed().shared(),
        })
    }

    /// Whether a failure latched the scope, so later uploads skip.
    pub fn is_latched(&self) -> bool {
        self.latched.load(Ordering::Relaxed)
    }

    /// How many declared storage sessions the scope holds. A diagnostic for tests.
    pub fn declared_session_count(&self) -> usize {
        self.contexts
            .lock()
            .values()
            .map(CallerOperationContext::declared_session_count)
            .sum()
    }

    fn latch(&self) {
        self.latched.store(true, Ordering::Relaxed);
    }

    /// Latch on a failure that says later uploads of this command would fail the same way.
    fn note(&self, error: &ProtocolError) {
        if lore_transport::is_managed_reconnect_expired(error)
            || lore_transport::is_quic_declaration_refused(error)
            || lore_transport::is_unsupported_client(error)
            || matches!(error, ProtocolError::Disconnected(_))
            // A lost answer too: on a connection that has gone silent, each later wave of
            // uploads would wait out its own answer bound.
            || lore_transport::is_unjournaled_answer_lost(error)
            || error.is_outcome_unknown()
        {
            self.latch();
        }
    }

    /// The caller operation for `partition`, created on first use.
    fn context_for(&self, partition: Partition) -> CallerOperationContext {
        self.contexts
            .lock()
            .entry(partition)
            .or_insert_with(|| {
                CallerOperationContext::new(uuid::Uuid::now_v7(), partition, self.journal.clone())
            })
            .clone()
    }

    /// Whether an upload may start now: not latched, and the command's connect said yes.
    async fn may_start(&self) -> bool {
        !self.is_latched() && self.ready.clone().await && !self.is_latched()
    }

    /// Run one upload leg on `session` in this scope.
    ///
    /// The leg runs in the caller operation for `session`'s partition and in a managed wait
    /// scope, so its reconnect, its session start and its send are bounded by the managed bound.
    pub(crate) async fn run<T, E, F>(
        self: &Arc<Self>,
        session: &StorageSession,
        leg: F,
    ) -> UploadLeg<T>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        if !self.may_start().await {
            return UploadLeg::Skipped;
        }
        let leg_state = Arc::new(Leg {
            uploads: self.clone(),
            refused: AtomicBool::new(false),
        });
        let refused = || leg_state.refused.load(Ordering::Relaxed);
        CURRENT
            .scope(
                leg_state.clone(),
                lore_transport::with_managed_workflow(async {
                    let partition = match session.partition().await {
                        Ok(partition) => partition,
                        Err(error) => {
                            self.note(&error);
                            lore_base::lore_debug!("Commit upload skipped: no session ({error:?})");
                            return UploadLeg::Failed { refused: false };
                        }
                    };
                    let context = self.context_for(partition);
                    match lore_transport::with_caller_operation(context, leg).await {
                        Ok(value) => UploadLeg::Done(value),
                        Err(error) => {
                            lore_base::lore_debug!("Commit upload failed, kept local ({error:?})");
                            UploadLeg::Failed { refused: refused() }
                        }
                    }
                }),
            )
            .await
    }
}

/// Record `error` on the scope the current task's upload leg runs in, if any. A no-op outside a
/// [`ManagedUploads`] scope. Called at each site where an upload's transport error is still a
/// [`ProtocolError`].
pub(crate) fn note_failure(error: &ProtocolError) {
    let _ = CURRENT.try_with(|leg| {
        leg.uploads.note(error);
        if matches!(
            error,
            ProtocolError::NotAuthorized(_)
                | ProtocolError::NotFound(_)
                | ProtocolError::AddressNotFound(_)
        ) {
            leg.refused.store(true, Ordering::Relaxed);
        }
    });
}

/// The journal of a [`ManagedUploads`] scope: it refuses every record.
///
/// A fragment `Put`, `Copy` or `PutResolved` writes no journal child, so the scope's uploads never
/// call it. Anything that does is a journaled verb that has no business in a commit's upload, and
/// it fails here, before its dispatch.
struct UploadOnlyJournal;

fn journal_refusal() -> ProtocolError {
    ProtocolError::internal("a commit's upload scope keeps no journal")
}

#[async_trait]
impl AttemptStore for UploadOnlyJournal {
    async fn record(&self, _record: &AttemptRecord) -> Result<(), ProtocolError> {
        Err(journal_refusal())
    }

    async fn lookup(&self, _attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        Ok(None)
    }

    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        Ok(Vec::new())
    }

    async fn record_ownership(&self, _ownership: &LockOwnership) -> Result<(), ProtocolError> {
        Err(journal_refusal())
    }

    async fn ownership_for(
        &self,
        _branch: &Context,
        _resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        Ok(None)
    }

    async fn clear_ownership(
        &self,
        _branch: &Context,
        _resource_hash: &Hash,
    ) -> Result<(), ProtocolError> {
        Err(journal_refusal())
    }

    async fn resolve(
        &self,
        _attempt: &AttemptId,
        _resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        Err(journal_refusal())
    }
}

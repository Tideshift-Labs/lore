// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The receiver's durable state, as a trait over WP-119's Step C API.
//!
//! Step C (`lore_postgres::domain::outbox::{membership, checkpoint}`) owns
//! every fenced fact this receiver depends on: which generation it is, what
//! position that generation captured, whether its baseline was recorded, and
//! whether the authoritative placement still equals what it captured. This
//! module does not reimplement any of that. It only narrows the six calls the
//! receiver makes into one object it can hold.
//!
//! # Why a trait rather than the pool directly
//!
//! Two reasons, both structural.
//!
//! First, the plugin factory receives a `toml::Value` and a
//! `NotificationPluginContext` — no Postgres pool. The pool is built in
//! `event_relay::wiring`, which is WP-119's file and owns the settings this
//! plugin must not read. A trait is the handoff point: `SCHEMA-119` hands in a
//! [`PostgresReceiverStore`] built on the pool it already owns, and nothing in
//! this component reaches across that seam to build one.
//!
//! Second, the receiver lifecycle's hardest cases are compare-and-set
//! outcomes — a placement that moved between the capture and the CAS, a
//! membership version that moved under a checkpoint report. Those are one line
//! to script through [`InMemoryReceiverStore`] and a live-Postgres race to
//! provoke otherwise.
//!
//! # What is deliberately absent
//!
//! No retirement call. A generation is retired *by* Step C — `readiness_cas`
//! retires it on a placement mismatch, and `retire_generation` is WP-119's
//! graceful-drain and hard-dead-member path, not a receiver's self-service. A
//! receiver that finds itself retired starts a new generation; it does not
//! reach back and write its own tombstone.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use async_trait::async_trait;
use lore_postgres::domain::outbox::CheckpointOutcome;
use lore_postgres::domain::outbox::CheckpointRecord;
use lore_postgres::domain::outbox::CheckpointReport;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::MembershipMember;
use lore_postgres::domain::outbox::MembershipSnapshot;
use lore_postgres::domain::outbox::MembershipState;
use lore_postgres::domain::outbox::membership::CapturedPosition;
use lore_postgres::pool::Pool;
use thiserror::Error;

/// Why a receiver-store call could not produce an outcome at all.
///
/// Distinct from a [`MembershipCas`] or [`CheckpointOutcome`] value: those are
/// *answers*, and every one of them is a fact the receiver acts on. This is
/// the absence of an answer, and the receiver treats it the way it treats a
/// transient stream failure — back off, acknowledge nothing, fail readiness.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ReceiverStoreError {
    /// Postgres was unreachable, or the statement failed.
    #[error("receiver store is unavailable: {0}")]
    Unavailable(String),

    /// The call was rejected before it reached Postgres, by Step C's own input
    /// validation. A receiver that provokes this has a configuration fault,
    /// not a transient one.
    #[error("receiver store rejected the request: {0}")]
    Rejected(String),
}

/// The receiver's seven durable operations.
#[async_trait]
pub trait ReceiverStore: Send + Sync + std::fmt::Debug {
    /// The cell this store is scoped to.
    fn cell_id(&self) -> &str;

    /// Read the current membership snapshot, including the reset fence.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the read could not complete.
    async fn read_membership(&self) -> Result<Option<MembershipSnapshot>, ReceiverStoreError>;

    /// Allocate a new generation for this receiver identity.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the write could not complete.
    async fn join(
        &self,
        receiver_identity: &str,
        expected_membership_version: i64,
    ) -> Result<MembershipCas, ReceiverStoreError>;

    /// Pin the position this generation will baseline and drain from.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the write could not complete.
    async fn record_capture(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
        captured: &CapturedPosition,
    ) -> Result<MembershipCas, ReceiverStoreError>;

    /// Record that this generation took its authoritative baseline.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the write could not complete.
    async fn record_baseline(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError>;

    /// Project this generation's contiguous frontier and blockers.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the write could not complete.
    async fn report_checkpoint(
        &self,
        report: &CheckpointReport,
    ) -> Result<CheckpointOutcome, ReceiverStoreError>;

    /// Compare-and-set this generation to ready, rereading the authoritative
    /// placement.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the write could not complete.
    async fn readiness_cas(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError>;

    /// Read back one generation's persisted frontier and blockers.
    ///
    /// The read that makes a resume possible. A generation that captured a
    /// position and then crashed cannot rebuild its frontier from that
    /// position — the broker does not redeliver a sequence the generation
    /// already acknowledged — so the persisted projection is the only record
    /// of what it proved. `None` is a generation that captured and never
    /// reported, which resumes at its captured position instead.
    ///
    /// # Errors
    /// [`ReceiverStoreError`] when the read could not complete.
    async fn read_checkpoint(
        &self,
        stream_identity: &str,
        stream_epoch: i64,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<Option<CheckpointRecord>, ReceiverStoreError>;
}

// ---------------------------------------------------------------------------
// The Postgres implementation
// ---------------------------------------------------------------------------

/// The real store, over WP-119's Step C API.
///
/// Holds a pool rather than a connection: every call borrows one connection
/// for the length of one statement or one short transaction, exactly as the
/// relay worker and the consumer-safety evaluator do on their own pools. A
/// receiver that held a connection across its idle interval would occupy a
/// pool slot for the life of the process.
#[derive(Clone, Debug)]
pub struct PostgresReceiverStore {
    pool: Pool,
    cell_id: String,
}

impl PostgresReceiverStore {
    /// Bind a store to one cell and one pool.
    pub fn new(pool: Pool, cell_id: impl Into<String>) -> Self {
        Self {
            pool,
            cell_id: cell_id.into(),
        }
    }
}

/// Classify a pool checkout failure.
///
/// Always unavailable: pool exhaustion, a refused connection, and a timeout
/// are all "ask again later", and none of them is evidence about whether a
/// write happened.
fn pool_error(error: impl std::fmt::Display) -> ReceiverStoreError {
    ReceiverStoreError::Unavailable(error.to_string())
}

/// Translate a Step C `DomainError` into this module's two classes.
///
/// An invalid-input rejection is this process's fault and will not fix itself,
/// so it is kept distinct from an unavailable database. Everything else is
/// treated as unavailable, which is the conservative reading: the receiver
/// then backs off and acknowledges nothing rather than deciding the write did
/// not happen.
fn classify(error: lore_postgres::domain::errors::DomainError) -> ReceiverStoreError {
    match error {
        lore_postgres::domain::errors::DomainError::InvalidInput(message) => {
            ReceiverStoreError::Rejected(message)
        }
        other => ReceiverStoreError::Unavailable(other.to_string()),
    }
}

#[async_trait]
impl ReceiverStore for PostgresReceiverStore {
    fn cell_id(&self) -> &str {
        &self.cell_id
    }

    async fn read_membership(&self) -> Result<Option<MembershipSnapshot>, ReceiverStoreError> {
        let client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::membership::read_membership_snapshot(
            &**client,
            &self.cell_id,
        )
        .await
        .map_err(classify)
    }

    async fn join(
        &self,
        receiver_identity: &str,
        expected_membership_version: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        let mut client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::membership::join_receiver(
            &mut client,
            &self.cell_id,
            receiver_identity,
            expected_membership_version,
        )
        .await
        .map_err(classify)
    }

    async fn record_capture(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
        captured: &CapturedPosition,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        let client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::membership::record_capture(
            &**client,
            &self.cell_id,
            receiver_identity,
            membership_generation,
            captured,
        )
        .await
        .map_err(classify)
    }

    async fn record_baseline(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        let client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::membership::record_baseline(
            &**client,
            &self.cell_id,
            receiver_identity,
            membership_generation,
        )
        .await
        .map_err(classify)
    }

    async fn report_checkpoint(
        &self,
        report: &CheckpointReport,
    ) -> Result<CheckpointOutcome, ReceiverStoreError> {
        let mut client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::checkpoint::report_checkpoint(
            &mut client,
            &self.cell_id,
            report,
        )
        .await
        .map_err(classify)
    }

    async fn readiness_cas(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        let mut client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::membership::readiness_cas(
            &mut client,
            &self.cell_id,
            receiver_identity,
            membership_generation,
        )
        .await
        .map_err(classify)
    }

    async fn read_checkpoint(
        &self,
        stream_identity: &str,
        stream_epoch: i64,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<Option<CheckpointRecord>, ReceiverStoreError> {
        let client = self.pool.get().await.map_err(pool_error)?;
        lore_postgres::domain::outbox::checkpoint::read_checkpoint(
            &**client,
            stream_identity,
            stream_epoch,
            receiver_identity,
            membership_generation,
        )
        .await
        .map_err(classify)
    }
}

// ---------------------------------------------------------------------------
// The in-memory implementation
// ---------------------------------------------------------------------------

/// One scripted override, consumed by the next matching call.
#[derive(Clone, Debug)]
enum Override {
    Join(Result<MembershipCas, ReceiverStoreError>),
    Capture(Result<MembershipCas, ReceiverStoreError>),
    Baseline(Result<MembershipCas, ReceiverStoreError>),
    Checkpoint(Result<CheckpointOutcome, ReceiverStoreError>),
    Readiness(Result<MembershipCas, ReceiverStoreError>),
}

/// One recorded call on an [`InMemoryReceiverStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreCall {
    /// A membership snapshot read.
    ReadMembership,
    /// A generation allocation, with the version it was attempted against.
    Join {
        /// The receiver identity that joined.
        receiver_identity: String,
        /// The membership version the caller compared against.
        expected_membership_version: i64,
    },
    /// A capture, with the position pinned.
    Capture {
        /// The generation captured for.
        membership_generation: i64,
        /// The position pinned.
        captured: CapturedPosition,
    },
    /// A baseline record.
    Baseline {
        /// The generation the baseline was recorded for.
        membership_generation: i64,
    },
    /// A checkpoint report.
    Checkpoint(Box<CheckpointReport>),
    /// A readiness compare-and-set.
    Readiness {
        /// The generation the CAS was attempted for.
        membership_generation: i64,
    },
    /// A persisted-checkpoint read back, as a resume performs.
    ReadCheckpoint {
        /// The generation the read was for.
        membership_generation: i64,
    },
}

#[derive(Debug, Default)]
struct InMemoryState {
    installed: bool,
    reset_in_progress: bool,
    current_stream_identity: Option<String>,
    current_stream_epoch: Option<i64>,
    membership_version: i64,
    next_generation: i64,
    /// A concurrent join that lands right after this receiver's own.
    advance_after_join: i64,
    /// Member rows, in join order.
    ///
    /// Modelled rather than stubbed out, because the receiver reads them: a
    /// bootstrap that failed after joining leaves an uncaptured `joining` row,
    /// and the next bootstrap is required to reuse it rather than allocate
    /// another. A fake that always reported an empty member list could not
    /// tell a receiver that reuses from one that leaks a generation per retry.
    members: Vec<MembershipMember>,
    calls: Vec<StoreCall>,
    overrides: Vec<Override>,
    frontier: Option<i64>,
    /// The persisted projection, keyed the way Step C keys it.
    ///
    /// Whole records rather than the bare frontier, because a resume's
    /// decision is made on the blockers as much as on the frontier: a
    /// checkpoint carrying a gap or a park is deliberately not resumable, and
    /// a fake that stored only the frontier could not tell the two apart.
    checkpoints: Vec<CheckpointRecord>,
}

/// Replace the record on Step C's conflict target, or append a new one.
fn upsert_checkpoint(checkpoints: &mut Vec<CheckpointRecord>, record: CheckpointRecord) {
    let existing = checkpoints.iter_mut().find(|current| {
        current.stream_identity == record.stream_identity
            && current.stream_epoch == record.stream_epoch
            && current.receiver_identity == record.receiver_identity
            && current.membership_generation == record.membership_generation
    });
    match existing {
        Some(current) => *current = record,
        None => checkpoints.push(record),
    }
}

impl InMemoryState {
    fn member_mut(
        &mut self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Option<&mut MembershipMember> {
        self.members.iter_mut().find(|member| {
            member.receiver_identity == receiver_identity
                && member.membership_generation == membership_generation
        })
    }
}

/// A deterministic, in-process receiver store.
///
/// Public rather than `#[cfg(test)]` because the integration suites under
/// `lore-server/tests/` are a separate crate. It models exactly the facts the
/// receiver reads back — the version counter, the generation counter, and the
/// last projected frontier — and lets every other outcome be scripted, so a
/// test names the boundary it is exercising rather than constructing a
/// database state that happens to produce it.
#[derive(Clone, Debug)]
pub struct InMemoryReceiverStore {
    cell_id: String,
    state: Arc<Mutex<InMemoryState>>,
}

impl InMemoryReceiverStore {
    /// A store for `cell_id` at membership version 1, allocating generations
    /// from 1.
    pub fn new(cell_id: impl Into<String>) -> Self {
        Self {
            cell_id: cell_id.into(),
            state: Arc::new(Mutex::new(InMemoryState {
                installed: true,
                reset_in_progress: false,
                current_stream_identity: Some("DURABLE-sfo3-cell-a".to_string()),
                current_stream_epoch: Some(8),
                membership_version: 1,
                next_generation: 1,
                advance_after_join: 0,
                members: Vec::new(),
                calls: Vec::new(),
                overrides: Vec::new(),
                frontier: None,
                checkpoints: Vec::new(),
            })),
        }
    }

    /// Model a cell whose `SCHEMA-119` install never ran, so no membership
    /// state row exists.
    pub fn uninstalled(&self) -> &Self {
        self.lock().installed = false;
        self
    }

    /// Install or clear the reset fence.
    pub fn set_reset_in_progress(&self, reset_in_progress: bool) -> &Self {
        self.lock().reset_in_progress = reset_in_progress;
        self
    }

    /// Move the cell's authoritative placement.
    pub fn set_current_placement(&self, stream_identity: &str, stream_epoch: i64) -> &Self {
        let mut state = self.lock();
        state.current_stream_identity = Some(stream_identity.to_string());
        state.current_stream_epoch = Some(stream_epoch);
        self
    }

    /// Place one member row directly, as a previous process left it.
    ///
    /// The resume path reads member rows it did not write itself: a receiver
    /// that captured a position and then restarted finds its own row already
    /// there, and the whole decision turns on what that row says. Scripting a
    /// [`ReceiverStore::join`] cannot produce one, because a join only ever
    /// makes an uncaptured `joining` row.
    ///
    /// The generation counter moves past the seeded row, so a later join in
    /// the same test allocates a fresh generation rather than colliding.
    pub fn seed_member(&self, member: MembershipMember) -> &Self {
        let mut state = self.lock();
        state.next_generation = state.next_generation.max(member.membership_generation + 1);
        state.members.push(member);
        self
    }

    /// Place one persisted checkpoint directly, as a previous process left it.
    ///
    /// Deliberately does not move [`Self::projected_frontier`]: that accessor
    /// answers "what did a report project", and a seeded row is state this
    /// process never reported.
    pub fn seed_checkpoint(&self, record: CheckpointRecord) -> &Self {
        upsert_checkpoint(&mut self.lock().checkpoints, record);
        self
    }

    /// Script the next [`ReceiverStore::join`].
    pub fn next_join(&self, outcome: Result<MembershipCas, ReceiverStoreError>) -> &Self {
        self.push_override(Override::Join(outcome));
        self
    }

    /// Script the next [`ReceiverStore::record_capture`].
    pub fn next_capture(&self, outcome: Result<MembershipCas, ReceiverStoreError>) -> &Self {
        self.push_override(Override::Capture(outcome));
        self
    }

    /// Script the next [`ReceiverStore::record_baseline`].
    pub fn next_baseline(&self, outcome: Result<MembershipCas, ReceiverStoreError>) -> &Self {
        self.push_override(Override::Baseline(outcome));
        self
    }

    /// Script the next [`ReceiverStore::report_checkpoint`].
    pub fn next_checkpoint(&self, outcome: Result<CheckpointOutcome, ReceiverStoreError>) -> &Self {
        self.push_override(Override::Checkpoint(outcome));
        self
    }

    /// Script the next [`ReceiverStore::readiness_cas`].
    pub fn next_readiness(&self, outcome: Result<MembershipCas, ReceiverStoreError>) -> &Self {
        self.push_override(Override::Readiness(outcome));
        self
    }

    /// Every call made so far, in order.
    pub fn calls(&self) -> Vec<StoreCall> {
        self.lock().calls.clone()
    }

    /// The last frontier a checkpoint report projected, if any.
    pub fn projected_frontier(&self) -> Option<i64> {
        self.lock().frontier
    }

    /// The current membership version.
    pub fn membership_version(&self) -> i64 {
        self.lock().membership_version
    }

    /// Move the membership version, as a concurrent join would.
    pub fn set_membership_version(&self, membership_version: i64) -> &Self {
        self.lock().membership_version = membership_version;
        self
    }

    /// Land a concurrent join immediately after this receiver's own.
    ///
    /// The cell's version moves by `delta` once the next join has returned its
    /// own value, so the joining receiver's version is stale by the time it
    /// reports its first checkpoint. That is the one race a bootstrap cannot
    /// avoid by ordering, and scripting a checkpoint outcome would not
    /// reproduce it: the point is that the store's real state disagrees with
    /// what the receiver holds.
    pub fn advance_membership_version_after_join(&self, delta: i64) -> &Self {
        self.lock().advance_after_join = delta;
        self
    }

    fn push_override(&self, value: Override) {
        self.lock().overrides.push(value);
    }

    /// Take the first queued override of the matching kind.
    ///
    /// Matched by kind rather than by position, so a test may queue several
    /// overrides in whatever order reads best and each is consumed by the call
    /// it names.
    fn take_override<T>(
        &self,
        matcher: impl Fn(&Override) -> Option<Result<T, ReceiverStoreError>>,
    ) -> Option<Result<T, ReceiverStoreError>> {
        let mut state = self.lock();
        let index = state
            .overrides
            .iter()
            .position(|value| matcher(value).is_some())?;
        let value = state.overrides.remove(index);
        matcher(&value)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InMemoryState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn record(&self, call: StoreCall) {
        self.lock().calls.push(call);
    }
}

#[async_trait]
impl ReceiverStore for InMemoryReceiverStore {
    fn cell_id(&self) -> &str {
        &self.cell_id
    }

    async fn read_membership(&self) -> Result<Option<MembershipSnapshot>, ReceiverStoreError> {
        self.record(StoreCall::ReadMembership);
        let state = self.lock();
        if !state.installed {
            return Ok(None);
        }
        Ok(Some(MembershipSnapshot {
            state: MembershipState {
                cell_id: self.cell_id.clone(),
                membership_version: state.membership_version,
                next_membership_generation: state.next_generation,
                reset_generation: 0,
                current_stream_identity: state.current_stream_identity.clone(),
                current_stream_epoch: state.current_stream_epoch,
                current_placement_revision: 1,
                updated_at: SystemTime::UNIX_EPOCH,
            },
            reset_in_progress: state.reset_in_progress,
            members: state.members.clone(),
        }))
    }

    async fn join(
        &self,
        receiver_identity: &str,
        expected_membership_version: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        self.record(StoreCall::Join {
            receiver_identity: receiver_identity.to_string(),
            expected_membership_version,
        });
        if let Some(scripted) = self.take_override(|value| match value {
            Override::Join(outcome) => Some(outcome.clone()),
            _ => None,
        }) {
            return scripted;
        }
        let mut state = self.lock();
        if state.membership_version != expected_membership_version {
            return Ok(MembershipCas::VersionConflict {
                current_membership_version: state.membership_version,
            });
        }
        let membership_generation = state.next_generation;
        state.next_generation += 1;
        state.membership_version += 1;
        // The member row's `membership_version` is stamped once here and never
        // updated, matching Step C's schema. A receiver that read it back as
        // the cell's live version would carry a stale one into its checkpoint
        // report, so the fake has to reproduce the staleness rather than paper
        // over it.
        let membership_version = state.membership_version;
        state.members.push(MembershipMember {
            receiver_identity: receiver_identity.to_string(),
            membership_generation,
            state: "joining".to_string(),
            membership_version,
            captured: None,
            baseline_at: None,
            ready_at: None,
        });
        // The concurrent join lands after ours has returned, so the value this
        // caller holds is correct at the moment it is handed over and stale
        // immediately afterwards.
        let advance = state.advance_after_join;
        state.membership_version += advance;
        Ok(MembershipCas::Applied {
            membership_version,
            membership_generation,
        })
    }

    async fn record_capture(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
        captured: &CapturedPosition,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        self.record(StoreCall::Capture {
            membership_generation,
            captured: captured.clone(),
        });
        if let Some(scripted) = self.take_override(|value| match value {
            Override::Capture(outcome) => Some(outcome.clone()),
            _ => None,
        }) {
            return scripted;
        }
        let mut state = self.lock();
        let Some(member) = state.member_mut(receiver_identity, membership_generation) else {
            return Ok(MembershipCas::GenerationNotFound);
        };
        if member.captured.is_some() {
            return Ok(MembershipCas::AlreadyRecorded);
        }
        member.captured = Some(captured.clone());
        let membership_version = member.membership_version;
        Ok(MembershipCas::Applied {
            membership_version,
            membership_generation,
        })
    }

    async fn record_baseline(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        self.record(StoreCall::Baseline {
            membership_generation,
        });
        if let Some(scripted) = self.take_override(|value| match value {
            Override::Baseline(outcome) => Some(outcome.clone()),
            _ => None,
        }) {
            return scripted;
        }
        let mut state = self.lock();
        let Some(member) = state.member_mut(receiver_identity, membership_generation) else {
            return Ok(MembershipCas::GenerationNotFound);
        };
        if member.captured.is_none() {
            return Ok(MembershipCas::WrongState {
                state: member.state.clone(),
            });
        }
        if member.baseline_at.is_some() {
            return Ok(MembershipCas::AlreadyRecorded);
        }
        member.baseline_at = Some(SystemTime::UNIX_EPOCH);
        let membership_version = member.membership_version;
        Ok(MembershipCas::Applied {
            membership_version,
            membership_generation,
        })
    }

    async fn report_checkpoint(
        &self,
        report: &CheckpointReport,
    ) -> Result<CheckpointOutcome, ReceiverStoreError> {
        self.record(StoreCall::Checkpoint(Box::new(report.clone())));
        if let Some(scripted) = self.take_override(|value| match value {
            Override::Checkpoint(outcome) => Some(outcome.clone()),
            _ => None,
        }) {
            return scripted;
        }
        let mut state = self.lock();
        // Step C compare-and-sets the report against the CELL's version, so the
        // fake does too. Without it a receiver could carry a stale version
        // through every report and its tests would never notice — and the one
        // version that is guaranteed stale is the one read before a join.
        if report.membership_version != state.membership_version {
            return Ok(CheckpointOutcome::MembershipVersionConflict {
                current_membership_version: state.membership_version,
            });
        }
        state.frontier = Some(report.contiguous_frontier);
        let now = SystemTime::UNIX_EPOCH;
        upsert_checkpoint(
            &mut state.checkpoints,
            CheckpointRecord {
                cell_id: self.cell_id.clone(),
                stream_identity: report.stream_identity.clone(),
                stream_epoch: report.stream_epoch,
                receiver_identity: report.receiver_identity.clone(),
                membership_generation: report.membership_generation,
                membership_version: report.membership_version,
                contiguous_frontier: report.contiguous_frontier,
                gaps: report.gaps.clone(),
                poison: report.poison.clone(),
                reported_at: now,
                projection_at: now,
            },
        );
        Ok(CheckpointOutcome::Applied {
            contiguous_frontier: report.contiguous_frontier,
        })
    }

    async fn readiness_cas(
        &self,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<MembershipCas, ReceiverStoreError> {
        self.record(StoreCall::Readiness {
            membership_generation,
        });
        if let Some(scripted) = self.take_override(|value| match value {
            Override::Readiness(outcome) => Some(outcome.clone()),
            _ => None,
        }) {
            return scripted;
        }
        let mut state = self.lock();
        // Step C's answers, in Step C's own order (`membership::readiness_cas`).
        // The order is part of the contract this fake stands in for: a fake
        // that reached the same verdicts by a different route would answer
        // differently for a row that trips two of them at once, and a fake
        // that skipped one outright would let a receiver reach readiness in a
        // state the real store refuses. That matters more now that
        // [`Self::seed_member`] can place a row this process never wrote.
        let (member_state, captured, baselined) = {
            let Some(member) = state.member_mut(receiver_identity, membership_generation) else {
                return Ok(MembershipCas::GenerationNotFound);
            };
            (
                member.state.clone(),
                member.captured.clone(),
                member.baseline_at.is_some(),
            )
        };
        // A generation that is already ready is not rewritten. This is the
        // shape a restart of a ready generation sees, and Step C answers it
        // BEFORE rereading the placement.
        if member_state == "ready" {
            return Ok(MembershipCas::AlreadyRecorded);
        }
        if member_state != "joining" {
            return Ok(MembershipCas::WrongState {
                state: member_state,
            });
        }
        let Some(captured) = captured else {
            return Ok(MembershipCas::WrongState {
                state: "joining (no captured position)".to_string(),
            });
        };
        if !baselined {
            return Ok(MembershipCas::WrongState {
                state: "joining (no authoritative baseline)".to_string(),
            });
        }
        // The fence the whole bootstrap order exists to reach: the placement
        // this generation RECORDED, compared against the cell's current one.
        // Step C retires the row on a mismatch.
        if state.current_stream_identity.as_deref() != Some(captured.stream_identity.as_str())
            || state.current_stream_epoch != Some(captured.stream_epoch)
        {
            let current_stream_identity = state.current_stream_identity.clone();
            let current_stream_epoch = state.current_stream_epoch;
            if let Some(member) = state.member_mut(receiver_identity, membership_generation) {
                member.state = "retired".to_string();
            }
            state.membership_version += 1;
            return Ok(MembershipCas::PlacementMoved {
                current_stream_identity,
                current_stream_epoch,
            });
        }
        // Step C refuses this CAS without a persisted checkpoint for THIS
        // generation at the current placement, so the fake refuses it too: a
        // baseline alone never marks a receiver caught up, and a fake that
        // granted readiness anyway would let a receiver that skipped its
        // checkpoint still pass its tests.
        let checkpointed = state.checkpoints.iter().any(|record| {
            record.receiver_identity == receiver_identity
                && record.membership_generation == membership_generation
                && Some(record.stream_identity.as_str()) == state.current_stream_identity.as_deref()
                && Some(record.stream_epoch) == state.current_stream_epoch
        });
        if !checkpointed {
            return Ok(MembershipCas::NoCheckpointAtCurrentPlacement);
        }
        let Some(member) = state.member_mut(receiver_identity, membership_generation) else {
            return Ok(MembershipCas::GenerationNotFound);
        };
        member.state = "ready".to_string();
        member.ready_at = Some(SystemTime::UNIX_EPOCH);
        let membership_version = state.membership_version;
        Ok(MembershipCas::Applied {
            membership_version,
            membership_generation,
        })
    }

    async fn read_checkpoint(
        &self,
        stream_identity: &str,
        stream_epoch: i64,
        receiver_identity: &str,
        membership_generation: i64,
    ) -> Result<Option<CheckpointRecord>, ReceiverStoreError> {
        self.record(StoreCall::ReadCheckpoint {
            membership_generation,
        });
        let state = self.lock();
        Ok(state
            .checkpoints
            .iter()
            .find(|record| {
                record.stream_identity == stream_identity
                    && record.stream_epoch == stream_epoch
                    && record.receiver_identity == receiver_identity
                    && record.membership_generation == membership_generation
            })
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        membership_generation: i64,
        membership_version: i64,
        contiguous_frontier: i64,
    ) -> CheckpointReport {
        CheckpointReport {
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            receiver_identity: "receiver-1".to_string(),
            membership_generation,
            membership_version,
            contiguous_frontier,
            gaps: Vec::new(),
            poison: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_join_at_the_current_version_allocates_the_next_generation() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        let outcome = store.join("receiver-1", 1).await.expect("join answers");
        assert_eq!(
            outcome,
            MembershipCas::Applied {
                membership_version: 2,
                membership_generation: 1,
            }
        );
    }

    #[tokio::test]
    async fn a_join_at_a_stale_version_conflicts_rather_than_allocating() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        store.set_membership_version(7);
        let outcome = store.join("receiver-1", 1).await.expect("join answers");
        assert_eq!(
            outcome,
            MembershipCas::VersionConflict {
                current_membership_version: 7,
            }
        );
    }

    /// Drive one generation through capture and baseline, so a readiness
    /// compare-and-set reaches the checkpoint fence rather than stopping at an
    /// earlier one.
    async fn ready_to_cas(store: &InMemoryReceiverStore, receiver_identity: &str) {
        store
            .join(receiver_identity, 1)
            .await
            .expect("join answers");
        store
            .record_capture(
                receiver_identity,
                1,
                &CapturedPosition {
                    stream_identity: "DURABLE-sfo3-cell-a".to_string(),
                    stream_epoch: 8,
                    start_sequence: 900,
                },
            )
            .await
            .expect("capture answers");
        store
            .record_baseline(receiver_identity, 1)
            .await
            .expect("baseline answers");
    }

    #[tokio::test]
    async fn a_scripted_outcome_is_consumed_once() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        ready_to_cas(&store, "receiver-1").await;
        store
            .report_checkpoint(&report(1, 2, 916))
            .await
            .expect("checkpoint answers");
        store.next_readiness(Ok(MembershipCas::PlacementMoved {
            current_stream_identity: Some("DURABLE-a-r2".to_string()),
            current_stream_epoch: Some(1),
        }));
        assert!(matches!(
            store.readiness_cas("receiver-1", 1).await,
            Ok(MembershipCas::PlacementMoved { .. })
        ));
        assert!(matches!(
            store.readiness_cas("receiver-1", 1).await,
            Ok(MembershipCas::Applied { .. })
        ));
    }

    /// The fake refuses readiness with no checkpoint behind it, the way Step C
    /// does. A fake that granted it would let a receiver skip the step the
    /// contract exists to require.
    #[tokio::test]
    async fn readiness_is_refused_without_a_checkpoint() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        ready_to_cas(&store, "receiver-1").await;
        assert_eq!(
            store.readiness_cas("receiver-1", 1).await,
            Ok(MembershipCas::NoCheckpointAtCurrentPlacement)
        );
    }

    /// A generation that has not captured cannot reach the checkpoint fence at
    /// all. Step C answers `WrongState` first, and a fake that answered
    /// `NoCheckpointAtCurrentPlacement` here would misreport which of the
    /// bootstrap's ordered steps was actually missing.
    #[tokio::test]
    async fn readiness_before_a_capture_is_the_wrong_state_not_a_missing_checkpoint() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        store.join("receiver-1", 1).await.expect("join answers");
        assert_eq!(
            store.readiness_cas("receiver-1", 1).await,
            Ok(MembershipCas::WrongState {
                state: "joining (no captured position)".to_string(),
            })
        );
    }

    /// The fence the ordered bootstrap exists to reach, modelled: the
    /// placement this generation RECORDED is compared against the cell's
    /// current one, and a mismatch retires the row. Without this the fake
    /// would grant readiness to a seeded generation Step C refuses, which is
    /// exactly the shape [`InMemoryReceiverStore::seed_member`] makes easy to
    /// build.
    #[tokio::test]
    async fn readiness_at_a_placement_that_moved_retires_rather_than_applying() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        ready_to_cas(&store, "receiver-1").await;
        store
            .report_checkpoint(&report(1, 2, 916))
            .await
            .expect("checkpoint answers");
        store.set_current_placement("DURABLE-sfo3-cell-a-r2", 9);
        assert!(matches!(
            store.readiness_cas("receiver-1", 1).await,
            Ok(MembershipCas::PlacementMoved { .. })
        ));
        let snapshot = store
            .read_membership()
            .await
            .expect("read answers")
            .expect("an installed cell has a snapshot");
        assert_eq!(snapshot.members[0].state, "retired");
    }

    /// A join leaves an uncaptured `joining` row that a later bootstrap can
    /// reuse. Without this the receiver cannot tell a fresh cell from one
    /// whose previous bootstrap failed after joining.
    #[tokio::test]
    async fn a_join_leaves_an_uncaptured_joining_member_row() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        store.join("receiver-1", 1).await.expect("join answers");
        let snapshot = store
            .read_membership()
            .await
            .expect("read answers")
            .expect("an installed cell has a snapshot");
        assert_eq!(snapshot.members.len(), 1);
        let member = &snapshot.members[0];
        assert_eq!(member.state, "joining");
        assert!(member.captured.is_none());
        assert!(member.baseline_at.is_none());
    }

    #[tokio::test]
    async fn a_checkpoint_report_projects_its_frontier() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        store.join("receiver-1", 1).await.expect("join answers");
        assert_eq!(
            store.report_checkpoint(&report(1, 2, 916)).await,
            Ok(CheckpointOutcome::Applied {
                contiguous_frontier: 916,
            })
        );
        assert_eq!(store.projected_frontier(), Some(916));
    }

    /// The version compare-and-set the projection performs, modelled. A report
    /// at a version the cell has moved past is refused, and the refusal names
    /// the version to resend at.
    #[tokio::test]
    async fn a_report_at_a_stale_membership_version_is_refused() {
        let store = InMemoryReceiverStore::new("sfo3-cell-a");
        store.join("receiver-1", 1).await.expect("join answers");
        store.set_membership_version(9);
        assert_eq!(
            store.report_checkpoint(&report(1, 2, 916)).await,
            Ok(CheckpointOutcome::MembershipVersionConflict {
                current_membership_version: 9,
            })
        );
        assert_eq!(store.projected_frontier(), None);
    }
}

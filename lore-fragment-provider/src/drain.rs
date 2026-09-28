// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Opaque reservation and maintenance values crossing the store/dispatch seam.

use lore_object_dispatch::drain_policy::DrainClient;
use lore_object_dispatch::drain_policy::DrainDescriptor;
use lore_object_dispatch::drain_policy::DrainError;
use lore_object_dispatch::drain_policy::DrainObservation;
use lore_object_dispatch::drain_policy::hex;
use lore_object_dispatch::spool::SpoolLayout;
use lore_object_dispatch::spool::SpoolObjectKey;
use lore_object_dispatch::spool::SpoolObjectKind;
use lore_object_dispatch::spool_writer::LinuxSpoolWriter;
use lore_object_dispatch::spool_writer::SpoolInventoryStep;
use lore_object_dispatch::spool_writer::SpoolPhysicalInventory;
use lore_object_dispatch::spool_writer::SpoolWriteError;
use lore_object_dispatch::spool_writer::SpoolWriteReceipt;

use super::*;

#[derive(Clone, Debug)]
pub struct FragmentDrainPolicyPin {
    pub cell_id: String,
    pub revision: String,
    pub digest: [u8; 32],
}

#[derive(Clone)]
pub struct FragmentDrainReservationInput {
    pub logical_request_id: Uuid,
    pub attempt_id: Uuid,
    pub upload_id: Uuid,
    pub spool_object_id: Uuid,
    pub upload_fence: u64,
    pub source_hash: String,
    pub source_epoch: u64,
    pub source_manifest: [u8; 32],
    pub remote_epoch: u64,
    pub remote_fence: u64,
    pub object_key: String,
    pub body_digest: [u8; 32],
    pub body_size: u64,
    pub send_not_after_ms: i64,
    pub hard_not_after_ms: i64,
}

impl fmt::Debug for FragmentDrainReservationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FragmentDrainReservationInput([REDACTED])")
    }
}

pub struct FragmentDrainReservationPlan {
    input: FragmentDrainReservationInput,
    prepared: Option<DrainDescriptor>,
}

impl FragmentDrainReservationPlan {
    pub fn new(input: FragmentDrainReservationInput) -> Self {
        Self {
            input,
            prepared: None,
        }
    }
}

pub struct FragmentDrainReservation {
    pub(super) descriptor: DrainDescriptor,
    layout: SpoolLayout,
    key: SpoolObjectKey,
    writer: Arc<LinuxSpoolWriter>,
}

pub struct FragmentDrainWriteReceipt(pub(super) SpoolWriteReceipt);

impl FragmentDrainReservation {
    pub(super) fn matches_receipt(&self, receipt: &SpoolWriteReceipt) -> bool {
        self.layout
            .derive_paths(&self.key)
            .is_ok_and(|paths| paths.opaque_handle() == receipt.opaque_handle())
    }
    /// Blocking I/O. The caller must retain its bounded blocking task until completion.
    pub fn write_body(
        &self,
        body: &[u8],
    ) -> Result<FragmentDrainWriteReceipt, FragmentProviderError> {
        if body.len() as u64 != self.descriptor.body_size
            || hex(blake3::hash(body).as_bytes()) != self.descriptor.body_digest
        {
            return Err(FragmentProviderError::ClaimBindingMismatch);
        }
        let receipt = match self.writer.write_put_body(&self.layout, &self.key, body) {
            Err(SpoolWriteError::BodyAlreadyPresent) => {
                self.writer
                    .reconcile_put_body(&self.layout, &self.key, body)
            }
            result => result,
        }
        .map_err(|_error| FragmentProviderError::DrainSpoolIo)?;
        Ok(FragmentDrainWriteReceipt(receipt))
    }

    pub fn budget_pin(&self) -> BudgetPin {
        BudgetPin {
            revision: self.descriptor.allocation_revision.clone(),
            fence: self.descriptor.allocation_fence,
        }
    }
}

type CleanupTask = tokio::task::JoinHandle<
    Result<(lore_object_dispatch::drain_spool::DrainCleanupIntent, bool), FragmentProviderError>,
>;
type PhysicalSpoolSample = (Option<u64>, Result<SpoolInventoryStep, SpoolWriteError>);
type ObservationTask = tokio::task::JoinHandle<PhysicalSpoolSample>;
/// Spool ledger bytes and files, as one `drain_observe_v1` read reported them.
type SpoolLedger = (u64, u64);

/// A completed walk older than this is not reported, as before.
const PHYSICAL_SPOOL_MAX_AGE: Duration = Duration::from_secs(300);

/// Pairs each completed physical walk with the ledger that bounds it (INV-FT F2).
///
/// A body is charged to its ledger before it is placed, and released only after
/// it is unlinked. So every body a walk counts was charged no later than the
/// walk's end and released no earlier than its start. Comparing a completed walk
/// with one later ledger read is not order-consistent: a cleanup burst after the
/// walk counted a body lowers that read, and a body placed after the read raises
/// the walk. The 2026-09-28 live check saw spool walks 0 to 2 s old over ledger.
///
/// The bound is the larger of the ledger read before the walk started and the
/// first ledger read after it completed, per component. It covers a window that
/// only grew and a window that only shrank. A window with both charges and
/// releases can still exceed both reads; readiness and staging give that a time
/// budget rather than treating one sample as unavailability.
///
/// The caller must keep the order this relies on: `before` is a read taken
/// before the step was issued, and `record_ledger` is called only with a read
/// taken after every step already recorded.
#[derive(Debug)]
pub struct WalkLedgerBound<W> {
    /// The latest ledger read. Every step recorded so far was issued before it.
    last_ledger: Option<(u64, u64)>,
    /// The ledger read before the walk in progress started, when known.
    walk_start: Option<(u64, u64)>,
    /// A completed walk still waiting for the first ledger read after it.
    unbound: Option<(W, Option<(u64, u64)>)>,
    /// The latest completed walk and the ledger bound it is compared with.
    bound: Option<(W, (u64, u64))>,
}

impl<W> Default for WalkLedgerBound<W> {
    fn default() -> Self {
        Self {
            last_ledger: None,
            walk_start: None,
            unbound: None,
            bound: None,
        }
    }
}

impl<W: Copy> WalkLedgerBound<W> {
    /// The latest ledger read, to pass as `before` for the next step.
    pub fn last_ledger(&self) -> Option<(u64, u64)> {
        self.last_ledger
    }

    /// Record one walk step. `before` is the latest ledger read when the step
    /// was issued, which precedes everything the step walked.
    pub fn record_step(&mut self, before: Option<(u64, u64)>, started: bool, completed: Option<W>) {
        if started {
            self.walk_start = before;
        }
        if let Some(completed) = completed {
            self.unbound = Some((completed, self.walk_start.take()));
        }
    }

    /// A failed step resets the walk, so nothing completed is left to report.
    pub fn record_failure(&mut self) {
        *self = Self {
            last_ledger: self.last_ledger,
            ..Self::default()
        };
    }

    /// Record a ledger read taken after every step recorded so far.
    pub fn record_ledger(&mut self, ledger: (u64, u64)) {
        self.last_ledger = Some(ledger);
        if let Some((walk, start)) = self.unbound.take() {
            let bound = start.map_or(ledger, |(bytes, files)| {
                (bytes.max(ledger.0), files.max(ledger.1))
            });
            self.bound = Some((walk, bound));
        }
    }

    /// The latest completed walk that has a bound, and that bound.
    pub fn current(&self) -> Option<(W, (u64, u64))> {
        self.bound
    }
}

type SpoolWalkBound = WalkLedgerBound<SpoolPhysicalInventory>;

fn record_spool_step(
    bound: &mut SpoolWalkBound,
    before: Option<SpoolLedger>,
    step: Result<SpoolInventoryStep, SpoolWriteError>,
) {
    match step {
        Ok(step) => bound.record_step(before, step.started, step.completed),
        Err(_) => bound.record_failure(),
    }
}

fn current_spool_walk(bound: &SpoolWalkBound) -> Option<(SpoolPhysicalInventory, SpoolLedger)> {
    bound
        .current()
        .filter(|(walk, _)| walk.completed_at.elapsed() <= PHYSICAL_SPOOL_MAX_AGE)
}

#[derive(Default)]
struct SpoolObservationState {
    /// The step in flight and the latest ledger read when it was issued.
    task: Option<(ObservationTask, Option<SpoolLedger>)>,
    walk: SpoolWalkBound,
}

pub struct FragmentDrainMaintenanceHandle {
    client: DrainClient,
    layout: SpoolLayout,
    boundary: String,
    cell: String,
    policy_pin: FragmentDrainPolicyPin,
    writer: Arc<LinuxSpoolWriter>,
    // The handle survives cancellation of cleanup_pass. There is at most one syscall lane.
    io: tokio::sync::Mutex<Option<CleanupTask>>,
    observation_io: tokio::sync::Mutex<SpoolObservationState>,
}

#[derive(Clone, Copy, Debug)]
pub struct FragmentDrainObservation {
    pub spool_bytes: u64,
    pub spool_files: u64,
    pub cleanup_backlog: u64,
    pub roots_usable: bool,
    pub metadata_full: bool,
    pub available_bytes: Option<u64>,
    pub physical_spool_bytes: Option<u64>,
    pub physical_spool_files: Option<u64>,
    /// Age of the completed spool inventory the physical fields report, taken
    /// when this observation was assembled. Observability only.
    pub physical_spool_age: Option<Duration>,
    /// The ledger bytes and files the physical fields must not exceed: the
    /// larger of the reads taken before that walk started and after it
    /// completed. `spool_bytes`/`spool_files` are the current read.
    pub physical_spool_ledger: Option<(u64, u64)>,
}

impl FragmentDrainObservation {
    /// Join the authority's ledger sample with the writer's own filesystem sample.
    fn assemble(
        sample: &DrainObservation,
        available_bytes: Option<u64>,
        physical: Option<(SpoolPhysicalInventory, SpoolLedger)>,
    ) -> Self {
        Self {
            spool_bytes: sample.spool_bytes,
            spool_files: sample.spool_files,
            cleanup_backlog: sample.cleanup_backlog,
            roots_usable: available_bytes.is_some(),
            metadata_full: sample.metadata_full,
            available_bytes,
            physical_spool_bytes: physical.map(|(inventory, _)| inventory.bytes),
            physical_spool_files: physical.map(|(inventory, _)| inventory.files),
            physical_spool_age: physical.map(|(inventory, _)| inventory.completed_at.elapsed()),
            physical_spool_ledger: physical.map(|(_, ledger)| ledger),
        }
    }

    /// The ledger the physical inventory is compared with. An observation
    /// built without a walk bound compares with the current read.
    pub fn physical_ledger_bound(&self) -> (u64, u64) {
        self.physical_spool_ledger
            .unwrap_or((self.spool_bytes, self.spool_files))
    }
}

impl FragmentDrainMaintenanceHandle {
    async fn read_ledger(&self) -> Result<DrainObservation, FragmentProviderError> {
        self.client
            .observe(&self.boundary, &self.cell)
            .await
            .map_err(FragmentProviderError::DrainAuthority)
    }

    /// One walk step, then the ledger. Reading the ledger after the step is what
    /// lets it bound a walk the step completed; see [`SpoolWalkBound`].
    pub async fn observe(&self) -> Result<FragmentDrainObservation, FragmentProviderError> {
        self.client
            .read(
                &self.boundary,
                &self.cell,
                &self.policy_pin.revision,
                &self.policy_pin.digest,
            )
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        let mut state = self.observation_io.lock().await;
        if state.task.is_none() {
            if state.walk.last_ledger().is_none() {
                // The first walk needs a read before it starts too.
                let sample = self.read_ledger().await?;
                state
                    .walk
                    .record_ledger((sample.spool_bytes, sample.spool_files));
            }
            let writer = self.writer.clone();
            let before = state.walk.last_ledger();
            state.task = Some((
                lore_base::lore_spawn_blocking!(move || {
                    (
                        writer.available_bytes().ok(),
                        writer.physical_usage_step(4096),
                    )
                }),
                before,
            ));
        }
        let (available_bytes, step, before) = match state.task.as_mut() {
            Some((task, before)) => {
                let before = *before;
                let (available_bytes, step) = task
                    .await
                    .unwrap_or((None, Err(SpoolWriteError::RootUnavailable)));
                (available_bytes, step, before)
            }
            None => (None, Err(SpoolWriteError::RootUnavailable), None),
        };
        state.task = None;
        record_spool_step(&mut state.walk, before, step);
        let sample = self.read_ledger().await?;
        state
            .walk
            .record_ledger((sample.spool_bytes, sample.spool_files));
        Ok(FragmentDrainObservation::assemble(
            &sample,
            available_bytes,
            current_spool_walk(&state.walk),
        ))
    }
    pub async fn cleanup_pass(&self, batch: u32) -> Result<u32, FragmentProviderError> {
        let batch = u16::try_from(batch)
            .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        let mut pending = self.io.lock().await;
        let mut count = 0;
        if let Some(task) = pending.as_mut() {
            let result = task.await;
            *pending = None;
            let (intent, removed) =
                result.map_err(|_error| FragmentProviderError::DrainSpoolIo)??;
            if release_retrying(|| self.client.release_cleanup(&intent)).await? {
                count += u32::from(removed);
            }
        }
        let ids = self
            .client
            .cleanup_candidates(&self.boundary, &self.cell, batch)
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        for id in ids {
            // Every replica scans the same candidates. Losing the row to another replica means
            // that replica is doing this work, so skip it rather than fail the whole pass.
            let intent = match self.client.claim_cleanup(id).await {
                Ok(intent) => intent,
                Err(DrainError::Contended) => continue,
                Err(error) => return Err(FragmentProviderError::DrainAuthority(error)),
            };
            let layout = self.layout.clone();
            let writer = self.writer.clone();
            *pending = Some(lore_base::lore_spawn_blocking!(move || {
                let removed = intent
                    .unlink_with_writer(&layout, &writer)
                    .map_err(|_error| FragmentProviderError::DrainSpoolIo)?;
                Ok((intent, removed))
            }));
            let result = match pending.as_mut() {
                Some(task) => task.await,
                None => return Err(FragmentProviderError::DrainSpoolIo),
            };
            *pending = None;
            let (intent, removed) =
                result.map_err(|_error| FragmentProviderError::DrainSpoolIo)??;
            // Rechecking a compact tombstone is not progress against backlog.
            if release_retrying(|| self.client.release_cleanup(&intent)).await? {
                count += u32::from(removed);
            }
        }
        Ok(count)
    }
}

/// How many times one pass tries a release before leaving it for a later pass.
const RELEASE_ATTEMPTS: usize = 3;

/// Retry a release another session won, at once. Every release updates the same quota counter
/// rows, so two replicas releasing different rows collide there, and the loser's row stays
/// claimed with its body already unlinked. The winner has committed by the time the loser
/// sees the conflict, so a retry reads the new counters. The retry is safe: the fence is
/// unchanged by a re-entrant claim, and a row already released returns without effect.
async fn release_retrying<F, Fut>(mut release: F) -> Result<bool, FragmentProviderError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), DrainError>>,
{
    for _ in 1..RELEASE_ATTEMPTS {
        match release().await {
            Err(DrainError::Contended) => {}
            result => return released(result),
        }
    }
    released(release().await)
}

/// Whether a cleanup release committed. A release lost to another replica committed nothing and
/// is left for a later pass: the claim is re-entrant and the unlink is idempotent. A lost
/// compaction after a committed release is already `Ok` from `release_cleanup`.
fn released(result: Result<(), DrainError>) -> Result<bool, FragmentProviderError> {
    match result {
        Ok(()) => Ok(true),
        Err(DrainError::Contended) => Ok(false),
        Err(error) => Err(FragmentProviderError::DrainAuthority(error)),
    }
}

impl FragmentProviderEntry {
    pub async fn drain_handles(
        self: &Arc<Self>,
        root: PathBuf,
        pin: FragmentDrainPolicyPin,
        preparation: Duration,
        send: Duration,
    ) -> Result<(FragmentDrainCapability, FragmentDrainMaintenanceHandle), FragmentProviderError>
    {
        let client = DrainClient::new(self.pool.clone());
        // CR-038 D5: before any spool state exists, refuse a cell without the metadata true-up.
        client
            .verify_schema_revision()
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        client
            .verify_activation_window(
                self.boundary().provider_boundary_id(),
                &pin.cell_id,
                &pin.revision,
                &pin.digest,
                preparation,
                send,
            )
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        let layout = SpoolLayout::new(root.clone())
            .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        let writer_layout = layout.clone();
        let writer = Arc::new(
            lore_base::lore_spawn_blocking!(move || LinuxSpoolWriter::open(
                &writer_layout,
                FRAGMENT_PROVIDER_INGRESS_CAP_BYTES
            ))
            .await
            .map_err(|_error| FragmentProviderError::DrainSpoolIo)?
            .map_err(|_error| FragmentProviderError::DrainSpoolIo)?,
        );
        let maintenance = FragmentDrainMaintenanceHandle {
            client,
            layout,
            boundary: self.boundary().provider_boundary_id().to_owned(),
            cell: pin.cell_id.clone(),
            policy_pin: pin.clone(),
            writer: writer.clone(),
            io: tokio::sync::Mutex::new(None),
            observation_io: tokio::sync::Mutex::new(SpoolObservationState::default()),
        };
        let mut capability = self
            .drain_capability(root)
            .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        capability.policy_pin = Some(pin);
        capability.spool_writer = Some(writer);
        Ok((capability, maintenance))
    }
}

impl FragmentDrainCapability {
    pub async fn reserve_spool(
        &self,
        plan: &mut FragmentDrainReservationPlan,
    ) -> Result<FragmentDrainReservation, FragmentProviderError> {
        let pin = self
            .policy_pin
            .as_ref()
            .ok_or(FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        let client = DrainClient::new(self.entry.pool.clone());
        let layout = SpoolLayout::new(self.spool_root.clone())
            .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        let key = SpoolObjectKey {
            provider_boundary_id: self.entry.boundary().provider_boundary_id().to_owned(),
            logical_request_id: plan.input.logical_request_id.to_string(),
            attempt_id: plan.input.attempt_id.to_string(),
            kind: SpoolObjectKind::Put,
        };
        if plan.prepared.is_none() {
            let (policy, allocation_revision, allocation_fence, allocation_expiry_ms) = client
                .read(
                    &key.provider_boundary_id,
                    &pin.cell_id,
                    &pin.revision,
                    &pin.digest,
                )
                .await
                .map_err(FragmentProviderError::DrainAuthority)?;
            let paths = layout
                .derive_paths(&key)
                .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
            let i = &plan.input;
            let d = DrainDescriptor {
                policy_revision: pin.revision.clone(),
                policy_digest: hex(&pin.digest),
                boundary: key.provider_boundary_id.clone(),
                cell: pin.cell_id.clone(),
                service: policy.service,
                logical_request_id: i.logical_request_id,
                attempt_id: i.attempt_id,
                upload_id: i.upload_id,
                spool_object_id: i.spool_object_id,
                upload_fence: i.upload_fence,
                source_hash: i.source_hash.clone(),
                source_epoch: i.source_epoch,
                source_manifest: hex(&i.source_manifest),
                remote_epoch: i.remote_epoch,
                remote_fence: i.remote_fence,
                object_key: i.object_key.clone(),
                body_digest: hex(&i.body_digest),
                body_size: i.body_size,
                send_not_after_ms: u64::try_from(i.send_not_after_ms)
                    .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?,
                hard_not_after_ms: u64::try_from(i.hard_not_after_ms)
                    .map_err(|_error| FragmentProviderError::DrainAuthority(DrainError::Invalid))?,
                prepared_ttl_ms: policy.maximum_ttl_ms,
                max_chunk_bytes: FRAGMENT_PROVIDER_INGRESS_CAP_BYTES,
                allocation_revision,
                allocation_fence,
                allocation_expiry_ms,
                boundary_digest: hex(paths.boundary_binding().boundary_blake3()),
                boundary_token: paths.boundary_binding().boundary_token().to_owned(),
                observation_digest: hex(&paths.observation_binding_blake3()),
            };
            d.canonical_bytes()
                .map_err(FragmentProviderError::DrainAuthority)?;
            // Store before the first database mutation, including cancellation and response loss.
            plan.prepared = Some(d);
        }
        let d = plan
            .prepared
            .as_ref()
            .ok_or(FragmentProviderError::DrainAuthority(DrainError::Invalid))?;
        if d.boundary != key.provider_boundary_id
            || d.cell != pin.cell_id
            || d.policy_revision != pin.revision
            || d.policy_digest != hex(&pin.digest)
        {
            return Err(FragmentProviderError::DrainAuthority(DrainError::Invalid));
        }
        client
            .reserve(d)
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        Ok(FragmentDrainReservation {
            descriptor: d.clone(),
            layout,
            key,
            writer: self
                .spool_writer
                .clone()
                .ok_or(FragmentProviderError::DrainSpoolIo)?,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) async fn assert_cleanup_recovers_after_worker_panic(
    maintenance: &FragmentDrainMaintenanceHandle,
) {
    let task: CleanupTask =
        lore_base::lore_spawn_blocking!("test-drain-cleanup-panic", move || {
            panic!("injected drain cleanup worker panic")
        });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panic worker terminates");
    *maintenance.io.lock().await = Some(task);
    assert!(matches!(
        maintenance.cleanup_pass(64).await,
        Err(FragmentProviderError::DrainSpoolIo)
    ));
    assert!(
        maintenance.io.lock().await.is_none(),
        "completed failed worker is consumed before returning its error"
    );
    assert_eq!(
        maintenance
            .cleanup_pass(64)
            .await
            .expect("next real SQL/filesystem cleanup pass must not repoll a completed panic"),
        0,
        "an already compact tombstone does not report fresh cleanup progress"
    );
    assert!(maintenance.io.lock().await.is_none());
}

#[cfg(test)]
mod observation_tests {
    use super::*;

    fn ledger() -> DrainObservation {
        DrainObservation {
            spool_bytes: 100,
            spool_files: 10,
            cleanup_backlog: 3,
            metadata_full: false,
        }
    }

    #[test]
    fn a_completed_spool_walk_reports_its_size_and_age() {
        let completed_at = std::time::Instant::now() - Duration::from_secs(7);
        let observation = FragmentDrainObservation::assemble(
            &ledger(),
            Some(1 << 20),
            Some((
                SpoolPhysicalInventory {
                    completed_at,
                    bytes: 150,
                    files: 12,
                },
                (160, 13),
            )),
        );
        assert_eq!(observation.physical_spool_bytes, Some(150));
        assert_eq!(observation.physical_spool_files, Some(12));
        let age = observation.physical_spool_age.expect("age");
        assert!(age >= Duration::from_secs(7), "{age:?}");
        assert!(age < Duration::from_secs(60), "{age:?}");
        assert_eq!(
            (observation.spool_bytes, observation.spool_files),
            (100, 10)
        );
        assert_eq!(observation.physical_spool_ledger, Some((160, 13)));
        assert_eq!(observation.physical_ledger_bound(), (160, 13));
        assert!(observation.roots_usable);
    }

    #[test]
    fn no_completed_spool_walk_reports_no_size_and_no_age() {
        let observation = FragmentDrainObservation::assemble(&ledger(), None, None);
        assert_eq!(observation.physical_spool_bytes, None);
        assert_eq!(observation.physical_spool_files, None);
        assert_eq!(observation.physical_spool_age, None);
        assert_eq!(observation.physical_spool_ledger, None);
        assert_eq!(observation.physical_ledger_bound(), (100, 10));
        assert!(!observation.roots_usable);
    }

    fn walk(bytes: u64, files: u64) -> SpoolPhysicalInventory {
        SpoolPhysicalInventory {
            completed_at: std::time::Instant::now(),
            bytes,
            files,
        }
    }

    fn step(started: bool, completed: Option<SpoolPhysicalInventory>) -> SpoolInventoryStep {
        SpoolInventoryStep { started, completed }
    }

    /// INV-FT row 67, the 2026-09-28 live shape: a walk counted 118 bodies, then
    /// cleanup released two before the next ledger read. The read after is
    /// below the walk; the read before it started is not.
    #[test]
    fn a_release_burst_after_the_walk_is_bounded_by_the_ledger_before_it() {
        let mut bound = SpoolWalkBound::default();
        bound.record_ledger((8_750_269, 118));
        record_spool_step(&mut bound, Some((8_750_269, 118)), Ok(step(true, None)));
        bound.record_ledger((8_750_269, 118));
        record_spool_step(
            &mut bound,
            Some((8_750_269, 118)),
            Ok(step(false, Some(walk(8_750_269, 118)))),
        );
        bound.record_ledger((8_492_370, 116));
        let (inventory, ledger) = bound.current().expect("bound walk");
        assert_eq!((inventory.bytes, inventory.files), (8_750_269, 118));
        assert_eq!(ledger, (8_750_269, 118));
    }

    /// A body placed after the ledger read and before the walk reached it counts
    /// physically; the read after the walk completed includes its reservation.
    #[test]
    fn a_body_placed_during_the_walk_is_bounded_by_the_ledger_after_it() {
        let mut bound = SpoolWalkBound::default();
        bound.record_ledger((100, 10));
        record_spool_step(
            &mut bound,
            Some((100, 10)),
            Ok(step(true, Some(walk(110, 11)))),
        );
        assert_eq!(
            bound.current(),
            None,
            "unbound until a read after completion"
        );
        bound.record_ledger((110, 11));
        let (_, ledger) = bound.current().expect("bound walk");
        assert_eq!(ledger, (110, 11));
    }

    /// The bound is taken per component: bytes and files may peak on
    /// different sides of the walk.
    #[test]
    fn each_component_takes_the_larger_side() {
        let mut bound = SpoolWalkBound::default();
        record_spool_step(&mut bound, Some((200, 5)), Ok(step(true, None)));
        record_spool_step(&mut bound, None, Ok(step(false, Some(walk(0, 0)))));
        bound.record_ledger((150, 9));
        assert_eq!(bound.current().expect("bound").1, (200, 9));
    }

    /// A walk that started with no earlier read is bounded by the read after it.
    #[test]
    fn a_walk_with_no_earlier_read_is_bounded_by_the_read_after_it() {
        let mut bound = SpoolWalkBound::default();
        record_spool_step(&mut bound, None, Ok(step(true, Some(walk(7, 1)))));
        bound.record_ledger((5, 1));
        assert_eq!(bound.current().expect("bound").1, (5, 1));
    }

    /// A later walk's start read belongs to that walk only.
    #[test]
    fn each_walk_uses_its_own_start_read() {
        let mut bound = SpoolWalkBound::default();
        record_spool_step(
            &mut bound,
            Some((500, 50)),
            Ok(step(true, Some(walk(1, 1)))),
        );
        bound.record_ledger((10, 1));
        assert_eq!(bound.current().expect("first").1, (500, 50));
        record_spool_step(&mut bound, Some((10, 1)), Ok(step(true, Some(walk(2, 1)))));
        bound.record_ledger((20, 2));
        assert_eq!(bound.current().expect("second").1, (20, 2));
    }

    /// The writer resets its walk on failure, so nothing completed is reported.
    #[test]
    fn a_failed_step_drops_every_walk() {
        let mut bound = SpoolWalkBound::default();
        record_spool_step(&mut bound, Some((1, 1)), Ok(step(true, Some(walk(1, 1)))));
        bound.record_ledger((1, 1));
        record_spool_step(
            &mut bound,
            Some((1, 1)),
            Err(SpoolWriteError::RootUnavailable),
        );
        bound.record_ledger((1, 1));
        assert_eq!(bound.current(), None);
        assert_eq!(bound.last_ledger, Some((1, 1)));
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;

    #[test]
    fn a_release_lost_to_another_replica_is_skipped_not_failed() {
        assert!(matches!(released(Ok(())), Ok(true)));
        assert!(matches!(released(Err(DrainError::Contended)), Ok(false)));
        for error in [
            DrainError::Refused,
            DrainError::Unavailable,
            DrainError::Invalid,
        ] {
            assert!(matches!(
                released(Err(error)),
                Err(FragmentProviderError::DrainAuthority(inner)) if inner == error
            ));
        }
    }

    /// Answers each attempt from `outcomes` in order and counts the attempts.
    async fn release_from(
        outcomes: &[Result<(), DrainError>],
    ) -> (Result<bool, FragmentProviderError>, usize) {
        let calls = std::cell::Cell::new(0);
        let result = release_retrying(|| {
            let index = calls.get();
            calls.set(index + 1);
            let outcome = outcomes[index];
            async move { outcome }
        })
        .await;
        (result, calls.get())
    }

    #[tokio::test]
    async fn a_contended_release_is_retried_before_it_is_left_for_the_next_rescan() {
        // Row 34, 2026-09-27: two replicas releasing different rows collide on the shared quota
        // counter rows, and the loser's row stayed in state 2 with its body already unlinked.
        let (result, calls) = release_from(&[Err(DrainError::Contended), Ok(())]).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(calls, 2);
        let (result, calls) = release_from(&[
            Err(DrainError::Contended),
            Err(DrainError::Contended),
            Ok(()),
        ])
        .await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(calls, 3);
    }

    #[tokio::test]
    async fn a_release_contended_on_every_attempt_is_skipped_after_the_bound() {
        let outcomes = [Err(DrainError::Contended); RELEASE_ATTEMPTS];
        let (result, calls) = release_from(&outcomes).await;
        assert!(matches!(result, Ok(false)));
        assert_eq!(calls, RELEASE_ATTEMPTS);
    }

    #[tokio::test]
    async fn a_committed_or_refused_release_is_not_retried() {
        let (result, calls) = release_from(&[Ok(())]).await;
        assert!(matches!(result, Ok(true)));
        assert_eq!(calls, 1);
        for error in [
            DrainError::Refused,
            DrainError::Unavailable,
            DrainError::Invalid,
        ] {
            let (result, calls) = release_from(&[Err(error)]).await;
            assert!(matches!(
                result,
                Err(FragmentProviderError::DrainAuthority(inner)) if inner == error
            ));
            assert_eq!(calls, 1, "{error:?} may have committed or is a verdict");
        }
    }
}

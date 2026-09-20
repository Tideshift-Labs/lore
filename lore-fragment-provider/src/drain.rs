// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Opaque reservation and maintenance values crossing the store/dispatch seam.

use lore_object_dispatch::drain_policy::DrainClient;
use lore_object_dispatch::drain_policy::DrainDescriptor;
use lore_object_dispatch::drain_policy::DrainError;
use lore_object_dispatch::drain_policy::hex;
use lore_object_dispatch::spool::SpoolLayout;
use lore_object_dispatch::spool::SpoolObjectKey;
use lore_object_dispatch::spool::SpoolObjectKind;
use lore_object_dispatch::spool_writer::LinuxSpoolWriter;
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
type PhysicalSpoolSample = (Option<u64>, Option<(u64, u64)>);
type ObservationTask = tokio::task::JoinHandle<PhysicalSpoolSample>;

pub struct FragmentDrainMaintenanceHandle {
    client: DrainClient,
    layout: SpoolLayout,
    boundary: String,
    cell: String,
    policy_pin: FragmentDrainPolicyPin,
    writer: Arc<LinuxSpoolWriter>,
    // The handle survives cancellation of cleanup_pass. There is at most one syscall lane.
    io: tokio::sync::Mutex<Option<CleanupTask>>,
    observation_io: tokio::sync::Mutex<Option<ObservationTask>>,
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
}

impl FragmentDrainMaintenanceHandle {
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
        let sample = self
            .client
            .observe(&self.boundary, &self.cell)
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        let mut pending = self.observation_io.lock().await;
        if pending.is_none() {
            let writer = self.writer.clone();
            *pending = Some(lore_base::lore_spawn_blocking!(move || {
                (
                    writer.available_bytes().ok(),
                    writer.physical_usage(4096).ok().flatten(),
                )
            }));
        }
        let (available_bytes, physical_usage) = match pending.as_mut() {
            Some(task) => task.await.unwrap_or((None, None)),
            None => (None, None),
        };
        *pending = None;
        Ok(FragmentDrainObservation {
            spool_bytes: sample.spool_bytes,
            spool_files: sample.spool_files,
            cleanup_backlog: sample.cleanup_backlog,
            roots_usable: available_bytes.is_some(),
            metadata_full: sample.metadata_full,
            available_bytes,
            physical_spool_bytes: physical_usage.map(|value| value.0),
            physical_spool_files: physical_usage.map(|value| value.1),
        })
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
            self.client
                .release_cleanup(&intent)
                .await
                .map_err(FragmentProviderError::DrainAuthority)?;
            count += u32::from(removed);
        }
        let ids = self
            .client
            .cleanup_candidates(&self.boundary, &self.cell, batch)
            .await
            .map_err(FragmentProviderError::DrainAuthority)?;
        for id in ids {
            let intent = self
                .client
                .claim_cleanup(id)
                .await
                .map_err(FragmentProviderError::DrainAuthority)?;
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
            self.client
                .release_cleanup(&intent)
                .await
                .map_err(FragmentProviderError::DrainAuthority)?;
            // Rechecking a compact tombstone is not progress against backlog.
            count += u32::from(removed);
        }
        Ok(count)
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
            observation_io: tokio::sync::Mutex::new(None),
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

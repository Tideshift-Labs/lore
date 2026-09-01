// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The governed provider client: cell boundary binding, the put execution plan, and the
//! charge-before-send kernel (WP-114 CD-5, CR-033 D4).
//!
//! This module is the crate's only place a provider attempt may be authorized. It holds no
//! provider SDK, no credential, no endpoint route, no database connection, no lock, and performs
//! no filesystem or network I/O. What it owns is the algebra CR-033 D4 requires around a send:
//!
//! - **One boundary.** Every attempt names a [`ProviderTarget`], and the cell's configured
//!   [`CellProviderBoundary`] must match its bucket, region, and endpoint host exactly, on every
//!   drain, repair, read, fallback, and operator path alike. There is no fallback route and no
//!   second bucket. The check bounds what this client *authorizes*: a transport that ignored
//!   [`AuthorizedProviderAttempt::target`] and addressed something else would still escape, so
//!   CD-6 owes a client built against the cell's one fixed endpoint, and that remains its
//!   obligation rather than something proved here.
//! - **Charge before send.** [`GovernedProviderClient::execute`] charges the CD-4 authority first
//!   and only then constructs an [`AuthorizedProviderAttempt`]. That permit is the sole input to
//!   [`ProviderTransport::issue`] and cannot be constructed outside this crate, so a transport can
//!   never be handed an attempt that was not charged.
//! - **One authorized attempt per grant.** A transport reports how many provider requests it
//!   issued, and anything other than one is a fail-closed error. This bounds what a transport may
//!   do *and admit to*; it is not, on its own, proof that the SDK's automatic retry is off, because
//!   a retry inside the SDK happens below the transport's one call and would be reported honestly
//!   as one. Disabling automatic retry is CD-6's construction obligation on the real client, and
//!   [`ProviderRetryPolicy`] is the declaration it must be built from. What this side can prove is
//!   narrower and still worth having: a transport cannot issue several requests under one grant and
//!   report them without closing the ledger.
//! - **No refund.** [`ProviderAttemptLedger`] has no refund path at all. A committed grant that
//!   never reached the provider stays charged, which is the valid, nonrefundable
//!   grant-without-attempt window; conservative charging explicitly does not claim exact-once.
//!
//! Nothing here is durable outcome authority. A provider report, including a listing or a
//! read-after-write observation, only ever produces a [`ProviderAttemptOutcome`], which converts
//! into no terminal result, no receipt, and no lifecycle transition. The cell database's committed
//! result row remains the only outcome authority.
//!
//! # What CD-5 deliberately does not wire
//!
//! CD-4's PostgreSQL authority now exists as an explicitly constructed dark implementation, while
//! CD-6's S3 transport does not. This module still ships [`UnwiredChargeAuthority`] and
//! [`UnwiredProviderTransport`] as the defaults; they fail closed on every call and can never report
//! a success. They are guards, not stubs: a client assembled from them charges nothing and sends
//! nothing, so compiling or testing this module authorizes no provider traffic. The budget pin a
//! request carries is passed through opaquely and only checked for shape and for exact echo by the
//! grant; the selected CD-4 authority resolves it against WP-121's unpublished per-cell envelope.
//!
//! One CD-5 obligation is met differently from the way WP-114 words it, and the difference is
//! deliberate. CD-5 says to charge every attempt class "including SDK-level retries". This kernel
//! instead makes an SDK-level retry a contract violation: one grant authorizes exactly one request,
//! and a transport that admits to more closes the ledger. Charging a retry the caller cannot
//! enumerate in advance would need the charge to happen after the send, which is the opposite of
//! charge-before-send. CD-6 must therefore build its client with retry disabled and re-enter this
//! kernel for each attempt, rather than retrying inside one.

use std::fmt;
use std::future::Future;

use thiserror::Error;

use crate::compaction::ObjectStoreProviderAttemptAudit;
use crate::compaction::provider_attempt_audit_is_valid;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_id;
use crate::no_dispatch::CanonicalNoDispatchProof;
use crate::spool::LedgerSpoolView;
use crate::spool::SpoolLayout;
use crate::spool::SpoolObjectKey;
use crate::spool::SpoolObjectKind;

/// Smallest part size S3-compatible multipart uploads accept for any part but the last.
pub const PROVIDER_MIN_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024;
/// Largest part size S3-compatible multipart uploads accept.
pub const PROVIDER_MAX_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Largest object a single-shot PUT may carry.
pub const PROVIDER_MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Largest number of parts one multipart upload may carry.
pub const PROVIDER_MAX_MULTIPART_PARTS: u32 = 10_000;
/// Longest provider-attempt admission window after the attempt UUIDv7 timestamp.
pub const PROVIDER_ATTEMPT_DEADLINE_HORIZON_MS: i64 = 5 * 60 * 1_000;

/// The closed set of physical provider attempt classes this cell may issue.
///
/// These are *physical* attempts, one charged operation each, not the logical operations of
/// `object_store_request_v1`. One logical PUT expands into a create, its parts, and a complete,
/// and CR-033 D4 charges each of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderAttemptClass {
    /// Bucket readiness probe (`HeadBucket`).
    Readiness,
    HeadObject,
    GetObject,
    PutObject,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    ListObjectsV2,
    ListObjectVersions,
    DeleteObject,
}

impl ProviderAttemptClass {
    pub const ALL: [Self; 11] = [
        Self::Readiness,
        Self::HeadObject,
        Self::GetObject,
        Self::PutObject,
        Self::CreateMultipartUpload,
        Self::UploadPart,
        Self::CompleteMultipartUpload,
        Self::AbortMultipartUpload,
        Self::ListObjectsV2,
        Self::ListObjectVersions,
        Self::DeleteObject,
    ];

    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Readiness => "Readiness",
            Self::HeadObject => "HeadObject",
            Self::GetObject => "GetObject",
            Self::PutObject => "PutObject",
            Self::CreateMultipartUpload => "CreateMultipartUpload",
            Self::UploadPart => "UploadPart",
            Self::CompleteMultipartUpload => "CompleteMultipartUpload",
            Self::AbortMultipartUpload => "AbortMultipartUpload",
            Self::ListObjectsV2 => "ListObjectsV2",
            Self::ListObjectVersions => "ListObjectVersions",
            Self::DeleteObject => "DeleteObject",
        }
    }

    /// Whether the class is a provider listing, which needs the capability gate and the stricter
    /// subordinate cap of CR-033 D4.
    pub const fn is_listing(self) -> bool {
        matches!(self, Self::ListObjectsV2 | Self::ListObjectVersions)
    }

    /// Whether the class transfers an object body and therefore requires a durable spooled body.
    pub const fn carries_object_body(self) -> bool {
        matches!(self, Self::PutObject | Self::UploadPart)
    }
}

/// The closed set of traffic classes that share the one cell budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderTrafficClass {
    Drain,
    DirectFallback,
    Read,
    Repair,
    Operator,
}

impl ProviderTrafficClass {
    pub const ALL: [Self; 5] = [
        Self::Drain,
        Self::DirectFallback,
        Self::Read,
        Self::Repair,
        Self::Operator,
    ];

    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Drain => "Drain",
            Self::DirectFallback => "DirectFallback",
            Self::Read => "Read",
            Self::Repair => "Repair",
            Self::Operator => "Operator",
        }
    }

    pub const fn cap_class(self) -> ProviderCapClass {
        match self {
            Self::Drain => ProviderCapClass::TrafficDrain,
            Self::DirectFallback => ProviderCapClass::TrafficDirectFallback,
            Self::Read => ProviderCapClass::TrafficRead,
            Self::Repair => ProviderCapClass::TrafficRepair,
            Self::Operator => ProviderCapClass::TrafficOperator,
        }
    }
}

/// The closed set of caps one charge consumes.
///
/// [`ProviderCapClass::SharedPhysicalBudget`] is the cell's one physical budget over its provider
/// boundary. Every other variant is a *subordinate* cap inside it. A class label never creates
/// another copy of a physical ceiling, so every charge consumes the shared budget as well as each
/// applicable subordinate cap, atomically, in CD-4's one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderCapClass {
    SharedPhysicalBudget,
    TrafficDrain,
    TrafficDirectFallback,
    TrafficRead,
    TrafficRepair,
    TrafficOperator,
    List,
}

impl ProviderCapClass {
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::SharedPhysicalBudget => "SharedPhysicalBudget",
            Self::TrafficDrain => "TrafficDrain",
            Self::TrafficDirectFallback => "TrafficDirectFallback",
            Self::TrafficRead => "TrafficRead",
            Self::TrafficRepair => "TrafficRepair",
            Self::TrafficOperator => "TrafficOperator",
            Self::List => "List",
        }
    }
}

/// The SDK's automatic retry setting, which has exactly one legal value.
///
/// The type exists so a provider client cannot be constructed without stating the setting, and so
/// the setting cannot be stated as anything but disabled. The setting itself is not the
/// enforcement: [`ProviderAttemptReport::provider_requests_issued`] is, because it is observable
/// from this side of the seam and a declaration is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderRetryPolicy(());

impl ProviderRetryPolicy {
    pub const fn disabled() -> Self {
        Self(())
    }

    pub const fn max_attempts(self) -> u32 {
        1
    }
}

/// Provider capabilities the cell's operator has granted.
///
/// Absent a capability the corresponding attempt class fails closed. There is no default-on
/// capability: [`ProviderCapabilities::none`] is the only starting point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderCapabilities {
    listing: bool,
}

impl ProviderCapabilities {
    pub const fn none() -> Self {
        Self { listing: false }
    }

    pub const fn with_listing(self) -> Self {
        Self { listing: true }
    }

    pub const fn listing(self) -> bool {
        self.listing
    }
}

/// The provider address an attempt is aimed at.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderTarget {
    pub bucket: String,
    pub region: String,
    pub endpoint_host: String,
}

impl fmt::Debug for ProviderTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderTarget")
            .field("bucket", &"[REDACTED]")
            .field("region", &"[REDACTED]")
            .field("endpoint_host", &"[REDACTED]")
            .finish()
    }
}

/// The cell's one configured provider boundary.
///
/// The type names no credential and holds no secret. A cell's credentials are scoped to this one
/// bucket by the operator; this value is the in-process check that nothing addresses anything else.
#[derive(Clone, PartialEq, Eq)]
pub struct CellProviderBoundary {
    provider_boundary_id: String,
    target: ProviderTarget,
}

impl CellProviderBoundary {
    pub fn new(
        provider_boundary_id: &str,
        bucket: &str,
        region: &str,
        endpoint_host: &str,
    ) -> Result<Self, ProviderClientError> {
        validate_canonical_id(provider_boundary_id)
            .map_err(|_| ProviderClientError::InvalidProviderBoundaryId)?;
        validate_bucket_name(bucket)?;
        validate_region(region)?;
        validate_endpoint_host(endpoint_host)?;
        Ok(Self {
            provider_boundary_id: provider_boundary_id.to_string(),
            target: ProviderTarget {
                bucket: bucket.to_string(),
                region: region.to_string(),
                endpoint_host: endpoint_host.to_string(),
            },
        })
    }

    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn target(&self) -> &ProviderTarget {
        &self.target
    }

    /// Rejects any target that is not exactly this cell's bucket, region, and endpoint host.
    pub fn validate_target(&self, target: &ProviderTarget) -> Result<(), ProviderClientError> {
        if target.bucket != self.target.bucket {
            return Err(ProviderClientError::BucketOutsideCellBoundary);
        }
        if target.region != self.target.region {
            return Err(ProviderClientError::RegionOutsideCell);
        }
        if target.endpoint_host != self.target.endpoint_host {
            return Err(ProviderClientError::EndpointOutsideCellRegion);
        }
        Ok(())
    }
}

impl fmt::Debug for CellProviderBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CellProviderBoundary")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("target", &self.target)
            .finish()
    }
}

fn validate_bucket_name(value: &str) -> Result<(), ProviderClientError> {
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || bytes.len() > 63
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        || value.contains("..")
        || value.contains(".-")
        || value.contains("-.")
    {
        return Err(ProviderClientError::InvalidBucketName);
    }
    let first = bytes.first().copied().unwrap_or(b'.');
    let last = bytes.last().copied().unwrap_or(b'.');
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !(last.is_ascii_lowercase() || last.is_ascii_digit())
    {
        return Err(ProviderClientError::InvalidBucketName);
    }
    // S3-compatible providers reject an IPv4-shaped bucket name, because it is ambiguous with a
    // path-style endpoint address, and reject the `xn--` punycode prefix.
    if value.starts_with("xn--") || is_ipv4_shaped(value) {
        return Err(ProviderClientError::InvalidBucketName);
    }
    Ok(())
}

fn is_ipv4_shaped(value: &str) -> bool {
    let mut labels = 0usize;
    for label in value.split('.') {
        labels += 1;
        if labels > 4 || label.is_empty() || !label.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    labels == 4
}

fn validate_region(value: &str) -> Result<(), ProviderClientError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || bytes.first() == Some(&b'-')
        || bytes.last() == Some(&b'-')
    {
        return Err(ProviderClientError::InvalidRegion);
    }
    Ok(())
}

fn validate_endpoint_host(value: &str) -> Result<(), ProviderClientError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 253 {
        return Err(ProviderClientError::InvalidEndpointHost);
    }
    // A single-label host is accepted. A dotted name is not the boundary control here: the exact
    // bucket, region, and host match is, so accepting one label loosens nothing. Requiring a dot
    // would make a container hostname such as `minio`, which a later local tier needs, expressible
    // only by loosening this validator at that point instead.
    let labels: Vec<&str> = value.split('.').collect();
    for label in labels {
        let label = label.as_bytes();
        if label.is_empty()
            || label.len() > 63
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
            || !label
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ProviderClientError::InvalidEndpointHost);
        }
    }
    Ok(())
}

/// Bounds the cell applies when planning a PUT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderPutLimits {
    /// Largest body a single-shot PUT may carry before the plan becomes multipart.
    pub multipart_threshold_bytes: u64,
    /// Size of every part but the last.
    pub part_size_bytes: u64,
    /// Largest number of parts this cell will plan, never above the provider's own ceiling.
    pub max_parts: u32,
}

impl ProviderPutLimits {
    fn validate(&self) -> Result<(), ProviderClientError> {
        if self.part_size_bytes < PROVIDER_MIN_PART_SIZE_BYTES
            || self.part_size_bytes > PROVIDER_MAX_PART_SIZE_BYTES
        {
            return Err(ProviderClientError::InvalidPutLimits);
        }
        if self.max_parts == 0 || self.max_parts > PROVIDER_MAX_MULTIPART_PARTS {
            return Err(ProviderClientError::InvalidPutLimits);
        }
        if self.multipart_threshold_bytes < self.part_size_bytes
            || self.multipart_threshold_bytes > PROVIDER_MAX_SINGLE_PUT_BYTES
        {
            return Err(ProviderClientError::InvalidPutLimits);
        }
        Ok(())
    }
}

/// The attempt sequence one logical PUT expands into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutObjectPlan {
    SingleShot {
        body_size: u64,
    },
    Multipart {
        body_size: u64,
        part_size_bytes: u64,
        part_count: u32,
        final_part_size_bytes: u64,
    },
}

impl PutObjectPlan {
    /// Number of provider attempts the plan charges when every attempt succeeds.
    ///
    /// An abort is contingent on failure and is charged when it is issued, so it is not counted
    /// here.
    pub const fn planned_attempt_count(self) -> u64 {
        match self {
            Self::SingleShot { .. } => 1,
            Self::Multipart { part_count, .. } => part_count as u64 + 2,
        }
    }

    /// The attempt class at `index` in the planned sequence.
    pub const fn attempt_class_at(self, index: u64) -> Option<ProviderAttemptClass> {
        match self {
            Self::SingleShot { .. } => {
                if index == 0 {
                    Some(ProviderAttemptClass::PutObject)
                } else {
                    None
                }
            }
            Self::Multipart { part_count, .. } => {
                let parts = part_count as u64;
                if index == 0 {
                    Some(ProviderAttemptClass::CreateMultipartUpload)
                } else if index <= parts {
                    Some(ProviderAttemptClass::UploadPart)
                } else if index == parts + 1 {
                    Some(ProviderAttemptClass::CompleteMultipartUpload)
                } else {
                    None
                }
            }
        }
    }

    /// Byte range of the 1-based `part_number`, or `None` outside the plan.
    ///
    /// The variants' fields are public so callers can match on a plan, which means a hand-built
    /// plan need not be one [`plan_put_object`] would mint. The arithmetic here is therefore
    /// checked and answers `None` where a plan's own numbers do not fit in a `u64`. That is all it
    /// checks: a hand-built plan whose parts do not tile its own `body_size` still yields ranges,
    /// and the ranges a request actually sends are revalidated against the durable body by
    /// [`GovernedProviderClient::authorize`], which is where a bad range is caught.
    pub const fn part_range(self, part_number: u32) -> Option<(u64, u64)> {
        match self {
            Self::SingleShot { .. } => None,
            Self::Multipart {
                part_size_bytes,
                part_count,
                final_part_size_bytes,
                ..
            } => {
                if part_number == 0 || part_number > part_count {
                    return None;
                }
                let offset = match (part_number as u64 - 1).checked_mul(part_size_bytes) {
                    Some(offset) => offset,
                    None => return None,
                };
                let length = if part_number == part_count {
                    final_part_size_bytes
                } else {
                    part_size_bytes
                };
                if offset.checked_add(length).is_none() {
                    return None;
                }
                Some((offset, length))
            }
        }
    }
}

/// Plans the attempt sequence for one PUT of `body_size` bytes.
pub fn plan_put_object(
    body_size: u64,
    limits: &ProviderPutLimits,
) -> Result<PutObjectPlan, ProviderClientError> {
    limits.validate()?;
    if body_size <= limits.multipart_threshold_bytes {
        return Ok(PutObjectPlan::SingleShot { body_size });
    }
    let part_count = body_size.div_ceil(limits.part_size_bytes);
    let part_count =
        u32::try_from(part_count).map_err(|_| ProviderClientError::MultipartPartCountExceeded)?;
    if part_count > limits.max_parts {
        return Err(ProviderClientError::MultipartPartCountExceeded);
    }
    let whole_parts = u64::from(part_count - 1)
        .checked_mul(limits.part_size_bytes)
        .ok_or(ProviderClientError::MultipartPartCountExceeded)?;
    let final_part_size_bytes = body_size
        .checked_sub(whole_parts)
        .ok_or(ProviderClientError::MultipartPartCountExceeded)?;
    Ok(PutObjectPlan::Multipart {
        body_size,
        part_size_bytes: limits.part_size_bytes,
        part_count,
        final_part_size_bytes,
    })
}

/// A PUT body proven durable in the cell's spool and bound to the request that owns it.
///
/// The only constructor is [`bind_durable_put_body`], and it accepts only a ledger row already in
/// [`LedgerSpoolView::Ready`]. A PUT attempt cannot be assembled without one, so the governed
/// client cannot send a body that is not durably spooled, and cannot send one request's body under
/// another request's identity.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableProviderPutBody {
    provider_boundary_id: String,
    logical_request_id: String,
    spool_attempt_id: String,
    opaque_handle: String,
    size: u64,
    blake3: [u8; 32],
}

impl DurableProviderPutBody {
    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn logical_request_id(&self) -> &str {
        &self.logical_request_id
    }

    /// The spool attempt that wrote this body, which is deliberately *not* the provider attempt
    /// that sends it and is deliberately not checked by
    /// [`GovernedProviderClient::validate_attempt`]. One spooled body is written once and then
    /// serves every part attempt of a multipart upload, so requiring it to equal the sending
    /// attempt's id would forbid multipart entirely. The binding that does the work is to the
    /// logical request and the boundary, both of which are checked.
    pub fn spool_attempt_id(&self) -> &str {
        &self.spool_attempt_id
    }

    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn blake3(&self) -> &[u8; 32] {
        &self.blake3
    }
}

impl fmt::Debug for DurableProviderPutBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableProviderPutBody")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("spool_attempt_id", &"[REDACTED]")
            .field("opaque_handle", &"[REDACTED]")
            .field("size", &self.size)
            .field("blake3", &"[REDACTED]")
            .finish()
    }
}

/// Binds a spool ledger row to the PUT body an attempt may send.
///
/// This derives the layout's path handle and requires the ledger's stored handle to equal it, so a
/// ready row recorded against a different request or boundary cannot be adopted. It performs no
/// filesystem access: readiness is the database's assertion, and physical revalidation belongs to
/// the spool verifier that minted the observation behind that assertion.
pub fn bind_durable_put_body(
    layout: &SpoolLayout,
    key: &SpoolObjectKey,
    ledger: &LedgerSpoolView,
) -> Result<DurableProviderPutBody, ProviderClientError> {
    if key.kind != SpoolObjectKind::Put {
        return Err(ProviderClientError::InvalidSpoolKind);
    }
    let paths = layout
        .derive_paths(key)
        .map_err(|_| ProviderClientError::InvalidSpoolKey)?;
    let LedgerSpoolView::Ready {
        opaque_handle,
        size,
        blake3,
    } = ledger
    else {
        return Err(ProviderClientError::PutBodyNotDurable);
    };
    if opaque_handle != paths.opaque_handle() {
        return Err(ProviderClientError::PutBodyHandleMismatch);
    }
    Ok(DurableProviderPutBody {
        provider_boundary_id: key.provider_boundary_id.clone(),
        logical_request_id: key.logical_request_id.clone(),
        spool_attempt_id: key.attempt_id.clone(),
        opaque_handle: opaque_handle.clone(),
        size: *size,
        blake3: *blake3,
    })
}

/// The byte range of one multipart part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderPutPart {
    pub part_number: u32,
    pub offset: u64,
    pub length: u64,
}

/// WP-121's frozen per-cell budget-configuration revision and its monotonic generation.
///
/// CD-5 treats the pin as opaque. It checks the shape, passes it to the charge authority, and
/// requires the grant to echo it exactly. Resolving the pin against the cell's current envelope is
/// CD-4's obligation, and the envelope is unpublished.
#[derive(Clone, PartialEq, Eq)]
pub struct BudgetPin {
    pub revision: String,
    pub fence: u64,
}

impl fmt::Debug for BudgetPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetPin")
            .field("revision", &"[REDACTED]")
            .field("fence", &self.fence)
            .finish()
    }
}

/// One physical provider attempt a caller asks the governed client to execute.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAttemptRequest {
    pub traffic_class: ProviderTrafficClass,
    pub attempt_class: ProviderAttemptClass,
    pub target: ProviderTarget,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub attempt_ordinal: u32,
    /// Provider-attempt deadline, evaluated only against the database admission clock.
    pub deadline_unix_ms: i64,
    pub budget_pin: BudgetPin,
    pub put_body: Option<DurableProviderPutBody>,
    pub put_part: Option<ProviderPutPart>,
}

impl fmt::Debug for ProviderAttemptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttemptRequest")
            .field("traffic_class", &self.traffic_class)
            .field("attempt_class", &self.attempt_class)
            .field("target", &self.target)
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("attempt_ordinal", &self.attempt_ordinal)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .field("budget_pin", &self.budget_pin)
            .field("put_body", &self.put_body)
            .field("put_part", &self.put_part)
            .finish()
    }
}

/// What the governed client asks CD-4's limiter to charge.
///
/// Constructed only by [`GovernedProviderClient::execute`], after the boundary, capability, and
/// body checks pass, so a charge request always describes an attempt this cell may make.
///
/// Deliberately not `Clone`, and deliberately without a public constructor. This value is the only
/// thing a [`ProviderChargeAuthority`] will charge, so an implementation that could retain a copy
/// past the call could charge again later, outside any ledger, producing a committed grant the
/// audit reports as zero in a shape the frozen encoder accepts. An implementation receives a borrow
/// that ends with the call and can keep nothing chargeable from it.
#[derive(PartialEq, Eq)]
pub struct ProviderChargeRequest {
    provider_boundary_id: String,
    traffic_class: ProviderTrafficClass,
    attempt_class: ProviderAttemptClass,
    attempt_units: u64,
    budget_pin: BudgetPin,
    logical_request_id: String,
    attempt_id: String,
    attempt_ordinal: u32,
    deadline_unix_ms: i64,
}

impl ProviderChargeRequest {
    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn traffic_class(&self) -> ProviderTrafficClass {
        self.traffic_class
    }

    pub fn attempt_class(&self) -> ProviderAttemptClass {
        self.attempt_class
    }

    /// Units this attempt consumes from every cap it touches. One physical attempt is one unit;
    /// a class label never scales it.
    pub fn attempt_units(&self) -> u64 {
        self.attempt_units
    }

    pub fn budget_pin(&self) -> &BudgetPin {
        &self.budget_pin
    }

    pub fn logical_request_id(&self) -> &str {
        &self.logical_request_id
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn attempt_ordinal(&self) -> u32 {
        self.attempt_ordinal
    }

    pub fn deadline_unix_ms(&self) -> i64 {
        self.deadline_unix_ms
    }

    /// Every cap this charge must consume atomically: the cell's one shared physical budget, the
    /// traffic class cap, and the stricter listing cap when the attempt is a listing.
    pub fn cap_classes(&self) -> Vec<ProviderCapClass> {
        let mut caps = vec![
            ProviderCapClass::SharedPhysicalBudget,
            self.traffic_class.cap_class(),
        ];
        if self.attempt_class.is_listing() {
            caps.push(ProviderCapClass::List);
        }
        caps
    }
}

impl fmt::Debug for ProviderChargeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderChargeRequest")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("traffic_class", &self.traffic_class)
            .field("attempt_class", &self.attempt_class)
            .field("attempt_units", &self.attempt_units)
            .field("budget_pin", &self.budget_pin)
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("attempt_ordinal", &self.attempt_ordinal)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .finish()
    }
}

/// A committed charge against the cell budget.
///
/// A grant bounds one attempt. It does not prove the attempt happened, and it is never refunded.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderChargeGrant {
    pub grant_id: String,
    pub traffic_class: ProviderTrafficClass,
    pub attempt_class: ProviderAttemptClass,
    pub charged_units: u64,
    pub budget_pin: BudgetPin,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub attempt_ordinal: u32,
    /// The cell database's clock at commit. Process time is not admission authority.
    pub granted_at_database_unix_ms: i64,
}

impl fmt::Debug for ProviderChargeGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderChargeGrant")
            .field("grant_id", &"[REDACTED]")
            .field("traffic_class", &self.traffic_class)
            .field("attempt_class", &self.attempt_class)
            .field("charged_units", &self.charged_units)
            .field("budget_pin", &self.budget_pin)
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("attempt_ordinal", &self.attempt_ordinal)
            .field(
                "granted_at_database_unix_ms",
                &self.granted_at_database_unix_ms,
            )
            .finish()
    }
}

/// Why CD-4's limiter refused or could not complete a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProviderChargeError {
    #[error("cell dispatch charge authority is not wired")]
    Unwired,
    #[error("cell dispatch charge rejected the pinned budget revision or generation")]
    BudgetPinRejected,
    #[error("cell dispatch shared physical budget is exhausted")]
    BudgetExhausted,
    #[error("cell dispatch subordinate class cap is exhausted")]
    ClassCapExhausted,
    #[error("cell dispatch budget configuration could not be resolved")]
    ConfigurationUnresolved,
    #[error("cell dispatch charge authority is unavailable")]
    AuthorityUnavailable,
    #[error("cell dispatch attempt deadline has elapsed")]
    DeadlineExceeded,
    /// The durable CAS proves this exact attempt was charged before this call. The current ledger
    /// must not count it again.
    #[error("cell dispatch attempt was already charged")]
    AttemptAlreadyCharged,
    /// A distinct recovery caller proved that the current fresh ledger did not yet count the
    /// durable charge. The governed client records it once and never sends under it.
    #[error("cell dispatch charge was recovered into a fresh ledger")]
    RecoveredCommittedCharge,
    /// The charge transaction's commit outcome cannot be proved.
    #[error("cell dispatch charge commit outcome is ambiguous")]
    AmbiguousCommit,
}

/// CD-4's shared cell-local limiter, seen from the provider client.
///
/// Every implementation must consume the cell's one shared
/// physical budget and each subordinate cap in [`ProviderChargeRequest::cap_classes`] atomically in
/// one transaction, and must fail closed when the budget configuration cannot be resolved rather
/// than falling back to an unbounded rate.
///
/// Dropping the returned future after it has started is cancellation-unsafe: the authority may
/// still commit. A caller must therefore treat cancellation while the future is pending exactly
/// like [`ProviderChargeError::AmbiguousCommit`]. [`GovernedProviderClient::execute`] does this
/// with an armed ledger guard that records one conservative grant if its own future is dropped
/// across the await.
///
/// **Any error other than `AmbiguousCommit`, `AttemptAlreadyCharged`, or
/// `RecoveredCommittedCharge` claims nothing was committed.** `AttemptAlreadyCharged` proves a
/// prior durable charge but must not increment the current ledger again. Only a distinct recovery
/// caller that knows it is rebuilding a fresh ledger may return `RecoveredCommittedCharge`.
/// [`GovernedProviderClient::execute`] counts a grant against the ledger for `Ok` and for
/// [`ProviderChargeError::AmbiguousCommit`] or
/// [`ProviderChargeError::RecoveredCommittedCharge`], and for no other error. So an implementation
/// that maps a connection drop around `COMMIT` to, say,
/// [`ProviderChargeError::AuthorityUnavailable`] makes the audit under-report a charge that may
/// have committed. Any outcome an implementation cannot prove uncommitted must be reported as
/// `AmbiguousCommit`, which is the conservative, nonrefundable arm.
pub trait ProviderChargeAuthority {
    fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> impl Future<Output = Result<ProviderChargeGrant, ProviderChargeError>> + Send;
}

struct ChargeCancellationGuard<'a> {
    ledger: &'a mut ProviderAttemptLedger,
    armed: bool,
}

impl<'a> ChargeCancellationGuard<'a> {
    fn new(ledger: &'a mut ProviderAttemptLedger) -> Self {
        Self {
            ledger,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn ledger(&mut self) -> &mut ProviderAttemptLedger {
        self.ledger
    }
}

impl Drop for ChargeCancellationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Once the charge future is pending, cancellation cannot prove that no commit reached
            // PostgreSQL. Count one conservative grant. Overflow poisons the ledger inside the
            // recorder; Drop has no caller to return that error to.
            let _ = self.ledger.record_committed_grant();
        }
    }
}

/// The shipped charge authority: it charges nothing and grants nothing.
///
/// This is the fail-closed guard that keeps CD-5 source-dark. It is not a stub that fakes a
/// success, and it has no configuration that could turn it into one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnwiredChargeAuthority;

impl ProviderChargeAuthority for UnwiredChargeAuthority {
    async fn charge(
        &self,
        _request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        Err(ProviderChargeError::Unwired)
    }
}

/// A charged attempt a transport may issue, and the only thing a transport is ever handed.
///
/// The constructor is crate-private, so no code outside this crate can build one. That is the
/// no-bypass property CR-033 D1 leaves reviewable by construction now that caller identity is
/// database-role identity rather than an mTLS binding.
pub struct AuthorizedProviderAttempt<'a> {
    request: &'a ProviderAttemptRequest,
    grant: &'a ProviderChargeGrant,
    retry_policy: ProviderRetryPolicy,
}

impl<'a> AuthorizedProviderAttempt<'a> {
    fn new(
        request: &'a ProviderAttemptRequest,
        grant: &'a ProviderChargeGrant,
        retry_policy: ProviderRetryPolicy,
    ) -> Self {
        Self {
            request,
            grant,
            retry_policy,
        }
    }

    pub fn traffic_class(&self) -> ProviderTrafficClass {
        self.request.traffic_class
    }

    pub fn attempt_class(&self) -> ProviderAttemptClass {
        self.request.attempt_class
    }

    pub fn target(&self) -> &ProviderTarget {
        &self.request.target
    }

    pub fn logical_request_id(&self) -> &str {
        &self.request.logical_request_id
    }

    pub fn attempt_id(&self) -> &str {
        &self.request.attempt_id
    }

    pub fn attempt_ordinal(&self) -> u32 {
        self.request.attempt_ordinal
    }

    pub fn put_body(&self) -> Option<&DurableProviderPutBody> {
        self.request.put_body.as_ref()
    }

    pub fn put_part(&self) -> Option<ProviderPutPart> {
        self.request.put_part
    }

    pub fn grant(&self) -> &ProviderChargeGrant {
        self.grant
    }

    /// The automatic-retry setting the transport's client must have been built with.
    pub fn retry_policy(&self) -> ProviderRetryPolicy {
        self.retry_policy
    }
}

impl fmt::Debug for AuthorizedProviderAttempt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedProviderAttempt")
            .field("request", &self.request)
            .field("grant", &self.grant)
            .finish()
    }
}

/// What the provider did with one issued attempt.
///
/// This is not a durable outcome. It records whether the provider's response was definite, never
/// what the object's lifecycle state now is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderAttemptOutcome {
    /// The provider returned a definite response, success or definite failure.
    Decisive,
    /// No definite response was observed. The charge stands and the effect is unknown.
    Ambiguous,
}

/// A transport's report on one authorized attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAttemptReport {
    pub outcome: ProviderAttemptOutcome,
    /// How many requests the transport actually put on the wire for this one authorized attempt.
    ///
    /// Exactly one is authorized. A transport whose SDK retried internally reports more than one
    /// and is rejected, because the extra requests were never charged.
    pub provider_requests_issued: u32,
}

/// A transport's assertion that it issued nothing.
///
/// Returning this is a claim that no request reached the provider. A transport that cannot prove
/// that must report [`ProviderAttemptOutcome::Ambiguous`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProviderTransportRefusal {
    #[error("cell provider transport is not wired")]
    Unwired,
}

/// CD-6's one governed S3 client for the cell's bucket, seen from the charge kernel.
///
/// An implementation must build its SDK client with automatic retry disabled, must issue exactly
/// one request per call, and must never address anything but the attempt's [`ProviderTarget`].
pub trait ProviderTransport {
    fn issue(
        &self,
        attempt: &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal>;
}

/// The shipped transport: it issues nothing.
///
/// CD-5 owns no provider SDK, endpoint, or credential, so the only transport that exists refuses
/// every attempt. A refusal is not a send, so a grant charged before it stays in the valid,
/// nonrefundable grant-without-attempt window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnwiredProviderTransport;

impl ProviderTransport for UnwiredProviderTransport {
    fn issue(
        &self,
        _attempt: &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal> {
        Err(ProviderTransportRefusal::Unwired)
    }
}

/// The attempt accounting one logical request accumulates, and the source of its retained
/// provider-attempt audit.
///
/// A ledger is bound to one boundary and one logical request at construction, and
/// [`GovernedProviderClient::execute`] refuses an attempt that names anything else. The audit this
/// produces is durable evidence attached to a compact receipt that carries its own
/// `logical_request_id`, and the frozen encoder validates only the counters, never whose counters
/// they are. Without the binding, one ledger could accumulate two requests' attempts and be
/// attached to one of them, and nothing anywhere would reject it.
///
/// There is no refund method. `provider_authority_refunded` is therefore always false, which is
/// also the only value [`crate::compaction::validate_and_encode_object_store_provider_attempt_audit`]
/// accepts.
///
/// `Clone` exists for callers that want to explore a hypothetical continuation, such as a test
/// matrix branching one prefix into several suffixes. A clone carries the same binding, so it
/// cannot be used to attribute one request's counters to another; what it can do is diverge from
/// the original and then be finalized as if it had not. Never finalize a request from a clone, only
/// from the ledger that request's own attempts were recorded on.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderAttemptLedger {
    provider_boundary_id: String,
    logical_request_id: String,
    attempt_count: u64,
    committed_grant_count: u64,
    no_dispatch_count: u64,
    decisive_terminal_count: u64,
    ambiguous_count: u64,
    poisoned: Option<ProviderClientError>,
}

impl ProviderAttemptLedger {
    /// Opens a ledger bound to one boundary and one logical request.
    ///
    /// There is deliberately no `Default`: an unbound ledger is exactly the artifact this binding
    /// exists to prevent.
    pub fn new(
        provider_boundary_id: &str,
        logical_request_id: &str,
    ) -> Result<Self, ProviderClientError> {
        validate_canonical_id(provider_boundary_id)
            .map_err(|_| ProviderClientError::InvalidProviderBoundaryId)?;
        canonical_uuid_v7_timestamp(logical_request_id)
            .map_err(|_| ProviderClientError::InvalidRequestIdentity)?;
        Ok(Self {
            provider_boundary_id: provider_boundary_id.to_string(),
            logical_request_id: logical_request_id.to_string(),
            attempt_count: 0,
            committed_grant_count: 0,
            no_dispatch_count: 0,
            decisive_terminal_count: 0,
            ambiguous_count: 0,
            poisoned: None,
        })
    }

    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn logical_request_id(&self) -> &str {
        &self.logical_request_id
    }

    pub fn attempt_count(&self) -> u64 {
        self.attempt_count
    }

    pub fn committed_grant_count(&self) -> u64 {
        self.committed_grant_count
    }

    pub fn no_dispatch_count(&self) -> u64 {
        self.no_dispatch_count
    }

    pub fn decisive_terminal_count(&self) -> u64 {
        self.decisive_terminal_count
    }

    pub fn ambiguous_count(&self) -> u64 {
        self.ambiguous_count
    }

    /// The error that closed this ledger, if any. A poisoned ledger yields no audit.
    pub fn poisoned(&self) -> Option<ProviderClientError> {
        self.poisoned
    }

    /// Records that the request resolved without any provider dispatch.
    ///
    /// A validated proof is required, and the retained audit algebra admits at most one no-dispatch
    /// record and none once a decisive terminal has been counted.
    ///
    /// The proof is required but not bound to this ledger's request, and cannot be:
    /// [`crate::no_dispatch::NoDispatchProofFields`] carries no request identity, so request A's
    /// ledger can still be finalized with a validated proof minted for request B. The ledger's own
    /// binding narrows this to the proof alone; closing it needs a request identity in the proof
    /// record, and CD-6 owns that producer.
    pub fn record_no_dispatch(
        &mut self,
        _proof: &CanonicalNoDispatchProof,
    ) -> Result<(), ProviderClientError> {
        if let Some(error) = self.poisoned {
            return Err(error);
        }
        // A no-dispatch proof asserts that nothing reached the provider, so an issued attempt
        // forbids it. A committed grant does not: a charge that never reached the wire is exactly
        // the case a no-dispatch proof records. A decisive terminal implies an issued attempt, so
        // it needs no separate clause here.
        if self.no_dispatch_count != 0 || self.attempt_count != 0 {
            return Err(ProviderClientError::NoDispatchNotPermitted);
        }
        self.no_dispatch_count = 1;
        Ok(())
    }

    /// The retained provider-attempt audit, for the logical request the caller is attaching it to.
    ///
    /// The caller must name that request and it must be this ledger's, so a caller reaching for
    /// the wrong ledger is told so at the point of the mistake. **This is not a binding, and the
    /// difference matters.** [`ObjectStoreProviderAttemptAudit`] is a public struct of public
    /// counters, and `ObjectStoreCompactReceiptInput` takes it beside a `logical_request_id` it
    /// never checks it against, so an audit obtained here for request A still attaches to request
    /// B's receipt, and one can be written as a struct literal without calling this at all.
    /// Binding `execute`'s input closed the half that could be closed from inside this module:
    /// one ledger can no longer accumulate two requests' attempts. Closing the other half means a
    /// bound audit type the receipt input requires, which is a contract change to the retained
    /// compact-receipt family and is recorded as an obligation in WP-114 rather than improvised
    /// here.
    ///
    /// Identity is checked before poison, matching [`GovernedProviderClient::execute`]: whether
    /// this is the caller's ledger at all precedes any question about the state it is in.
    pub fn audit_for(
        &self,
        logical_request_id: &str,
    ) -> Result<ObjectStoreProviderAttemptAudit, ProviderClientError> {
        if logical_request_id != self.logical_request_id {
            return Err(ProviderClientError::LedgerRequestMismatch);
        }
        if let Some(error) = self.poisoned {
            return Err(error);
        }
        let audit = ObjectStoreProviderAttemptAudit {
            attempt_count: self.attempt_count,
            committed_grant_count: self.committed_grant_count,
            no_dispatch_count: self.no_dispatch_count,
            decisive_terminal_count: self.decisive_terminal_count,
            ambiguous_count: self.ambiguous_count,
            provider_authority_refunded: false,
            audit_blake3: None,
        };
        // The frozen encoder's own predicate, called rather than restated, so this producer and
        // `compaction`'s encoder cannot drift into disagreeing about what a valid audit is. Every
        // state reachable today satisfies it; the call is what makes a later wrong transition fail
        // here, at the ledger, instead of at a compact receipt far downstream.
        if !provider_attempt_audit_is_valid(&audit) {
            return Err(ProviderClientError::LedgerAlgebraViolation);
        }
        Ok(audit)
    }

    fn poison(&mut self, error: ProviderClientError) -> ProviderClientError {
        if self.poisoned.is_none() {
            self.poisoned = Some(error);
        }
        error
    }

    // A counter that cannot be advanced leaves the ledger understating a charge or an attempt, so
    // every increment closes the ledger on overflow rather than returning a recoverable error.
    fn record_committed_grant(&mut self) -> Result<(), ProviderClientError> {
        match self.committed_grant_count.checked_add(1) {
            Some(next) => {
                self.committed_grant_count = next;
                Ok(())
            }
            None => Err(self.poison(ProviderClientError::LedgerOverflow)),
        }
    }

    fn record_issued_attempt(&mut self) -> Result<(), ProviderClientError> {
        match self.attempt_count.checked_add(1) {
            Some(next) => {
                self.attempt_count = next;
                Ok(())
            }
            None => Err(self.poison(ProviderClientError::LedgerOverflow)),
        }
    }

    fn record_decisive_terminal(&mut self) -> Result<(), ProviderClientError> {
        match self.decisive_terminal_count.checked_add(1) {
            Some(next) => {
                self.decisive_terminal_count = next;
                Ok(())
            }
            None => Err(self.poison(ProviderClientError::LedgerOverflow)),
        }
    }

    fn record_ambiguous(&mut self) -> Result<(), ProviderClientError> {
        match self.ambiguous_count.checked_add(1) {
            Some(next) => {
                self.ambiguous_count = next;
                Ok(())
            }
            None => Err(self.poison(ProviderClientError::LedgerOverflow)),
        }
    }
}

impl fmt::Debug for ProviderAttemptLedger {
    // Binding the ledger to an identity gave it two fields that must not reach a diagnostic
    // surface, so the derive it used to carry no longer suffices.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderAttemptLedger")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_count", &self.attempt_count)
            .field("committed_grant_count", &self.committed_grant_count)
            .field("no_dispatch_count", &self.no_dispatch_count)
            .field("decisive_terminal_count", &self.decisive_terminal_count)
            .field("ambiguous_count", &self.ambiguous_count)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

/// The cell's one governed provider client.
pub struct GovernedProviderClient<C, T> {
    boundary: CellProviderBoundary,
    capabilities: ProviderCapabilities,
    retry_policy: ProviderRetryPolicy,
    charge_authority: C,
    transport: T,
}

impl<C, T> GovernedProviderClient<C, T>
where
    C: ProviderChargeAuthority,
    T: ProviderTransport,
{
    pub fn new(
        boundary: CellProviderBoundary,
        capabilities: ProviderCapabilities,
        retry_policy: ProviderRetryPolicy,
        charge_authority: C,
        transport: T,
    ) -> Self {
        Self {
            boundary,
            capabilities,
            retry_policy,
            charge_authority,
            transport,
        }
    }

    pub fn boundary(&self) -> &CellProviderBoundary {
        &self.boundary
    }

    pub fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }

    pub fn retry_policy(&self) -> ProviderRetryPolicy {
        self.retry_policy
    }

    /// Charges one attempt and, only if the grant binds it exactly, issues it.
    ///
    /// Every failure path is fail-closed: a rejected request never charges, a charge that commits
    /// is never refunded, and a grant that does not bind the attempt closes the ledger instead of
    /// sending under it.
    pub async fn execute(
        &self,
        ledger: &mut ProviderAttemptLedger,
        request: &ProviderAttemptRequest,
    ) -> Result<ProviderAttemptOutcome, ProviderClientError> {
        // Identity first, ahead of the poison flag and the no-dispatch guard alike, and the same
        // order `ProviderAttemptLedger::audit_for` uses: "is this even my ledger" precedes every
        // question about the state that ledger is in, so a caller holding the wrong one is told
        // that rather than handed a fault belonging to a request it is not working on. The audit
        // this ledger produces is attached to a compact receipt carrying its own request identity,
        // and the frozen encoder validates the counters without knowing whose they are, so the
        // binding has to be checked here or nowhere. Refused before anything is charged or sent,
        // and so without closing the ledger.
        if ledger.provider_boundary_id() != self.boundary.provider_boundary_id
            || ledger.logical_request_id() != request.logical_request_id
        {
            return Err(ProviderClientError::LedgerRequestMismatch);
        }
        if let Some(error) = ledger.poisoned() {
            return Err(error);
        }
        // A recorded no-dispatch proof asserts the request resolved without reaching the provider,
        // so dispatching afterwards would contradict a durable claim. The refusal happens before
        // anything is charged or sent, which makes it the same class of caller-sequencing fault
        // `record_no_dispatch` refuses, and it is refused the same way: the ledger stays open and
        // keeps its truthful no-dispatch audit rather than being closed over a call that had no
        // effect.
        if ledger.no_dispatch_count() != 0 {
            return Err(ProviderClientError::DispatchAfterNoDispatch);
        }
        let charge_request = self.authorize(request)?;

        // The authority contract permits the database commit to outlive a dropped future. Arm the
        // ledger before polling it, then disarm only after a concrete result is in hand.
        let mut charge_guard = ChargeCancellationGuard::new(ledger);
        let charge_result = self.charge_authority.charge(&charge_request).await;
        charge_guard.disarm();
        let grant = match charge_result {
            Ok(grant) => grant,
            Err(ProviderChargeError::AmbiguousCommit) => {
                // The commit is unresolved, so conservative charging counts the grant and forbids
                // the send. This is the valid, nonrefundable grant-without-attempt window.
                charge_guard.ledger().record_committed_grant()?;
                return Err(ProviderClientError::ChargeAmbiguous);
            }
            Err(ProviderChargeError::RecoveredCommittedCharge) => {
                charge_guard.ledger().record_committed_grant()?;
                return Err(ProviderClientError::ChargeRecovered);
            }
            Err(error) => return Err(ProviderClientError::ChargeRefused(error)),
        };

        if let Err(error) = validate_grant(&charge_request, &grant) {
            // A returned grant may have committed even though it does not describe this attempt,
            // so it is counted and never refunded, and the ledger closes rather than sending.
            charge_guard.ledger().record_committed_grant()?;
            return Err(charge_guard.ledger().poison(error));
        }
        charge_guard.ledger().record_committed_grant()?;

        let attempt = AuthorizedProviderAttempt::new(request, &grant, self.retry_policy);
        let report = match self.transport.issue(&attempt) {
            Ok(report) => report,
            Err(refusal) => return Err(ProviderClientError::TransportRefused(refusal)),
        };

        match report.provider_requests_issued {
            0 => Err(charge_guard
                .ledger()
                .poison(ProviderClientError::TransportReportInconsistent)),
            1 => {
                charge_guard.ledger().record_issued_attempt()?;
                match report.outcome {
                    ProviderAttemptOutcome::Decisive => {
                        charge_guard.ledger().record_decisive_terminal()?
                    }
                    ProviderAttemptOutcome::Ambiguous => {
                        charge_guard.ledger().record_ambiguous()?
                    }
                }
                Ok(report.outcome)
            }
            _ => {
                // Only one request was authorized and charged. The rest escaped authority, so the
                // ledger closes and this request produces no audit.
                charge_guard.ledger().record_issued_attempt()?;
                Err(charge_guard
                    .ledger()
                    .poison(ProviderClientError::TransportIssuedUnauthorizedRequests))
            }
        }
    }

    /// Validates a request against the cell boundary, the capability gate, and the body rules,
    /// without charging or sending anything.
    ///
    /// This is the public half of [`Self::authorize`]. It deliberately does not hand back the
    /// [`ProviderChargeRequest`], because that value is the only thing a
    /// [`ProviderChargeAuthority`] will charge, and a caller holding both it and the authority
    /// could charge outside any ledger — producing a committed grant the audit reports as zero,
    /// in a shape the frozen encoder accepts. Together with that type having no public constructor
    /// and no `Clone`, charging outside a ledger is unreachable rather than merely discouraged.
    pub fn validate_attempt(
        &self,
        request: &ProviderAttemptRequest,
    ) -> Result<(), ProviderClientError> {
        self.authorize(request)?;
        Ok(())
    }

    /// Validates a request against the cell boundary, the capability gate, and the body rules, and
    /// returns the charge it implies. Charges nothing and sends nothing.
    fn authorize(
        &self,
        request: &ProviderAttemptRequest,
    ) -> Result<ProviderChargeRequest, ProviderClientError> {
        self.boundary.validate_target(&request.target)?;
        if request.attempt_class.is_listing() && !self.capabilities.listing {
            return Err(ProviderClientError::ListCapabilityNotGranted);
        }
        canonical_uuid_v7_timestamp(&request.logical_request_id)
            .map_err(|_| ProviderClientError::InvalidRequestIdentity)?;
        let attempt_timestamp = canonical_uuid_v7_timestamp(&request.attempt_id)
            .map_err(|_| ProviderClientError::InvalidRequestIdentity)?;
        if request.attempt_ordinal == 0 {
            return Err(ProviderClientError::InvalidAttemptOrdinal);
        }
        let latest_deadline = i64::try_from(attempt_timestamp)
            .ok()
            .and_then(|timestamp| timestamp.checked_add(PROVIDER_ATTEMPT_DEADLINE_HORIZON_MS))
            .ok_or(ProviderClientError::InvalidAttemptDeadline)?;
        if request.deadline_unix_ms < 0 || request.deadline_unix_ms > latest_deadline {
            return Err(ProviderClientError::InvalidAttemptDeadline);
        }
        validate_budget_pin(&request.budget_pin)?;
        self.validate_body(request)?;
        Ok(ProviderChargeRequest {
            provider_boundary_id: self.boundary.provider_boundary_id.clone(),
            traffic_class: request.traffic_class,
            attempt_class: request.attempt_class,
            attempt_units: 1,
            budget_pin: request.budget_pin.clone(),
            logical_request_id: request.logical_request_id.clone(),
            attempt_id: request.attempt_id.clone(),
            attempt_ordinal: request.attempt_ordinal,
            deadline_unix_ms: request.deadline_unix_ms,
        })
    }

    fn validate_body(&self, request: &ProviderAttemptRequest) -> Result<(), ProviderClientError> {
        let carries_body = request.attempt_class.carries_object_body();
        let body = match (&request.put_body, carries_body) {
            (Some(body), true) => body,
            (None, false) => {
                if request.put_part.is_some() {
                    return Err(ProviderClientError::PutPartNotPermitted);
                }
                return Ok(());
            }
            (None, true) => return Err(ProviderClientError::PutBodyRequired),
            (Some(_), false) => return Err(ProviderClientError::PutBodyNotPermitted),
        };
        if body.provider_boundary_id != self.boundary.provider_boundary_id {
            return Err(ProviderClientError::PutBodyBoundaryMismatch);
        }
        if body.logical_request_id != request.logical_request_id {
            return Err(ProviderClientError::PutBodyRequestMismatch);
        }
        match request.attempt_class {
            ProviderAttemptClass::PutObject => {
                if request.put_part.is_some() {
                    return Err(ProviderClientError::PutPartNotPermitted);
                }
                if body.size > PROVIDER_MAX_SINGLE_PUT_BYTES {
                    return Err(ProviderClientError::SinglePutBodyTooLarge);
                }
            }
            ProviderAttemptClass::UploadPart => {
                let part = request
                    .put_part
                    .ok_or(ProviderClientError::PutPartRequired)?;
                if part.part_number == 0 || part.part_number > PROVIDER_MAX_MULTIPART_PARTS {
                    return Err(ProviderClientError::InvalidPutPart);
                }
                if part.length == 0 || part.length > PROVIDER_MAX_PART_SIZE_BYTES {
                    return Err(ProviderClientError::InvalidPutPart);
                }
                let end = part
                    .offset
                    .checked_add(part.length)
                    .ok_or(ProviderClientError::InvalidPutPart)?;
                if end > body.size {
                    return Err(ProviderClientError::InvalidPutPart);
                }
                // Only the part that ends the body may be short. Whether a part is final is
                // derivable from the range alone, so the plan does not have to be threaded here.
                if end < body.size && part.length < PROVIDER_MIN_PART_SIZE_BYTES {
                    return Err(ProviderClientError::InvalidPutPart);
                }
            }
            _ => return Err(ProviderClientError::PutBodyNotPermitted),
        }
        Ok(())
    }
}

impl<C, T> fmt::Debug for GovernedProviderClient<C, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedProviderClient")
            .field("boundary", &self.boundary)
            .field("capabilities", &self.capabilities)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

/// Validates the shape of WP-121's budget-configuration revision.
///
/// This is WP-121's frozen byte grammar. It is narrower than the crate's general canonical
/// identifier: a revision is a flat token, so `/` and `:` are excluded and the length is capped
/// well below the general 256-byte bound. Comparison remains case-sensitive and byte-for-byte.
fn validate_budget_revision(value: &str) -> Result<(), ProviderClientError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProviderClientError::InvalidBudgetPin);
    }
    Ok(())
}

fn validate_budget_pin(pin: &BudgetPin) -> Result<(), ProviderClientError> {
    validate_budget_revision(&pin.revision)?;
    // WP-121's frozen sequence starts at one. Rotation is enforced by the cell database and uses
    // exact checked prior-plus-one arithmetic; this seam only rejects the out-of-domain zero.
    if pin.fence == 0 {
        return Err(ProviderClientError::InvalidBudgetPin);
    }
    Ok(())
}

fn validate_grant(
    request: &ProviderChargeRequest,
    grant: &ProviderChargeGrant,
) -> Result<(), ProviderClientError> {
    canonical_uuid_v7_timestamp(&grant.grant_id)
        .map_err(|_| ProviderClientError::GrantDoesNotBindAttempt)?;
    if grant.traffic_class != request.traffic_class
        || grant.attempt_class != request.attempt_class
        || grant.charged_units != request.attempt_units
        || grant.budget_pin != request.budget_pin
        || grant.logical_request_id != request.logical_request_id
        || grant.attempt_id != request.attempt_id
        || grant.attempt_ordinal != request.attempt_ordinal
        || grant.granted_at_database_unix_ms < 0
        || grant.granted_at_database_unix_ms >= request.deadline_unix_ms
    {
        return Err(ProviderClientError::GrantDoesNotBindAttempt);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProviderClientError {
    #[error("cell provider boundary ID is invalid")]
    InvalidProviderBoundaryId,
    #[error("cell provider bucket name is invalid")]
    InvalidBucketName,
    #[error("cell provider region is invalid")]
    InvalidRegion,
    #[error("cell provider endpoint host is invalid")]
    InvalidEndpointHost,
    #[error("provider attempt names a bucket outside the cell boundary")]
    BucketOutsideCellBoundary,
    #[error("provider attempt names a region outside the cell")]
    RegionOutsideCell,
    #[error("provider attempt names an endpoint outside the cell region")]
    EndpointOutsideCellRegion,
    #[error("provider listing capability is not granted for this cell")]
    ListCapabilityNotGranted,
    #[error("provider attempt request identity is not canonical UUIDv7")]
    InvalidRequestIdentity,
    #[error("provider attempt ordinal must be positive")]
    InvalidAttemptOrdinal,
    #[error("provider attempt deadline is outside the bounded admission window")]
    InvalidAttemptDeadline,
    #[error("provider attempt budget pin is invalid")]
    InvalidBudgetPin,
    #[error("provider put limits are outside the supported range")]
    InvalidPutLimits,
    #[error("provider multipart plan exceeds the permitted part count")]
    MultipartPartCountExceeded,
    #[error("object-dispatch spool key names the wrong object kind")]
    InvalidSpoolKind,
    #[error("object-dispatch spool key is invalid")]
    InvalidSpoolKey,
    #[error("provider put body is not durably spooled")]
    PutBodyNotDurable,
    #[error("provider put body handle does not match its spool key")]
    PutBodyHandleMismatch,
    #[error("provider put body belongs to another provider boundary")]
    PutBodyBoundaryMismatch,
    #[error("provider put body belongs to another logical request")]
    PutBodyRequestMismatch,
    #[error("provider attempt class requires a durable put body")]
    PutBodyRequired,
    #[error("provider attempt class does not carry a put body")]
    PutBodyNotPermitted,
    #[error("provider single-shot put body exceeds the provider maximum")]
    SinglePutBodyTooLarge,
    #[error("provider upload-part attempt requires a part range")]
    PutPartRequired,
    #[error("provider attempt class does not carry a part range")]
    PutPartNotPermitted,
    #[error("provider upload-part range is invalid for its body")]
    InvalidPutPart,
    #[error("cell dispatch charge was refused: {0}")]
    ChargeRefused(#[source] ProviderChargeError),
    #[error("cell dispatch charge committed ambiguously and no attempt may be issued under it")]
    ChargeAmbiguous,
    #[error("cell dispatch charge was recovered and no attempt may be issued under it")]
    ChargeRecovered,
    #[error("cell dispatch grant does not bind this attempt")]
    GrantDoesNotBindAttempt,
    #[error("cell provider transport issued nothing: {0}")]
    TransportRefused(ProviderTransportRefusal),
    #[error("cell provider transport reported a successful call that issued no request")]
    TransportReportInconsistent,
    #[error("cell provider transport issued more requests than were charged")]
    TransportIssuedUnauthorizedRequests,
    #[error(
        "provider attempt ledger already recorded a no-dispatch, attempt, or decisive terminal"
    )]
    NoDispatchNotPermitted,
    #[error("provider attempt may not be dispatched after a no-dispatch proof was recorded")]
    DispatchAfterNoDispatch,
    #[error("provider attempt ledger is bound to another boundary or logical request")]
    LedgerRequestMismatch,
    #[error("provider attempt ledger counters violate the retained audit algebra")]
    LedgerAlgebraViolation,
    #[error("provider attempt ledger counter overflowed")]
    LedgerOverflow,
}

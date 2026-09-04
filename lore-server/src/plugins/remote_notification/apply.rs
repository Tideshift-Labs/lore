// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Idempotent application of one `DURABLE_INVALIDATION`, and the seam it
//! applies against.
//!
//! # The comparison is only valid within one aggregate
//!
//! Two `aggregate_version` values are comparable only within one
//! `(event_kind, aggregate_kind, aggregate_identity)` under one repository.
//! That is why [`AggregateKey`] carries all four, and why the ordering itself
//! is delegated to `lore_postgres`'s
//! [`StoredAggregateVersion::compare_within_aggregate`] rather than
//! reimplemented here: one ordering, shared by the producer that wrote the row
//! and the receiver that consumes it, is the only way a duplicate stays a
//! duplicate across the seam.
//!
//! **Two same-named types.** `lore_postgres`'s `AggregateVersion` is the typed
//! Postgres storage encoding; this crate's [`super::envelope::AggregateVersion`]
//! is the wire-facing envelope struct. They are different types in different
//! crates that name the same domain concept, so the stored one is imported
//! under an alias throughout this module.
//!
//! # Why the invalidation target is a trait
//!
//! A cell in `remote` mode mounts no local public notification service, so the
//! process-local derived state a durable invalidation evicts is whatever the
//! surrounding server actually holds — today, in a stock loreserver, nothing.
//! [`NoopInvalidationTarget`] is therefore the honest default rather than a
//! placeholder: it makes the ordering (baseline before drain, refetch before
//! acknowledgement) real and executable, and gives `SCHEMA-119` one named
//! place to hand in a target when a cell gains derived state worth evicting.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_postgres::domain::outbox::VersionOrder;
use lore_postgres::domain::outbox::version::AggregateVersion as StoredAggregateVersion;

use super::envelope::AggregateVersion;
use super::envelope::DurableInvalidationBody;

/// The tuple an `aggregate_version` may be compared within.
///
/// A version from a different key is not "older" or "newer"; it is unrelated,
/// and treating it as ordered is the mistake this type exists to prevent.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AggregateKey {
    /// The repository the event scopes to, as its raw 16 bytes.
    ///
    /// Raw bytes rather than [`RepositoryId`], because `lore_base`'s
    /// `Partition` implements neither `Hash` nor the borrow a map key needs.
    /// The bytes are the identity either way.
    pub repository: [u8; super::envelope::REPOSITORY_BYTES],
    /// CR-032's event kind.
    pub event_kind: String,
    /// CR-032's aggregate kind.
    pub aggregate_kind: String,
    /// CR-032's aggregate identity.
    pub aggregate_identity: String,
}

impl AggregateKey {
    /// The key one durable body belongs to.
    pub fn of(repository: RepositoryId, body: &DurableInvalidationBody) -> Self {
        Self {
            repository: *repository.data(),
            event_kind: body.event_kind.clone(),
            aggregate_kind: body.aggregate_kind.clone(),
            aggregate_identity: body.aggregate_identity.clone(),
        }
    }
}

/// Why a wire `aggregate_version` could not be compared at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionDecodeError {
    /// The identity component is wider than the storage encoding accepts.
    /// Narrower than the envelope's own 128-byte bound by CR-032's pin, so a
    /// 121..=128-byte identity is transportable but not storable and must be
    /// parked rather than silently truncated.
    IdentityTooWide,
}

impl VersionDecodeError {
    /// The bounded poison class this decode failure parks under.
    pub fn poison_class(self) -> &'static str {
        match self {
            Self::IdentityTooWide => "AGGREGATE_VERSION_IDENTITY_TOO_WIDE",
        }
    }
}

/// Convert one wire version into the shared storage encoding.
///
/// # Errors
/// [`VersionDecodeError::IdentityTooWide`] when the identity exceeds the
/// storage encoding's bound.
pub fn to_stored(version: &AggregateVersion) -> Result<StoredAggregateVersion, VersionDecodeError> {
    let identity = version
        .identity
        .as_ref()
        .map(|identity| identity.as_bytes().to_vec())
        .unwrap_or_default();
    StoredAggregateVersion::new(version.ordinal, identity)
        .map_err(|_| VersionDecodeError::IdentityTooWide)
}

/// Per-aggregate applied-version state for one receiver generation.
///
/// Process-local and generation-scoped on purpose. A new generation takes an
/// authoritative baseline, so inheriting a predecessor's decisions would let a
/// stale belief survive the very step that exists to discard it.
#[derive(Debug, Default)]
pub struct AppliedVersions {
    applied: HashMap<AggregateKey, StoredAggregateVersion>,
}

impl AppliedVersions {
    /// An empty state, as a fresh baseline leaves it.
    pub fn new() -> Self {
        Self::default()
    }

    /// How the incoming version relates to what this generation has applied.
    ///
    /// An aggregate with nothing applied yet answers
    /// [`VersionOrder::NextOrdinal`]: the first event after an authoritative
    /// baseline is the next one to apply, not a gap. A gap is a *skip within a
    /// sequence this generation was already following*, which requires a
    /// previous decision to skip past.
    pub fn verdict(&self, key: &AggregateKey, incoming: &StoredAggregateVersion) -> VersionOrder {
        match self.applied.get(key) {
            None => VersionOrder::NextOrdinal,
            Some(applied) => incoming.compare_within_aggregate(applied),
        }
    }

    /// Record that `incoming` is now the applied version for `key`.
    pub fn record(&mut self, key: AggregateKey, incoming: StoredAggregateVersion) {
        self.applied.insert(key, incoming);
    }

    /// Forget every version for one repository, as an authoritative refetch of
    /// that repository does.
    ///
    /// After a refetch the process holds authoritative state, so the next
    /// event for any of that repository's aggregates is the next one to apply
    /// whatever its ordinal — which is exactly what an emptied entry says.
    pub fn forget_repository(&mut self, repository: RepositoryId) {
        let bytes = *repository.data();
        self.applied.retain(|key, _| key.repository != bytes);
    }

    /// Forget everything, as a fresh authoritative baseline does.
    pub fn clear(&mut self) {
        self.applied.clear();
    }

    /// Number of aggregates with an applied version. Diagnostics only.
    pub fn tracked(&self) -> usize {
        self.applied.len()
    }
}

/// The process-local derived state a durable invalidation acts on.
///
/// Every method is infallible by design. An invalidation is an instruction to
/// *discard* a belief, and a discard that could fail would leave the process
/// holding state it has been told is wrong while reporting success. A target
/// that needs I/O to refresh should evict synchronously and refresh lazily.
#[async_trait]
pub trait InvalidationTarget: Send + Sync + std::fmt::Debug {
    /// Discard every process-local derived belief for this cell.
    ///
    /// Called once per receiver generation, after the position is captured and
    /// before the drain. This is the authoritative baseline: everything the
    /// process believed about any repository is dropped, so nothing decided
    /// under a previous epoch survives into this one.
    async fn baseline(&self);

    /// Discard every process-local derived belief for one repository, because
    /// a gap or an incomparable version made ordering undecidable.
    async fn refetch_repository(&self, repository: RepositoryId);

    /// Apply one invalidation to one repository's derived state.
    async fn apply_invalidation(&self, repository: RepositoryId, body: &DurableInvalidationBody);
}

/// The default target for a cell with no process-local derived state.
///
/// A `remote`-mode loreserver mounts no local public notification service and
/// keeps no repository-scoped cache the notification plane feeds, so there is
/// nothing to evict. This is not a stub for missing work: it is the correct
/// target for the deployment shape this plugin exists to serve.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopInvalidationTarget;

#[async_trait]
impl InvalidationTarget for NoopInvalidationTarget {
    async fn baseline(&self) {}
    async fn refetch_repository(&self, _repository: RepositoryId) {}
    async fn apply_invalidation(&self, _repository: RepositoryId, _body: &DurableInvalidationBody) {
    }
}

/// One recorded call on a [`RecordingInvalidationTarget`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetCall {
    /// [`InvalidationTarget::baseline`].
    Baseline,
    /// [`InvalidationTarget::refetch_repository`].
    Refetch(RepositoryId),
    /// [`InvalidationTarget::apply_invalidation`], with the event kind and the
    /// version ordinal that was applied.
    Apply {
        /// The repository the invalidation named.
        repository: RepositoryId,
        /// CR-032's event kind, so an assertion can name the event.
        event_kind: String,
        /// The applied ordinal.
        ordinal: u64,
    },
}

/// An invalidation target that records the ordered calls made against it.
///
/// Public rather than `#[cfg(test)]` because the integration suites under
/// `lore-server/tests/` are a separate crate. The ordering it records is the
/// contract's ordering: baseline before any apply, refetch before the
/// acknowledgement that follows a gap.
#[derive(Clone, Debug, Default)]
pub struct RecordingInvalidationTarget {
    calls: Arc<Mutex<Vec<TargetCall>>>,
}

impl RecordingInvalidationTarget {
    /// A target with no recorded calls.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call made so far, in order.
    pub fn calls(&self) -> Vec<TargetCall> {
        match self.calls.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// How many baselines have been taken.
    pub fn baselines(&self) -> usize {
        self.calls()
            .iter()
            .filter(|call| matches!(call, TargetCall::Baseline))
            .count()
    }

    fn record(&self, call: TargetCall) {
        match self.calls.lock() {
            Ok(mut guard) => guard.push(call),
            Err(poisoned) => poisoned.into_inner().push(call),
        }
    }
}

#[async_trait]
impl InvalidationTarget for RecordingInvalidationTarget {
    async fn baseline(&self) {
        self.record(TargetCall::Baseline);
    }

    async fn refetch_repository(&self, repository: RepositoryId) {
        self.record(TargetCall::Refetch(repository));
    }

    async fn apply_invalidation(&self, repository: RepositoryId, body: &DurableInvalidationBody) {
        self.record(TargetCall::Apply {
            repository,
            event_kind: body.event_kind.clone(),
            ordinal: body.aggregate_version.ordinal,
        });
    }
}

// ---------------------------------------------------------------------------
// Decoding one delivered envelope
// ---------------------------------------------------------------------------

/// The three poison classes the contract names.
///
/// "Invalid scope, malformed identity, or unsupported version follows the
/// poison path." Every decode failure maps onto exactly one of them, plus two
/// this component adds for conditions the contract's three do not cover. The
/// set is closed and `&'static str`, so a class can be a metric label and a
/// projected blocker without carrying an identifier.
pub const POISON_CLASS_SCOPE_MISMATCH: &str = "SCOPE_MISMATCH";
/// A field violated its width, was absent, or the envelope did not decode.
pub const POISON_CLASS_MALFORMED_IDENTITY: &str = "MALFORMED_IDENTITY";
/// A transport or payload version this build does not speak.
pub const POISON_CLASS_UNSUPPORTED_SCHEMA: &str = "UNSUPPORTED_SCHEMA";
/// A `LIVE_HINT` or `SHADOW_OBSERVATION` arrived on the durable stream.
pub const POISON_CLASS_UNEXPECTED_CLASS: &str = "UNEXPECTED_DELIVERY_CLASS";

/// Why one delivered envelope could not be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryViolation {
    /// The envelope failed the shared wire validation.
    Envelope(super::envelope::EnvelopeViolation),
    /// The envelope names a different cell than this receiver serves.
    ///
    /// Its own variant rather than an [`super::envelope::EnvelopeViolation`],
    /// because the shared validation cannot know which cell is expected: it
    /// checks the grammar of `cell_id`, not its value.
    ForeignCell,
    /// The delivery class was not `DURABLE_INVALIDATION`.
    UnexpectedDeliveryClass,
    /// The payload version is outside this cell's configured range.
    UnsupportedPayloadVersion,
    /// `aggregate_version` was absent. Its own variant because the wire type
    /// makes it optional while the contract makes it required.
    MissingAggregateVersion,
}

impl DeliveryViolation {
    /// The bounded poison class this violation parks under.
    pub const fn poison_class(self) -> &'static str {
        use super::envelope::EnvelopeViolation as E;
        match self {
            Self::ForeignCell => POISON_CLASS_SCOPE_MISMATCH,
            Self::UnexpectedDeliveryClass => POISON_CLASS_UNEXPECTED_CLASS,
            Self::UnsupportedPayloadVersion => POISON_CLASS_UNSUPPORTED_SCHEMA,
            Self::MissingAggregateVersion => POISON_CLASS_MALFORMED_IDENTITY,
            Self::Envelope(violation) => match violation {
                E::UnknownTransportVersion | E::UnsupportedPayloadVersion => {
                    POISON_CLASS_UNSUPPORTED_SCHEMA
                }
                E::InvalidCellId
                | E::ZeroRepository
                | E::InvalidRepositoryWidth
                | E::LoreEventRepositoryMismatch => POISON_CLASS_SCOPE_MISMATCH,
                _ => POISON_CLASS_MALFORMED_IDENTITY,
            },
        }
    }
}

/// One decoded delivery, ready to apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedDelivery {
    /// The repository the event scopes to.
    pub repository: RepositoryId,
    /// The typed body.
    pub body: DurableInvalidationBody,
}

/// Decode and scope-check one delivered `DURABLE_INVALIDATION`.
///
/// Every bound the encode path enforces is re-enforced here, against the same
/// constants. That is not redundant: the encode path bounds what *this* cell
/// publishes, and this bounds what some other producer, on some other version,
/// sent. A receiver that trusted the producer's validation would be trusting
/// the exact thing the poison path exists for.
///
/// # Errors
/// The first [`DeliveryViolation`] found. The caller parks the event under
/// [`DeliveryViolation::poison_class`] and does not acknowledge it.
pub fn decode_durable_delivery(
    envelope: &super::wire::PrivateEnvelopeV1,
    expected_cell_id: &str,
    payload_version_min: u32,
    payload_version_max: u32,
) -> Result<DecodedDelivery, DeliveryViolation> {
    use super::envelope::ACTOR_MAX_BYTES;
    use super::envelope::AGGREGATE_IDENTITY_MAX_BYTES;
    use super::envelope::AGGREGATE_KIND_MAX_BYTES;
    use super::envelope::AGGREGATE_VERSION_IDENTITY_MAX_BYTES;
    use super::envelope::EVENT_KIND_MAX_BYTES;
    use super::envelope::EnvelopeViolation;
    use super::envelope::IDEMPOTENCY_KEY_BYTES;
    use super::envelope::PAYLOAD_MAX_BYTES;
    use super::envelope::REPOSITORY_BYTES;
    use super::envelope::validate_wire_envelope;
    use super::wire::private_envelope_v1::Body;

    validate_wire_envelope(envelope).map_err(DeliveryViolation::Envelope)?;

    // Scope first. A message for another cell is not this receiver's to apply
    // however well formed it is, and the gateway rejecting a mismatch upstream
    // is not a reason to trust one that arrived anyway.
    if envelope.cell_id != expected_cell_id {
        return Err(DeliveryViolation::ForeignCell);
    }

    let Some(Body::DurableInvalidation(body)) = envelope.body.as_ref() else {
        return Err(DeliveryViolation::UnexpectedDeliveryClass);
    };

    if !(payload_version_min..=payload_version_max).contains(&body.payload_version) {
        return Err(DeliveryViolation::UnsupportedPayloadVersion);
    }
    if body.repository_generation == 0 {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::MissingRepositoryGeneration,
        ));
    }
    if body.event_kind.is_empty() || body.event_kind.len() > EVENT_KIND_MAX_BYTES {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::EventKindTooLong,
        ));
    }
    if body.aggregate_kind.is_empty() || body.aggregate_kind.len() > AGGREGATE_KIND_MAX_BYTES {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::AggregateKindTooLong,
        ));
    }
    if body.aggregate_identity.is_empty()
        || body.aggregate_identity.len() > AGGREGATE_IDENTITY_MAX_BYTES
    {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::AggregateIdentityTooLong,
        ));
    }
    if body.actor.len() > ACTOR_MAX_BYTES {
        return Err(DeliveryViolation::Envelope(EnvelopeViolation::ActorTooLong));
    }
    if body.payload.len() > PAYLOAD_MAX_BYTES {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::PayloadOverCap,
        ));
    }
    if body.idempotency_key.len() != IDEMPOTENCY_KEY_BYTES {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::InvalidIdempotencyKeyWidth,
        ));
    }
    let Some(version) = body.aggregate_version.as_ref() else {
        return Err(DeliveryViolation::MissingAggregateVersion);
    };
    if version.identity.len() > AGGREGATE_VERSION_IDENTITY_MAX_BYTES {
        return Err(DeliveryViolation::Envelope(
            EnvelopeViolation::AggregateVersionIdentityTooLong,
        ));
    }

    let mut repository = RepositoryId::default();
    let mut bytes = [0u8; REPOSITORY_BYTES];
    bytes.copy_from_slice(&envelope.repository[..REPOSITORY_BYTES]);
    *repository.data_mut() = bytes;

    let mut idempotency_key = [0u8; IDEMPOTENCY_KEY_BYTES];
    idempotency_key.copy_from_slice(&body.idempotency_key[..IDEMPOTENCY_KEY_BYTES]);

    Ok(DecodedDelivery {
        repository,
        body: DurableInvalidationBody {
            payload_version: body.payload_version,
            idempotency_key,
            event_kind: body.event_kind.clone(),
            repository_generation: body.repository_generation,
            aggregate_kind: body.aggregate_kind.clone(),
            aggregate_identity: body.aggregate_identity.clone(),
            aggregate_version: AggregateVersion {
                ordinal: version.ordinal,
                identity: if version.identity.is_empty() {
                    None
                } else {
                    Some(version.identity.clone())
                },
            },
            payload: body.payload.clone(),
            // An absent or unrepresentable `committed_at` defaults rather than
            // parking, and that is deliberate: the contract makes this field a
            // diagnostic and says outright it is never ordering authority.
            // Ordering comes from `aggregate_version`, which IS bound-checked
            // above. Parking an otherwise applicable invalidation over a bad
            // diagnostic timestamp would stall a frontier for something no
            // decision reads.
            committed_at: body
                .committed_at
                .as_ref()
                .copied()
                .and_then(|timestamp| std::time::SystemTime::try_from(timestamp).ok())
                .unwrap_or(std::time::UNIX_EPOCH),
            actor: if body.actor.is_empty() {
                None
            } else {
                Some(body.actor.clone())
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use bytes::Bytes;

    use super::*;

    fn repository(byte: u8) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = [byte; 16];
        id
    }

    fn body(ordinal: u64, identity: Option<&str>) -> DurableInvalidationBody {
        DurableInvalidationBody {
            payload_version: 1,
            idempotency_key: [3; 32],
            event_kind: "branch.pushed".to_string(),
            repository_generation: 1,
            aggregate_kind: "branch".to_string(),
            aggregate_identity: "0123456789abcdef".to_string(),
            aggregate_version: AggregateVersion {
                ordinal,
                identity: identity.map(str::to_string),
            },
            payload: Bytes::new(),
            committed_at: UNIX_EPOCH,
            actor: None,
        }
    }

    fn stored(ordinal: u64, identity: Option<&str>) -> StoredAggregateVersion {
        to_stored(&AggregateVersion {
            ordinal,
            identity: identity.map(str::to_string),
        })
        .expect("a short identity encodes")
    }

    #[test]
    fn an_unknown_aggregate_is_the_next_ordinal_not_a_gap() {
        let versions = AppliedVersions::new();
        let key = AggregateKey::of(repository(1), &body(417, None));
        assert_eq!(
            versions.verdict(&key, &stored(417, None)),
            VersionOrder::NextOrdinal,
            "the first event after an authoritative baseline is applied, not refetched"
        );
    }

    #[test]
    fn the_same_version_twice_is_a_duplicate() {
        let mut versions = AppliedVersions::new();
        let key = AggregateKey::of(repository(1), &body(417, Some("abc")));
        versions.record(key.clone(), stored(417, Some("abc")));
        assert_eq!(
            versions.verdict(&key, &stored(417, Some("abc"))),
            VersionOrder::Equal
        );
    }

    #[test]
    fn a_lower_ordinal_is_stale() {
        let mut versions = AppliedVersions::new();
        let key = AggregateKey::of(repository(1), &body(417, None));
        versions.record(key.clone(), stored(417, None));
        assert_eq!(
            versions.verdict(&key, &stored(416, None)),
            VersionOrder::Older
        );
    }

    #[test]
    fn a_skipped_ordinal_is_a_gap_and_the_contiguous_one_is_not() {
        let mut versions = AppliedVersions::new();
        let key = AggregateKey::of(repository(1), &body(417, None));
        versions.record(key.clone(), stored(417, None));
        assert_eq!(
            versions.verdict(&key, &stored(418, None)),
            VersionOrder::NextOrdinal
        );
        assert_eq!(
            versions.verdict(&key, &stored(420, None)),
            VersionOrder::Newer
        );
    }

    #[test]
    fn the_same_ordinal_with_a_different_identity_is_incomparable() {
        let mut versions = AppliedVersions::new();
        let key = AggregateKey::of(repository(1), &body(417, Some("abc")));
        versions.record(key.clone(), stored(417, Some("abc")));
        assert_eq!(
            versions.verdict(&key, &stored(417, Some("def"))),
            VersionOrder::Incomparable
        );
    }

    /// Two repositories are never one aggregate, however identical the rest of
    /// the tuple is.
    #[test]
    fn the_repository_is_part_of_the_key() {
        let mut versions = AppliedVersions::new();
        let first = AggregateKey::of(repository(1), &body(417, None));
        let second = AggregateKey::of(repository(2), &body(417, None));
        versions.record(first, stored(417, None));
        assert_eq!(
            versions.verdict(&second, &stored(1, None)),
            VersionOrder::NextOrdinal
        );
    }

    #[test]
    fn forgetting_one_repository_leaves_the_others_alone() {
        let mut versions = AppliedVersions::new();
        let first = AggregateKey::of(repository(1), &body(417, None));
        let second = AggregateKey::of(repository(2), &body(417, None));
        versions.record(first, stored(417, None));
        versions.record(second.clone(), stored(417, None));
        versions.forget_repository(repository(1));
        assert_eq!(versions.tracked(), 1);
        assert_eq!(
            versions.verdict(&second, &stored(417, None)),
            VersionOrder::Equal
        );
    }

    /// The envelope admits a 128-byte identity; the storage encoding admits
    /// 120. A value in between is transportable and not storable, so it parks
    /// rather than truncating into a different version.
    #[test]
    fn an_identity_wider_than_the_storage_encoding_is_a_decode_failure() {
        let wide = "x".repeat(121);
        assert_eq!(
            to_stored(&AggregateVersion {
                ordinal: 1,
                identity: Some(wide),
            }),
            Err(VersionDecodeError::IdentityTooWide)
        );
        assert_eq!(
            VersionDecodeError::IdentityTooWide.poison_class(),
            "AGGREGATE_VERSION_IDENTITY_TOO_WIDE"
        );
    }

    #[tokio::test]
    async fn the_recording_target_preserves_call_order() {
        let target = RecordingInvalidationTarget::new();
        target.baseline().await;
        target
            .apply_invalidation(repository(1), &body(417, None))
            .await;
        target.refetch_repository(repository(1)).await;
        assert_eq!(
            target.calls(),
            vec![
                TargetCall::Baseline,
                TargetCall::Apply {
                    repository: repository(1),
                    event_kind: "branch.pushed".to_string(),
                    ordinal: 417,
                },
                TargetCall::Refetch(repository(1)),
            ]
        );
        assert_eq!(target.baselines(), 1);
    }
}

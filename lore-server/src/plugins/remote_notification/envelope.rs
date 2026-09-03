// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The private envelope's typed model, its bounds, and the mapping from a Lore
//! event into transport version 1.
//!
//! [`wire`](super::wire) decides only what the bytes look like. Everything the
//! notification-plane contract states about *values* is enforced here, before a
//! byte leaves this process:
//!
//! - the identity bounds (`cell_id` grammar and width, 16-byte non-zero
//!   repository, 16-byte event id, 32-byte idempotency key);
//! - the width bounds that make the 80 KiB durable envelope cap derivable
//!   (`producer_instance_id`, `event_kind`, `aggregate_kind`,
//!   `aggregate_identity`, `aggregate_version.identity`, `actor`, `payload`);
//! - class/body agreement, so a `DURABLE_INVALIDATION` can never carry a
//!   `lore_event` and a `LIVE_HINT` can never carry a durable body; and
//! - the unconditional repository check: `lore.notification.Event` carries
//!   `bytes repository = 3` outside its payload `oneof`, so the embedded public
//!   event's repository must equal the envelope's on every variant.
//!
//! A gateway repeats these checks. Doing them here as well means a violation is
//! a local `Terminal` classification rather than a round trip that burns a
//! retry budget.

use std::time::SystemTime;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use prost::Message;

use super::config::PRODUCER_INSTANCE_ID_MAX_BYTES;
use super::config::cell_id_is_valid;
use super::wire;

/// Exact width of a repository identifier and of an event id.
pub const REPOSITORY_BYTES: usize = 16;
pub const EVENT_ID_BYTES: usize = 16;
/// Exact width of CR-032's BLAKE3 idempotency key.
pub const IDEMPOTENCY_KEY_BYTES: usize = 32;

/// Contract widths that make the envelope size cap derivable (amendment A-14).
pub const EVENT_KIND_MAX_BYTES: usize = 64;
pub const AGGREGATE_KIND_MAX_BYTES: usize = 64;
pub const AGGREGATE_IDENTITY_MAX_BYTES: usize = 256;
pub const AGGREGATE_VERSION_IDENTITY_MAX_BYTES: usize = 128;
pub const ACTOR_MAX_BYTES: usize = 256;

/// CR-032's frozen F-032-2 payload cap.
pub const PAYLOAD_MAX_BYTES: usize = 65_536;
/// The durable envelope cap (amendment A-1). Bounds the WHOLE envelope, not
/// only its payload.
pub const DURABLE_ENVELOPE_MAX_BYTES: usize = 81_920;

/// Subject suffixes. A producer never picks an arbitrary or wildcard subject.
const SUBJECT_LIVE: &str = "live";
const SUBJECT_DURABLE: &str = "durable";
const SUBJECT_SHADOW: &str = "shadow";

/// Why an envelope was rejected before publication.
///
/// Every variant carries a fixed low-cardinality label. No variant carries a
/// repository, event id, actor, or payload: those belong in protected
/// structured logs, never in a metric dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeViolation {
    UnknownTransportVersion,
    InvalidCellId,
    /// The placement epoch is absent. Zero is the protobuf default, and the
    /// contract makes the epoch a required monotonic value.
    MissingPlacementEpoch,
    ZeroRepository,
    /// The repository field was not exactly 16 bytes wide.
    InvalidRepositoryWidth,
    InvalidEventIdWidth,
    ProducerInstanceIdTooLong,
    ClassBodyMismatch,
    LoreEventRepositoryMismatch,
    UnsupportedPayloadVersion,
    InvalidIdempotencyKeyWidth,
    MissingRepositoryGeneration,
    /// `event_kind` was absent or over its 64-byte width. The two share a
    /// variant because both mean the same thing to a producer: the field does
    /// not satisfy its contract bound.
    EventKindTooLong,
    /// `aggregate_kind` was absent or over its 64-byte width.
    AggregateKindTooLong,
    /// `aggregate_identity` was absent or over its 256-byte width.
    AggregateIdentityTooLong,
    AggregateVersionIdentityTooLong,
    ActorTooLong,
    PayloadOverCap,
    EnvelopeOverCap,
}

impl EnvelopeViolation {
    /// A stable, low-cardinality label for metrics and protected logs.
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::UnknownTransportVersion => "unknown_transport_version",
            Self::InvalidCellId => "invalid_cell_id",
            Self::MissingPlacementEpoch => "missing_placement_epoch",
            Self::ZeroRepository => "zero_repository",
            Self::InvalidRepositoryWidth => "invalid_repository_width",
            Self::InvalidEventIdWidth => "invalid_event_id_width",
            Self::ProducerInstanceIdTooLong => "producer_instance_id_too_long",
            Self::ClassBodyMismatch => "class_body_mismatch",
            Self::LoreEventRepositoryMismatch => "lore_event_repository_mismatch",
            Self::UnsupportedPayloadVersion => "unsupported_payload_version",
            Self::InvalidIdempotencyKeyWidth => "invalid_idempotency_key_width",
            Self::MissingRepositoryGeneration => "missing_repository_generation",
            Self::EventKindTooLong => "event_kind_too_long",
            Self::AggregateKindTooLong => "aggregate_kind_too_long",
            Self::AggregateIdentityTooLong => "aggregate_identity_too_long",
            Self::AggregateVersionIdentityTooLong => "aggregate_version_identity_too_long",
            Self::ActorTooLong => "actor_too_long",
            Self::PayloadOverCap => "payload_over_cap",
            Self::EnvelopeOverCap => "envelope_over_cap",
        }
    }
}

impl std::fmt::Display for EnvelopeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_metric_label())
    }
}

/// The stable publication identity of one logical event.
///
/// Constructed once, before the event enters the bounded retry queue, and
/// reused for every retry of that publication. That is the whole point of the
/// type: a `[u8; 16]` that is created in exactly one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventId([u8; EVENT_ID_BYTES]);

impl EventId {
    /// Mints a fresh stable event id. Call once per logical publication.
    pub fn new_v4() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Adopts an id another component already minted, so a relay republishing a
    /// retained outbox row keeps its original stable key.
    pub const fn from_bytes(bytes: [u8; EVENT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; EVENT_ID_BYTES] {
        &self.0
    }

    /// The hyphenated form the public `lore.notification.Event.id` carries.
    pub fn to_hyphenated(self) -> String {
        uuid::Uuid::from_bytes(self.0).to_string()
    }
}

/// Common envelope fields, shared by every delivery class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeCommon {
    pub cell_id: String,
    pub placement_epoch: u64,
    pub event_id: EventId,
    pub repository: RepositoryId,
    pub producer_instance_id: String,
    pub produced_at: SystemTime,
}

/// The `aggregate_version` comparison tuple's transport form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateVersion {
    /// The revision number, fence, generation, or epoch the owning mutation
    /// committed.
    pub ordinal: u64,
    /// The exact revision hash where the event kind has one.
    pub identity: Option<String>,
}

/// The `DURABLE_INVALIDATION` body, as CR-032's relay builds it from a
/// committed outbox row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableInvalidationBody {
    pub payload_version: u32,
    pub idempotency_key: [u8; IDEMPOTENCY_KEY_BYTES],
    pub event_kind: String,
    pub repository_generation: u64,
    pub aggregate_kind: String,
    pub aggregate_identity: String,
    pub aggregate_version: AggregateVersion,
    pub payload: Bytes,
    pub committed_at: SystemTime,
    pub actor: Option<String>,
}

/// A complete `DURABLE_INVALIDATION` envelope: the publication unit WP-119's
/// relay hands to [`super::client::PrivateGatewayClient::publish_durable_invalidation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableEnvelopeV1 {
    pub common: EnvelopeCommon,
    pub body: DurableInvalidationBody,
}

/// A complete best-effort envelope: `LIVE_HINT` or `SHADOW_OBSERVATION`.
#[derive(Clone, Debug, PartialEq)]
pub struct HintEnvelopeV1 {
    pub common: EnvelopeCommon,
    /// `true` for `SHADOW_OBSERVATION`, which reaches only `.shadow` and can
    /// never produce a public or durable side effect.
    pub shadow: bool,
    /// The public event, still typed. It is serialized only at encode time, so
    /// the repository check below reads the real field rather than re-parsing.
    pub lore_event: lore_proto::lore::notification::Event,
}

impl EnvelopeCommon {
    fn validate(&self) -> Result<(), EnvelopeViolation> {
        if !cell_id_is_valid(&self.cell_id) {
            return Err(EnvelopeViolation::InvalidCellId);
        }
        if self.placement_epoch == 0 {
            return Err(EnvelopeViolation::MissingPlacementEpoch);
        }
        if self.repository.is_zero() {
            return Err(EnvelopeViolation::ZeroRepository);
        }
        if self.producer_instance_id.len() > PRODUCER_INSTANCE_ID_MAX_BYTES {
            return Err(EnvelopeViolation::ProducerInstanceIdTooLong);
        }
        Ok(())
    }

    fn repository_hex(&self) -> String {
        hex::encode(self.repository.data())
    }

    fn to_wire(&self, delivery_class: wire::DeliveryClassV1) -> wire::PrivateEnvelopeV1 {
        wire::PrivateEnvelopeV1 {
            transport_version: wire::TRANSPORT_VERSION,
            cell_id: self.cell_id.clone(),
            placement_epoch: self.placement_epoch,
            event_id: Bytes::copy_from_slice(self.event_id.as_bytes()),
            repository: Bytes::copy_from_slice(self.repository.data()),
            delivery_class: delivery_class as i32,
            producer_instance_id: self.producer_instance_id.clone(),
            produced_at: Some(prost_types::Timestamp::from(self.produced_at)),
            body: None,
        }
    }
}

impl HintEnvelopeV1 {
    /// The exact-repository subject this envelope belongs on. The gateway
    /// derives its own; this exists so a test and a diagnostic can name the
    /// same string the contract does.
    pub fn subject(&self) -> String {
        let suffix = if self.shadow {
            SUBJECT_SHADOW
        } else {
            SUBJECT_LIVE
        };
        format!(
            "lore.v1.cell.{}.repo.{}.{suffix}",
            self.common.cell_id,
            self.common.repository_hex()
        )
    }

    /// Validates every bound this class carries, then encodes to the wire type.
    ///
    /// # Errors
    /// Returns the first [`EnvelopeViolation`] found. A live hint that violates
    /// a bound is dropped locally rather than sent.
    pub fn encode(&self) -> Result<wire::PrivateEnvelopeV1, EnvelopeViolation> {
        self.common.validate()?;

        // Unconditional: `lore.notification.Event` carries `bytes repository = 3`
        // outside its payload oneof, so this holds on every variant.
        if self.lore_event.repository.as_ref() != self.common.repository.data().as_slice() {
            return Err(EnvelopeViolation::LoreEventRepositoryMismatch);
        }

        let class = if self.shadow {
            wire::DeliveryClassV1::ShadowObservation
        } else {
            wire::DeliveryClassV1::LiveHint
        };
        let mut envelope = self.common.to_wire(class);
        envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(wire::encode(
            &self.lore_event,
        )));
        Ok(envelope)
    }
}

impl DurableEnvelopeV1 {
    /// The exact-repository durable subject this envelope belongs on.
    pub fn subject(&self) -> String {
        format!(
            "lore.v1.cell.{}.repo.{}.{SUBJECT_DURABLE}",
            self.common.cell_id,
            self.common.repository_hex()
        )
    }

    /// Validates every bound this class carries, then encodes to the wire type.
    ///
    /// The serialized size is checked last, against the whole envelope, because
    /// the cap bounds the envelope rather than only its payload. With every
    /// field inside its width the worst legal envelope is 67 584 bytes, so this
    /// check is defense in depth against a producer that violated a width
    /// without tripping the per-field check.
    ///
    /// # Errors
    /// Returns the first [`EnvelopeViolation`] found.
    pub fn encode(
        &self,
        supported_payload_versions: std::ops::RangeInclusive<u32>,
    ) -> Result<wire::PrivateEnvelopeV1, EnvelopeViolation> {
        self.common.validate()?;
        let body = &self.body;

        if !supported_payload_versions.contains(&body.payload_version) {
            return Err(EnvelopeViolation::UnsupportedPayloadVersion);
        }
        if body.repository_generation == 0 {
            return Err(EnvelopeViolation::MissingRepositoryGeneration);
        }
        if body.event_kind.is_empty() || body.event_kind.len() > EVENT_KIND_MAX_BYTES {
            return Err(EnvelopeViolation::EventKindTooLong);
        }
        if body.aggregate_kind.is_empty() || body.aggregate_kind.len() > AGGREGATE_KIND_MAX_BYTES {
            return Err(EnvelopeViolation::AggregateKindTooLong);
        }
        if body.aggregate_identity.is_empty()
            || body.aggregate_identity.len() > AGGREGATE_IDENTITY_MAX_BYTES
        {
            return Err(EnvelopeViolation::AggregateIdentityTooLong);
        }
        if let Some(identity) = body.aggregate_version.identity.as_deref()
            && identity.len() > AGGREGATE_VERSION_IDENTITY_MAX_BYTES
        {
            return Err(EnvelopeViolation::AggregateVersionIdentityTooLong);
        }
        if let Some(actor) = body.actor.as_deref()
            && actor.len() > ACTOR_MAX_BYTES
        {
            return Err(EnvelopeViolation::ActorTooLong);
        }
        if body.payload.len() > PAYLOAD_MAX_BYTES {
            return Err(EnvelopeViolation::PayloadOverCap);
        }

        let mut envelope = self
            .common
            .to_wire(wire::DeliveryClassV1::DurableInvalidation);
        envelope.body = Some(wire::private_envelope_v1::Body::DurableInvalidation(
            wire::DurableInvalidationBodyV1 {
                payload_version: body.payload_version,
                idempotency_key: Bytes::copy_from_slice(&body.idempotency_key),
                event_kind: body.event_kind.clone(),
                repository_generation: body.repository_generation,
                aggregate_kind: body.aggregate_kind.clone(),
                aggregate_identity: body.aggregate_identity.clone(),
                aggregate_version: Some(wire::AggregateVersionV1 {
                    ordinal: body.aggregate_version.ordinal,
                    identity: body.aggregate_version.identity.clone().unwrap_or_default(),
                }),
                payload: body.payload.clone(),
                committed_at: Some(prost_types::Timestamp::from(body.committed_at)),
                actor: body.actor.clone().unwrap_or_default(),
            },
        ));

        if envelope.encoded_len() > DURABLE_ENVELOPE_MAX_BYTES {
            return Err(EnvelopeViolation::EnvelopeOverCap);
        }
        Ok(envelope)
    }
}

/// Validates a decoded wire envelope's class/body agreement and transport
/// version.
///
/// The encode paths above cannot construct a mismatch, so this exists for the
/// receive side and for a component test that hand-builds a wire envelope. It is
/// the check the invalid fixtures `class-body-mismatch-*` and
/// `unknown-transport-version` name.
///
/// # Errors
/// Returns the violation the contract requires a gateway to reject before
/// publication.
pub fn validate_wire_envelope(envelope: &wire::PrivateEnvelopeV1) -> Result<(), EnvelopeViolation> {
    use wire::private_envelope_v1::Body;

    if envelope.transport_version != wire::TRANSPORT_VERSION {
        return Err(EnvelopeViolation::UnknownTransportVersion);
    }
    if !cell_id_is_valid(&envelope.cell_id) {
        return Err(EnvelopeViolation::InvalidCellId);
    }
    if envelope.producer_instance_id.len() > PRODUCER_INSTANCE_ID_MAX_BYTES {
        return Err(EnvelopeViolation::ProducerInstanceIdTooLong);
    }
    if envelope.event_id.len() != EVENT_ID_BYTES {
        return Err(EnvelopeViolation::InvalidEventIdWidth);
    }
    if envelope.placement_epoch == 0 {
        return Err(EnvelopeViolation::MissingPlacementEpoch);
    }
    if envelope.repository.len() != REPOSITORY_BYTES {
        return Err(EnvelopeViolation::InvalidRepositoryWidth);
    }
    if envelope.repository.iter().all(|&b| b == 0) {
        return Err(EnvelopeViolation::ZeroRepository);
    }

    let class = wire::DeliveryClassV1::try_from(envelope.delivery_class)
        .map_err(|_| EnvelopeViolation::ClassBodyMismatch)?;
    match (class, envelope.body.as_ref()) {
        (
            wire::DeliveryClassV1::LiveHint | wire::DeliveryClassV1::ShadowObservation,
            Some(Body::LoreEvent(_)),
        ) => {}
        (wire::DeliveryClassV1::DurableInvalidation, Some(Body::DurableInvalidation(body))) => {
            if body.idempotency_key.len() != IDEMPOTENCY_KEY_BYTES {
                return Err(EnvelopeViolation::InvalidIdempotencyKeyWidth);
            }
        }
        _ => return Err(EnvelopeViolation::ClassBodyMismatch),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use lore_proto::lore::notification;

    use super::*;

    fn repository(byte: u8) -> RepositoryId {
        let mut id = RepositoryId::default();
        *id.data_mut() = [byte; REPOSITORY_BYTES];
        id
    }

    fn common(repo: RepositoryId) -> EnvelopeCommon {
        EnvelopeCommon {
            cell_id: "sfo3-cell-a".to_string(),
            placement_epoch: 12,
            event_id: EventId::from_bytes([7; EVENT_ID_BYTES]),
            repository: repo,
            producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
            produced_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
        }
    }

    fn lore_event(repo: RepositoryId) -> notification::Event {
        notification::Event {
            id: "3f1a2b4c-5d6e-4f70-8192-a3b4c5d6e7f8".to_string(),
            time: None,
            repository: Bytes::copy_from_slice(repo.data()),
            event: Some(notification::event::Event::BranchCreated(
                notification::BranchCreated {
                    branch: Bytes::from_static(&[1; 16]),
                },
            )),
        }
    }

    fn durable_body() -> DurableInvalidationBody {
        DurableInvalidationBody {
            payload_version: 1,
            idempotency_key: [3; IDEMPOTENCY_KEY_BYTES],
            event_kind: "branch.tip_advanced".to_string(),
            repository_generation: 8814,
            aggregate_kind: "branch".to_string(),
            aggregate_identity: "b1c2d3e4f5061728".to_string(),
            aggregate_version: AggregateVersion {
                ordinal: 417,
                identity: Some("revision:2c9f0a7b4d1e6358a0b1c2d3e4f50617".to_string()),
            },
            payload: Bytes::from_static(b"{}"),
            committed_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
            actor: Some("user:0193f2ac-7b41-7c92-a5d1-4e8f0b3c6d27".to_string()),
        }
    }

    #[test]
    fn a_live_hint_encodes_with_the_contract_subject() {
        let repo = repository(0x9f);
        let hint = HintEnvelopeV1 {
            common: common(repo),
            shadow: false,
            lore_event: lore_event(repo),
        };
        assert_eq!(
            hint.subject(),
            "lore.v1.cell.sfo3-cell-a.repo.9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f.live"
        );
        let encoded = hint.encode().expect("valid live hint");
        assert_eq!(encoded.transport_version, wire::TRANSPORT_VERSION);
        assert_eq!(
            encoded.delivery_class,
            wire::DeliveryClassV1::LiveHint as i32
        );
        validate_wire_envelope(&encoded).expect("self-encoded envelope validates");
    }

    #[test]
    fn a_shadow_observation_uses_only_the_shadow_subject() {
        let repo = repository(0x9f);
        let hint = HintEnvelopeV1 {
            common: common(repo),
            shadow: true,
            lore_event: lore_event(repo),
        };
        assert!(hint.subject().ends_with(".shadow"));
        let encoded = hint.encode().expect("valid shadow observation");
        assert_eq!(
            encoded.delivery_class,
            wire::DeliveryClassV1::ShadowObservation as i32
        );
    }

    #[test]
    fn an_embedded_event_for_another_repository_is_rejected_before_publication() {
        let hint = HintEnvelopeV1 {
            common: common(repository(0x9f)),
            shadow: false,
            lore_event: lore_event(repository(0x0a)),
        };
        assert_eq!(
            hint.encode().expect_err("mismatched repository"),
            EnvelopeViolation::LoreEventRepositoryMismatch
        );
    }

    #[test]
    fn a_zero_repository_is_rejected_before_publication() {
        let hint = HintEnvelopeV1 {
            common: common(RepositoryId::default()),
            shadow: false,
            lore_event: lore_event(RepositoryId::default()),
        };
        assert_eq!(
            hint.encode().expect_err("zero repository"),
            EnvelopeViolation::ZeroRepository
        );
    }

    #[test]
    fn an_invalid_cell_id_is_rejected_before_publication() {
        let repo = repository(0x9f);
        let mut c = common(repo);
        c.cell_id = "sfo3_cell_a".to_string();
        let hint = HintEnvelopeV1 {
            common: c,
            shadow: false,
            lore_event: lore_event(repo),
        };
        assert_eq!(
            hint.encode().expect_err("invalid cell id"),
            EnvelopeViolation::InvalidCellId
        );
    }

    #[test]
    fn a_durable_envelope_encodes_and_stays_under_the_cap() {
        let envelope = DurableEnvelopeV1 {
            common: common(repository(0x9f)),
            body: durable_body(),
        };
        assert!(envelope.subject().ends_with(".durable"));
        let encoded = envelope.encode(1..=1).expect("valid durable envelope");
        assert!(encoded.encoded_len() <= DURABLE_ENVELOPE_MAX_BYTES);
        validate_wire_envelope(&encoded).expect("self-encoded envelope validates");
    }

    #[test]
    fn a_maximal_durable_envelope_is_still_transportable() {
        // The worst case the contract's size accounting predicts: every
        // variable-width field at its maximum and a 64 KiB payload.
        let mut body = durable_body();
        body.event_kind = "e".repeat(EVENT_KIND_MAX_BYTES);
        body.aggregate_kind = "k".repeat(AGGREGATE_KIND_MAX_BYTES);
        body.aggregate_identity = "i".repeat(AGGREGATE_IDENTITY_MAX_BYTES);
        body.aggregate_version.identity = Some("v".repeat(AGGREGATE_VERSION_IDENTITY_MAX_BYTES));
        body.actor = Some("a".repeat(ACTOR_MAX_BYTES));
        body.payload = Bytes::from(vec![0xABu8; PAYLOAD_MAX_BYTES]);
        let mut c = common(repository(0x9f));
        c.cell_id = "c".repeat(63);
        c.producer_instance_id = "p".repeat(PRODUCER_INSTANCE_ID_MAX_BYTES);

        let encoded = DurableEnvelopeV1 { common: c, body }
            .encode(1..=1)
            .expect("the maximal legal envelope is accepted");
        assert!(
            encoded.encoded_len() <= DURABLE_ENVELOPE_MAX_BYTES,
            "maximal envelope was {} bytes, cap is {DURABLE_ENVELOPE_MAX_BYTES}",
            encoded.encoded_len()
        );

        // The cap alone is a weak assertion: it would still hold if a field
        // silently lost its bound. The contract derives the cap from a
        // 2048-byte non-payload budget, so pin THAT, measured on an envelope
        // where every variable-width field really is at its maximum.
        const NON_PAYLOAD_BUDGET_BYTES: usize = 2_048;
        let non_payload = encoded.encoded_len() - PAYLOAD_MAX_BYTES;
        assert!(
            non_payload <= NON_PAYLOAD_BUDGET_BYTES,
            "non-payload content was {non_payload} bytes; the contract's size accounting budgets \
             {NON_PAYLOAD_BUDGET_BYTES} and derives the {DURABLE_ENVELOPE_MAX_BYTES} cap from it"
        );
    }

    #[test]
    fn an_over_width_producer_instance_id_is_rejected_before_publication() {
        let repo = repository(0x9f);
        let mut c = common(repo);
        c.producer_instance_id = "p".repeat(PRODUCER_INSTANCE_ID_MAX_BYTES + 1);
        let hint = HintEnvelopeV1 {
            common: c,
            shadow: false,
            lore_event: lore_event(repo),
        };
        assert_eq!(
            hint.encode().expect_err("producer instance id width"),
            EnvelopeViolation::ProducerInstanceIdTooLong
        );
    }

    #[test]
    fn a_zero_placement_epoch_is_rejected_on_both_classes() {
        let repo = repository(0x9f);
        let mut c = common(repo);
        c.placement_epoch = 0;
        let hint = HintEnvelopeV1 {
            common: c.clone(),
            shadow: false,
            lore_event: lore_event(repo),
        };
        assert_eq!(
            hint.encode().expect_err("zero placement epoch"),
            EnvelopeViolation::MissingPlacementEpoch
        );
        let durable = DurableEnvelopeV1 {
            common: c,
            body: durable_body(),
        };
        assert_eq!(
            durable.encode(1..=1).expect_err("zero placement epoch"),
            EnvelopeViolation::MissingPlacementEpoch
        );
    }

    #[test]
    fn a_wrong_width_repository_is_distinguished_from_a_zero_repository() {
        let mut envelope = common(repository(0x9f)).to_wire(wire::DeliveryClassV1::LiveHint);
        envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
            Bytes::from_static(b"x"),
        ));
        envelope.repository = Bytes::from_static(&[1u8; 8]);
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("repository width"),
            EnvelopeViolation::InvalidRepositoryWidth
        );

        envelope.repository = Bytes::from_static(&[0u8; REPOSITORY_BYTES]);
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("zero repository"),
            EnvelopeViolation::ZeroRepository
        );
    }

    #[test]
    fn a_payload_over_the_frozen_cap_is_rejected() {
        let mut body = durable_body();
        body.payload = Bytes::from(vec![0u8; PAYLOAD_MAX_BYTES + 1]);
        let envelope = DurableEnvelopeV1 {
            common: common(repository(0x9f)),
            body,
        };
        assert_eq!(
            envelope.encode(1..=1).expect_err("payload over cap"),
            EnvelopeViolation::PayloadOverCap
        );
    }

    #[test]
    fn every_deferred_width_is_enforced() {
        /// One width mutation and the violation it must produce.
        type WidthCase = (Box<dyn Fn(&mut DurableInvalidationBody)>, EnvelopeViolation);

        let cases: Vec<WidthCase> = vec![
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.event_kind = "e".repeat(EVENT_KIND_MAX_BYTES + 1);
                }),
                EnvelopeViolation::EventKindTooLong,
            ),
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.aggregate_kind = "k".repeat(AGGREGATE_KIND_MAX_BYTES + 1);
                }),
                EnvelopeViolation::AggregateKindTooLong,
            ),
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.aggregate_identity = "i".repeat(AGGREGATE_IDENTITY_MAX_BYTES + 1);
                }),
                EnvelopeViolation::AggregateIdentityTooLong,
            ),
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.aggregate_version.identity =
                        Some("v".repeat(AGGREGATE_VERSION_IDENTITY_MAX_BYTES + 1));
                }),
                EnvelopeViolation::AggregateVersionIdentityTooLong,
            ),
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.actor = Some("a".repeat(ACTOR_MAX_BYTES + 1));
                }),
                EnvelopeViolation::ActorTooLong,
            ),
            (
                Box::new(|b: &mut DurableInvalidationBody| {
                    b.repository_generation = 0;
                }),
                EnvelopeViolation::MissingRepositoryGeneration,
            ),
        ];
        for (mutate, expected) in cases {
            let mut body = durable_body();
            mutate(&mut body);
            let envelope = DurableEnvelopeV1 {
                common: common(repository(0x9f)),
                body,
            };
            assert_eq!(envelope.encode(1..=1).expect_err("width"), expected);
        }
    }

    #[test]
    fn an_unsupported_payload_version_is_rejected_rather_than_read_as_an_older_shape() {
        let mut body = durable_body();
        body.payload_version = 2;
        let envelope = DurableEnvelopeV1 {
            common: common(repository(0x9f)),
            body,
        };
        assert_eq!(
            envelope.encode(1..=1).expect_err("unknown payload version"),
            EnvelopeViolation::UnsupportedPayloadVersion
        );
    }

    #[test]
    fn a_class_body_mismatch_is_rejected_in_both_directions() {
        let repo = repository(0x9f);
        // A durable class carrying a lore_event body.
        let mut envelope = common(repo).to_wire(wire::DeliveryClassV1::DurableInvalidation);
        envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
            Bytes::from_static(b"x"),
        ));
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("durable carrying lore_event"),
            EnvelopeViolation::ClassBodyMismatch
        );

        // A live class carrying a durable body.
        let mut envelope = common(repo).to_wire(wire::DeliveryClassV1::LiveHint);
        envelope.body = Some(wire::private_envelope_v1::Body::DurableInvalidation(
            wire::DurableInvalidationBodyV1::default(),
        ));
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("live carrying durable body"),
            EnvelopeViolation::ClassBodyMismatch
        );
    }

    #[test]
    fn an_unknown_transport_version_is_rejected() {
        let mut envelope = common(repository(0x9f)).to_wire(wire::DeliveryClassV1::LiveHint);
        envelope.body = Some(wire::private_envelope_v1::Body::LoreEvent(
            Bytes::from_static(b"x"),
        ));
        envelope.transport_version = 2;
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("transport version"),
            EnvelopeViolation::UnknownTransportVersion
        );
    }

    #[test]
    fn a_wrong_width_idempotency_key_is_rejected() {
        let mut envelope =
            common(repository(0x9f)).to_wire(wire::DeliveryClassV1::DurableInvalidation);
        envelope.body = Some(wire::private_envelope_v1::Body::DurableInvalidation(
            wire::DurableInvalidationBodyV1 {
                idempotency_key: Bytes::from_static(&[1; 16]),
                ..Default::default()
            },
        ));
        assert_eq!(
            validate_wire_envelope(&envelope).expect_err("idempotency key width"),
            EnvelopeViolation::InvalidIdempotencyKeyWidth
        );
    }

    #[test]
    fn an_event_id_is_stable_across_its_own_reuse() {
        let id = EventId::new_v4();
        assert_eq!(
            id.as_bytes(),
            EventId::from_bytes(*id.as_bytes()).as_bytes()
        );
        assert_eq!(id.to_hyphenated().len(), 36);
    }
}

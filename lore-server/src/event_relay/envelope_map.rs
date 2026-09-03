// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Committed outbox row to private `DURABLE_INVALIDATION` envelope.
//!
//! This is the only place the two halves of CR-032 meet. The row is
//! Postgres-shaped: raw bytes, `i64`s, an opaque encoded `aggregate_version`.
//! The envelope is contract-shaped: bounded UTF-8 strings, `u64`s, a decoded
//! ordinal plus an optional identity. Everything that can go wrong between them
//! is a property of the **row**, not of the gateway, so every failure here is
//! terminal and event-specific: the same row will fail the same way on every
//! future attempt, and CR-032 requires such a row to be dead-lettered without
//! blocking the rows behind it rather than retried forever.
//!
//! # The stable keys are carried, never recomputed
//!
//! `event_id` and `idempotency_key` come off the row verbatim. CR-032 requires a
//! republished event to keep its original keys, and the cheapest way to
//! guarantee that is for this module to have no way to derive either one.
//!
//! # PIN(WP-119): bytes to text, and what that costs the identity bound
//!
//! The row stores `aggregate_id` and the `aggregate_version` identity as raw
//! bytes; the notification-plane contract's envelope carries both as UTF-8
//! strings. Nothing in either document pins the conversion. This module uses
//! lowercase hex, which is the representation the contract already uses for the
//! repository in a subject, is total over arbitrary bytes, and round-trips.
//!
//! Hex doubles the width, and that interacts with one bound. CR-032 F-032-4
//! stops the stored `aggregate_version` identity at 120 bytes on the reasoning
//! that the transport bounds it at 128 — an argument that only holds if the
//! bytes pass through unchanged. Hex-encoded, a 120-byte identity is 240
//! characters and the envelope refuses it. So the effective relay-transportable
//! identity is **64 raw bytes**, and a row above that is terminal poison with a
//! named class rather than a truncated or fabricated value.
//!
//! **This narrows a frozen bound, and the narrowing is not this module's to
//! make.** `lorehub/docs/contracts/fixtures/lore-notification-plane/aggregate-version.json`
//! pins a `max-identity-120` vector as the maximum legal value, on the stated
//! grounds that a committed row is always transportable; contract amendment
//! A-19 says the same in prose. With `AggregateVersionV1.identity` typed as a
//! UTF-8 `string` (amendment A-20), **no** encoding carries 120 arbitrary bytes
//! within 128 UTF-8 bytes, so the fixture's claim cannot hold for an identity
//! that is not already valid UTF-8 — the field's type is the defect, not the
//! conversion. Hex is the right choice given a string field.
//!
//! Raised for the CR owner as a contract amendment: either type that field
//! `bytes`, or narrow F-032-4's producer bound to 64. Nothing is at risk today
//! — every event kind CR-032 pins carries an empty identity, a 32-byte revision
//! hash, or a lock owner token, all far inside 64 — and a row in the 65..=120
//! window fails loudly rather than silently.
//!
//! `aggregate_id` has no such problem: the column CHECK bounds it at 64 bytes,
//! so its hex form is at most 128 characters against a 256-byte transport bound.

use std::time::SystemTime;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_postgres::domain::outbox::AggregateVersion as StoredAggregateVersion;
use lore_postgres::domain::outbox::OutboxEventRecord;

use crate::plugins::remote_notification::AggregateVersion as WireAggregateVersion;
use crate::plugins::remote_notification::DurableEnvelopeV1;
use crate::plugins::remote_notification::DurableInvalidationBody;
use crate::plugins::remote_notification::EnvelopeCommon;
use crate::plugins::remote_notification::EventId;
use crate::plugins::remote_notification::envelope::AGGREGATE_VERSION_IDENTITY_MAX_BYTES;
use crate::plugins::remote_notification::envelope::EVENT_KIND_MAX_BYTES;
use crate::plugins::remote_notification::envelope::PAYLOAD_MAX_BYTES;
use crate::plugins::remote_notification::envelope::REPOSITORY_BYTES;

/// F-032-4's producer bound on `aggregate_id`, in hex characters.
///
/// The seam pins the raw column at 64 bytes, strictly narrower than the
/// envelope's 256-byte `aggregate_identity`, and the column CHECK enforces it.
/// Hex doubles it.
const MAX_PRODUCER_IDENTITY_HEX_CHARS: usize = 64 * 2;

/// The widest `aggregate_version` identity that survives hex encoding, in raw
/// bytes. See the module's `PIN(WP-119)` note for why this is not F-032-4's
/// 120.
pub const MAX_TRANSPORTABLE_VERSION_IDENTITY_BYTES: usize =
    AGGREGATE_VERSION_IDENTITY_MAX_BYTES / 2;

/// The per-process envelope fields, which come from configuration rather than
/// from any row.
///
/// Held separately from the row so a single misconfigured value cannot be
/// mistaken for row data, and so the mapping function stays pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSource {
    /// This cell's identity, from trusted server configuration. A row carrying
    /// a different cell is refused rather than relabelled.
    pub cell_id: String,
    /// Current placement epoch.
    pub placement_epoch: u64,
    /// Bounded opaque diagnostic identity of this loreserver process.
    pub producer_instance_id: String,
}

/// Why a committed row cannot become an envelope.
///
/// Every variant is terminal and event-specific. None of them can be fixed by
/// republishing, and each carries a fixed low-cardinality class string that
/// becomes both the dead-letter `terminal_class` and the metric label — so the
/// class set is closed by construction rather than by convention.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapFailure {
    /// `repository_id` was not exactly 16 bytes.
    #[error("outbox row repository_id is {0} bytes, not {REPOSITORY_BYTES}")]
    RepositoryIdWidth(usize),
    /// `repository_id` is all zeroes, which the contract reserves.
    #[error("outbox row repository_id is the zero repository")]
    ZeroRepository,
    /// The row belongs to a different cell than this process serves.
    #[error("outbox row belongs to cell `{row}`, but this process is cell `{configured}`")]
    CellIdMismatch {
        /// The cell recorded on the row.
        row: String,
        /// The cell this process is configured as.
        configured: String,
    },
    /// `repository_generation` is negative and cannot be a `u64` generation.
    #[error("outbox row repository_generation is negative: {0}")]
    NegativeRepositoryGeneration(i64),
    /// `repository_generation` is zero, which the envelope reserves as absent.
    #[error("outbox row repository_generation is zero, which the envelope reserves as absent")]
    ZeroRepositoryGeneration,
    /// `event_kind` is empty or over the contract width.
    #[error("outbox row event_kind is empty or over {EVENT_KIND_MAX_BYTES} bytes")]
    EventKindWidth,
    /// `aggregate_kind` is empty or over the contract width.
    #[error("outbox row aggregate_kind is empty or over its contract width")]
    AggregateKindWidth,
    /// `aggregate_id` is empty, or its hex form exceeds the transport bound.
    #[error("outbox row aggregate_id is empty or not transportable as {0} hex characters")]
    AggregateIdentityNotTransportable(usize),
    /// `aggregate_version` is not a valid F-032-4 v1 encoding.
    #[error("outbox row aggregate_version is not a valid v1 encoding: {0}")]
    AggregateVersionUndecodable(String),
    /// The decoded identity's hex form exceeds the transport bound. See the
    /// module's `PIN(WP-119)` note.
    #[error("outbox row aggregate_version identity is not transportable as {0} hex characters")]
    AggregateVersionIdentityNotTransportable(usize),
    /// `payload_schema_version` is negative.
    #[error("outbox row payload_schema_version is negative: {0}")]
    NegativePayloadSchemaVersion(i32),
    /// The payload exceeds CR-032's frozen 64 KiB cap.
    #[error("outbox row payload is {0} bytes, over the {PAYLOAD_MAX_BYTES}-byte cap")]
    PayloadOverCap(usize),
}

impl MapFailure {
    /// The fixed class string recorded on the dead letter and used as a metric
    /// label. Low cardinality, and free of any row identity.
    pub const fn as_terminal_class(&self) -> &'static str {
        match self {
            Self::RepositoryIdWidth(_) => "repository_id_width",
            Self::ZeroRepository => "zero_repository",
            Self::CellIdMismatch { .. } => "cell_id_mismatch",
            Self::NegativeRepositoryGeneration(_) => "negative_repository_generation",
            Self::ZeroRepositoryGeneration => "zero_repository_generation",
            Self::EventKindWidth => "event_kind_width",
            Self::AggregateKindWidth => "aggregate_kind_width",
            Self::AggregateIdentityNotTransportable(_) => "aggregate_identity_not_transportable",
            Self::AggregateVersionUndecodable(_) => "aggregate_version_undecodable",
            Self::AggregateVersionIdentityNotTransportable(_) => {
                "aggregate_version_identity_not_transportable"
            }
            Self::NegativePayloadSchemaVersion(_) => "negative_payload_schema_version",
            Self::PayloadOverCap(_) => "payload_over_cap",
        }
    }
}

/// Build the publication unit for one committed row.
///
/// Pure: no clock, no randomness, no I/O. `produced_at` is taken from the
/// caller's `now` so a test can pin the whole envelope, and because the
/// contract makes it a diagnostic rather than an ordering authority.
pub fn map_event(
    record: &OutboxEventRecord,
    source: &EnvelopeSource,
    now: SystemTime,
) -> Result<DurableEnvelopeV1, MapFailure> {
    if record.cell_id != source.cell_id {
        return Err(MapFailure::CellIdMismatch {
            row: record.cell_id.clone(),
            configured: source.cell_id.clone(),
        });
    }

    // `From<&[u8]> for Partition` reads a 16-byte prefix and silently yields
    // the zero partition for anything shorter, so the width is checked here
    // rather than delegated to the conversion.
    let repository_bytes: [u8; REPOSITORY_BYTES] = record
        .repository_id
        .as_slice()
        .try_into()
        .map_err(|_| MapFailure::RepositoryIdWidth(record.repository_id.len()))?;
    let repository = RepositoryId::from(repository_bytes);
    if repository.is_zero() {
        return Err(MapFailure::ZeroRepository);
    }

    let repository_generation = u64::try_from(record.repository_generation)
        .map_err(|_| MapFailure::NegativeRepositoryGeneration(record.repository_generation))?;
    if repository_generation == 0 {
        return Err(MapFailure::ZeroRepositoryGeneration);
    }

    if record.event_kind.is_empty() || record.event_kind.len() > EVENT_KIND_MAX_BYTES {
        return Err(MapFailure::EventKindWidth);
    }
    if record.aggregate_kind.is_empty()
        || record.aggregate_kind.len()
            > crate::plugins::remote_notification::envelope::AGGREGATE_KIND_MAX_BYTES
    {
        return Err(MapFailure::AggregateKindWidth);
    }

    // Bounded at the **producer's** width, not the transport's. F-032-4 pins
    // `aggregate_id` at 64 bytes, deliberately narrower than the envelope's
    // 256-byte `aggregate_identity`, and the column CHECK enforces it. Checking
    // against the wider transport bound here would admit a 65..=128-byte row
    // that the schema says cannot exist, so the narrower bound is the one that
    // can actually catch a drifted column.
    let aggregate_identity = hex::encode(&record.aggregate_id);
    if aggregate_identity.is_empty() || aggregate_identity.len() > MAX_PRODUCER_IDENTITY_HEX_CHARS {
        return Err(MapFailure::AggregateIdentityNotTransportable(
            aggregate_identity.len(),
        ));
    }

    let stored_version = StoredAggregateVersion::decode(&record.aggregate_version)
        .map_err(|e| MapFailure::AggregateVersionUndecodable(e.to_string()))?;
    let version_identity = if stored_version.identity.is_empty() {
        None
    } else {
        let encoded = hex::encode(&stored_version.identity);
        if stored_version.identity.len() > MAX_TRANSPORTABLE_VERSION_IDENTITY_BYTES {
            return Err(MapFailure::AggregateVersionIdentityNotTransportable(
                encoded.len(),
            ));
        }
        Some(encoded)
    };

    let payload_version = u32::try_from(record.payload_schema_version)
        .map_err(|_| MapFailure::NegativePayloadSchemaVersion(record.payload_schema_version))?;
    if record.payload.len() > PAYLOAD_MAX_BYTES {
        return Err(MapFailure::PayloadOverCap(record.payload.len()));
    }

    Ok(DurableEnvelopeV1 {
        common: EnvelopeCommon {
            cell_id: source.cell_id.clone(),
            placement_epoch: source.placement_epoch,
            event_id: EventId::from_bytes(*record.event_id.as_bytes()),
            repository,
            producer_instance_id: source.producer_instance_id.clone(),
            produced_at: now,
        },
        body: DurableInvalidationBody {
            payload_version,
            idempotency_key: record.idempotency_key,
            event_kind: record.event_kind.clone(),
            repository_generation,
            aggregate_kind: record.aggregate_kind.clone(),
            aggregate_identity,
            aggregate_version: WireAggregateVersion {
                ordinal: stored_version.ordinal,
                identity: version_identity,
            },
            payload: Bytes::copy_from_slice(&record.payload),
            committed_at: record.created_at,
            // CR-032's INV-FL R-SHOULD-3 disposition: `actor` is not an outbox
            // row field. The bounded payload carries actor identity where the
            // owning mutation resolved one, and this projection would need a
            // per-event-kind payload decoder to lift it out. No pinned event
            // kind's consumer needs it yet.
            // TODO(WP-119 Step C): project `actor` out of the bounded payload
            // once a named consumer requires it.
            actor: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    use uuid::Uuid;

    use super::*;
    use crate::plugins::remote_notification::envelope::AGGREGATE_IDENTITY_MAX_BYTES;

    fn source() -> EnvelopeSource {
        EnvelopeSource {
            cell_id: "cell-a".to_string(),
            placement_epoch: 7,
            producer_instance_id: "loreserver-1".to_string(),
        }
    }

    fn record() -> OutboxEventRecord {
        OutboxEventRecord {
            event_id: Uuid::from_bytes([9u8; 16]),
            cell_id: "cell-a".to_string(),
            idempotency_key: [3u8; 32],
            repository_id: vec![1u8; 16],
            repository_generation: 12,
            event_kind: "branch.pushed".to_string(),
            aggregate_kind: "branch".to_string(),
            aggregate_id: b"main".to_vec(),
            aggregate_version: StoredAggregateVersion::new(4, vec![0xAB; 32])
                .expect("in bounds")
                .encode(),
            payload_schema_version: 1,
            payload: b"{}".to_vec(),
            created_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_100)
    }

    #[test]
    fn a_well_formed_row_maps_and_keeps_its_stable_keys() {
        let record = record();
        let envelope = map_event(&record, &source(), now()).expect("maps");
        assert_eq!(
            envelope.common.event_id.as_bytes(),
            record.event_id.as_bytes()
        );
        assert_eq!(envelope.body.idempotency_key, record.idempotency_key);
        assert_eq!(envelope.common.cell_id, "cell-a");
        assert_eq!(envelope.common.placement_epoch, 7);
        assert_eq!(envelope.body.repository_generation, 12);
        assert_eq!(envelope.body.aggregate_version.ordinal, 4);
        assert_eq!(
            envelope.body.aggregate_version.identity.as_deref(),
            Some("ab".repeat(32).as_str())
        );
        assert_eq!(envelope.body.aggregate_identity, hex::encode(b"main"));
        assert_eq!(envelope.body.committed_at, record.created_at);
        assert_eq!(envelope.body.actor, None);
    }

    /// The mapping must not be able to relabel a row onto this cell.
    #[test]
    fn a_row_from_another_cell_is_terminal() {
        let mut record = record();
        record.cell_id = "cell-b".to_string();
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(failure.as_terminal_class(), "cell_id_mismatch");
    }

    /// `From<&[u8]> for Partition` would have silently produced the zero
    /// repository from a short slice, which is the exact defect this width
    /// check exists for.
    #[test]
    fn a_short_repository_id_is_terminal_rather_than_silently_zeroed() {
        let mut record = record();
        record.repository_id = vec![1u8; 8];
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(failure.as_terminal_class(), "repository_id_width");
    }

    #[test]
    fn a_zero_repository_is_terminal() {
        let mut record = record();
        record.repository_id = vec![0u8; 16];
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(failure.as_terminal_class(), "zero_repository");
    }

    #[test]
    fn a_negative_or_zero_repository_generation_is_terminal() {
        let mut record = record();
        record.repository_generation = -1;
        assert_eq!(
            map_event(&record, &source(), now())
                .expect_err("must refuse")
                .as_terminal_class(),
            "negative_repository_generation"
        );
        record.repository_generation = 0;
        assert_eq!(
            map_event(&record, &source(), now())
                .expect_err("must refuse")
                .as_terminal_class(),
            "zero_repository_generation"
        );
    }

    #[test]
    fn an_undecodable_aggregate_version_is_terminal() {
        let mut record = record();
        record.aggregate_version = vec![0u8; 4];
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(failure.as_terminal_class(), "aggregate_version_undecodable");
    }

    /// The PIN: hex doubles the width, so the stored 120-byte ceiling is wider
    /// than what the envelope can carry. A row in that window must be named
    /// poison, never truncated.
    #[test]
    fn an_identity_that_hex_widens_past_the_transport_bound_is_terminal() {
        let mut record = record();
        record.aggregate_version = StoredAggregateVersion::new(4, vec![0xCD; 65])
            .expect("inside the stored bound")
            .encode();
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(
            failure.as_terminal_class(),
            "aggregate_version_identity_not_transportable"
        );
        // And exactly 64 raw bytes is the widest that still fits.
        record.aggregate_version = StoredAggregateVersion::new(4, vec![0xCD; 64])
            .expect("inside the stored bound")
            .encode();
        let envelope = map_event(&record, &source(), now()).expect("64 raw bytes must map");
        assert_eq!(
            envelope
                .body
                .aggregate_version
                .identity
                .as_deref()
                .map(str::len),
            Some(AGGREGATE_VERSION_IDENTITY_MAX_BYTES)
        );
    }

    #[test]
    fn an_empty_aggregate_id_is_terminal() {
        let mut record = record();
        record.aggregate_id = Vec::new();
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(
            failure.as_terminal_class(),
            "aggregate_identity_not_transportable"
        );
    }

    /// The guard is on F-032-4's 64-byte producer bound, not the envelope's
    /// wider 256. Checking against the transport width would admit a row the
    /// schema says cannot exist, which is exactly the drifted column this is
    /// meant to catch, and no other assertion in the suite would notice.
    #[test]
    fn an_aggregate_id_wider_than_the_producer_bound_is_terminal() {
        let mut record = record();
        record.aggregate_id = vec![0xEE; 64];
        let envelope = map_event(&record, &source(), now()).expect("64 bytes is the bound");
        assert_eq!(
            envelope.body.aggregate_identity.len(),
            MAX_PRODUCER_IDENTITY_HEX_CHARS
        );

        record.aggregate_id = vec![0xEE; 65];
        let failure = map_event(&record, &source(), now()).expect_err("65 bytes must refuse");
        assert_eq!(
            failure.as_terminal_class(),
            "aggregate_identity_not_transportable"
        );
        // And it is refused well below the transport's own 256-byte width, so
        // this cannot be passing because of the envelope's own check.
        const _: () = assert!(MAX_PRODUCER_IDENTITY_HEX_CHARS < AGGREGATE_IDENTITY_MAX_BYTES);
    }

    #[test]
    fn an_over_cap_payload_is_terminal() {
        let mut record = record();
        record.payload = vec![0u8; PAYLOAD_MAX_BYTES + 1];
        let failure = map_event(&record, &source(), now()).expect_err("must refuse");
        assert_eq!(failure.as_terminal_class(), "payload_over_cap");
    }

    /// The class strings are the dead-letter vocabulary and a metric label set,
    /// so they must stay bounded, unique, and free of interpolation.
    #[test]
    fn every_terminal_class_is_a_distinct_bounded_label() {
        let classes = [
            MapFailure::RepositoryIdWidth(1),
            MapFailure::ZeroRepository,
            MapFailure::CellIdMismatch {
                row: "a".into(),
                configured: "b".into(),
            },
            MapFailure::NegativeRepositoryGeneration(-1),
            MapFailure::ZeroRepositoryGeneration,
            MapFailure::EventKindWidth,
            MapFailure::AggregateKindWidth,
            MapFailure::AggregateIdentityNotTransportable(0),
            MapFailure::AggregateVersionUndecodable("x".into()),
            MapFailure::AggregateVersionIdentityNotTransportable(0),
            MapFailure::NegativePayloadSchemaVersion(-1),
            MapFailure::PayloadOverCap(0),
        ];
        let mut labels: Vec<&'static str> =
            classes.iter().map(MapFailure::as_terminal_class).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total, "terminal classes must be distinct");
        for label in labels {
            assert!(!label.is_empty());
            assert!(label.is_ascii());
            assert!(label.len() <= 64, "must fit the terminal_class column");
        }
    }
}

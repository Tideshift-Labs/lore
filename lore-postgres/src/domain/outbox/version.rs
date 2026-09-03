// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The typed `aggregate_version` encoding (CR-032 F-032-4 / PIN-2; SCHEMA-119).
//!
//! The base schema stores `aggregate_version` as opaque bounded bytes and the
//! append API never interprets it. That is still true of the *storage*: this
//! module adds the one canonical **encoding** producers and consumers agree on,
//! so that "compare the aggregate version" is a decidable operation rather than
//! a per-event-kind convention.
//!
//! # Encoding v1
//!
//! ```text
//! [0..8]   ordinal, 8-byte big-endian unsigned
//! [8..N]   identity, 0..=120 opaque bytes
//! ```
//!
//! Total width is 8..=128 bytes. Big-endian is deliberate: it makes the
//! encoded bytes sort in the same order as the ordinal, so a byte comparison
//! and an ordinal comparison never disagree.
//!
//! The ordinal holds whatever monotonic scalar the owning mutation committed —
//! revision number, fence, generation, or epoch. The identity holds the exact
//! revision hash where the event kind has one, and is empty where it does not.
//!
//! # Comparability
//!
//! Per the notification-plane contract, two versions are comparable only within
//! one `(event_kind, aggregate_kind, aggregate_identity)`. Any other pair is
//! incomparable and forces authoritative refetch rather than an ordering
//! decision. This type therefore deliberately implements neither `Ord` nor
//! `PartialOrd`: an ordering trait would let a caller compare two versions from
//! different aggregates and get an answer, and the answer would be meaningless.
//! [`AggregateVersion::compare_within_aggregate`] is the only ordering, and its
//! name says what the caller must have already established.
//!
//! # PIN(WP-119): the identity bound is narrower than the contract's
//!
//! `lorehub/docs/contracts/lore-notification-plane.md` bounds the wire
//! envelope's `aggregate_version.identity` at 128 bytes, which would make the
//! encoded total 8..=136. WP-119's steering pins the encoding at a total of
//! 8..=128, i.e. an identity of 0..=120. The narrower reading is the
//! conservative one — every value this module can produce is inside the
//! contract's envelope bound, and the schema's own 256-byte CHECK is a superset
//! of both — so it is taken here. Widening to 136 later is compatible with
//! every value already encoded; narrowing would not be. Raise it with the CR
//! owner before any producer needs a 121..=128-byte identity.

use crate::domain::errors::DomainError;

/// Width of the big-endian ordinal prefix.
pub const AGGREGATE_VERSION_ORDINAL_BYTES: usize = 8;
/// Maximum opaque identity suffix. See the module's `PIN(WP-119)` note.
pub const MAX_AGGREGATE_VERSION_IDENTITY_BYTES: usize = 120;
/// Minimum encoded width: the ordinal alone, with an empty identity.
pub const MIN_AGGREGATE_VERSION_BYTES: usize = AGGREGATE_VERSION_ORDINAL_BYTES;
/// Maximum encoded width.
pub const MAX_ENCODED_AGGREGATE_VERSION_BYTES: usize =
    AGGREGATE_VERSION_ORDINAL_BYTES + MAX_AGGREGATE_VERSION_IDENTITY_BYTES;

/// One decoded `aggregate_version`.
///
/// No `Ord`/`PartialOrd` by design; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateVersion {
    /// The monotonic scalar the owning mutation committed.
    pub ordinal: u64,
    /// Opaque identity component, empty where the event kind has none.
    pub identity: Vec<u8>,
}

/// The result of comparing two versions of the *same* aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrder {
    /// The observed version precedes the known one: a stale no-op.
    Older,
    /// Same ordinal and same identity: a duplicate.
    Equal,
    /// The observed version follows the known one by exactly one ordinal.
    NextOrdinal,
    /// The observed version follows, but not contiguously: a gap.
    Newer,
    /// Same ordinal, different identity. Not an ordering — the two versions
    /// disagree about what that ordinal was, which forces authoritative
    /// refetch rather than a decision.
    Incomparable,
}

impl AggregateVersion {
    /// Build a version, rejecting an over-wide identity before it can reach a
    /// row or an envelope.
    pub fn new(ordinal: u64, identity: Vec<u8>) -> Result<Self, DomainError> {
        if identity.len() > MAX_AGGREGATE_VERSION_IDENTITY_BYTES {
            return Err(DomainError::InvalidInput(format!(
                "outbox aggregate_version identity exceeds \
                 {MAX_AGGREGATE_VERSION_IDENTITY_BYTES} bytes: {}",
                identity.len()
            )));
        }
        Ok(Self { ordinal, identity })
    }

    /// A version with no identity component.
    pub fn ordinal_only(ordinal: u64) -> Self {
        Self {
            ordinal,
            identity: Vec::new(),
        }
    }

    /// Encode to the bytes stored in `lore_outbox_events.aggregate_version`.
    ///
    /// Infallible because [`AggregateVersion::new`] is the only fallible
    /// constructor and it already rejected an over-wide identity;
    /// [`AggregateVersion::ordinal_only`] cannot produce one.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AGGREGATE_VERSION_ORDINAL_BYTES + self.identity.len());
        out.extend_from_slice(&self.ordinal.to_be_bytes());
        out.extend_from_slice(&self.identity);
        out
    }

    /// Decode stored bytes, rejecting any width outside 8..=128.
    pub fn decode(bytes: &[u8]) -> Result<Self, DomainError> {
        validate_encoded(bytes)?;
        let mut ordinal_bytes = [0u8; AGGREGATE_VERSION_ORDINAL_BYTES];
        ordinal_bytes.copy_from_slice(&bytes[..AGGREGATE_VERSION_ORDINAL_BYTES]);
        Ok(Self {
            ordinal: u64::from_be_bytes(ordinal_bytes),
            identity: bytes[AGGREGATE_VERSION_ORDINAL_BYTES..].to_vec(),
        })
    }

    /// Compare against another version **of the same aggregate**.
    ///
    /// The caller must already have established that both versions carry the
    /// same `(event_kind, aggregate_kind, aggregate_identity)`; nothing in this
    /// type can check that, which is exactly why the ordering is not a trait
    /// impl.
    pub fn compare_within_aggregate(&self, other: &Self) -> VersionOrder {
        match self.ordinal.cmp(&other.ordinal) {
            std::cmp::Ordering::Less => VersionOrder::Older,
            std::cmp::Ordering::Greater => {
                if self.ordinal == other.ordinal.saturating_add(1) {
                    VersionOrder::NextOrdinal
                } else {
                    VersionOrder::Newer
                }
            }
            std::cmp::Ordering::Equal => {
                if self.identity == other.identity {
                    VersionOrder::Equal
                } else {
                    VersionOrder::Incomparable
                }
            }
        }
    }
}

/// Reject stored `aggregate_version` bytes that are not a v1 encoding.
///
/// Separate from [`AggregateVersion::decode`] so `append`'s `validate` can
/// enforce the width without allocating a decoded value for an event it is
/// about to insert as opaque bytes.
pub fn validate_encoded(bytes: &[u8]) -> Result<(), DomainError> {
    if bytes.len() < MIN_AGGREGATE_VERSION_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox aggregate_version must carry an {AGGREGATE_VERSION_ORDINAL_BYTES}-byte \
             big-endian ordinal, got {} bytes",
            bytes.len()
        )));
    }
    if bytes.len() > MAX_ENCODED_AGGREGATE_VERSION_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox aggregate_version exceeds the encoded \
             {MAX_ENCODED_AGGREGATE_VERSION_BYTES}-byte bound: {}",
            bytes.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips_with_an_identity() {
        let v = AggregateVersion::new(0x0102_0304_0506_0708, vec![0xAB; 32]).expect("in bounds");
        let encoded = v.encode();
        assert_eq!(encoded.len(), 8 + 32);
        assert_eq!(&encoded[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(AggregateVersion::decode(&encoded).expect("decode"), v);
    }

    #[test]
    fn encode_decode_round_trips_without_an_identity() {
        let v = AggregateVersion::ordinal_only(1);
        let encoded = v.encode();
        assert_eq!(encoded.len(), 8);
        assert_eq!(AggregateVersion::decode(&encoded).expect("decode"), v);
    }

    /// The whole reason the ordinal is big-endian: byte order and numeric order
    /// must not be able to disagree.
    #[test]
    fn encoded_bytes_sort_in_ordinal_order() {
        let mut encoded: Vec<Vec<u8>> = [3u64, 1, 258, 2, 257]
            .into_iter()
            .map(|o| AggregateVersion::ordinal_only(o).encode())
            .collect();
        encoded.sort();
        let ordinals: Vec<u64> = encoded
            .iter()
            .map(|b| AggregateVersion::decode(b).expect("decode").ordinal)
            .collect();
        assert_eq!(ordinals, vec![1, 2, 3, 257, 258]);
    }

    #[test]
    fn a_short_encoding_is_rejected() {
        for len in 0..MIN_AGGREGATE_VERSION_BYTES {
            let bytes = vec![0u8; len];
            assert!(
                matches!(
                    AggregateVersion::decode(&bytes),
                    Err(DomainError::InvalidInput(_))
                ),
                "{len} bytes must be rejected"
            );
        }
    }

    #[test]
    fn the_widest_legal_encoding_is_accepted_and_one_more_byte_is_not() {
        let widest = vec![0u8; MAX_ENCODED_AGGREGATE_VERSION_BYTES];
        assert!(AggregateVersion::decode(&widest).is_ok());
        let too_wide = vec![0u8; MAX_ENCODED_AGGREGATE_VERSION_BYTES + 1];
        assert!(matches!(
            AggregateVersion::decode(&too_wide),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn new_rejects_an_over_wide_identity() {
        let identity = vec![0u8; MAX_AGGREGATE_VERSION_IDENTITY_BYTES + 1];
        assert!(matches!(
            AggregateVersion::new(1, identity),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn same_ordinal_with_a_different_identity_is_incomparable_not_equal() {
        let a = AggregateVersion::new(7, b"hash-a".to_vec()).expect("in bounds");
        let b = AggregateVersion::new(7, b"hash-b".to_vec()).expect("in bounds");
        assert_eq!(a.compare_within_aggregate(&b), VersionOrder::Incomparable);
    }

    #[test]
    fn ordering_distinguishes_contiguous_from_gapped() {
        let known = AggregateVersion::ordinal_only(7);
        assert_eq!(
            AggregateVersion::ordinal_only(8).compare_within_aggregate(&known),
            VersionOrder::NextOrdinal
        );
        assert_eq!(
            AggregateVersion::ordinal_only(9).compare_within_aggregate(&known),
            VersionOrder::Newer
        );
        assert_eq!(
            AggregateVersion::ordinal_only(6).compare_within_aggregate(&known),
            VersionOrder::Older
        );
        assert_eq!(known.compare_within_aggregate(&known), VersionOrder::Equal);
    }

    /// `u64::MAX` as the known version must not make its own successor look
    /// contiguous through a wrapping add.
    #[test]
    fn a_saturating_successor_does_not_wrap() {
        let known = AggregateVersion::ordinal_only(u64::MAX);
        assert_eq!(
            AggregateVersion::ordinal_only(0).compare_within_aggregate(&known),
            VersionOrder::Older
        );
    }
}

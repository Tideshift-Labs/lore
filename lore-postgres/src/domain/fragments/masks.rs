// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031's payload-flag partition, and the flag-persistence rule it settles.
//!
//! These two masks are **new constants introduced by CR-031 in `lore-postgres`**
//! (R-SHOULD-4). They are not existing facts about `lore-base` or `lore-storage`,
//! and the review that raised this found an implementer would otherwise grep for
//! them, find nothing, and invent them in a file this package does not own.
//!
//! # The flag-persistence conflict, resolved
//!
//! Two shared sources describe the same bits differently:
//!
//! - `lore-storage/src/immutable_store.rs:104-109` says `PayloadStored*`,
//!   `PayloadLocalCachePriority`, and `PayloadRevisionState` "must persist
//!   through the storage system".
//! - `lore-aws/src/store/object_metadata.rs:38-40` excludes `PayloadStored*` and
//!   `PayloadLocalCachePriority` from `PAYLOAD_FLAGS`, retaining only
//!   `PayloadFragmented | PayloadCompressed | PayloadRevisionState`.
//!
//! CR-031 records the reviewed winner rather than leaving it implicit, because
//! leaving it implicit is exactly how WP-105 happened: adopting `lore-aws`'s
//! allowlist for this crate dropped `PayloadLocalCachePriority`, which
//! `lore-storage::load_fragment` keyed its always-cache-locally exemption on,
//! and every offline revision-state read broke fork-wide.
//!
//! **The winner is `lore-aws`'s partition, on the narrow question of what a
//! stored object's metadata carries**, for one reason that is a property of the
//! bits rather than a preference between files: [`CONTENT_STRUCTURE_MASK`] and
//! [`ENCODING_MASK`] together are exactly `PAYLOAD_FLAGS`, and every bit in them
//! describes **what the payload is**. `PayloadStored*` and
//! `PayloadLocalCachePriority` describe what a *host* should do with it, and are
//! derived from the current tier on read. The `lore-storage` comment is right
//! about the *wire and cache* contract and wrong only as a claim about stored
//! object metadata; WP-105's fix already re-keyed the consumer onto
//! `PayloadRevisionState`, which is on this side of the line.
//!
//! The rule to apply when adding a bit: key the allowlist on what the flag
//! **describes**, never on what a host should do with it.

use lore_base::types::FragmentFlags;

/// Bits that describe the payload's content structure, and therefore its
/// identity. These persist as stored representation and take part in semantic
/// comparison when an existing object is adopted.
///
/// `PayloadRevisionState` is deliberately here rather than treated as a
/// per-machine hint. That reclassification is the WP-105 bug, and this constant
/// is where it is prevented from recurring.
pub const CONTENT_STRUCTURE_MASK: u32 =
    FragmentFlags::PayloadFragmented.bits() | FragmentFlags::PayloadRevisionState.bits();

/// Bits that describe how the payload is encoded. The whole compressor group,
/// so an unknown future compressor is caught by the shared structural validator
/// rather than silently masked off here.
pub const ENCODING_MASK: u32 = FragmentFlags::PayloadCompressed.bits();

/// Bits that are derived from the current storage tier on read and must **not**
/// be trusted from candidate object metadata.
///
/// Reconstructing these is correct; persisting them is what makes a fragment's
/// recorded identity depend on which host last touched it.
pub const DERIVED_TIER_MASK: u32 =
    FragmentFlags::PayloadStored.bits() | FragmentFlags::PayloadLocalCachePriority.bits();

/// The encodings this program can decode for semantic comparison.
///
/// This is CR-031's **policy**, not a property of the shared validator.
/// `validate_fragment_metadata` accepts an Oodle2-flagged fragment, because
/// `FRAGMENT_FLAGS_DEFINED_COMPRESSORS` is `LZ4 | Oodle2 | Zstd`
/// (`lore-storage/src/immutable_store.rs:113-115`). Oodle2 therefore passes
/// structural validation and fails closed one step later, at decode, as
/// recognized-but-unsupported — unless this binary was built with the `oodle`
/// feature.
///
/// Validation order matters and is fixed: shared structural validation first,
/// then decode. Never a locally copied subset of the structural rules.
pub fn decodable_encoding(flags: u32) -> DecodeSupport {
    let encoding = flags & ENCODING_MASK;
    if encoding == 0 {
        return DecodeSupport::Supported;
    }
    if encoding == FragmentFlags::PayloadCompressedLZ4.bits()
        || encoding == FragmentFlags::PayloadCompressedZstd.bits()
    {
        return DecodeSupport::Supported;
    }
    if encoding == FragmentFlags::PayloadCompressedOodle2.bits() {
        // Recognized. Whether it is decodable is a build property, and the
        // distinction is load-bearing: on a cell without the feature a legacy
        // Oodle2 object is unrepairable rather than corrupt, and reporting it
        // as corruption would send an operator looking for damaged bytes.
        return if cfg!(feature = "oodle") {
            DecodeSupport::Supported
        } else {
            DecodeSupport::RecognizedUnsupported
        };
    }
    DecodeSupport::Undefined
}

/// Whether this build can decode a given encoding, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeSupport {
    /// Raw, LZ4, Zstd, or Oodle2 on an `oodle`-enabled build.
    Supported,
    /// A compressor the shared validator defines and this build cannot decode.
    /// Unrepairable here; not corruption.
    RecognizedUnsupported,
    /// Not a defined compressor, or more than one compression bit. The shared
    /// structural validator rejects this before decode is ever reached, so
    /// seeing it here means validation was skipped.
    Undefined,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_masks_partition_exactly_the_stored_payload_flags() {
        // This is the whole argument for the reclassification in the module
        // docs. If a future flag lands in `PAYLOAD_FLAGS` without joining one
        // of these two masks, the reasoning stops holding and this fails.
        assert_eq!(
            CONTENT_STRUCTURE_MASK | ENCODING_MASK,
            lore_aws::store::object_metadata::PAYLOAD_FLAGS,
            "CONTENT_STRUCTURE_MASK | ENCODING_MASK must be exactly PAYLOAD_FLAGS"
        );
    }

    #[test]
    fn the_two_masks_do_not_overlap() {
        assert_eq!(CONTENT_STRUCTURE_MASK & ENCODING_MASK, 0);
    }

    #[test]
    fn derived_tier_bits_are_disjoint_from_persisted_identity() {
        assert_eq!(DERIVED_TIER_MASK & CONTENT_STRUCTURE_MASK, 0);
        assert_eq!(DERIVED_TIER_MASK & ENCODING_MASK, 0);
    }

    #[test]
    fn payload_revision_state_persists_as_content_structure() {
        // The WP-105 regression guard. `PayloadRevisionState` describes what
        // the payload IS, so it is retained; dropping it as "a per-machine
        // hint" is the documented bug.
        assert_ne!(
            CONTENT_STRUCTURE_MASK & FragmentFlags::PayloadRevisionState.bits(),
            0
        );
    }

    #[test]
    fn local_cache_priority_is_derived_not_persisted() {
        assert_ne!(
            DERIVED_TIER_MASK & FragmentFlags::PayloadLocalCachePriority.bits(),
            0
        );
        assert_eq!(
            CONTENT_STRUCTURE_MASK & FragmentFlags::PayloadLocalCachePriority.bits(),
            0
        );
    }

    #[test]
    fn raw_lz4_and_zstd_decode_and_an_undefined_compressor_does_not() {
        assert_eq!(decodable_encoding(0), DecodeSupport::Supported);
        assert_eq!(
            decodable_encoding(FragmentFlags::PayloadCompressedLZ4.bits()),
            DecodeSupport::Supported
        );
        assert_eq!(
            decodable_encoding(FragmentFlags::PayloadCompressedZstd.bits()),
            DecodeSupport::Supported
        );
        // Two compression bits at once. The shared structural validator rejects
        // this first; reaching here at all means validation was skipped.
        assert_eq!(
            decodable_encoding(
                FragmentFlags::PayloadCompressedLZ4.bits()
                    | FragmentFlags::PayloadCompressedZstd.bits()
            ),
            DecodeSupport::Undefined
        );
    }

    #[test]
    fn oodle2_support_follows_the_build_feature_and_is_never_undefined() {
        let verdict = decodable_encoding(FragmentFlags::PayloadCompressedOodle2.bits());
        // Whichever way this build was configured, Oodle2 is RECOGNIZED. The
        // failure this pins is reporting it as `Undefined`, which would send a
        // legacy Oodle2 object down the generic-corruption path.
        assert_ne!(verdict, DecodeSupport::Undefined);
        if cfg!(feature = "oodle") {
            assert_eq!(verdict, DecodeSupport::Supported);
        } else {
            assert_eq!(verdict, DecodeSupport::RecognizedUnsupported);
        }
    }

    #[test]
    fn content_structure_and_encoding_bits_survive_a_flag_round_trip() {
        let stored = FragmentFlags::PayloadRevisionState.bits()
            | FragmentFlags::PayloadCompressedZstd.bits()
            | FragmentFlags::PayloadLocalCachePriority.bits()
            | FragmentFlags::PayloadStoredDurable.bits();
        let persisted = stored & (CONTENT_STRUCTURE_MASK | ENCODING_MASK);
        assert_ne!(persisted & FragmentFlags::PayloadRevisionState.bits(), 0);
        assert_ne!(persisted & FragmentFlags::PayloadCompressedZstd.bits(), 0);
        assert_eq!(persisted & DERIVED_TIER_MASK, 0);
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031 lifecycle states and the readability predicate.
//!
//! One enum, one encoding, one place that decides what "readable" means. The
//! whole point of the coordinator is that `query`, `get_metadata`, `get`,
//! `copy`, push proof, and stats stop each implementing that predicate
//! separately — so it lives here and nowhere else.

use crate::domain::errors::DomainError;

/// Lifecycle state of one FragmentId's current epoch.
///
/// The encodings are a fresh dense range and deliberately do **not** reuse the
/// legacy `lore_fragment_state` values (`0`, `1`, `256`, `512`), which are
/// `FragmentFlags` bits. Sharing a column domain between the two would make a
/// half-migrated cell's rows silently legible to the wrong reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FragmentLifecycleState {
    /// Fenced intent only: an epoch and fence are allocated, no association is
    /// published, and nothing is readable.
    PreparingStage,
    /// Fenced intent only, for the direct-write path.
    PreparingRemote,
    /// A finalized durable staged file plus a committed manifest is
    /// representation authority.
    Staged,
    /// The exact immutable object named by the manifest, with validated
    /// metadata, is representation authority.
    Remote,
    /// Bounded recursive-delete progress. Not readable.
    DeletingChildren,
    /// Physical purge in progress and no live association remains.
    DeletingPayload,
    /// The expected authority was observed absent, truncated, or corrupt.
    /// **Durable evidence, not a row deletion**: associations and the last
    /// manifest are retained for diagnosis and for repair to build on.
    Missing,
    /// Physical obliteration of the current epoch completed.
    Tombstoned,
}

impl FragmentLifecycleState {
    /// Stored encoding.
    pub fn bits(self) -> i16 {
        match self {
            Self::PreparingStage => 1,
            Self::PreparingRemote => 2,
            Self::Staged => 3,
            Self::Remote => 4,
            Self::DeletingChildren => 5,
            Self::DeletingPayload => 6,
            Self::Missing => 7,
            Self::Tombstoned => 8,
        }
    }

    /// Decode one stored encoding.
    pub fn from_bits(bits: i16) -> Result<Self, DomainError> {
        match bits {
            1 => Ok(Self::PreparingStage),
            2 => Ok(Self::PreparingRemote),
            3 => Ok(Self::Staged),
            4 => Ok(Self::Remote),
            5 => Ok(Self::DeletingChildren),
            6 => Ok(Self::DeletingPayload),
            7 => Ok(Self::Missing),
            8 => Ok(Self::Tombstoned),
            other => Err(DomainError::Internal(format!(
                "unknown fragment lifecycle state {other}"
            ))),
        }
    }

    /// Whether this state names a representation a positive result may be
    /// served from.
    ///
    /// This is the single readability predicate. Everything else — a live
    /// association, a complete manifest, a fence that has not moved — is
    /// checked alongside it by the resolver, never instead of it.
    pub fn is_readable(self) -> bool {
        matches!(self, Self::Staged | Self::Remote)
    }

    /// Whether the head is inside a deletion sequence, which forbids publishing
    /// a new association against it.
    pub fn is_deleting(self) -> bool {
        matches!(self, Self::DeletingChildren | Self::DeletingPayload)
    }

    /// Whether the head is a fenced intent that has not published anything.
    pub fn is_preparing(self) -> bool {
        matches!(self, Self::PreparingStage | Self::PreparingRemote)
    }

    /// Stable name for diagnostics and error text. Never parsed.
    pub fn label(self) -> &'static str {
        match self {
            Self::PreparingStage => "PreparingStage",
            Self::PreparingRemote => "PreparingRemote",
            Self::Staged => "Staged",
            Self::Remote => "Remote",
            Self::DeletingChildren => "DeletingChildren",
            Self::DeletingPayload => "DeletingPayload",
            Self::Missing => "Missing",
            Self::Tombstoned => "Tombstoned",
        }
    }
}

/// Which of the two authorities backs one epoch's representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochAuthority {
    /// A durable staged file on this cell's filesystem.
    Staged,
    /// An immutable object in this cell's provider bucket.
    Remote,
}

impl EpochAuthority {
    /// Stored encoding.
    pub fn bits(self) -> i16 {
        match self {
            Self::Staged => super::schema::AUTHORITY_STAGED,
            Self::Remote => super::schema::AUTHORITY_REMOTE,
        }
    }

    /// Decode one stored encoding.
    pub fn from_bits(bits: i16) -> Result<Self, DomainError> {
        match bits {
            super::schema::AUTHORITY_STAGED => Ok(Self::Staged),
            super::schema::AUTHORITY_REMOTE => Ok(Self::Remote),
            other => Err(DomainError::Internal(format!(
                "unknown fragment epoch authority {other}"
            ))),
        }
    }

    /// The lifecycle state a committed epoch of this authority publishes.
    pub fn readable_state(self) -> FragmentLifecycleState {
        match self {
            Self::Staged => FragmentLifecycleState::Staged,
            Self::Remote => FragmentLifecycleState::Remote,
        }
    }
}

/// Why a head is `Missing`. Bounded so the column stays a closed vocabulary
/// rather than an unbounded free-text field on a hot table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingDiagnostic {
    /// The expected authority was not there.
    Absent,
    /// It was there and short.
    Truncated,
    /// It was there, whole, and did not match its manifest.
    Corrupt,
    /// Structural validation of the stored representation failed.
    InvalidStructure,
    /// The representation uses a defined compressor this build cannot decode.
    ///
    /// Distinct from [`Self::Corrupt`] on purpose: the bytes may be perfectly
    /// good, and the remedy is a binary built with the codec feature rather
    /// than a repair. A cell without the `oodle` feature reports this for a
    /// legacy Oodle2 object.
    UnrepairableEncoding,
}

impl MissingDiagnostic {
    /// Stored encoding.
    pub fn bits(self) -> i16 {
        match self {
            Self::Absent => super::schema::DIAGNOSTIC_ABSENT,
            Self::Truncated => super::schema::DIAGNOSTIC_TRUNCATED,
            Self::Corrupt => super::schema::DIAGNOSTIC_CORRUPT,
            Self::InvalidStructure => super::schema::DIAGNOSTIC_INVALID_STRUCTURE,
            Self::UnrepairableEncoding => super::schema::DIAGNOSTIC_UNREPAIRABLE_ENCODING,
        }
    }

    /// Decode one stored encoding. `0` means "no diagnosis", which is only
    /// valid on a head that is not `Missing`, so it is not decodable here.
    pub fn from_bits(bits: i16) -> Result<Self, DomainError> {
        match bits {
            super::schema::DIAGNOSTIC_ABSENT => Ok(Self::Absent),
            super::schema::DIAGNOSTIC_TRUNCATED => Ok(Self::Truncated),
            super::schema::DIAGNOSTIC_CORRUPT => Ok(Self::Corrupt),
            super::schema::DIAGNOSTIC_INVALID_STRUCTURE => Ok(Self::InvalidStructure),
            super::schema::DIAGNOSTIC_UNREPAIRABLE_ENCODING => Ok(Self::UnrepairableEncoding),
            other => Err(DomainError::Internal(format!(
                "unknown missing diagnostic class {other}"
            ))),
        }
    }

    /// Whether an in-band repair could plausibly fix this cell's copy.
    ///
    /// `false` for [`Self::UnrepairableEncoding`], which needs a differently
    /// built binary rather than different bytes.
    pub fn is_repairable_here(self) -> bool {
        !matches!(self, Self::UnrepairableEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_round_trips_through_its_encoding() {
        let states = [
            FragmentLifecycleState::PreparingStage,
            FragmentLifecycleState::PreparingRemote,
            FragmentLifecycleState::Staged,
            FragmentLifecycleState::Remote,
            FragmentLifecycleState::DeletingChildren,
            FragmentLifecycleState::DeletingPayload,
            FragmentLifecycleState::Missing,
            FragmentLifecycleState::Tombstoned,
        ];
        for state in states {
            assert_eq!(
                FragmentLifecycleState::from_bits(state.bits()),
                Ok(state),
                "{} did not round trip",
                state.label()
            );
        }
    }

    #[test]
    fn state_encodings_stay_inside_the_schema_check_range() {
        // `lore_fragment_lifecycle.state` is `CHECK (state BETWEEN 1 AND 8)`.
        // A ninth state added without widening the CHECK would fail 23514 at
        // runtime on a real cell rather than here.
        for bits in 1..=8i16 {
            assert!(
                FragmentLifecycleState::from_bits(bits).is_ok(),
                "state {bits} is inside the CHECK range but does not decode"
            );
        }
        assert!(FragmentLifecycleState::from_bits(0).is_err());
        assert!(FragmentLifecycleState::from_bits(9).is_err());
    }

    #[test]
    fn only_staged_and_remote_are_readable() {
        assert!(FragmentLifecycleState::Staged.is_readable());
        assert!(FragmentLifecycleState::Remote.is_readable());
        for state in [
            FragmentLifecycleState::PreparingStage,
            FragmentLifecycleState::PreparingRemote,
            FragmentLifecycleState::DeletingChildren,
            FragmentLifecycleState::DeletingPayload,
            FragmentLifecycleState::Missing,
            FragmentLifecycleState::Tombstoned,
        ] {
            assert!(
                !state.is_readable(),
                "{} must not be readable",
                state.label()
            );
        }
    }

    #[test]
    fn readable_states_match_the_schemas_readable_shape_check() {
        // `lore_fragment_lifecycle_readable_shape` is
        // `(state IN (3, 4)) = (manifest_id IS NOT NULL)`. If `is_readable`
        // and that CHECK ever disagree, a readable head could carry no
        // manifest, which is the one shape the resolver cannot defend against.
        for bits in 1..=8i16 {
            let state = FragmentLifecycleState::from_bits(bits)
                .expect("every encoding in the CHECK range decodes");
            assert_eq!(
                state.is_readable(),
                bits == 3 || bits == 4,
                "{} disagrees with the schema readable-shape CHECK",
                state.label()
            );
        }
    }

    #[test]
    fn missing_is_not_a_deleting_state() {
        // CR-031 keeps `Missing` deliberately outside the deleting set: a new
        // association may still be published against a missing fragment, and
        // repair is the exit. Folding it in would close that exit.
        assert!(!FragmentLifecycleState::Missing.is_deleting());
        assert!(FragmentLifecycleState::DeletingChildren.is_deleting());
        assert!(FragmentLifecycleState::DeletingPayload.is_deleting());
        assert!(!FragmentLifecycleState::Tombstoned.is_deleting());
    }

    #[test]
    fn an_unrepairable_encoding_is_distinct_from_corruption() {
        assert!(!MissingDiagnostic::UnrepairableEncoding.is_repairable_here());
        assert!(MissingDiagnostic::Corrupt.is_repairable_here());
        assert_ne!(
            MissingDiagnostic::UnrepairableEncoding.bits(),
            MissingDiagnostic::Corrupt.bits()
        );
    }

    #[test]
    fn every_diagnostic_round_trips_and_stays_inside_the_check_range() {
        for diagnostic in [
            MissingDiagnostic::Absent,
            MissingDiagnostic::Truncated,
            MissingDiagnostic::Corrupt,
            MissingDiagnostic::InvalidStructure,
            MissingDiagnostic::UnrepairableEncoding,
        ] {
            assert_eq!(
                MissingDiagnostic::from_bits(diagnostic.bits()),
                Ok(diagnostic)
            );
            // `diagnostic_class` is `CHECK (diagnostic_class BETWEEN 0 AND 5)`.
            assert!((1..=5).contains(&diagnostic.bits()));
        }
    }

    #[test]
    fn each_authority_publishes_its_own_readable_state() {
        assert_eq!(
            EpochAuthority::Staged.readable_state(),
            FragmentLifecycleState::Staged
        );
        assert_eq!(
            EpochAuthority::Remote.readable_state(),
            FragmentLifecycleState::Remote
        );
        for authority in [EpochAuthority::Staged, EpochAuthority::Remote] {
            assert_eq!(EpochAuthority::from_bits(authority.bits()), Ok(authority));
            assert!(authority.readable_state().is_readable());
        }
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure shared-spool layout and crash-boundary classification.
//!
//! This module performs no filesystem access and grants no cleanup, publication, ledger, quota, or
//! dispatch authority. Its observations must be produced by a future transaction-integrated,
//! no-follow filesystem verifier. Every candidate decision still requires row-locked revalidation.

use std::fmt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use thiserror::Error;

use crate::auth::validate_id;
use crate::request::decode_canonical_uuid_v7;

pub const SPOOL_LAYOUT_REVISION_V1: &str = "object-store-spool-layout-v1";
const BOUNDARY_TOKEN_PREFIX: &str = "odsb_";
const FANOUT_DOMAIN: &[u8] = b"object-store-spool-fanout-v1\0";
const OBSERVATION_BINDING_DOMAIN: &[u8] = b"object-store-spool-observation-v1\0";
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolObjectKind {
    Put,
    Result,
}

impl SpoolObjectKind {
    fn path_component(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Result => "result",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SpoolObjectKey {
    pub provider_boundary_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub kind: SpoolObjectKind,
}

impl fmt::Debug for SpoolObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolObjectKey")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SpoolBoundaryBinding {
    provider_boundary_id: String,
    boundary_blake3: [u8; 32],
    boundary_token: String,
}

impl SpoolBoundaryBinding {
    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn boundary_blake3(&self) -> &[u8; 32] {
        &self.boundary_blake3
    }

    pub fn boundary_token(&self) -> &str {
        &self.boundary_token
    }
}

impl fmt::Debug for SpoolBoundaryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolBoundaryBinding")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("boundary_blake3", &"[REDACTED]")
            .field("boundary_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SpoolLayout {
    shared_spool_root: PathBuf,
}

impl SpoolLayout {
    pub fn new(shared_spool_root: PathBuf) -> Result<Self, SpoolLayoutError> {
        validate_absolute_root(&shared_spool_root)?;
        Ok(Self { shared_spool_root })
    }

    pub fn derive_boundary_binding(
        &self,
        provider_boundary_id: &str,
    ) -> Result<SpoolBoundaryBinding, SpoolLayoutError> {
        validate_id(provider_boundary_id).map_err(|_| SpoolLayoutError::InvalidBoundaryId)?;
        let (boundary_blake3, boundary_token) = derive_boundary_token(provider_boundary_id);
        Ok(SpoolBoundaryBinding {
            provider_boundary_id: provider_boundary_id.to_string(),
            boundary_blake3,
            boundary_token,
        })
    }

    pub fn derive_paths(&self, key: &SpoolObjectKey) -> Result<SpoolPaths, SpoolLayoutError> {
        let binding = self.derive_boundary_binding(&key.provider_boundary_id)?;
        let logical_uuid = decode_canonical_uuid_v7(&key.logical_request_id)
            .map_err(|_| SpoolLayoutError::InvalidUuidV7)?;
        decode_canonical_uuid_v7(&key.attempt_id).map_err(|_| SpoolLayoutError::InvalidUuidV7)?;
        let fanout = fanout_hex(logical_uuid);
        let filename = format!("{}.blob", key.attempt_id);
        let part_filename = format!("{}.part", key.attempt_id);
        let kind = key.kind.path_component();
        let opaque_handle = format!(
            "{SPOOL_LAYOUT_REVISION_V1}/{}/{kind}/{fanout}/{}/{filename}",
            binding.boundary_token, key.logical_request_id
        );
        let observation_binding_blake3 = observation_binding_blake3(&opaque_handle);
        let directory = self
            .shared_spool_root
            .join(SPOOL_LAYOUT_REVISION_V1)
            .join(&binding.boundary_token)
            .join(kind)
            .join(&fanout)
            .join(&key.logical_request_id);
        Ok(SpoolPaths {
            final_path: directory.join(filename),
            part_path: directory.join(part_filename),
            opaque_handle,
            boundary_binding: binding,
            observation_binding_blake3,
        })
    }
}

impl fmt::Debug for SpoolLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolLayout")
            .field("shared_spool_root", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SpoolPaths {
    final_path: PathBuf,
    part_path: PathBuf,
    opaque_handle: String,
    boundary_binding: SpoolBoundaryBinding,
    observation_binding_blake3: [u8; 32],
}

impl SpoolPaths {
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    pub fn opaque_handle(&self) -> &str {
        &self.opaque_handle
    }

    pub fn boundary_binding(&self) -> &SpoolBoundaryBinding {
        &self.boundary_binding
    }
}

impl fmt::Debug for SpoolPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpoolPaths")
            .field("final_path", &"[REDACTED]")
            .field("part_path", &"[REDACTED]")
            .field("opaque_handle", &"[REDACTED]")
            .field("boundary_binding", &self.boundary_binding)
            .finish()
    }
}

pub fn validate_spool_boundary_binding(
    expected_provider_boundary_id: &str,
    stored_provider_boundary_id: &str,
    stored_boundary_blake3: &[u8; 32],
    stored_boundary_token: &str,
) -> Result<SpoolBoundaryBinding, SpoolLayoutError> {
    validate_id(expected_provider_boundary_id).map_err(|_| SpoolLayoutError::InvalidBoundaryId)?;
    let (expected_digest, expected_token) = derive_boundary_token(expected_provider_boundary_id);
    if stored_provider_boundary_id != expected_provider_boundary_id
        || stored_boundary_blake3 != &expected_digest
        || stored_boundary_token != expected_token
    {
        return Err(SpoolLayoutError::BoundaryBindingMismatch);
    }
    Ok(SpoolBoundaryBinding {
        provider_boundary_id: expected_provider_boundary_id.to_string(),
        boundary_blake3: expected_digest,
        boundary_token: expected_token,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub enum LedgerSpoolView {
    Absent,
    Reserved {
        expected_size: u64,
        expected_blake3: [u8; 32],
        accounted_prefix_bytes: u64,
    },
    Ready {
        opaque_handle: String,
        size: u64,
        blake3: [u8; 32],
    },
    Released {
        release_receipt_blake3: [u8; 32],
    },
}

impl fmt::Debug for LedgerSpoolView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("LedgerSpoolView::Absent"),
            Self::Reserved {
                expected_size,
                accounted_prefix_bytes,
                ..
            } => formatter
                .debug_struct("LedgerSpoolView::Reserved")
                .field("expected_size", expected_size)
                .field("expected_blake3", &"[REDACTED]")
                .field("accounted_prefix_bytes", accounted_prefix_bytes)
                .finish(),
            Self::Ready { size, .. } => formatter
                .debug_struct("LedgerSpoolView::Ready")
                .field("opaque_handle", &"[REDACTED]")
                .field("size", size)
                .field("blake3", &"[REDACTED]")
                .finish(),
            Self::Released { .. } => formatter
                .debug_struct("LedgerSpoolView::Released")
                .field("release_receipt_blake3", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedFileObservation {
    path_binding_blake3: [u8; 32],
    kind: VerifiedFileObservationKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
// These variants are constructed only by this module's future no-follow verifier. Keeping the enum
// private is what prevents callers from fabricating recovery evidence before that verifier lands.
#[allow(dead_code)]
enum VerifiedFileObservationKind {
    None,
    Part { size: u64, blake3: Option<[u8; 32]> },
    Blob { size: u64, blake3: [u8; 32] },
    Both,
    UnsafeOrNonRegular,
}

impl fmt::Debug for VerifiedFileObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rendered = formatter.debug_struct("VerifiedFileObservation");
        rendered.field("path_binding_blake3", &"[REDACTED]");
        match self.kind {
            VerifiedFileObservationKind::None => rendered.field("kind", &"None"),
            VerifiedFileObservationKind::Part { size, blake3 } => rendered
                .field("kind", &"Part")
                .field("size", &size)
                .field("blake3", &blake3.map(|_| "[REDACTED]")),
            VerifiedFileObservationKind::Blob { size, .. } => rendered
                .field("kind", &"Blob")
                .field("size", &size)
                .field("blake3", &"[REDACTED]"),
            VerifiedFileObservationKind::Both => rendered.field("kind", &"Both"),
            VerifiedFileObservationKind::UnsafeOrNonRegular => {
                rendered.field("kind", &"UnsafeOrNonRegular")
            }
        };
        rendered.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolRecoveryDecision {
    ConsistentAbsent,
    AwaitUpload,
    RevalidateAccountedPrefix,
    CandidateForFinalPublication,
    CandidateForReadyCommit,
    ConsistentReady,
    CleanupOnlyCandidate,
    FailClosed(SpoolRecoveryInconsistency),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolRecoveryInconsistency {
    InvalidLedgerState,
    MissingAccountedPrefix,
    UnexpectedPartLength,
    PartDigestMismatch,
    BlobMismatch,
    MultipleArtifacts,
    UnsafeFileType,
    MissingReadyBlob,
    ReadyHandleMismatch,
    ObservationPathMismatch,
}

pub fn classify_spool_recovery(
    ledger: &LedgerSpoolView,
    observation: VerifiedFileObservation,
    paths: &SpoolPaths,
) -> SpoolRecoveryDecision {
    if observation.path_binding_blake3 != paths.observation_binding_blake3 {
        return SpoolRecoveryDecision::FailClosed(
            SpoolRecoveryInconsistency::ObservationPathMismatch,
        );
    }
    match ledger {
        LedgerSpoolView::Absent => classify_absent_or_released(observation.kind),
        LedgerSpoolView::Released { .. } => classify_absent_or_released(observation.kind),
        LedgerSpoolView::Reserved {
            expected_size,
            expected_blake3,
            accounted_prefix_bytes,
        } => classify_reserved(
            *expected_size,
            expected_blake3,
            *accounted_prefix_bytes,
            observation.kind,
        ),
        LedgerSpoolView::Ready {
            opaque_handle,
            size,
            blake3,
        } => classify_ready(opaque_handle, *size, blake3, observation.kind, paths),
    }
}

fn classify_absent_or_released(observation: VerifiedFileObservationKind) -> SpoolRecoveryDecision {
    match observation {
        VerifiedFileObservationKind::None => SpoolRecoveryDecision::ConsistentAbsent,
        VerifiedFileObservationKind::Part { .. }
        | VerifiedFileObservationKind::Blob { .. }
        | VerifiedFileObservationKind::Both => SpoolRecoveryDecision::CleanupOnlyCandidate,
        VerifiedFileObservationKind::UnsafeOrNonRegular => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        }
    }
}

fn classify_reserved(
    expected_size: u64,
    expected_blake3: &[u8; 32],
    accounted_prefix_bytes: u64,
    observation: VerifiedFileObservationKind,
) -> SpoolRecoveryDecision {
    if accounted_prefix_bytes > expected_size {
        return SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::InvalidLedgerState);
    }
    match observation {
        VerifiedFileObservationKind::None if accounted_prefix_bytes == 0 => {
            SpoolRecoveryDecision::AwaitUpload
        }
        VerifiedFileObservationKind::None => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MissingAccountedPrefix)
        }
        VerifiedFileObservationKind::Part { size, .. } if size != accounted_prefix_bytes => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnexpectedPartLength)
        }
        VerifiedFileObservationKind::Part { size, .. } if size < expected_size => {
            SpoolRecoveryDecision::RevalidateAccountedPrefix
        }
        VerifiedFileObservationKind::Part {
            size,
            blake3: Some(blake3),
        } if size == expected_size && blake3 == *expected_blake3 => {
            SpoolRecoveryDecision::CandidateForFinalPublication
        }
        VerifiedFileObservationKind::Part { .. } => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::PartDigestMismatch)
        }
        VerifiedFileObservationKind::Blob { size, blake3 }
            if size == expected_size && blake3 == *expected_blake3 =>
        {
            SpoolRecoveryDecision::CandidateForReadyCommit
        }
        VerifiedFileObservationKind::Blob { .. } => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::BlobMismatch)
        }
        VerifiedFileObservationKind::Both => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MultipleArtifacts)
        }
        VerifiedFileObservationKind::UnsafeOrNonRegular => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        }
    }
}

fn classify_ready(
    opaque_handle: &str,
    expected_size: u64,
    expected_blake3: &[u8; 32],
    observation: VerifiedFileObservationKind,
    paths: &SpoolPaths,
) -> SpoolRecoveryDecision {
    if opaque_handle != paths.opaque_handle {
        return SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::ReadyHandleMismatch);
    }
    match observation {
        VerifiedFileObservationKind::Blob { size, blake3 }
            if size == expected_size && blake3 == *expected_blake3 =>
        {
            SpoolRecoveryDecision::ConsistentReady
        }
        VerifiedFileObservationKind::Blob { .. } => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::BlobMismatch)
        }
        VerifiedFileObservationKind::None => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MissingReadyBlob)
        }
        VerifiedFileObservationKind::Part { .. } => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MissingReadyBlob)
        }
        VerifiedFileObservationKind::Both => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MultipleArtifacts)
        }
        VerifiedFileObservationKind::UnsafeOrNonRegular => {
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        }
    }
}

fn validate_absolute_root(root: &Path) -> Result<(), SpoolLayoutError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(SpoolLayoutError::InvalidSharedSpoolRoot);
    }
    Ok(())
}

fn fanout_hex(logical_uuid: [u8; 16]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FANOUT_DOMAIN);
    hasher.update(&logical_uuid);
    let digest = hasher.finalize();
    format!("{:02x}{:02x}", digest.as_bytes()[0], digest.as_bytes()[1])
}

fn derive_boundary_token(provider_boundary_id: &str) -> ([u8; 32], String) {
    let digest = *blake3::hash(provider_boundary_id.as_bytes()).as_bytes();
    let token = format!("{BOUNDARY_TOKEN_PREFIX}{}", encode_base32_lower(&digest));
    (digest, token)
}

fn observation_binding_blake3(opaque_handle: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OBSERVATION_BINDING_DOMAIN);
    hasher.update(opaque_handle.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests;

fn encode_base32_lower(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len().div_ceil(5) * 8);
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for byte in value {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::from((accumulator >> bits) & 0x1f);
            encoded.push(char::from(BASE32_LOWER[index]));
        }
        if bits == 0 {
            accumulator = 0;
        } else {
            accumulator &= (1u16 << bits) - 1;
        }
    }
    if bits > 0 {
        let index = usize::from((accumulator << (5 - bits)) & 0x1f);
        encoded.push(char::from(BASE32_LOWER[index]));
    }
    encoded
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SpoolLayoutError {
    #[error("shared object-dispatch spool root is not an absolute normalized path")]
    InvalidSharedSpoolRoot,
    #[error("object-dispatch spool boundary ID is invalid")]
    InvalidBoundaryId,
    #[error("object-dispatch spool request identity is not canonical UUIDv7")]
    InvalidUuidV7,
    #[error("object-dispatch spool boundary binding does not match")]
    BoundaryBindingMismatch,
}

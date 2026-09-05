// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 R-BLOCK-2: the one shared reader of domain-operation request metadata.
//!
//! Operation identity for a governed repository/branch mutation is carried as
//! gRPC **request metadata**, not as protobuf message fields. That is what keeps
//! CR-029 `[SERVER]`-clean: no `.proto` message changes, so the package order
//! WP-116-before-WP-120 survives. The header names follow the fork's existing
//! convention (`lore-transport/src/grpc/mod.rs:62-67`, which already carries
//! `urc-repository-id-bin`, `lore-partition-bin`, `x-epic-correlation-id`, and
//! `x-lore-revision-list-strategy`).
//!
//! # One reader, at handler entry
//!
//! Per-handler ad hoc reads of these headers are **forbidden**. The fork has
//! been burned by body-versus-metadata divergence before: CR-010 and
//! `lorehub/docs/learnings/loreserver-body-repo-authz-recheck.md` record what a
//! second reading of the same identity at a different layer costs. Every
//! governed handler calls [`extract`] or [`require`] exactly once, before any
//! handler logic, and threads the resulting value onward.
//!
//! # Fail closed, before admission
//!
//! Under enforcement a governed mutation whose required headers are absent,
//! duplicated with divergent values, wrong-length, of an unknown fingerprint
//! version, or not an RFC 9562 UUIDv7 is rejected **before** any authorization
//! side effect, with `INVALID_ARGUMENT`. Nothing is truncated or coerced into a
//! usable value.
//!
//! # Tenant scope keys exclude `urc-*` (R-BLOCK-5)
//!
//! The receipt key's `tenant_scope_key` is a versioned canonical tuple over the
//! **target** resource identity, derived independently of the token's resource
//! list. `auth/jwt.rs` accepts a wildcard `urc-*` resource, and the repository
//! v1 service runs under the authn-only `JWTAuthnInterceptor`, so a
//! token-derived scope is both unsatisfiable for create (no repository exists
//! yet) and ambiguous under a wildcard. The builders below take raw target
//! identity bytes and refuse anything shaped like a `urc-` resource string, so
//! `urc-*` cannot reach a scope key even by accident.
//!
//! The guarantee is about **provenance**, not about substring-freedom of the
//! encoded key: no scope-key component is ever sourced from the token's
//! resource list, and any component that begins with `urc-` is refused. A
//! principal identifier that happens to contain those four bytes part-way
//! through is not a resource identifier and is not rejected — components are
//! length-prefixed and namespace-tagged, so it cannot be confused with one.

use tonic::Status;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

/// Caller-chosen RFC 9562 UUIDv7 identifying one governed operation.
pub const OPERATION_ID_KEY: &str = "lore-domain-operation-id-bin";
/// One version byte followed by exactly that version's fingerprint bytes.
pub const FINGERPRINT_KEY: &str = "lore-domain-operation-fingerprint-bin";
/// The single-use consume token returned by `domain_operation_prepare`.
pub const PREPARE_TOKEN_KEY: &str = "lore-domain-prepare-token-bin";
/// Frozen CR-029 mediated receipt-namespace tuple.
pub const MEDIATED_SCOPE_KEY: &str = "lore-domain-mediated-scope-bin";

// PIN(WP-120, 2026-09-05): the client's own attempt identity, sent on every mutating dispatch.
//
// Plain ASCII, so no `-bin` suffix: the value is the hyphenated lowercase UUIDv7 that
// `lore_transport::outcome::AttemptId`'s `Display` renders, and a `-bin` key would make tonic
// expect base64. The client half is `lore-transport`'s `ATTEMPT_ID_METADATA_KEY`; the two
// literals must stay equal.
//
// Why the client sends an identity at all, when this server already mints an operation id: the
// server's id is only ever learned from the response, and the case this whole rail exists for is
// the response that never arrived. Nothing the server already holds can join a lost attempt to
// its receipt, so the client supplies something it minted before dispatch and the server files it
// alongside.
//
// It is an identifier, never an authority. The receipt namespace still comes from the verified
// token, so two clients that mint the same UUID collide only with themselves.
/// The client's own attempt identity for one mutating dispatch.
pub const ATTEMPT_ID_KEY: &str = "lore-attempt-id";

/// A UUID is 16 bytes. Any other length is rejected, never padded or truncated.
pub const OPERATION_ID_LEN: usize = 16;
/// `PrepareResult::Prepared.token` is `[u8; 32]`.
pub const PREPARE_TOKEN_LEN: usize = 32;
/// Fingerprint schema version 1 is BLAKE3, so exactly 32 bytes after the
/// version byte (`lore-postgres/src/domain/schema.rs` pins
/// `octet_length(fingerprint) = 32`).
pub const FINGERPRINT_V1_LEN: usize = 32;
/// The only fingerprint schema version this server accepts today.
pub const FINGERPRINT_VERSION_V1: u8 = 1;
/// Version 1 of the mediated-scope tuple.
pub const MEDIATED_SCOPE_VERSION_V1: u8 = 1;
/// Version + org UUID + canonical 49-byte principal namespace.
pub const MEDIATED_SCOPE_V1_LEN: usize = 66;
/// Exact canonical principal namespace width for carriage v1.
pub const MEDIATED_PRINCIPAL_NAMESPACE_V1_LEN: usize = 49;

// PIN(WP-116, 2026-09-04): claim carriage header, CR-029 amendment owed.
//
// `lore-domain-claim-witness-bin`, version 1, exactly 161 bytes, integers
// big-endian:
//
// ```text
//   0    1   version = 1
//   1   16   claim_id
//  17    8   claim_revision              u64, 1..=MAX_WIRE_REVISION
//  25   32   claim_verification_witness
//  57    8   authorization_revision      u64, 1..=MAX_WIRE_REVISION
//  65   32   verification_nonce
//  97   32   bound_fields_digest
// 129   32   consumed_ticket_sha256
// ```
//
// CR-029 freezes the four carriage headers above but not this one. The
// amendment naming it is owed; until it lands, this comment is the contract,
// and `packages/lore-client/src/domain-operation-metadata.ts` plus
// `apps/auth-grpc/src/service-rebac.ts` are the platform sides that must agree.
//
// Why one header rather than three for the claim triple: the authorization
// witness is as uncarried as the claim is. Lore records it at
// `domain_operation_prepare` time, but `domain_operation_receipt_get` returns
// bounded timing metadata only and deliberately never the witness, so the
// create call site can reach neither. Seven values are needed, not three, and
// one versioned fixed-width tuple makes present-together-or-absent structural
// rather than a rule five separate readers have to remember — the same reason
// [`MEDIATED_SCOPE_KEY`] is one header.
/// Frozen CR-029 attached-claim witness for a governed repository create.
pub const CLAIM_WITNESS_KEY: &str = "lore-domain-claim-witness-bin";
/// Version 1 of the attached-claim witness tuple.
pub const CLAIM_WITNESS_VERSION_V1: u8 = 1;
/// Version + claim triple + authorization witness. See the PIN above.
pub const CLAIM_WITNESS_V1_LEN: usize = 161;

/// Largest revision this server forwards to auth-grpc.
///
/// The platform verifier reads both revisions through `positiveWireInteger`,
/// which is `Number.isSafeInteger`-bounded, so a `u64` above 2^53-1 cannot
/// survive the crossing intact. Refusing it here makes that a decisive
/// client-side wire error at the gate instead of an opaque `PERMISSION_DENIED`
/// from a verifier comparing a silently rounded value.
pub const MAX_WIRE_REVISION: u64 = (1u64 << 53) - 1;

/// Version byte leading every tenant scope key this server builds.
pub const SCOPE_KEY_VERSION_V1: u8 = 1;
/// Fixed method constant for repository create, whose target repository does not
/// exist yet and so cannot supply the scope on its own.
pub const SCOPE_METHOD_REPOSITORY_CREATE_V1: &[u8] = b"repository-create-v1\0";
/// Fixed method constant for every other governed operation, whose scope is the
/// target repository identity.
pub const SCOPE_METHOD_REPOSITORY_V1: &[u8] = b"repository-v1\0";
/// Fixed namespace constant for a mediated operation, whose scope is the
/// auth-grpc-verified `(org UUID, principal-v1\0 || Principal.userId)` tuple.
pub const SCOPE_METHOD_MEDIATED_V1: &[u8] = b"mediated-v1\0";
/// Principal-namespace tag inside a mediated scope key.
pub const SCOPE_PRINCIPAL_NAMESPACE_V1: &[u8] = b"principal-v1\0";

/// A `urc-` resource string must never reach a scope key. Checked as a byte
/// prefix so a deliberately crafted 16-byte value cannot slip past the length
/// check either.
const URC_PREFIX: &[u8] = b"urc-";

/// Validated domain-operation identity, read exactly once per request.
///
/// Holds no authorization decision: under CR-029 the authorization outcome is
/// separate server-only witness evidence and is never a receipt-key input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainOperationMetadata {
    /// RFC 9562 UUIDv7, exactly 16 bytes on the wire.
    pub operation_id: Uuid,
    /// Fingerprint schema version, from the leading header byte.
    pub fingerprint_version: i32,
    /// The fingerprint bytes that version defines, with the version byte
    /// stripped.
    pub fingerprint: Vec<u8>,
    /// The single-use prepare token.
    pub prepare_token: [u8; PREPARE_TOKEN_LEN],
    /// Mediated receipt namespace, present only for the control-plane service
    /// principal and interpreted by the shared admission function.
    pub mediated_scope: Option<MediatedScope>,
    /// Attached platform claim, present only alongside a mediated scope.
    ///
    /// Carried rather than derived, and never an authority input here: Lore
    /// forwards these bytes to auth-grpc, which exact-matches every one of them
    /// against its own claim and authorization rows. A caller that supplies
    /// values it did not receive gets a conclusive denial from the verifier, not
    /// a widened path through this server.
    pub claim_witness: Option<ClaimWitness>,
}

/// Validated version-1 attached-claim witness. See [`CLAIM_WITNESS_KEY`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimWitness {
    /// Platform claim row identity.
    pub claim_id: [u8; OPERATION_ID_LEN],
    /// Monotonic claim revision.
    pub claim_revision: u64,
    /// Opaque claim verification witness. Never a digest input.
    pub claim_verification_witness: [u8; DIGEST_LEN],
    /// Monotonic authorization revision.
    pub authorization_revision: u64,
    /// Immutable verification nonce from the platform consume transition.
    pub verification_nonce: [u8; DIGEST_LEN],
    /// Digest over the authorization's bound fields.
    pub bound_fields_digest: [u8; DIGEST_LEN],
    /// SHA-256 commitment to the consumed preclaim ticket.
    pub consumed_ticket_sha256: [u8; DIGEST_LEN],
}

/// Width of every 256-bit digest in the claim witness.
pub const DIGEST_LEN: usize = 32;

/// Validated version-1 mediated receipt namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatedScope {
    pub org_uuid: [u8; 16],
    pub initiating_principal_namespace: [u8; MEDIATED_PRINCIPAL_NAMESPACE_V1_LEN],
}

/// Typed pre-admission failure. Every variant is decisive and client-caused:
/// none is retryable and none has produced a side effect.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainOperationMetadataError {
    /// A required header is missing entirely.
    #[error("missing required domain-operation header {header}")]
    Absent {
        /// The header that was absent.
        header: &'static str,
    },

    /// The header is present more than once with values that are not
    /// byte-identical. Picking the first would be exactly the divergence CR-010
    /// records, so it is refused instead.
    #[error("domain-operation header {header} repeated with divergent values")]
    DivergentDuplicate {
        /// The header that diverged.
        header: &'static str,
    },

    /// The header is not decodable as binary metadata.
    #[error("domain-operation header {header} is not valid binary metadata: {detail}")]
    Malformed {
        /// The header that failed to decode.
        header: &'static str,
        /// Decoder detail, safe to surface.
        detail: String,
    },

    /// The header decoded but is the wrong length for its schema.
    #[error("domain-operation header {header} has {actual} bytes, expected {expected}")]
    WrongLength {
        /// The header that was the wrong length.
        header: &'static str,
        /// Length this schema requires.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },

    /// The fingerprint header's leading version byte names a schema this server
    /// does not implement. Never coerced to the nearest known version.
    #[error("unsupported domain-operation fingerprint version {version}")]
    UnsupportedFingerprintVersion {
        /// The version byte supplied.
        version: u8,
    },

    /// The mediated-scope value names an unsupported schema.
    #[error("unsupported domain-operation mediated-scope version {version}")]
    UnsupportedMediatedScopeVersion { version: u8 },

    /// The mediated-scope principal bytes are not the frozen canonical form.
    #[error("domain-operation mediated-scope principal namespace is not canonical")]
    InvalidMediatedPrincipalNamespace,

    /// The claim-witness value names an unsupported schema.
    #[error("unsupported domain-operation claim-witness version {version}")]
    UnsupportedClaimWitnessVersion {
        /// The version byte supplied.
        version: u8,
    },

    /// A claim-witness revision is zero or beyond what the platform verifier
    /// can compare. Never clamped to the nearest representable value.
    #[error("domain-operation claim-witness {field} is {value}, expected 1..={max}")]
    ClaimWitnessRevisionOutOfRange {
        /// Which revision was out of range.
        field: &'static str,
        /// The value supplied.
        value: u64,
        /// Largest value the platform verifier can compare.
        max: u64,
    },

    /// The operation ID is 16 bytes but is not an RFC 9562 UUIDv7.
    #[error("domain-operation ID is not an RFC 9562 UUIDv7 (version {version})")]
    NotUuidV7 {
        /// UUID version nibble found.
        version: usize,
    },

    /// Some but not all of the original three headers were supplied. Partial carriage is
    /// never treated as absence, because absence has a legacy carve-out and
    /// partial carriage does not.
    #[error("partial domain-operation carriage: {present} present without {missing}")]
    PartialCarriage {
        /// A header that was supplied.
        present: &'static str,
        /// A header that was not.
        missing: &'static str,
    },
}

impl From<DomainOperationMetadataError> for Status {
    fn from(value: DomainOperationMetadataError) -> Self {
        // Client-caused and decisive. `INVALID_ARGUMENT` falls to
        // `lore-transport/src/error.rs`'s `_ => internal` arm, so it is never
        // replayed as a `Disconnected` reconnect the way `UNKNOWN` would be.
        Status::invalid_argument(value.to_string())
    }
}

/// Read one binary header, requiring a single value of an exact length.
fn read_exact_bin(
    metadata: &MetadataMap,
    header: &'static str,
    expected: usize,
) -> Result<Vec<u8>, DomainOperationMetadataError> {
    let bytes =
        read_bin(metadata, header)?.ok_or(DomainOperationMetadataError::Absent { header })?;
    if bytes.len() != expected {
        return Err(DomainOperationMetadataError::WrongLength {
            header,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Read one binary header, refusing divergent duplicates. `Ok(None)` means the
/// header is absent; a repeated header whose values are byte-identical is
/// accepted, because it carries no ambiguity.
fn read_bin(
    metadata: &MetadataMap,
    header: &'static str,
) -> Result<Option<Vec<u8>>, DomainOperationMetadataError> {
    let mut found: Option<Vec<u8>> = None;
    for value in metadata.get_all_bin(header).iter() {
        let bytes = value
            .to_bytes()
            .map_err(|e| DomainOperationMetadataError::Malformed {
                header,
                detail: e.to_string(),
            })?
            .to_vec();
        match &found {
            None => found = Some(bytes),
            Some(first) if *first == bytes => {}
            Some(_) => {
                return Err(DomainOperationMetadataError::DivergentDuplicate { header });
            }
        }
    }
    Ok(found)
}

/// Read one ASCII header, refusing divergent duplicates.
///
/// The plain-text sibling of [`read_bin`], with the same duplicate rule and for the same reason:
/// picking the first of two disagreeing values is the divergence CR-010 records.
fn read_ascii(
    metadata: &MetadataMap,
    header: &'static str,
) -> Result<Option<String>, DomainOperationMetadataError> {
    let mut found: Option<String> = None;
    for value in metadata.get_all(header).iter() {
        let text = value
            .to_str()
            .map_err(|e| DomainOperationMetadataError::Malformed {
                header,
                detail: e.to_string(),
            })?
            .to_owned();
        match &found {
            None => found = Some(text),
            Some(first) if *first == text => {}
            Some(_) => {
                return Err(DomainOperationMetadataError::DivergentDuplicate { header });
            }
        }
    }
    Ok(found)
}

/// Read the optional client attempt id.
///
/// Absent is ordinary and not an error: a client older than WP-120 sends nothing, and the
/// mutation proceeds with no reconciliation aid attached.
///
/// Present-but-unreadable is refused rather than ignored, and the asymmetry is deliberate. A
/// client sends this header because it intends to ask about the attempt later. Completing the
/// mutation while quietly discarding the identity would leave that client holding an id this
/// server never filed, and it could not tell the difference between an attempt with no receipt
/// and one whose header this server dropped. Refusing a mutation the caller can reissue under a
/// fresh id is the smaller harm than completing one it can never ask about.
///
/// The v7 check is not decoration. The receipt rail classifies replay by a UUID's embedded
/// timestamp, so a non-v7 value would be filed as an identity nothing can order.
pub fn extract_attempt_id(
    metadata: &MetadataMap,
) -> Result<Option<Uuid>, DomainOperationMetadataError> {
    let Some(text) = read_ascii(metadata, ATTEMPT_ID_KEY)? else {
        return Ok(None);
    };
    let attempt =
        Uuid::parse_str(text.trim()).map_err(|e| DomainOperationMetadataError::Malformed {
            header: ATTEMPT_ID_KEY,
            detail: e.to_string(),
        })?;
    if attempt.get_version_num() != 7 {
        return Err(DomainOperationMetadataError::Malformed {
            header: ATTEMPT_ID_KEY,
            detail: format!(
                "attempt id is UUID version {}, not the required 7",
                attempt.get_version_num()
            ),
        });
    }
    Ok(Some(attempt))
}

/// Check RFC 9562 version and variant bits. A 16-byte value that is not a
/// UUIDv7 is rejected rather than accepted as an opaque identifier, because the
/// receipt state machine classifies REPLAY versus fresh by `uuid_v7_timestamp`,
/// which is meaningless for any other version.
fn parse_uuid_v7(bytes: &[u8]) -> Result<Uuid, DomainOperationMetadataError> {
    let array: [u8; OPERATION_ID_LEN] =
        bytes
            .try_into()
            .map_err(|_| DomainOperationMetadataError::WrongLength {
                header: OPERATION_ID_KEY,
                expected: OPERATION_ID_LEN,
                actual: bytes.len(),
            })?;
    let uuid = Uuid::from_bytes(array);
    let version = uuid.get_version_num();
    if version != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
        return Err(DomainOperationMetadataError::NotUuidV7 { version });
    }
    Ok(uuid)
}

/// Split the fingerprint header into its version byte and payload, requiring
/// the exact payload length that version defines.
fn parse_fingerprint(bytes: &[u8]) -> Result<(i32, Vec<u8>), DomainOperationMetadataError> {
    let (version, payload) =
        bytes
            .split_first()
            .ok_or(DomainOperationMetadataError::WrongLength {
                header: FINGERPRINT_KEY,
                expected: 1 + FINGERPRINT_V1_LEN,
                actual: 0,
            })?;
    if *version != FINGERPRINT_VERSION_V1 {
        return Err(
            DomainOperationMetadataError::UnsupportedFingerprintVersion { version: *version },
        );
    }
    if payload.len() != FINGERPRINT_V1_LEN {
        return Err(DomainOperationMetadataError::WrongLength {
            header: FINGERPRINT_KEY,
            expected: 1 + FINGERPRINT_V1_LEN,
            actual: 1 + payload.len(),
        });
    }
    Ok((i32::from(*version), payload.to_vec()))
}

/// Read and validate the original three headers and optional mediated scope
/// when any carriage is present.
///
/// `Ok(None)` means **none** of the three was supplied: the legacy,
/// enforcement-off carve-out. Partial carriage is an error, never absence, so a
/// caller that supplies two of three cannot fall through the carve-out.
pub fn extract(
    metadata: &MetadataMap,
) -> Result<Option<DomainOperationMetadata>, DomainOperationMetadataError> {
    let id = read_bin(metadata, OPERATION_ID_KEY)?;
    let fingerprint = read_bin(metadata, FINGERPRINT_KEY)?;
    let token = read_bin(metadata, PREPARE_TOKEN_KEY)?;
    let mediated = read_bin(metadata, MEDIATED_SCOPE_KEY)?;
    let claim = read_bin(metadata, CLAIM_WITNESS_KEY)?;

    match (id.is_some(), fingerprint.is_some(), token.is_some()) {
        (false, false, false) if mediated.is_none() && claim.is_none() => return Ok(None),
        (false, false, false) => {
            return Err(DomainOperationMetadataError::PartialCarriage {
                present: if mediated.is_some() {
                    MEDIATED_SCOPE_KEY
                } else {
                    CLAIM_WITNESS_KEY
                },
                missing: OPERATION_ID_KEY,
            });
        }
        (true, false, _) => {
            return Err(DomainOperationMetadataError::PartialCarriage {
                present: OPERATION_ID_KEY,
                missing: FINGERPRINT_KEY,
            });
        }
        (true, true, false) => {
            return Err(DomainOperationMetadataError::PartialCarriage {
                present: OPERATION_ID_KEY,
                missing: PREPARE_TOKEN_KEY,
            });
        }
        (false, true, _) => {
            return Err(DomainOperationMetadataError::PartialCarriage {
                present: FINGERPRINT_KEY,
                missing: OPERATION_ID_KEY,
            });
        }
        (false, false, true) => {
            return Err(DomainOperationMetadataError::PartialCarriage {
                present: PREPARE_TOKEN_KEY,
                missing: OPERATION_ID_KEY,
            });
        }
        (true, true, true) => {}
    }

    Ok(Some(validated(metadata)?))
}

/// Read and validate the original three headers, requiring every one of them,
/// plus the optional mediated-scope extension.
///
/// This is the enforcement path: absence is a decisive pre-admission rejection,
/// not a carve-out.
pub fn require(
    metadata: &MetadataMap,
) -> Result<DomainOperationMetadata, DomainOperationMetadataError> {
    validated(metadata)
}

fn validated(
    metadata: &MetadataMap,
) -> Result<DomainOperationMetadata, DomainOperationMetadataError> {
    let id_bytes = read_exact_bin(metadata, OPERATION_ID_KEY, OPERATION_ID_LEN)?;
    let operation_id = parse_uuid_v7(&id_bytes)?;

    let fingerprint_bytes =
        read_bin(metadata, FINGERPRINT_KEY)?.ok_or(DomainOperationMetadataError::Absent {
            header: FINGERPRINT_KEY,
        })?;
    let (fingerprint_version, fingerprint) = parse_fingerprint(&fingerprint_bytes)?;

    let token_bytes = read_exact_bin(metadata, PREPARE_TOKEN_KEY, PREPARE_TOKEN_LEN)?;
    let mut prepare_token = [0u8; PREPARE_TOKEN_LEN];
    prepare_token.copy_from_slice(&token_bytes);

    let mediated_scope = read_bin(metadata, MEDIATED_SCOPE_KEY)?
        .map(|value| parse_mediated_scope(&value))
        .transpose()?;

    let claim_witness = read_bin(metadata, CLAIM_WITNESS_KEY)?
        .map(|value| parse_claim_witness(&value))
        .transpose()?;

    Ok(DomainOperationMetadata {
        operation_id,
        fingerprint_version,
        fingerprint,
        prepare_token,
        mediated_scope,
        claim_witness,
    })
}

/// Split the fixed-width claim-witness tuple. See [`CLAIM_WITNESS_KEY`]'s PIN
/// for the layout this reads.
fn parse_claim_witness(bytes: &[u8]) -> Result<ClaimWitness, DomainOperationMetadataError> {
    // Converted to a fixed-width array rather than length-checked and then
    // sliced, so the width is one fact the type system carries instead of a
    // precondition each read below has to restate. Every `chunk` call is then
    // total by construction.
    let value: &[u8; CLAIM_WITNESS_V1_LEN] =
        bytes
            .try_into()
            .map_err(|_| DomainOperationMetadataError::WrongLength {
                header: CLAIM_WITNESS_KEY,
                expected: CLAIM_WITNESS_V1_LEN,
                actual: bytes.len(),
            })?;
    if value[0] != CLAIM_WITNESS_VERSION_V1 {
        return Err(
            DomainOperationMetadataError::UnsupportedClaimWitnessVersion { version: value[0] },
        );
    }

    Ok(ClaimWitness {
        claim_id: chunk::<OPERATION_ID_LEN>(value, 1),
        claim_revision: read_revision(&chunk::<8>(value, 17), "claim_revision")?,
        claim_verification_witness: chunk::<DIGEST_LEN>(value, 25),
        authorization_revision: read_revision(&chunk::<8>(value, 57), "authorization_revision")?,
        verification_nonce: chunk::<DIGEST_LEN>(value, 65),
        bound_fields_digest: chunk::<DIGEST_LEN>(value, 97),
        consumed_ticket_sha256: chunk::<DIGEST_LEN>(value, 129),
    })
}

/// Copy `N` bytes out of the fixed-width claim-witness value at `OFFSET`.
///
/// Both the source width and the read width are compile-time constants, so an
/// offset past the end is a build failure rather than a runtime panic on
/// attacker-supplied bytes.
fn chunk<const N: usize>(value: &[u8; CLAIM_WITNESS_V1_LEN], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&value[offset..offset + N]);
    out
}

/// Read one big-endian `u64` revision, bounded to what the platform verifier
/// can compare. Zero is refused too: both revisions are monotonic counters that
/// start at one, and the verifier treats zero as out of bounds.
fn read_revision(
    bytes: &[u8; 8],
    field: &'static str,
) -> Result<u64, DomainOperationMetadataError> {
    let value = u64::from_be_bytes(*bytes);
    if value == 0 || value > MAX_WIRE_REVISION {
        return Err(
            DomainOperationMetadataError::ClaimWitnessRevisionOutOfRange {
                field,
                value,
                max: MAX_WIRE_REVISION,
            },
        );
    }
    Ok(value)
}

fn parse_mediated_scope(bytes: &[u8]) -> Result<MediatedScope, DomainOperationMetadataError> {
    if bytes.len() != MEDIATED_SCOPE_V1_LEN {
        return Err(DomainOperationMetadataError::WrongLength {
            header: MEDIATED_SCOPE_KEY,
            expected: MEDIATED_SCOPE_V1_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[0] != MEDIATED_SCOPE_VERSION_V1 {
        return Err(
            DomainOperationMetadataError::UnsupportedMediatedScopeVersion { version: bytes[0] },
        );
    }
    let mut org_uuid = [0u8; 16];
    org_uuid.copy_from_slice(&bytes[1..17]);
    let mut initiating_principal_namespace = [0u8; MEDIATED_PRINCIPAL_NAMESPACE_V1_LEN];
    initiating_principal_namespace.copy_from_slice(&bytes[17..]);
    scope_key_mediated_namespace(&org_uuid, &initiating_principal_namespace)
        .map_err(|_| DomainOperationMetadataError::InvalidMediatedPrincipalNamespace)?;
    Ok(MediatedScope {
        org_uuid,
        initiating_principal_namespace,
    })
}

// --- Tenant scope keys (R-BLOCK-5) -----------------------------------------

/// Why a scope key could not be built. Both variants are provenance errors: a
/// caller handed identity bytes that a scope key must not be derived from.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeKeyError {
    /// The target identity was not the exact raw byte length expected. Every
    /// `urc-` resource string fails here too: `urc-*` is 5 bytes and
    /// `urc-<32 hex>` is 36.
    #[error("scope key component {component} has {actual} bytes, expected {expected}")]
    WrongLength {
        /// Which component was wrong.
        component: &'static str,
        /// Length required.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },

    /// The bytes begin with an ASCII `urc-` resource prefix. A token resource
    /// string must never become a tenant scope, so this is refused even at the
    /// exact identity length.
    #[error(
        "scope key component {component} is a urc- resource string, which never appears in a scope key"
    )]
    UrcResource {
        /// Which component carried the prefix.
        component: &'static str,
    },

    /// A mediated principal namespace was not the frozen
    /// `principal-v1\0` plus lowercase canonical UUID representation.
    #[error("scope key principal namespace is not canonical principal-v1 UUID bytes")]
    InvalidPrincipalNamespace,
}

/// A raw 16-byte target identity, checked for length and `urc-` provenance.
///
/// The length arm already rejects every real resource string — `urc-*` is 5
/// bytes and `urc-<32 hex>` is 36 — so the prefix arm is defence in depth here
/// and only becomes load-bearing on [`scope_key_mediated`]'s unbounded
/// `principal_user_id`. It is kept on both so the rule reads the same wherever
/// a component enters.
fn checked_identity(component: &'static str, bytes: &[u8]) -> Result<(), ScopeKeyError> {
    if bytes.starts_with(URC_PREFIX) {
        return Err(ScopeKeyError::UrcResource { component });
    }
    if bytes.len() != OPERATION_ID_LEN {
        return Err(ScopeKeyError::WrongLength {
            component,
            expected: OPERATION_ID_LEN,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Scope key for a direct repository create.
///
/// The repository does not exist yet, so the scope is the fixed method constant
/// plus the caller-chosen repository UUID from `RepositoryCreateRequest.id`,
/// never the token's resource list, which under a wildcard `urc-*` would be
/// ambiguous and under authn-only registration carries no authorized scope at
/// all.
pub fn scope_key_repository_create(repository_id: &[u8]) -> Result<Vec<u8>, ScopeKeyError> {
    checked_identity("repository_id", repository_id)?;
    build_scope_key(SCOPE_METHOD_REPOSITORY_CREATE_V1, &[repository_id])
}

/// Scope key for every other direct governed operation: the target repository
/// identity under a fixed constant.
pub fn scope_key_target_repository(repository_id: &[u8]) -> Result<Vec<u8>, ScopeKeyError> {
    checked_identity("repository_id", repository_id)?;
    build_scope_key(SCOPE_METHOD_REPOSITORY_V1, &[repository_id])
}

/// Scope key for a mediated operation: the auth-grpc-verified canonical tuple
/// `(org UUID, principal-v1\0 || Principal.userId)` from the versioned preclaim-
/// authorization witness. The initiating human stays separate claim audit data.
pub fn scope_key_mediated(
    org_uuid: &[u8],
    principal_user_id: &[u8],
) -> Result<Vec<u8>, ScopeKeyError> {
    checked_identity("org_uuid", org_uuid)?;
    if principal_user_id.starts_with(URC_PREFIX) {
        return Err(ScopeKeyError::UrcResource {
            component: "principal_user_id",
        });
    }
    let mut principal =
        Vec::with_capacity(SCOPE_PRINCIPAL_NAMESPACE_V1.len() + principal_user_id.len());
    principal.extend_from_slice(SCOPE_PRINCIPAL_NAMESPACE_V1);
    principal.extend_from_slice(principal_user_id);
    build_scope_key(SCOPE_METHOD_MEDIATED_V1, &[org_uuid, &principal])
}

/// Scope key for a mediated operation when the caller already carries the
/// frozen canonical principal namespace. The namespace is validated and
/// encoded byte-for-byte; it is never tagged a second time.
pub fn scope_key_mediated_namespace(
    org_uuid: &[u8],
    principal_namespace: &[u8],
) -> Result<Vec<u8>, ScopeKeyError> {
    checked_identity("org_uuid", org_uuid)?;
    let principal_id = principal_namespace
        .strip_prefix(SCOPE_PRINCIPAL_NAMESPACE_V1)
        .ok_or(ScopeKeyError::InvalidPrincipalNamespace)?;
    let principal_id =
        std::str::from_utf8(principal_id).map_err(|_| ScopeKeyError::InvalidPrincipalNamespace)?;
    let parsed =
        Uuid::parse_str(principal_id).map_err(|_| ScopeKeyError::InvalidPrincipalNamespace)?;
    if parsed.to_string() != principal_id {
        return Err(ScopeKeyError::InvalidPrincipalNamespace);
    }
    build_scope_key(SCOPE_METHOD_MEDIATED_V1, &[org_uuid, principal_namespace])
}

/// Longest component this encoding admits.
///
/// Applied to the component as encoded, so for [`scope_key_mediated`] it bounds
/// the `principal-v1\\0` tag plus the principal id together: the caller-facing
/// limit on `principal_user_id` is `MAX_SCOPE_COMPONENT_LEN - 13`, not the
/// constant itself.
///
/// Every real component is an identity of at most a few dozen bytes. The bound
/// exists so the length prefix below can never be a truncated value: silently
/// clamping an oversized length would make two different tuples encode to the
/// same bytes, which is exactly what length-prefixing is here to prevent.
const MAX_SCOPE_COMPONENT_LEN: usize = 1024;

/// Length-prefix the method **and** every component so two different tuples
/// cannot canonicalise to the same bytes.
///
/// The method is prefixed too, rather than relying on the constants above being
/// NUL-terminated and prefix-free. That property is true today, but it is an
/// invariant nothing checks and that a future constant could quietly break —
/// and the failure mode would be two different operations sharing one tenant
/// scope, which is the worst outcome this function has.
fn build_scope_key(method: &[u8], components: &[&[u8]]) -> Result<Vec<u8>, ScopeKeyError> {
    let payload: usize = components.iter().map(|c| c.len() + 4).sum();
    let mut out = Vec::with_capacity(1 + 4 + method.len() + payload);
    out.push(SCOPE_KEY_VERSION_V1);
    push_component("method", method, &mut out)?;
    for component in components {
        push_component("identity", component, &mut out)?;
    }
    Ok(out)
}

/// Append one length-prefixed component, refusing a length the prefix cannot
/// represent exactly.
fn push_component(
    component: &'static str,
    bytes: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), ScopeKeyError> {
    if bytes.len() > MAX_SCOPE_COMPONENT_LEN {
        return Err(ScopeKeyError::WrongLength {
            component,
            expected: MAX_SCOPE_COMPONENT_LEN,
            actual: bytes.len(),
        });
    }
    // Infallible given the bound above, but written as a conversion rather than
    // a cast so a change to the bound cannot silently truncate.
    let len = u32::try_from(bytes.len()).map_err(|_| ScopeKeyError::WrongLength {
        component,
        expected: MAX_SCOPE_COMPONENT_LEN,
        actual: bytes.len(),
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use tonic::Code;
    use tonic::metadata::BinaryMetadataValue;
    use uuid::Uuid;

    use super::*;

    // --- construction helpers -----------------------------------------

    fn valid_operation_id() -> Uuid {
        Uuid::now_v7()
    }

    fn valid_operation_id_bytes() -> Vec<u8> {
        valid_operation_id().as_bytes().to_vec()
    }

    fn valid_fingerprint_header() -> Vec<u8> {
        let mut bytes = vec![FINGERPRINT_VERSION_V1];
        bytes.extend(std::iter::repeat_n(0xAB, FINGERPRINT_V1_LEN));
        bytes
    }

    fn valid_prepare_token_bytes() -> Vec<u8> {
        vec![0xCD; PREPARE_TOKEN_LEN]
    }

    fn insert(metadata: &mut MetadataMap, key: &'static str, bytes: &[u8]) {
        metadata.insert_bin(key, BinaryMetadataValue::from_bytes(bytes));
    }

    fn metadata_with(pairs: &[(&'static str, Vec<u8>)]) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        for (key, bytes) in pairs {
            insert(&mut metadata, key, bytes);
        }
        metadata
    }

    /// One well-formed set of the three headers, plus the values used to build
    /// it so a test can assert on the parsed result.
    fn valid_metadata() -> (MetadataMap, Uuid, [u8; PREPARE_TOKEN_LEN]) {
        let operation_id = valid_operation_id();
        let token_vec = valid_prepare_token_bytes();
        let token: [u8; PREPARE_TOKEN_LEN] = token_vec
            .clone()
            .try_into()
            .expect("valid_prepare_token_bytes returns PREPARE_TOKEN_LEN bytes");
        let metadata = metadata_with(&[
            (OPERATION_ID_KEY, operation_id.as_bytes().to_vec()),
            (FINGERPRINT_KEY, valid_fingerprint_header()),
            (PREPARE_TOKEN_KEY, token_vec),
        ]);
        (metadata, operation_id, token)
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    // --- 1. happy path ---------------------------------------------------

    #[test]
    fn require_parses_all_three_headers_on_the_happy_path() {
        let (metadata, operation_id, token) = valid_metadata();

        let parsed = require(&metadata).expect("well-formed metadata must parse");

        assert_eq!(parsed.operation_id, operation_id);
        assert_eq!(
            parsed.fingerprint_version,
            i32::from(FINGERPRINT_VERSION_V1)
        );
        assert_eq!(parsed.fingerprint, vec![0xAB; FINGERPRINT_V1_LEN]);
        assert_eq!(parsed.prepare_token, token);
    }

    #[test]
    fn extract_agrees_with_require_when_all_headers_are_present() {
        let (metadata, ..) = valid_metadata();

        let extracted = extract(&metadata)
            .expect("well-formed metadata must parse")
            .expect("all three headers present must not fall through the absence carve-out");
        let required = require(&metadata).expect("well-formed metadata must parse");

        assert_eq!(extracted, required);
    }

    // --- 2. absent ---------------------------------------------------------

    #[test]
    fn absent_extract_is_none_but_require_is_absent() {
        let metadata = MetadataMap::new();

        assert_eq!(extract(&metadata), Ok(None));
        assert_eq!(
            require(&metadata),
            Err(DomainOperationMetadataError::Absent {
                header: OPERATION_ID_KEY
            })
        );
    }

    // --- 3. partial carriage -----------------------------------------------

    /// One partial-carriage case: the header/bytes pairs present on the
    /// request, and the `PartialCarriage` error `extract` must report for
    /// them.
    type PartialCarriageCase = (Vec<(&'static str, Vec<u8>)>, DomainOperationMetadataError);

    #[test]
    fn partial_carriage_never_falls_through_the_absence_carve_out() {
        let id = valid_operation_id_bytes();
        let fingerprint = valid_fingerprint_header();
        let token = valid_prepare_token_bytes();

        let cases: Vec<PartialCarriageCase> = vec![
            (
                vec![(OPERATION_ID_KEY, id.clone())],
                DomainOperationMetadataError::PartialCarriage {
                    present: OPERATION_ID_KEY,
                    missing: FINGERPRINT_KEY,
                },
            ),
            (
                vec![
                    (OPERATION_ID_KEY, id.clone()),
                    (PREPARE_TOKEN_KEY, token.clone()),
                ],
                DomainOperationMetadataError::PartialCarriage {
                    present: OPERATION_ID_KEY,
                    missing: FINGERPRINT_KEY,
                },
            ),
            (
                vec![
                    (OPERATION_ID_KEY, id.clone()),
                    (FINGERPRINT_KEY, fingerprint.clone()),
                ],
                DomainOperationMetadataError::PartialCarriage {
                    present: OPERATION_ID_KEY,
                    missing: PREPARE_TOKEN_KEY,
                },
            ),
            (
                vec![(FINGERPRINT_KEY, fingerprint.clone())],
                DomainOperationMetadataError::PartialCarriage {
                    present: FINGERPRINT_KEY,
                    missing: OPERATION_ID_KEY,
                },
            ),
            (
                vec![
                    (FINGERPRINT_KEY, fingerprint.clone()),
                    (PREPARE_TOKEN_KEY, token.clone()),
                ],
                DomainOperationMetadataError::PartialCarriage {
                    present: FINGERPRINT_KEY,
                    missing: OPERATION_ID_KEY,
                },
            ),
            (
                vec![(PREPARE_TOKEN_KEY, token.clone())],
                DomainOperationMetadataError::PartialCarriage {
                    present: PREPARE_TOKEN_KEY,
                    missing: OPERATION_ID_KEY,
                },
            ),
        ];

        for (pairs, expected) in cases {
            let metadata = metadata_with(&pairs);
            assert_eq!(
                extract(&metadata),
                Err(expected),
                "partial carriage of {pairs:?} must never fall through to Ok(None)"
            );
        }
    }

    // --- 4. wrong length -----------------------------------------------------

    #[test]
    fn operation_id_wrong_length_is_rejected_without_truncation_or_padding() {
        for len in [OPERATION_ID_LEN - 1, OPERATION_ID_LEN + 1] {
            let (mut metadata, ..) = valid_metadata();
            insert(&mut metadata, OPERATION_ID_KEY, &vec![0xEE; len]);

            let err = require(&metadata).expect_err("wrong length operation id must be rejected");

            assert_eq!(
                err,
                DomainOperationMetadataError::WrongLength {
                    header: OPERATION_ID_KEY,
                    expected: OPERATION_ID_LEN,
                    actual: len,
                }
            );
        }
    }

    #[test]
    fn prepare_token_wrong_length_is_rejected_without_truncation_or_padding() {
        for len in [PREPARE_TOKEN_LEN - 1, PREPARE_TOKEN_LEN + 1] {
            let (mut metadata, ..) = valid_metadata();
            insert(&mut metadata, PREPARE_TOKEN_KEY, &vec![0xEE; len]);

            let err = require(&metadata).expect_err("wrong length prepare token must be rejected");

            assert_eq!(
                err,
                DomainOperationMetadataError::WrongLength {
                    header: PREPARE_TOKEN_KEY,
                    expected: PREPARE_TOKEN_LEN,
                    actual: len,
                }
            );
        }
    }

    #[test]
    fn fingerprint_payload_wrong_length_is_rejected_without_truncation_or_padding() {
        for payload_len in [FINGERPRINT_V1_LEN - 1, FINGERPRINT_V1_LEN + 1] {
            let (mut metadata, ..) = valid_metadata();
            let mut bytes = vec![FINGERPRINT_VERSION_V1];
            bytes.extend(std::iter::repeat_n(0xAB, payload_len));
            insert(&mut metadata, FINGERPRINT_KEY, &bytes);

            let err =
                require(&metadata).expect_err("wrong length fingerprint payload must be rejected");

            assert_eq!(
                err,
                DomainOperationMetadataError::WrongLength {
                    header: FINGERPRINT_KEY,
                    expected: 1 + FINGERPRINT_V1_LEN,
                    actual: 1 + payload_len,
                }
            );
        }
    }

    // --- 5. wrong version ----------------------------------------------------

    #[test]
    fn fingerprint_unsupported_version_is_never_coerced_to_v1() {
        for version in [0u8, 2u8, 255u8] {
            let (mut metadata, ..) = valid_metadata();
            let mut bytes = vec![version];
            bytes.extend(std::iter::repeat_n(0xAB, FINGERPRINT_V1_LEN));
            insert(&mut metadata, FINGERPRINT_KEY, &bytes);

            let err =
                require(&metadata).expect_err("unsupported fingerprint version must be rejected");

            assert_eq!(
                err,
                DomainOperationMetadataError::UnsupportedFingerprintVersion { version }
            );
        }
    }

    // --- 6. non-UUIDv7 -------------------------------------------------------

    #[test]
    fn operation_id_that_is_a_uuid_v4_is_rejected() {
        let (mut metadata, ..) = valid_metadata();
        let v4 = Uuid::new_v4();
        insert(&mut metadata, OPERATION_ID_KEY, v4.as_bytes());

        let err = require(&metadata).expect_err("a UUIDv4 operation id must be rejected");

        assert_eq!(err, DomainOperationMetadataError::NotUuidV7 { version: 4 });
    }

    #[test]
    fn operation_id_with_non_rfc4122_variant_bits_is_rejected() {
        let (mut metadata, ..) = valid_metadata();
        let mut bytes = *Uuid::now_v7().as_bytes();
        // Force the NCS variant (top bit of byte 8 clear) while keeping the
        // version-7 nibble in byte 6, so only the variant check is at fault.
        bytes[8] &= 0x3F;
        insert(&mut metadata, OPERATION_ID_KEY, &bytes);

        let err =
            require(&metadata).expect_err("a non-RFC4122 variant operation id must be rejected");

        assert_eq!(err, DomainOperationMetadataError::NotUuidV7 { version: 7 });
    }

    #[test]
    fn operation_id_that_is_a_genuine_uuid_v7_is_accepted() {
        let (metadata, operation_id, _) = valid_metadata();

        let parsed = require(&metadata).expect("a genuine UUIDv7 must be accepted");

        assert_eq!(parsed.operation_id, operation_id);
    }

    // --- 7. divergent duplicate header --------------------------------------

    #[test]
    fn divergent_duplicate_operation_id_is_rejected() {
        let (mut metadata, operation_id, _) = valid_metadata();
        let mut divergent = *operation_id.as_bytes();
        divergent[0] ^= 0xFF;
        metadata.append_bin(
            OPERATION_ID_KEY,
            BinaryMetadataValue::from_bytes(&divergent),
        );

        let err =
            require(&metadata).expect_err("a divergent duplicate operation id must be rejected");

        assert_eq!(
            err,
            DomainOperationMetadataError::DivergentDuplicate {
                header: OPERATION_ID_KEY
            }
        );
    }

    #[test]
    fn divergent_duplicate_fingerprint_is_rejected() {
        let (mut metadata, ..) = valid_metadata();
        let mut divergent = valid_fingerprint_header();
        *divergent
            .last_mut()
            .expect("fingerprint header is non-empty") ^= 0xFF;
        metadata.append_bin(FINGERPRINT_KEY, BinaryMetadataValue::from_bytes(&divergent));

        let err =
            require(&metadata).expect_err("a divergent duplicate fingerprint must be rejected");

        assert_eq!(
            err,
            DomainOperationMetadataError::DivergentDuplicate {
                header: FINGERPRINT_KEY
            }
        );
    }

    #[test]
    fn divergent_duplicate_prepare_token_is_rejected() {
        let (mut metadata, _, token) = valid_metadata();
        let mut divergent = token;
        divergent[0] ^= 0xFF;
        metadata.append_bin(
            PREPARE_TOKEN_KEY,
            BinaryMetadataValue::from_bytes(&divergent),
        );

        let err =
            require(&metadata).expect_err("a divergent duplicate prepare token must be rejected");

        assert_eq!(
            err,
            DomainOperationMetadataError::DivergentDuplicate {
                header: PREPARE_TOKEN_KEY
            }
        );
    }

    #[test]
    fn byte_identical_duplicate_header_is_accepted() {
        let (mut metadata, operation_id, token) = valid_metadata();
        // Repeat every header with byte-identical values: no ambiguity, so this
        // must not be treated as divergent.
        metadata.append_bin(
            OPERATION_ID_KEY,
            BinaryMetadataValue::from_bytes(operation_id.as_bytes()),
        );
        metadata.append_bin(
            FINGERPRINT_KEY,
            BinaryMetadataValue::from_bytes(&valid_fingerprint_header()),
        );
        metadata.append_bin(PREPARE_TOKEN_KEY, BinaryMetadataValue::from_bytes(&token));

        let parsed = require(&metadata).expect("byte-identical duplicates carry no ambiguity");

        assert_eq!(parsed.operation_id, operation_id);
        assert_eq!(parsed.prepare_token, token);
    }

    // --- 8. status mapping -----------------------------------------------

    #[test]
    fn every_variant_maps_to_invalid_argument() {
        let variants = vec![
            DomainOperationMetadataError::Absent {
                header: OPERATION_ID_KEY,
            },
            DomainOperationMetadataError::DivergentDuplicate {
                header: FINGERPRINT_KEY,
            },
            DomainOperationMetadataError::Malformed {
                header: PREPARE_TOKEN_KEY,
                detail: "bad binary metadata".to_string(),
            },
            DomainOperationMetadataError::WrongLength {
                header: OPERATION_ID_KEY,
                expected: OPERATION_ID_LEN,
                actual: 15,
            },
            DomainOperationMetadataError::UnsupportedFingerprintVersion { version: 9 },
            DomainOperationMetadataError::NotUuidV7 { version: 4 },
            DomainOperationMetadataError::PartialCarriage {
                present: OPERATION_ID_KEY,
                missing: FINGERPRINT_KEY,
            },
        ];

        for variant in variants {
            assert_eq!(Status::from(variant).code(), Code::InvalidArgument);
        }
    }

    // The R-BLOCK-1 guard: `INVALID_ARGUMENT` must never collapse into the
    // transport's replay-triggering `Disconnected` arm the way `Unknown`
    // (CR-029's originally proposed code) would.
    #[test]
    fn invalid_argument_status_never_collapses_into_the_transport_replay_arm() {
        let status = Status::from(DomainOperationMetadataError::Absent {
            header: OPERATION_ID_KEY,
        });
        assert_eq!(status.code(), Code::InvalidArgument);

        let protocol_error = lore_transport::error::ProtocolError::from(status);

        assert!(!matches!(
            protocol_error,
            lore_transport::error::ProtocolError::Disconnected(_)
        ));
    }

    // --- 9. tenant scope keys (R-BLOCK-5) -----------------------------------

    #[test]
    fn repository_create_and_target_repository_scope_keys_differ_but_share_shape() {
        let repository_id = *Uuid::new_v4().as_bytes();

        let create_key = scope_key_repository_create(&repository_id).expect("valid repository id");
        let target_key = scope_key_target_repository(&repository_id).expect("valid repository id");

        assert_ne!(create_key, target_key);
        assert_eq!(create_key[0], SCOPE_KEY_VERSION_V1);
        assert_eq!(target_key[0], SCOPE_KEY_VERSION_V1);
        assert!(contains_subslice(&create_key, &repository_id));
        assert!(contains_subslice(&target_key, &repository_id));
    }

    // Injectivity of the encoding: no two distinct (method, components) pairs
    // built from this module's own constants may canonicalise to the same
    // bytes. A pairwise check over a small grid, not just "these two specific
    // outputs differ" (which the constants' happening to differ in length
    // already gave for free, independent of whether the encoding is sound).
    #[test]
    fn build_scope_key_is_injective_across_the_module_s_method_constants() {
        let methods: [&[u8]; 3] = [
            SCOPE_METHOD_REPOSITORY_CREATE_V1,
            SCOPE_METHOD_REPOSITORY_V1,
            SCOPE_METHOD_MEDIATED_V1,
        ];
        let component_sets: [&[&[u8]]; 3] = [
            &[b"AAAAAAAAAAAAAAAA"],
            &[b"AAAAAAAAAAAAAAA"],
            &[b"AAAAAAAAAAAAAAAA", b"BBBB"],
        ];

        let mut keys = Vec::new();
        for method in methods {
            for components in component_sets {
                let key =
                    build_scope_key(method, components).expect("bounded components must encode");
                keys.push(key);
            }
        }

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "pair ({i}, {j}) of the grid collided");
            }
        }
    }

    // The pre-fix encoding omitted a method length prefix, so a method whose
    // bytes happened to equal another pair's declared component length could
    // canonicalise identically to that pair's own concatenation. This is a
    // constructed instance of exactly that collision class (worked out by
    // hand against the old `method || len(component) || component` layout),
    // pinned to prove it no longer collides now that the method is
    // length-prefixed too.
    #[test]
    fn build_scope_key_no_longer_collides_across_a_method_length_prefix_boundary() {
        let method_a: &[u8] = &[0x00, 0x00, 0x00, 0x0E];
        let component_a: &[u8] = b"HELLOWORLD";

        let method_b: &[u8] = b"";
        let component_b: &[u8] = &[
            0x00, 0x00, 0x00, 0x0A, b'H', b'E', b'L', b'L', b'O', b'W', b'O', b'R', b'L', b'D',
        ];

        let key_a =
            build_scope_key(method_a, &[component_a]).expect("bounded components must encode");
        let key_b =
            build_scope_key(method_b, &[component_b]).expect("bounded components must encode");

        assert_ne!(
            key_a, key_b,
            "distinct (method, component) pairs must never canonicalise to the same key"
        );
    }

    #[test]
    fn principal_component_at_the_exact_bound_is_accepted() {
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal_user_id =
            vec![b'x'; MAX_SCOPE_COMPONENT_LEN - SCOPE_PRINCIPAL_NAMESPACE_V1.len()];

        scope_key_mediated(&org_uuid, &principal_user_id)
            .expect("a component at the exact bound must be accepted");
    }

    // The old `u32::try_from(...).unwrap_or(u32::MAX)` would have silently
    // clamped an oversized length rather than reporting it, breaking
    // injectivity. Pin that an over-bound component is refused, not
    // truncated.
    #[test]
    fn principal_component_one_byte_over_the_bound_is_rejected() {
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal_user_id =
            vec![b'x'; MAX_SCOPE_COMPONENT_LEN - SCOPE_PRINCIPAL_NAMESPACE_V1.len() + 1];

        let err = scope_key_mediated(&org_uuid, &principal_user_id)
            .expect_err("one byte over the bound must be rejected, not silently truncated");

        assert_eq!(
            err,
            ScopeKeyError::WrongLength {
                component: "identity",
                expected: MAX_SCOPE_COMPONENT_LEN,
                actual: MAX_SCOPE_COMPONENT_LEN + 1,
            }
        );
    }

    #[test]
    fn urc_resource_strings_are_rejected_by_every_builder() {
        let wildcard: &[u8] = b"urc-*";
        let full_resource = format!("urc-{}", "a".repeat(32));

        for input in [wildcard, full_resource.as_bytes()] {
            assert_eq!(
                scope_key_repository_create(input),
                Err(ScopeKeyError::UrcResource {
                    component: "repository_id"
                })
            );
            assert_eq!(
                scope_key_target_repository(input),
                Err(ScopeKeyError::UrcResource {
                    component: "repository_id"
                })
            );
        }
    }

    #[test]
    fn a_crafted_16_byte_urc_prefixed_value_is_rejected_as_urc_resource_not_wrong_length() {
        let mut crafted = [0u8; OPERATION_ID_LEN];
        crafted[..4].copy_from_slice(b"urc-");
        for (i, byte) in crafted[4..].iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(crafted.len(), OPERATION_ID_LEN);

        let err = scope_key_target_repository(&crafted)
            .expect_err("a urc- prefixed value must be rejected even at the exact length");

        assert_eq!(
            err,
            ScopeKeyError::UrcResource {
                component: "repository_id"
            }
        );
    }

    #[test]
    fn mediated_scope_key_rejects_urc_principal_and_tags_the_principal_namespace() {
        let org_uuid = *Uuid::new_v4().as_bytes();

        let err = scope_key_mediated(&org_uuid, b"urc-something")
            .expect_err("a urc- principal id must be rejected");
        assert_eq!(
            err,
            ScopeKeyError::UrcResource {
                component: "principal_user_id"
            }
        );

        let key = scope_key_mediated(&org_uuid, b"user-1234").expect("a valid principal id");
        assert!(contains_subslice(&key, SCOPE_PRINCIPAL_NAMESPACE_V1));
    }

    #[test]
    fn canonical_mediated_namespace_is_encoded_once_and_noncanonical_forms_fail() {
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal_id = "11111111-1111-4111-8111-111111111111";
        let canonical = format!("principal-v1\0{principal_id}");

        let from_id = scope_key_mediated(&org_uuid, principal_id.as_bytes())
            .expect("raw principal id encodes");
        let from_namespace = scope_key_mediated_namespace(&org_uuid, canonical.as_bytes())
            .expect("canonical namespace encodes");
        assert_eq!(from_namespace, from_id);

        for invalid in [
            principal_id.as_bytes(),
            b"principal-v1\0not-a-uuid".as_slice(),
            b"principal-v1\x0011111111-1111-4111-8111-11111111111A".as_slice(),
        ] {
            assert_eq!(
                scope_key_mediated_namespace(&org_uuid, invalid),
                Err(ScopeKeyError::InvalidPrincipalNamespace)
            );
        }
    }

    // Realistic identity shapes only: 16-byte binary UUIDs for repository/org
    // identity, and principal ids that don't happen to embed the ASCII
    // sequence `urc-` outside the leading position. `checked_identity` and the
    // mediated principal check are prefix guards (`starts_with(URC_PREFIX)`),
    // not a substring-freedom guarantee over the whole encoded output — see
    // `mid_string_urc_occurrence_in_a_principal_id_is_not_rejected` below for
    // the documented boundary of that guard.
    #[test]
    fn no_produced_scope_key_ever_contains_a_urc_resource_prefix() {
        let repository_ids: Vec<[u8; OPERATION_ID_LEN]> =
            (0..8).map(|_| *Uuid::new_v4().as_bytes()).collect();
        let principals: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"user-1".to_vec(),
            vec![0u8; 40],
            vec![0xFFu8; 40],
            (0u8..=63).collect(),
            b"0194b726b34e72b0b45550b88a967076".to_vec(),
        ];

        for repository_id in &repository_ids {
            let create_key =
                scope_key_repository_create(repository_id).expect("valid repository id");
            let target_key =
                scope_key_target_repository(repository_id).expect("valid repository id");
            assert!(!contains_subslice(&create_key, URC_PREFIX));
            assert!(!contains_subslice(&target_key, URC_PREFIX));

            for principal in &principals {
                let mediated_key = scope_key_mediated(repository_id, principal)
                    .expect("valid mediated components");
                assert!(
                    !contains_subslice(&mediated_key, URC_PREFIX),
                    "mediated scope key must never contain urc-: repo={repository_id:?} principal={principal:?}"
                );
            }
        }
    }

    // Documents the actual boundary of the `urc-` guard: it is a *prefix*
    // check on each raw identity component (`starts_with(URC_PREFIX)`), not a
    // substring-freedom guarantee over the encoded key. A `principal_user_id`
    // that merely embeds `urc-` past its first four bytes is not "shaped like
    // a urc- resource string" (which by definition starts with it), so it is
    // accepted, and those bytes are carried verbatim into the key. Real
    // `Principal.userId` values are opaque hex/token ids that cannot contain
    // this ASCII sequence in practice; this test pins current behavior for a
    // synthetic id that does, rather than leaving the boundary unrecorded.
    #[test]
    fn mid_string_urc_occurrence_in_a_principal_id_is_not_rejected() {
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal: &[u8] = b"principal-with-a-urc-like-suffix-but-not-a-prefix";

        let key = scope_key_mediated(&org_uuid, principal)
            .expect("a urc- occurrence past the first four bytes is not the prefix guard");

        assert!(contains_subslice(&key, URC_PREFIX));
    }

    // --- 10. WP-116 guarded-stop contract gap (CR-029 rail unwireability) --
    //
    // CORRECTED STORY (2026-08-30, after a reviewer round): an earlier version
    // of this section framed the inequality test below as itself pinning the
    // WP-116 gap, and its comment said the gap would be "closed" if that test
    // ever started failing. That was imprecise and is now fixed. What's true:
    //
    // - `scope_key_mediated(org, user_id)` and
    //   `scope_key_mediated_namespace(org, "principal-v1\0" + user_id)` are
    //   BYTE-IDENTICAL, and `GovernedScope::Mediated` (`lore-server/src/domain.rs`)
    //   already exists and calls the former. An agreeing derivation already
    //   exists on the handler side -- derivation disagreement is NOT the
    //   blocker. See `mediated_scope_key_derivation_already_agrees_with_the_prepare_side`
    //   below (general encoding-boundary coverage for the same equality lives
    //   in `canonical_mediated_namespace_is_encoded_once_and_noncanonical_forms_fail`
    //   above; this copy exists to carry the WP-116 narrative explicitly).
    // - The real blocker is CARRIAGE, and it has TWO sites, only one of which
    //   this file pins. The three request-metadata headers this module reads
    //   carry neither `org_uuid` nor the initiating principal namespace --
    //   `domain_operation_metadata_carries_no_org_or_principal_identity`
    //   below is a compile-time pin over exactly that site, breaking the
    //   build the day this module's carriage struct grows an org/principal
    //   field. The SECOND carriage site, `AuthorizationToken`
    //   (`lore-server/src/auth/jwt.rs:60`), is NOT pinned here on purpose: it
    //   mirrors an upstream JWT contract and an exhaustive destructure over
    //   it would churn on every upstream refresh. Closing MISSING-1 (or any
    //   change that adds an org claim to `AuthorizationToken`) must be
    //   checked against that struct by hand -- this file's pin alone does not
    //   prove full carriage coverage.
    //
    // The inequality test immediately below is real and stays, but it is a
    // PERMANENT invariant, not a gap indicator: two different scope-key
    // families (`repository-create-v1\0` / `repository-v1\0` vs
    // `mediated-v1\0`) must never collide, forever, independent of whether the
    // carriage gap is ever closed -- that is ordinary tenant-isolation hygiene
    // across scope kinds, and it stays green even after the gap closes.
    #[test]
    fn direct_and_mediated_scope_key_families_never_collide() {
        // The identical 16 bytes stand in for "the same logical operation's
        // target identity" on both sides: a mediated key uses them as the org
        // UUID, and a direct handler key uses them as the repository UUID.
        // Reusing the exact same bytes gives the inequality assertion its
        // strongest form -- any difference in the encoded keys comes only
        // from the method tag and framing, not from different input identity
        // bytes happening to differ.
        let shared_identity = *Uuid::new_v4().as_bytes();
        let principal_namespace = format!("principal-v1\0{}", Uuid::new_v4());

        let mediated_key =
            scope_key_mediated_namespace(&shared_identity, principal_namespace.as_bytes())
                .expect("valid mediated namespace components");
        let handler_target_key =
            scope_key_target_repository(&shared_identity).expect("valid repository id");
        let handler_create_key =
            scope_key_repository_create(&shared_identity).expect("valid repository id");

        assert_ne!(
            mediated_key, handler_target_key,
            "a mediated scope key must never collide with a GovernedScope::TargetRepository \
             key for the same logical operation -- this is a permanent cross-family \
             tenant-isolation invariant, not evidence of the WP-116 carriage gap"
        );
        assert_ne!(
            mediated_key, handler_create_key,
            "a mediated scope key must never collide with a GovernedScope::RepositoryCreate \
             key for the same logical operation"
        );
    }

    // WP-116 pin 2a: an agreeing derivation already exists on the handler
    // side. `GovernedScope::Mediated` (`domain.rs`) calls `scope_key_mediated`
    // directly; `DomainOperationPrepare`'s `receipt_key`
    // (`grpc/domain/v1/service.rs`) calls `scope_key_mediated_namespace`. This
    // proves the two produce byte-identical output for the same
    // (org, principal) pair, so unifying derivation is not what closing the
    // WP-116 gap requires.
    #[test]
    fn mediated_scope_key_derivation_already_agrees_with_the_prepare_side() {
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal_id = Uuid::new_v4().to_string();
        let canonical_namespace = format!("principal-v1\0{principal_id}");

        let via_handler_builder = scope_key_mediated(&org_uuid, principal_id.as_bytes())
            .expect("GovernedScope::Mediated's own builder");
        let via_prepare_builder =
            scope_key_mediated_namespace(&org_uuid, canonical_namespace.as_bytes())
                .expect("DomainOperationPrepare's own builder");

        assert_eq!(
            via_handler_builder, via_prepare_builder,
            "scope_key_mediated and scope_key_mediated_namespace must keep agreeing for the \
             same (org, principal) pair -- if this ever fails, a real derivation gap has \
             appeared and the WP-116 story above needs to be revisited"
        );
    }

    // WP-116 pin 2b: a COMPILE-TIME pin on ONE of the two carriage sites, not
    // a runtime assertion and not full carriage coverage. `DomainOperationMetadata`
    // is exhaustively destructured with no `..` rest pattern, so the day this
    // struct gains an `org_uuid`/principal field, this destructure fails to
    // compile with "pattern does not mention field ..." -- forcing whoever
    // lands that change to revisit this test and the WP-116 guarded-stop
    // story it documents, rather than the gap silently closing unnoticed.
    // This does NOT cover the second carriage site, `AuthorizationToken`
    // (`lore-server/src/auth/jwt.rs:60`) -- deliberately not pinned by an
    // exhaustive destructure here, since it mirrors an upstream JWT contract
    // and would churn on every upstream refresh; check it by hand.
    #[test]
    fn domain_operation_metadata_has_only_the_frozen_carriage_fields() {
        let (metadata, ..) = valid_metadata();
        let parsed = require(&metadata).expect("well-formed metadata must parse");

        let DomainOperationMetadata {
            operation_id: _,
            fingerprint_version: _,
            fingerprint: _,
            prepare_token: _,
            mediated_scope: _,
            claim_witness: _,
        } = parsed;
    }

    // --- claim-witness carriage rejections --------------------------------
    //
    // The `admit`-level and callback-level cases live in `domain/p12_tests.rs`
    // and every one of them feeds a well-formed value. These are the other half:
    // the parser's fail-closed contract, which nothing else exercises. Each
    // asserts the error VARIANT rather than merely that an error occurred,
    // because a length rejection and a version rejection have different fixes
    // and a test that cannot tell them apart cannot catch the two being
    // confused.

    /// A well-formed 161-byte claim witness with distinct, non-default values
    /// in every slot, so a test that perturbs one field cannot pass by
    /// accidentally matching another.
    fn valid_claim_witness_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CLAIM_WITNESS_V1_LEN);
        bytes.push(CLAIM_WITNESS_VERSION_V1);
        bytes.extend_from_slice(&[0xA1; 16]); // claim_id
        bytes.extend_from_slice(&7u64.to_be_bytes()); // claim_revision
        bytes.extend_from_slice(&[0xA2; 32]); // claim_verification_witness
        bytes.extend_from_slice(&11u64.to_be_bytes()); // authorization_revision
        bytes.extend_from_slice(&[0xA3; 32]); // verification_nonce
        bytes.extend_from_slice(&[0xA4; 32]); // bound_fields_digest
        bytes.extend_from_slice(&[0xA5; 32]); // consumed_ticket_sha256
        assert_eq!(
            bytes.len(),
            CLAIM_WITNESS_V1_LEN,
            "fixture layout drifted from CLAIM_WITNESS_V1_LEN"
        );
        bytes
    }

    /// The three core headers plus a claim witness built from `mutate`.
    fn metadata_with_claim_witness(mutate: impl FnOnce(&mut Vec<u8>)) -> MetadataMap {
        let (mut metadata, ..) = valid_metadata();
        let mut witness = valid_claim_witness_bytes();
        mutate(&mut witness);
        insert(&mut metadata, CLAIM_WITNESS_KEY, &witness);
        metadata
    }

    #[test]
    fn a_well_formed_claim_witness_parses_into_every_field() {
        let metadata = metadata_with_claim_witness(|_| {});
        let parsed = require(&metadata).expect("a well-formed claim witness must parse");
        let claim = parsed
            .claim_witness
            .expect("the claim witness must be present");
        assert_eq!(claim.claim_id, [0xA1; 16]);
        assert_eq!(claim.claim_revision, 7);
        assert_eq!(claim.claim_verification_witness, [0xA2; 32]);
        assert_eq!(claim.authorization_revision, 11);
        assert_eq!(claim.verification_nonce, [0xA3; 32]);
        assert_eq!(claim.bound_fields_digest, [0xA4; 32]);
        assert_eq!(claim.consumed_ticket_sha256, [0xA5; 32]);
    }

    #[test]
    fn a_claim_witness_of_the_wrong_length_is_refused_never_padded_or_truncated() {
        for actual in [0usize, CLAIM_WITNESS_V1_LEN - 1, CLAIM_WITNESS_V1_LEN + 1] {
            let metadata = metadata_with_claim_witness(|witness| witness.resize(actual, 0));
            let error = require(&metadata).expect_err("a wrong-length claim witness must refuse");
            assert_eq!(
                error,
                DomainOperationMetadataError::WrongLength {
                    header: CLAIM_WITNESS_KEY,
                    expected: CLAIM_WITNESS_V1_LEN,
                    actual,
                },
                "{actual} bytes must be refused as a length error"
            );
            assert_eq!(Status::from(error).code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn an_unknown_claim_witness_version_is_refused_not_coerced_to_version_one() {
        for version in [0u8, 2, 255] {
            let metadata = metadata_with_claim_witness(|witness| witness[0] = version);
            let error = require(&metadata).expect_err("an unknown version must refuse");
            assert_eq!(
                error,
                DomainOperationMetadataError::UnsupportedClaimWitnessVersion { version },
                "version {version} must be refused rather than read as version 1"
            );
            assert_eq!(Status::from(error).code(), Code::InvalidArgument);
        }
    }

    /// Both revisions, at both ends of the accepted range.
    ///
    /// The upper bound is the whole reason `MAX_WIRE_REVISION` exists: the
    /// platform verifier compares both through `Number.isSafeInteger`, so a
    /// value above 2^53-1 cannot survive the crossing. Pinning only the
    /// rejection would leave the bound free to drift inward and silently refuse
    /// legitimate revisions, so the largest ACCEPTED value is pinned too.
    #[test]
    fn a_claim_witness_revision_outside_one_to_max_wire_revision_is_refused() {
        // offset, field name as the error reports it
        let slots = [(17usize, "claim_revision"), (57, "authorization_revision")];
        for (offset, field) in slots {
            for value in [0u64, MAX_WIRE_REVISION + 1, u64::MAX] {
                let metadata = metadata_with_claim_witness(|witness| {
                    witness[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
                });
                let error = require(&metadata).expect_err("an out-of-range revision must refuse");
                assert_eq!(
                    error,
                    DomainOperationMetadataError::ClaimWitnessRevisionOutOfRange {
                        field,
                        value,
                        max: MAX_WIRE_REVISION,
                    },
                    "{field} = {value} must be refused, and the error must name \
                     {field} rather than the other revision"
                );
                assert_eq!(Status::from(error).code(), Code::InvalidArgument);
            }

            let metadata = metadata_with_claim_witness(|witness| {
                witness[offset..offset + 8].copy_from_slice(&MAX_WIRE_REVISION.to_be_bytes());
            });
            let parsed = require(&metadata)
                .unwrap_or_else(|error| panic!("{field} at MAX_WIRE_REVISION must parse: {error}"));
            let claim = parsed
                .claim_witness
                .expect("the claim witness must be present");
            let read = if offset == 17 {
                claim.claim_revision
            } else {
                claim.authorization_revision
            };
            assert_eq!(read, MAX_WIRE_REVISION);
        }
    }

    #[test]
    fn a_divergent_duplicate_claim_witness_is_refused_and_an_identical_one_is_not() {
        let (mut metadata, ..) = valid_metadata();
        let witness = valid_claim_witness_bytes();
        insert(&mut metadata, CLAIM_WITNESS_KEY, &witness);
        metadata.append_bin(CLAIM_WITNESS_KEY, BinaryMetadataValue::from_bytes(&witness));
        require(&metadata).expect("a byte-identical repeat carries no ambiguity");

        let mut divergent = witness.clone();
        divergent[1] ^= 0xFF;
        metadata.append_bin(
            CLAIM_WITNESS_KEY,
            BinaryMetadataValue::from_bytes(&divergent),
        );
        let error = require(&metadata).expect_err("a divergent repeat must refuse");
        assert_eq!(
            error,
            DomainOperationMetadataError::DivergentDuplicate {
                header: CLAIM_WITNESS_KEY,
            }
        );
        assert_eq!(Status::from(error).code(), Code::InvalidArgument);
    }

    /// The one that matters most.
    ///
    /// If a lone claim witness fell through `extract`'s legacy carve-out to
    /// `Ok(None)`, a caller could attach a claim and be silently handed the
    /// unsynchronised legacy path while believing it had been admitted. Absence
    /// has a carve-out; partial carriage does not.
    #[test]
    fn a_claim_witness_alone_is_partial_carriage_never_the_legacy_carve_out() {
        let metadata = metadata_with(&[(CLAIM_WITNESS_KEY, valid_claim_witness_bytes())]);
        let error = extract(&metadata).expect_err("a lone claim witness must refuse");
        assert_eq!(
            error,
            DomainOperationMetadataError::PartialCarriage {
                present: CLAIM_WITNESS_KEY,
                missing: OPERATION_ID_KEY,
            }
        );
        assert_eq!(Status::from(error).code(), Code::InvalidArgument);

        // The carve-out itself still works: no carriage at all is `Ok(None)`.
        assert!(
            extract(&MetadataMap::new())
                .expect("no carriage must not error")
                .is_none(),
            "an empty metadata map is still the legacy carve-out"
        );
    }
}

#[cfg(test)]
mod p12_tests;

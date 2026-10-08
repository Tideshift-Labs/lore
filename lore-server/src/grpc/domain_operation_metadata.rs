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
//! version, or not an RFC 9562 `UUIDv7` is rejected **before** any authorization
//! side effect, with `INVALID_ARGUMENT`. Nothing is truncated or coerced into a
//! usable value.
//!
//! # Tenant scope keys exclude `urc-*` (R-BLOCK-5)
//!
//! The receipt key's `tenant_scope_key` is a versioned canonical tuple over the
//! **target** resource identity, derived independently of the token's resource
//! list. `auth/jwt.rs` accepts a wildcard `urc-*` resource, and the repository
//! v1 service runs under the authn-only `JWTInterceptor`, so a
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

/// Caller-chosen RFC 9562 `UUIDv7` identifying one governed operation.
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

// PIN(WP-120, 2026-09-05): the human's own authentication JWT, carried beside
// `authorization` on a governed mutation.
//
// Plain ASCII for the same reason `lore-attempt-id` is: the value is a bearer
// string, and a `-bin` key would make tonic expect base64. The client half is
// `lore-transport`'s `AUTHN_BEARER_METADATA_KEY`; the two literals must stay
// equal.
//
// Why this header exists at all, when the call already carries `authorization`.
// The internal prepare forwards a bearer to the platform's repository-operation
// verifier, which authenticates the HUMAN rather than trusting this server's
// report of identity (CR-029). On every service under the repo-scoped
// `JWTInterceptor`, `authorization` carries the client's *exchanged*
// multiresource authorization token: audience `["lore-storage", <host>]`, with a
// `resources` claim. The verifier requires the human authentication JWT and
// refuses a token carrying a `resources` claim outright, so lifting
// `authorization` made every released-client governed mutation on an armed cell
// fail UNAUTHENTICATED. The two credentials answer different questions and are
// carried separately.
//
// It is a credential, never an identity assertion by this server. Nothing here
// reads its claims; it is relayed to the verifier, which verifies it itself.
/// The human's own authentication bearer, forwarded to the operation verifier.
pub const AUTHN_BEARER_KEY: &str = "lore-authn-bearer";

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
#[lore_macro::test_pub]
const URC_PREFIX: &[u8] = b"urc-";

/// Validated domain-operation identity, read exactly once per request.
///
/// Holds no authorization decision: under CR-029 the authorization outcome is
/// separate server-only witness evidence and is never a receipt-key input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainOperationMetadata {
    /// RFC 9562 `UUIDv7`, exactly 16 bytes on the wire.
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

    /// The operation ID is 16 bytes but is not an RFC 9562 `UUIDv7`.
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

/// Read the human's forwarded authentication bearer.
///
/// Returns the header VERBATIM, `Bearer ` framing included, because the verifier
/// is handed exactly what the human's client sent and re-verifies it itself.
/// Nothing here parses or trusts its contents.
///
/// A blank or whitespace-only value reads as absent rather than as a bearer.
/// Forwarding it would reach the verifier as an empty credential and come back
/// as an authentication failure, which reads to an operator as "your login is
/// wrong" when the real fact is that the client sent no credential at all. The
/// caller's own refusal names that fact.
///
/// Divergent duplicates are refused by [`read_ascii`], as they are for every
/// other header here: two different credentials on one call is not a request
/// this server gets to pick a winner for.
pub fn extract_authn_bearer(
    metadata: &MetadataMap,
) -> Result<Option<String>, DomainOperationMetadataError> {
    Ok(read_ascii(metadata, AUTHN_BEARER_KEY)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty()))
}

/// The one refusal for a governed mutation that arrived without [`AUTHN_BEARER_KEY`].
///
/// `FAILED_PRECONDITION`, not `UNAUTHENTICATED`: the caller's credentials may be
/// perfectly good. What is missing is carriage this server needs, and the fix is
/// a newer client rather than a fresh login — so the status has to send the
/// operator to the right place, and the message names the header outright.
///
/// There is deliberately **no fallback to `authorization`**. That fallback is
/// the defect: it silently forwards the exchanged multiresource token, which the
/// verifier refuses, and turns a missing header into an authentication failure
/// nobody can trace back to carriage.
pub fn missing_authn_bearer() -> Status {
    Status::failed_precondition(MISSING_AUTHN_BEARER_MESSAGE)
}

/// The exact text of [`missing_authn_bearer`]. Named so tests can pin it.
///
/// Names both causes rather than only the expected one. A client that predates
/// this carriage and a client authenticating with a delegated credential that
/// holds no human token produce an identical absent header, and telling the
/// second to upgrade sends it after a fix it already has.
pub const MISSING_AUTHN_BEARER_MESSAGE: &str = "Governed mutations require the human authentication bearer in the lore-authn-bearer \
     metadata header, and this call carried none. Either the client predates WP-120 \
     authn-bearer carriage and sends only the exchanged authorization token, or it is \
     authenticating with a delegated credential that holds no human authentication token.";

/// Check RFC 9562 version and variant bits. A 16-byte value that is not a
/// `UUIDv7` is rejected rather than accepted as an opaque identifier, because the
/// receipt state machine classifies REPLAY versus fresh by `uuid_v7_timestamp`,
/// which is meaningless for any other version.
fn parse_uuid_v7(bytes: &[u8]) -> Result<Uuid, DomainOperationMetadataError> {
    let array: [u8; OPERATION_ID_LEN] =
        bytes
            .try_into()
            .map_err(|_err| DomainOperationMetadataError::WrongLength {
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
            .map_err(|_err| DomainOperationMetadataError::WrongLength {
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
        .map_err(|_err| DomainOperationMetadataError::InvalidMediatedPrincipalNamespace)?;
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
    let principal_id = std::str::from_utf8(principal_id)
        .map_err(|_err| ScopeKeyError::InvalidPrincipalNamespace)?;
    let parsed =
        Uuid::parse_str(principal_id).map_err(|_err| ScopeKeyError::InvalidPrincipalNamespace)?;
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
#[lore_macro::test_pub]
const MAX_SCOPE_COMPONENT_LEN: usize = 1024;

/// Length-prefix the method **and** every component so two different tuples
/// cannot canonicalise to the same bytes.
///
/// The method is prefixed too, rather than relying on the constants above being
/// NUL-terminated and prefix-free. That property is true today, but it is an
/// invariant nothing checks and that a future constant could quietly break —
/// and the failure mode would be two different operations sharing one tenant
/// scope, which is the worst outcome this function has.
#[lore_macro::test_pub]
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
    let len = u32::try_from(bytes.len()).map_err(|_err| ScopeKeyError::WrongLength {
        component,
        expected: MAX_SCOPE_COMPONENT_LEN,
        actual: bytes.len(),
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

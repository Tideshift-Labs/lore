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

    /// The operation ID is 16 bytes but is not an RFC 9562 UUIDv7.
    #[error("domain-operation ID is not an RFC 9562 UUIDv7 (version {version})")]
    NotUuidV7 {
        /// UUID version nibble found.
        version: usize,
    },

    /// Some but not all of the three headers were supplied. Partial carriage is
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

/// Read and validate all three headers when any of them is present.
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

    match (id.is_some(), fingerprint.is_some(), token.is_some()) {
        (false, false, false) => return Ok(None),
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

/// Read and validate all three headers, requiring every one of them.
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

    Ok(DomainOperationMetadata {
        operation_id,
        fingerprint_version,
        fingerprint,
        prepare_token,
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
}

/// A raw 16-byte target identity, checked for length and `urc-` provenance.
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
    Ok(build_scope_key(
        SCOPE_METHOD_REPOSITORY_CREATE_V1,
        &[repository_id],
    ))
}

/// Scope key for every other direct governed operation: the target repository
/// identity under a fixed constant.
pub fn scope_key_target_repository(repository_id: &[u8]) -> Result<Vec<u8>, ScopeKeyError> {
    checked_identity("repository_id", repository_id)?;
    Ok(build_scope_key(
        SCOPE_METHOD_REPOSITORY_V1,
        &[repository_id],
    ))
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
    Ok(build_scope_key(
        SCOPE_METHOD_MEDIATED_V1,
        &[org_uuid, &principal],
    ))
}

/// Length-prefix every component so two different tuples cannot canonicalise to
/// the same bytes.
fn build_scope_key(method: &[u8], components: &[&[u8]]) -> Vec<u8> {
    let payload: usize = components.iter().map(|c| c.len() + 4).sum();
    let mut out = Vec::with_capacity(1 + method.len() + payload);
    out.push(SCOPE_KEY_VERSION_V1);
    out.extend_from_slice(method);
    for component in components {
        let len = u32::try_from(component.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(component);
    }
    out
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
}

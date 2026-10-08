// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, CR-029): the tests of `lore_server::grpc::domain_operation_metadata`,
//! moved out of the inline module when upstream set `[lib] test = false`.

use lore_server::grpc::domain_operation_metadata::*;
use tonic::Status;
use tonic::metadata::MetadataMap;

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

mod p12_tests;

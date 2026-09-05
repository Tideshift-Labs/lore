// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-120 / CR-029: pins that the rebac stub's direct-human mutation policy
// (`active_active_two_process_support::rebac_stub::policy`) does not drift
// from the platform's own authority,
// `lorehub/packages/control-plane/src/mutation-authorization.ts`, and its
// handler, `lorehub/apps/auth-grpc/src/service-human-authorization.ts`. Those
// two files and their own tests remain the source of truth; this file only
// proves our Rust test double agrees with them.
//
// Pure and offline: no Postgres, MinIO, NATS, gateway, or spawned process.
#[cfg(all(test, feature = "integration_tests"))]
mod rebac_stub_policy_tests {
    use crate::active_active_two_process_support::rebac_stub::policy::*;

    // --- fixtures shared across the table/ordering/prefix tests -------------

    /// The ten direct-human families paired with the platform's pinned role
    /// floor (`DIRECT_MUTATION_POLICY` in `mutation-authorization.ts`).
    const CASES: &[(&str, Role)] = &[
        ("branch.push", Role::Developer),
        ("branch.metadata-set", Role::Developer),
        ("repository.metadata-set", Role::Maintainer),
        ("repository.delete", Role::Maintainer),
        ("repository.obliterate", Role::Owner),
        ("lock.acquire", Role::Developer),
        ("lock.renew", Role::Developer),
        ("lock.release", Role::Developer),
        ("lock.force_release", Role::Owner),
        ("lock.admin_acquire", Role::Owner),
    ];

    /// The platform's own `DIRECT_MUTATION_METHODS` order, copied verbatim.
    const EXPECTED_METHOD_ORDER: [&str; 10] = [
        "repository.delete",
        "repository.metadata-set",
        "branch.metadata-set",
        "branch.push",
        "repository.obliterate",
        "lock.acquire",
        "lock.renew",
        "lock.release",
        "lock.force_release",
        "lock.admin_acquire",
    ];

    const LOCK_METHODS: [&str; 5] = [
        "lock.acquire",
        "lock.renew",
        "lock.release",
        "lock.force_release",
        "lock.admin_acquire",
    ];

    const MUTATION_ONLY_METHODS: [&str; 5] = [
        "branch.push",
        "branch.metadata-set",
        "repository.metadata-set",
        "repository.delete",
        "repository.obliterate",
    ];

    const ALL_ROLES: [Role; 4] = [Role::Viewer, Role::Developer, Role::Maintainer, Role::Owner];

    /// Near-miss method names that share a prefix with a real family but must
    /// never be treated as one. PIN(WP-120, 2026-09-04): the platform matches
    /// by equality, never by prefix — a prefix match would make
    /// `repository.delete-everything` a `repository.delete`.
    const NEAR_MISS_METHODS: [&str; 5] = [
        "repository.delete-everything",
        "lock.force_release_all",
        "branch.pushed",
        "repository.deleteX",
        "lock.acquire ", // trailing space
    ];

    const MUTATION_SCOPE_LITERAL: &str = "repository-v1";
    const CREATE_SCOPE_LITERAL: &str = "repository-create-v1";
    const LOCK_SCOPE_LITERAL: &str = "lock-tenant-scope-v1";

    /// Embed `literal` inside unrelated noise bytes, mirroring that
    /// `scope_matches_mutation_family` matches by substring, never by parsing
    /// or exact framing.
    fn scope_with_literal(literal: &str) -> Vec<u8> {
        let mut scope = vec![0xAA, 0xAA, 0xAA, 0xAA];
        scope.extend_from_slice(literal.as_bytes());
        scope.extend_from_slice(&[0xBB, 0xBB, 0xBB, 0xBB]);
        scope
    }

    // --- 1. the table itself --------------------------------------------------

    #[test]
    fn direct_mutation_methods_match_the_platforms_pinned_order() {
        assert_eq!(
            DIRECT_MUTATION_METHODS, EXPECTED_METHOD_ORDER,
            "DIRECT_MUTATION_METHODS must mirror the platform's DIRECT_MUTATION_METHODS order exactly"
        );
    }

    #[test]
    fn required_role_matches_the_platforms_pinned_floor_for_every_direct_family() {
        for (method, expected_role) in CASES {
            assert_eq!(
                required_role(method),
                Some(*expected_role),
                "required_role({method:?}) diverged from the platform's DIRECT_MUTATION_POLICY floor"
            );
        }
    }

    #[test]
    fn required_role_denies_the_mediated_create_family_empty_and_unknown_methods() {
        assert_eq!(
            required_role(MEDIATED_ONLY_METHOD),
            None,
            "repository.create must never be treated as a direct family"
        );
        assert_eq!(
            required_role(""),
            None,
            "the empty method must be denied, not treated as some default family"
        );
        assert_eq!(
            required_role("some.unknown.family"),
            None,
            "an unrecognized family must deny, not default-allow"
        );
        assert!(
            !method_permits_role(MEDIATED_ONLY_METHOD, Some(Role::Owner)),
            "even an owner must be denied a direct authorization for repository.create"
        );
    }

    // --- 2. role ordering ------------------------------------------------------

    #[test]
    fn method_permits_role_matches_ordering_and_denies_a_null_role() {
        for (method, min_role) in CASES {
            for role in ALL_ROLES {
                let permitted = method_permits_role(method, Some(role));
                if role.rank() >= min_role.rank() {
                    assert!(
                        permitted,
                        "{method} must permit {role:?}, which is at or above the {min_role:?} floor"
                    );
                } else {
                    assert!(
                        !permitted,
                        "{method} must deny {role:?}, which is below the {min_role:?} floor"
                    );
                }
            }
            assert!(
                !method_permits_role(method, None),
                "{method} must fail closed on a null role"
            );
        }
    }

    // --- 3. equality, never prefix ---------------------------------------------

    #[test]
    fn near_miss_method_names_are_denied_not_prefix_matched() {
        for method in NEAR_MISS_METHODS {
            assert_eq!(
                required_role(method),
                None,
                "{method:?} must not be treated as a direct family by prefix"
            );
            for role in ALL_ROLES {
                assert!(
                    !method_permits_role(method, Some(role)),
                    "{method:?} must deny every role, including {role:?}"
                );
            }
            assert!(
                !is_lock_mutation_method(method),
                "{method:?} must not be classified as a lock family by prefix"
            );
        }
    }

    #[test]
    fn is_lock_mutation_method_matches_exactly_the_five_lock_families() {
        for method in LOCK_METHODS {
            assert!(
                is_lock_mutation_method(method),
                "{method} must be classified as a lock family"
            );
        }
        for method in MUTATION_ONLY_METHODS {
            assert!(
                !is_lock_mutation_method(method),
                "{method} must not be classified as a lock family"
            );
        }
        assert!(!is_lock_mutation_method(MEDIATED_ONLY_METHOD));
        assert!(!is_lock_mutation_method(""));
        assert!(!is_lock_mutation_method("bogus.method"));
    }

    // --- 4. scope family --------------------------------------------------------

    #[test]
    fn scope_matches_mutation_family_requires_the_lock_domain_for_lock_families() {
        let lock_scope = scope_with_literal(LOCK_SCOPE_LITERAL);
        let mutation_scope = scope_with_literal(MUTATION_SCOPE_LITERAL);
        let create_scope = scope_with_literal(CREATE_SCOPE_LITERAL);
        for method in LOCK_METHODS {
            assert!(
                scope_matches_mutation_family(method, &lock_scope),
                "{method} with a lock-domain scope must match"
            );
            assert!(
                !scope_matches_mutation_family(method, &mutation_scope),
                "{method} with a mutation-domain scope must not match"
            );
            assert!(
                !scope_matches_mutation_family(method, &create_scope),
                "{method} with a create-shaped scope must be refused even though it is a lock family"
            );
            assert!(
                !scope_matches_mutation_family(method, &[]),
                "{method} with an empty scope must not match"
            );
        }
    }

    #[test]
    fn scope_matches_mutation_family_requires_the_mutation_domain_for_mutation_families() {
        let lock_scope = scope_with_literal(LOCK_SCOPE_LITERAL);
        let mutation_scope = scope_with_literal(MUTATION_SCOPE_LITERAL);
        let create_scope = scope_with_literal(CREATE_SCOPE_LITERAL);
        for method in MUTATION_ONLY_METHODS {
            assert!(
                scope_matches_mutation_family(method, &mutation_scope),
                "{method} with a mutation-domain scope must match"
            );
            assert!(
                !scope_matches_mutation_family(method, &lock_scope),
                "{method} with a lock-domain scope must not match"
            );
            assert!(
                !scope_matches_mutation_family(method, &create_scope),
                "{method} with a create-shaped scope must be refused"
            );
            assert!(
                !scope_matches_mutation_family(method, &[]),
                "{method} with an empty scope must not match"
            );
        }
    }

    #[test]
    fn scope_matches_mutation_family_denies_unknown_methods_regardless_of_scope() {
        let lock_scope = scope_with_literal(LOCK_SCOPE_LITERAL);
        let mutation_scope = scope_with_literal(MUTATION_SCOPE_LITERAL);
        let create_scope = scope_with_literal(CREATE_SCOPE_LITERAL);
        for method in ["bogus.method", "", MEDIATED_ONLY_METHOD] {
            assert!(!scope_matches_mutation_family(method, &lock_scope));
            assert!(!scope_matches_mutation_family(method, &mutation_scope));
            assert!(!scope_matches_mutation_family(method, &create_scope));
            assert!(!scope_matches_mutation_family(method, &[]));
        }
    }

    #[test]
    fn create_domain_literal_does_not_contain_the_mutation_domain_literal() {
        // PIN(WP-120, 2026-09-04): the platform's own comment observes that
        // "repository-create-v1" does not contain "repository-v1" -- the
        // character after "repository-" is 'c', not 'v'. A naive substring
        // check that got this wrong would let a create-shaped scope satisfy a
        // mutation family. Checked independently of
        // `scope_matches_mutation_family`'s own create short-circuit.
        let create = CREATE_SCOPE_LITERAL.as_bytes();
        let mutation = MUTATION_SCOPE_LITERAL.as_bytes();
        assert!(
            !create
                .windows(mutation.len())
                .any(|window| window == mutation),
            "the create-domain literal must never contain the mutation-domain literal as a byte subsequence"
        );
    }

    // --- 5, 6, 7: the bound-fields digest ---------------------------------------
    //
    // The known-answer vectors below were produced by running the platform's
    // own `directAuthorizationBoundFieldsDigest`
    // (`lorehub/packages/control-plane/src/mutation-authorization.ts`) over
    // the two fixed bindings defined here, via `bun`. The platform's own tests
    // remain the authority for that function; these vectors exist to prove our
    // Rust double is byte-compatible with it, not merely self-consistent.

    const OPERATION_ID: [u8; 16] = [
        0x01, 0x88, 0x2f, 0x40, 0x5b, 0x1c, 0x71, 0xa9, 0x8b, 0x3d, 0x5e, 0x02, 0x77, 0x91, 0xc4,
        0x66,
    ];
    const SCOPE_BYTES: [u8; 24] = [0x30; 24];
    const FINGERPRINT: [u8; 32] = [0x11; 32];
    const CANONICAL_INTENT_DIGEST: [u8; 32] = [0x22; 32];
    const REPOSITORY_ID: [u8; 16] = [0x33; 16];
    const VERIFICATION_NONCE: [u8; 32] = [0x55; 32];
    const BRANCH_ID_A: [u8; 16] = [0x44; 16];

    const ALT_OPERATION_ID: [u8; 16] = [0x99; 16];
    const ALT_SCOPE: [u8; 24] = [0x31; 24];
    const ALT_FINGERPRINT: [u8; 32] = [0x77; 32];
    const ALT_CANONICAL_INTENT_DIGEST: [u8; 32] = [0x88; 32];
    const ALT_REPOSITORY_ID: [u8; 16] = [0xab; 16];
    const ALT_VERIFICATION_NONCE: [u8; 32] = [0xcd; 32];
    const ALT_AUTHORIZATION_ID: [u8; 16] = [0xef; 16];

    fn hex_to_32(hex: &str) -> [u8; 32] {
        assert_eq!(
            hex.len(),
            64,
            "digest fixture must be exactly 32 bytes / 64 hex chars"
        );
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex digit pair");
        }
        out
    }

    /// The baseline binding underlying both known-answer vectors (branch_id =
    /// vector A's 16 non-empty bytes) and every "every field is bound" case.
    fn baseline_binding() -> DirectAuthorizationBinding<'static> {
        DirectAuthorizationBinding {
            verified_issuer: "https://id.commit0.localhost",
            authenticated_subject: "case-i-writer",
            operation_id: &OPERATION_ID,
            method: "branch.push",
            scope: &SCOPE_BYTES,
            fingerprint_version: 1,
            fingerprint: &FINGERPRINT,
            canonical_intent_digest: &CANONICAL_INTENT_DIGEST,
            repository_id: &REPOSITORY_ID,
            branch_id: &BRANCH_ID_A,
            authorization_id: &OPERATION_ID,
            authorization_revision: 1,
            verification_nonce: &VERIFICATION_NONCE,
        }
    }

    #[test]
    fn digest_matches_platform_known_answer_vector_a_with_branch_id() {
        let expected =
            hex_to_32("a7941dfaea01b967312cd346d1154e12cd0a64dd4b96a5a03a6436c18771eb7e");
        assert_eq!(
            bound_fields_digest(&baseline_binding()),
            expected,
            "bound_fields_digest diverged from the platform's directAuthorizationBoundFieldsDigest for vector A (non-empty branch_id)"
        );
    }

    #[test]
    fn digest_matches_platform_known_answer_vector_b_with_empty_branch_id() {
        let binding = DirectAuthorizationBinding {
            branch_id: &[],
            ..baseline_binding()
        };
        let expected =
            hex_to_32("6ab0bde51f1c90376d3b33fb815a2ea0c9e7b57813a9fe3aea856604971c1f3a");
        assert_eq!(
            bound_fields_digest(&binding),
            expected,
            "bound_fields_digest diverged from the platform's directAuthorizationBoundFieldsDigest for vector B (empty branch_id, as sent for the five mutation families)"
        );
    }

    /// A LOCK-family vector, with the scope shape the lock coordinator really
    /// builds and a UUID subject.
    ///
    /// The two vectors above both use a mutation family, a synthetic scope and
    /// `fingerprint_version = 1`. The lock families are the ones that carry a
    /// differently shaped scope — no leading version byte, no length-prefixed
    /// domain — and the only ones that send a real `branch_id`, so a digest
    /// agreement proved only on the mutation shape would leave the half this
    /// harness's case H actually exercises unpinned.
    ///
    /// Generated the same way the others were: by running the platform's own
    /// `directAuthorizationBoundFieldsDigest`.
    #[test]
    fn digest_matches_platform_known_answer_vector_for_a_lock_family_scope() {
        let subject = "0198f2c1-4b7a-7d3e-9c05-6a1e8b4407d2";
        let mut scope = Vec::new();
        scope.extend_from_slice(b"lock-tenant-scope-v1\0");
        scope.extend_from_slice(&16u32.to_be_bytes());
        scope.extend_from_slice(&REPOSITORY_ID);
        scope.extend_from_slice(&16u32.to_be_bytes());
        scope.extend_from_slice(&BRANCH_ID_A);
        assert_eq!(scope.len(), 61, "the lock scope framing must be 61 bytes");

        let binding = DirectAuthorizationBinding {
            authenticated_subject: subject,
            method: "lock.acquire",
            scope: &scope,
            ..baseline_binding()
        };
        assert_eq!(
            bound_fields_digest(&binding),
            hex_to_32("a057c6ddb350e39b9924cad090d1c5787446fde8f5b1385fabd5bb9c6672beb0"),
            "bound_fields_digest diverged from the platform for a lock-family scope"
        );

        // The same binding with a different fingerprint version. Every other
        // vector uses 1, so nothing else would catch a wrong sub-framing of the
        // one field that is length-prefixed TWICE: as a u32 big-endian value,
        // and then as a four-byte part.
        let versioned = DirectAuthorizationBinding {
            fingerprint_version: 2,
            ..binding
        };
        assert_eq!(
            bound_fields_digest(&versioned),
            hex_to_32("c69b91aa021c2a44ca9c411c47bdf18ce0bb0e80d971b5a666474400cb383ec9"),
            "bound_fields_digest diverged from the platform for fingerprint_version 2"
        );
    }

    #[test]
    fn digest_is_injective_across_the_issuer_subject_boundary() {
        // The property the length prefixes exist for: without them, ("ab",
        // "c") and ("a", "bc") would hash identically.
        let issuer_ab_subject_c = DirectAuthorizationBinding {
            verified_issuer: "ab",
            authenticated_subject: "c",
            ..baseline_binding()
        };
        let issuer_a_subject_bc = DirectAuthorizationBinding {
            verified_issuer: "a",
            authenticated_subject: "bc",
            ..baseline_binding()
        };
        assert_ne!(
            bound_fields_digest(&issuer_ab_subject_c),
            bound_fields_digest(&issuer_a_subject_bc),
            "length-prefixed framing must prevent a boundary shift between adjacent string fields from producing the same digest"
        );
    }

    #[test]
    fn digest_binds_every_field_independently() {
        let baseline_digest = bound_fields_digest(&baseline_binding());

        let cases: Vec<(&str, DirectAuthorizationBinding<'static>)> = vec![
            (
                "verified_issuer",
                DirectAuthorizationBinding {
                    verified_issuer: "https://different.example",
                    ..baseline_binding()
                },
            ),
            (
                "authenticated_subject",
                DirectAuthorizationBinding {
                    authenticated_subject: "someone-else",
                    ..baseline_binding()
                },
            ),
            (
                "operation_id",
                DirectAuthorizationBinding {
                    operation_id: &ALT_OPERATION_ID,
                    ..baseline_binding()
                },
            ),
            (
                "method",
                DirectAuthorizationBinding {
                    method: "lock.acquire",
                    ..baseline_binding()
                },
            ),
            (
                "scope",
                DirectAuthorizationBinding {
                    scope: &ALT_SCOPE,
                    ..baseline_binding()
                },
            ),
            (
                "fingerprint_version",
                DirectAuthorizationBinding {
                    fingerprint_version: 2,
                    ..baseline_binding()
                },
            ),
            (
                "fingerprint",
                DirectAuthorizationBinding {
                    fingerprint: &ALT_FINGERPRINT,
                    ..baseline_binding()
                },
            ),
            (
                "canonical_intent_digest",
                DirectAuthorizationBinding {
                    canonical_intent_digest: &ALT_CANONICAL_INTENT_DIGEST,
                    ..baseline_binding()
                },
            ),
            (
                // Without this, a principal with developer on repository A
                // could obtain a branch.push witness whose intent digest
                // named repository B.
                "repository_id",
                DirectAuthorizationBinding {
                    repository_id: &ALT_REPOSITORY_ID,
                    ..baseline_binding()
                },
            ),
            (
                "branch_id",
                DirectAuthorizationBinding {
                    branch_id: &[],
                    ..baseline_binding()
                },
            ),
            (
                "authorization_id",
                DirectAuthorizationBinding {
                    authorization_id: &ALT_AUTHORIZATION_ID,
                    ..baseline_binding()
                },
            ),
            (
                "authorization_revision",
                DirectAuthorizationBinding {
                    authorization_revision: 2,
                    ..baseline_binding()
                },
            ),
            (
                "verification_nonce",
                DirectAuthorizationBinding {
                    verification_nonce: &ALT_VERIFICATION_NONCE,
                    ..baseline_binding()
                },
            ),
        ];

        for (field, variant) in &cases {
            assert_ne!(
                bound_fields_digest(variant),
                baseline_digest,
                "changing only `{field}` must change the digest"
            );
        }
    }

    #[test]
    fn direct_authorization_revision_is_pinned_to_one() {
        assert_eq!(
            DIRECT_AUTHORIZATION_REVISION, 1,
            "a direct authorization is minted at VERIFIED with no earlier state to advance from"
        );
    }
}

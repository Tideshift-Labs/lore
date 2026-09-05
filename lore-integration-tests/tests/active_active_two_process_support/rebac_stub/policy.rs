// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The direct-human mutation policy this stub decides with.
//!
//! PIN(WP-120, 2026-09-05): this is a **test double**. The authority is the
//! platform's own authorizer, which lives in the sibling repository at
//! `lorehub/packages/control-plane/src/mutation-authorization.ts` (the table,
//! the scope-family tripwire and the bound-fields preimage) and
//! `lorehub/apps/auth-grpc/src/service-human-authorization.ts` (the handler
//! ordering and the shape checks). Those files and their own tests decide what
//! is correct; everything here exists so two real loreserver processes have
//! something on the other end of `auth_url` that behaves the same way.
//!
//! Two things are deliberately NOT mirrored, because this stub has neither a
//! repository catalog nor an ACL store: the org lookup and the effective-role
//! resolution. Roles are granted to this stub explicitly by the case, per
//! repository and per subject, and an ungranted repository is denied — which is
//! the same fail-closed shape `findRepoByPartition` returning null produces on
//! the platform, reached by a different road. See `rebac_stub`'s own
//! documentation for the full divergence list.

use ring::digest;

/// The repo-role lattice, as `@lorehub/mint` orders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Developer,
    Maintainer,
    Owner,
}

impl Role {
    /// Rank in the lattice. Compared with `>=`, never with equality, so a role
    /// above the floor clears it.
    pub fn rank(self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Developer => 1,
            Self::Maintainer => 2,
            Self::Owner => 3,
        }
    }

    /// Parse the platform's own lowercase spelling, or `None`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "viewer" => Some(Self::Viewer),
            "developer" => Some(Self::Developer),
            "maintainer" => Some(Self::Maintainer),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    /// The platform's own spelling, for a denial message.
    pub fn name(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Developer => "developer",
            Self::Maintainer => "maintainer",
            Self::Owner => "owner",
        }
    }
}

/// The ten direct-human families, in the platform's own order.
///
/// Six governed families minus `repository.create`, plus the five lock families
/// `lore-postgres` freezes in its lock coordinator.
pub const DIRECT_MUTATION_METHODS: [&str; 10] = [
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

/// The mediated-only family, refused here by name rather than merely being
/// absent from the table, so a denial is legible.
pub const MEDIATED_ONLY_METHOD: &str = "repository.create";

/// The revision every direct authorization carries.
///
/// PIN(WP-120, 2026-09-04): 1, always. A direct authorization is minted straight
/// at VERIFIED and has no earlier state to advance from, unlike the mediated
/// rail which reaches 2 by advancing ISSUED -> VERIFIED.
pub const DIRECT_AUTHORIZATION_REVISION: u64 = 1;

/// The role floor each family requires.
///
/// The platform states this twice — a Lore permission and the lowest role
/// carrying it — and proves at module load that the two agree. This double
/// cannot re-derive the permission half without a copy of the whole `mint`
/// lattice, so it carries the role half and leans on the platform's own
/// coherence check for the rest. A drift is caught by the policy suite, which
/// pins these ten pairs against the platform file.
const POLICY: [(&str, Role); 10] = [
    ("repository.delete", Role::Maintainer),
    ("repository.metadata-set", Role::Maintainer),
    ("branch.metadata-set", Role::Developer),
    ("branch.push", Role::Developer),
    ("repository.obliterate", Role::Owner),
    ("lock.acquire", Role::Developer),
    ("lock.renew", Role::Developer),
    ("lock.release", Role::Developer),
    ("lock.force_release", Role::Owner),
    ("lock.admin_acquire", Role::Owner),
];

/// The five branch-scoped lock families, which carry a different scope shape.
const LOCK_MUTATION_METHODS: [&str; 5] = [
    "lock.acquire",
    "lock.renew",
    "lock.release",
    "lock.force_release",
    "lock.admin_acquire",
];

/// The role a principal must hold for `method`, or `None` when `method` is not
/// a direct family at all.
///
/// `None` is a refusal, never a default-allow. Every caller must treat an
/// unknown method — `repository.create` included — as denied.
///
/// PIN(WP-120, 2026-09-04): matched by EQUALITY, never by prefix. A prefix match
/// would make `repository.delete-everything` a `repository.delete`, and would
/// make `lock.force_release_all` a `lock.release`.
pub fn required_role(method: &str) -> Option<Role> {
    POLICY
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, role)| *role)
}

/// Does an effective role clear the gate for `method`?
///
/// Fail-closed on every axis: an absent role, an unknown method, and the
/// mediated create family all deny.
pub fn method_permits_role(method: &str, role: Option<Role>) -> bool {
    match (required_role(method), role) {
        (Some(required), Some(held)) => held.rank() >= required.rank(),
        _ => false,
    }
}

/// True for exactly the five lock families. Equality, never prefix.
pub fn is_lock_mutation_method(method: &str) -> bool {
    LOCK_MUTATION_METHODS.contains(&method)
}

/// Domain literals inside Lore's tenant scope keys.
///
/// PIN(WP-120, 2026-09-04), from `lore-server/src/grpc/domain_operation_metadata.rs`
/// and `lore-postgres/src/domain/locks/coordinator.rs`:
///
/// ```text
/// mutation  0x01 || u32be(len) || "repository-v1\0"        || u32be(16) || repository_id
/// create    0x01 || u32be(len) || "repository-create-v1\0" || u32be(16) || repository_id
/// lock      "lock-tenant-scope-v1\0" || u32be(16) || repository_id || u32be(16) || branch_id
/// ```
///
/// MATCHED AS SUBSTRINGS, not parsed, for the platform's own two reasons. The
/// three shapes are not uniform — the two repository forms carry a leading
/// version byte and length-prefix their domain, the lock form does neither — so
/// one parsing rule cannot cover all three. And a byte-exact parser was already
/// wrong once on the platform side, having been given the mutation domain
/// length as 13 when it is 14; a substring test does not depend on that
/// arithmetic and survived the correction unchanged.
///
/// The literals do not overlap: `repository-create-v1` does not contain
/// `repository-v1`, because the character after `repository-` is `c`, not `v`.
const SCOPE_DOMAIN_MUTATION: &[u8] = b"repository-v1";
const SCOPE_DOMAIN_CREATE: &[u8] = b"repository-create-v1";
const SCOPE_DOMAIN_LOCK: &[u8] = b"lock-tenant-scope-v1";

/// Byte-level substring test.
///
/// `windows` yields nothing when the needle is longer than the haystack, which
/// is the right answer here, and every needle above is a non-empty constant, so
/// the zero-width panic is unreachable.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Does `scope`'s domain agree with `method`'s family?
///
/// A TRIPWIRE, not a filter. loreserver refuses a direct-human
/// `repository.create` at its own admission gate, so a create-shaped scope
/// should never arrive; if one does, something upstream is wrong in a way no
/// honest caller produces and the right answer is to refuse. The lock/mutation
/// split is the same check in the ordinary direction.
///
/// Fail-closed: an unknown method returns false.
pub fn scope_matches_mutation_family(method: &str, scope: &[u8]) -> bool {
    if required_role(method).is_none() {
        return false;
    }
    // Refused on every family, create included — create is not a direct family
    // at all, so there is no method this may accompany.
    if contains_bytes(scope, SCOPE_DOMAIN_CREATE) {
        return false;
    }
    if is_lock_mutation_method(method) {
        contains_bytes(scope, SCOPE_DOMAIN_LOCK)
    } else {
        contains_bytes(scope, SCOPE_DOMAIN_MUTATION)
    }
}

/// Everything the direct-authorization witness digest is computed over.
///
/// Borrowed rather than owned because every field is already held by the
/// request being answered; copying thirteen buffers to hash them once would be
/// the only allocation on this path.
pub struct DirectAuthorizationBinding<'a> {
    pub verified_issuer: &'a str,
    pub authenticated_subject: &'a str,
    pub operation_id: &'a [u8],
    pub method: &'a str,
    pub scope: &'a [u8],
    pub fingerprint_version: u32,
    pub fingerprint: &'a [u8],
    pub canonical_intent_digest: &'a [u8],
    pub repository_id: &'a [u8],
    /// Empty for the five mutation families. That is a deferral, not the
    /// absence of a branch: loreserver's admission gate holds a
    /// repository-only scope and the branch is not known until the coordinator
    /// call site, so `branch.push` and `branch.metadata-set` send empty even
    /// though they do name a branch.
    pub branch_id: &'a [u8],
    /// Frozen equal to `operation_id` by CR-029.
    pub authorization_id: &'a [u8],
    pub authorization_revision: u64,
    pub verification_nonce: &'a [u8],
}

/// The frozen domain separator.
const DIRECT_AUTHORIZATION_DOMAIN_V1: &[u8] = b"repository-operation-direct-authorization-v1\0";

/// SHA-256 over the frozen `repository-operation-direct-authorization-v1`
/// preimage.
///
/// PIN(WP-120, 2026-09-04): the domain literal, then the parts below in this
/// exact order, each length-prefixed with a big-endian u32. `branch_id` is
/// prefixed as empty when absent, so the framing stays unambiguous either way.
///
/// Deliberately NOT the mediated `repository-operation-authorization-v1`
/// construction: that one includes `consumed_ticket_sha256` and is paired with
/// an `expected_claim_identity_digest`, both of which exist only because a
/// mediated operation has a committed preclaim ticket and a claim to fence. A
/// direct human operation has neither.
///
/// Note what loreserver does and does not check on the way back in.
/// `verify_direct_echo` (`lore-server/src/domain.rs`) compares every identity
/// and binding field and checks that this digest is 32 bytes wide — but it does
/// NOT recompute it. So a stub returning 32 arbitrary bytes here would be
/// accepted. Computing it honestly is therefore not something loreserver forces
/// on this double; it is the reason a case that passes through this stub is
/// evidence about the wire contract rather than about a rubber stamp.
///
/// OWED(WP-120): the only thing pinning this against the platform is a set of
/// known-answer vectors in `tests/rebac_stub_policy_test.rs`, generated by
/// running the platform's `directAuthorizationBoundFieldsDigest` and then
/// hand-carried here. That catches a change on THIS side and not one on the
/// platform's. The matching half is a vector pinned in the platform's own suite
/// beside `lorehub/packages/control-plane/src/mutation-authorization.ts`, so a
/// preimage edit fails on whichever side made it. Until that exists, treat a
/// green run of these vectors as evidence that the double has not drifted, not
/// that the contract has not.
pub fn bound_fields_digest(binding: &DirectAuthorizationBinding<'_>) -> [u8; 32] {
    let fingerprint_version = binding.fingerprint_version.to_be_bytes();
    let authorization_revision = binding.authorization_revision.to_be_bytes();
    let parts: [&[u8]; 13] = [
        binding.verified_issuer.as_bytes(),
        binding.authenticated_subject.as_bytes(),
        binding.operation_id,
        binding.method.as_bytes(),
        binding.scope,
        &fingerprint_version,
        binding.fingerprint,
        binding.canonical_intent_digest,
        binding.repository_id,
        binding.branch_id,
        binding.authorization_id,
        &authorization_revision,
        binding.verification_nonce,
    ];

    let mut preimage = Vec::with_capacity(
        DIRECT_AUTHORIZATION_DOMAIN_V1.len()
            + parts.iter().map(|part| part.len() + 4).sum::<usize>(),
    );
    preimage.extend_from_slice(DIRECT_AUTHORIZATION_DOMAIN_V1);
    for part in parts {
        // Without the prefixes, ("ab", "c") and ("a", "bc") would hash
        // identically, and two different bindings sharing a digest is the one
        // failure this value exists to prevent.
        let length = u32::try_from(part.len())
            .expect("a direct-authorization field fits the big-endian u32 frame");
        preimage.extend_from_slice(&length.to_be_bytes());
        preimage.extend_from_slice(part);
    }

    let computed = digest::digest(&digest::SHA256, &preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(computed.as_ref());
    out
}

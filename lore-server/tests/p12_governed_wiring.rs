// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-level completeness guard for CR029-CARRIAGE-INTENT-V1.
//!
//! Runtime mutation behavior belongs to the real-Postgres component tier. This
//! file pins the closed list of authenticated handler entry sites so a new
//! family-local digest or a leftover guarded site cannot be missed by a green
//! canonicalizer suite.

struct Site {
    label: &'static str,
    source: &'static str,
    family: &'static str,
}

/// The sites that refuse governed carriage. Five, not three.
///
/// Each is guarded for a different reason and they must not be collapsed into
/// one "not done yet" bucket. **Forwarded v1 create** is fenced by CR-029's
/// CARRIAGE-02-LORE until a frozen authenticated forwarding contract exists, and
/// has no verified principal to admit against at all — a whole contract is
/// missing.
///
/// **Both repository deletes** are a narrower case since WP-119 Part D, and the
/// reason is updated rather than left as "not done yet": their shared seam,
/// `GovernedRepositoryDelete`, is built — projection rows, the one classified
/// `repository.tombstoned` event, the `RepositoryDeleteInput` carriage, the
/// coordinator call, and the outcome mapping — and one input has no derivation.
/// `RepositoryDeleteProof::Unfrozen` fails the seam closed, and the handlers
/// keep refusing at **entry** so a delete that will certainly refuse never first
/// performs the ReBAC `DeleteResource` side effect. Two fences, one missing
/// value;
/// `the_repository_delete_seam_is_complete_except_its_unfrozen_proof` pins that
/// the second fence is the only one left.
///
/// **Both branch deletes** are new here, and they are a genuine tightening
/// rather than a new blocker: until now neither site read the domain-operation
/// headers at all (WP-119 writer inventory B4 and B5), so carriage was silently
/// ignored and a caller that asked for governed semantics got today's
/// unsynchronised single-key write while believing it had been admitted. They
/// now refuse, for two missing artefacts rather than one:
///
/// 1. The same unfrozen tombstone proof, which `BranchDeleteProof::Unfrozen`
///    fences at the seam.
/// 2. **No `CanonicalIntent::BranchDelete` family.** CR-029 freezes six, Lore
///    defines those six, and the platform canonicalizer defines the same six, so
///    `GovernedBranchDelete::prepare` has no digest a handler could hand it.
///
/// The second is why these two refuse at entry and cannot reach their seam's own
/// fence, and why they are guarded rather than wired even though
/// `PostgresDomainStore::branch_delete` is complete.
/// `the_branch_delete_seam_is_complete_except_its_unfrozen_proof` pins that.
const GUARDED_SITES: [&str; 5] = [
    include_str!("../src/grpc/forwarded_repository/v1/repository_create.rs"),
    include_str!("../src/grpc/handlers/repository_delete.rs"),
    include_str!("../src/grpc/repository/v1/repository_delete.rs"),
    include_str!("../src/grpc/handlers/branch_delete.rs"),
    include_str!("../src/grpc/revision/v1/branch_delete.rs"),
];

/// The shared governed seam both create sites commit through.
const GOVERNED_SEAM: &str = include_str!("../src/domain.rs");

/// The one Lore-side declaration of CR-029's frozen canonical-intent families.
///
/// Included so a pin on "which families exist" reads the declaration rather than
/// prose that happens to name one.
const INTENT_FAMILIES: &str = include_str!("../src/domain_intent.rs");

/// The forwarded v1 branch-delete entry point, which is deliberately NOT in
/// [`GUARDED_SITES`].
///
/// Forwarded repository create IS guarded, so the asymmetry needs recording
/// rather than leaving to look like an oversight. That site reaches a local
/// coordinator call path and had a gate to place; this one reaches
/// `branch_delete_implementation` on a service that holds no domain context and
/// has no verified principal to admit against, which is CR-029's CARRIAGE-02-LORE
/// case in full. It is fenced by the missing authenticated-forwarding contract,
/// not by a `reject_unwired_governed_operation` call, and listing it among the
/// guarded sites would assert a gate that is not there.
const FORWARDED_BRANCH_DELETE: &str =
    include_str!("../src/grpc/forwarded_revision/v1/branch_delete.rs");

const WIRED_SITES: [Site; 8] = [
    Site {
        label: "v0/v1 shared branch push",
        source: include_str!("../src/grpc/handlers/branch_push.rs"),
        family: "CanonicalIntent::BranchPush",
    },
    Site {
        label: "v0 obliterate",
        source: include_str!("../src/grpc/handlers/obliterate.rs"),
        family: "CanonicalIntent::Obliterate",
    },
    Site {
        label: "v0 repository metadata CAS",
        source: include_str!("../src/grpc/handlers/repository_metadata_set.rs"),
        family: "CanonicalIntent::RepositoryMetadataCas",
    },
    Site {
        label: "v1 repository metadata CAS",
        source: include_str!("../src/grpc/repository/v1/repository_metadata_set.rs"),
        family: "CanonicalIntent::RepositoryMetadataCas",
    },
    Site {
        label: "v0 branch metadata CAS",
        source: include_str!("../src/grpc/handlers/branch_metadata_set.rs"),
        family: "CanonicalIntent::BranchMetadataCas",
    },
    Site {
        label: "v1 branch metadata CAS",
        source: include_str!("../src/grpc/revision/v1/branch_metadata_set.rs"),
        family: "CanonicalIntent::BranchMetadataCas",
    },
    Site {
        label: "v0 repository create",
        source: include_str!("../src/grpc/handlers/repository_create.rs"),
        family: "CanonicalIntent::RepositoryCreate",
    },
    Site {
        label: "v1 repository create",
        source: include_str!("../src/grpc/repository/v1/repository_create.rs"),
        family: "CanonicalIntent::RepositoryCreate",
    },
];

#[test]
fn every_authenticated_site_uses_the_one_canonical_intent_definition() {
    for site in WIRED_SITES {
        assert!(
            site.source.contains(site.family),
            "{} must construct {}",
            site.label,
            site.family
        );
        assert!(
            site.source.contains("canonical_intent_digest("),
            "{} must derive its binding through the shared digest function",
            site.label
        );
    }
    assert!(
        WIRED_SITES[0]
            .source
            .contains(".branch_push_commit(&self.operation")
    );
    // WP-116 Part 1: the push must hand its classified event to the
    // coordinator.
    //
    // Scoped to the `BranchPushCommitInput` literal, not to the whole file.
    // `include_str!` pulls in `#[cfg(test)] mod tests` too, so a file-wide
    // `contains`/`!contains` pair is both unsound (a test fixture writing
    // `event: None` fails it spuriously) and too weak (a regression to
    // `let event = None;` above the literal satisfies it). The literal is the
    // one place where feeding versus not feeding the coordinator is decided.
    let literal = {
        let start = WIRED_SITES[0]
            .source
            .find("let input = BranchPushCommitInput {")
            .expect("branch push must build its coordinator input as a struct literal");
        let rest = &WIRED_SITES[0].source[start..];
        let end = rest
            .find("\n        };")
            .expect("the BranchPushCommitInput literal must terminate");
        &rest[..end]
    };
    // No trailing newline in the needle: `event,` is the literal's last field,
    // so the slice ends immediately after it.
    assert!(
        literal.contains("\n            event,"),
        "branch push must pass its built event to the coordinator; a literal \
         that sets `event: None`, or omits the field, has regressed to the \
         pre-WP-116 unfed outbox"
    );
    assert!(
        !literal.contains("event: None"),
        "branch push must not regress to an unfed outbox event"
    );
    // The event has to come from the shared pinned builder rather than a
    // second, file-local definition of the same classification. This is the
    // same rule `the_removed_inline_branch_push_definition_cannot_return`
    // enforces for the canonical intent digest.
    assert_eq!(
        WIRED_SITES[0]
            .source
            .matches("outbox_builders::branch_pushed(")
            .count(),
        1,
        "branch push must build its event through exactly one call to the \
         shared pinned builder"
    );

    // WP-116 Part 2: every metadata-CAS site goes through the one shared
    // governed seam and the one shared coordinator method. Four near-identical
    // handlers is how two of them come to mean different things, which is the
    // divergence CR-029 exists to end, so the pin is on the seam rather than on
    // each handler's own text.
    // Selected by family rather than by index into `WIRED_SITES`: hard-coded
    // positions silently stop selecting the right rows the moment a site is
    // added or reordered, and this loop's assertions would then pass by
    // checking nothing.
    let mut checked = 0usize;
    for site in WIRED_SITES
        .iter()
        .filter(|site| site.family.ends_with("MetadataCas"))
    {
        checked += 1;
        assert!(
            site.source.contains("GovernedMetadataCas::prepare("),
            "{} must admit through the shared governed metadata-CAS seam",
            site.label
        );
        assert!(
            site.source.contains("MetadataCasOutcome::Lost(observed)"),
            "{} must preserve CR-029 Phase 5's in-band pointer on CAS loss, \
             not map the loss to an error",
            site.label
        );
        assert!(
            !site.source.contains("reject_unwired_governed_operation("),
            "{} is wired and must not still refuse governed carriage",
            site.label
        );
    }
    assert_eq!(
        checked, 4,
        "all four metadata-CAS sites must be selected; a filter matching none          would let this loop pass by checking nothing"
    );
}

/// WP-116 Part 3: both authenticated repository-create sites commit through the
/// one shared governed seam, and that seam emits the pair CR-032 classifies.
#[test]
fn both_repository_create_sites_publish_through_the_shared_governed_seam() {
    let mut checked = 0usize;
    for site in WIRED_SITES
        .iter()
        .filter(|site| site.family.ends_with("RepositoryCreate"))
    {
        checked += 1;
        assert!(
            site.source.contains("GovernedRepositoryCreate::prepare("),
            "{} must admit through the shared governed create seam",
            site.label
        );
        assert!(
            site.source.contains("governed_repository_create("),
            "{} must publish through the one shared governed create body, not \
             a second copy of it",
            site.label
        );
    }
    assert_eq!(
        checked, 2,
        "both create sites must be selected; a filter matching none would let \
         this loop pass by checking nothing"
    );

    // The v0 site is wired outright. The v1 site keeps exactly one refusal, for
    // its forwarding branch: a cell that forwards has no local coordinator call
    // site, and CARRIAGE-02-LORE fences the forwarded entry point. More than
    // one occurrence means the direct path has regressed to refusing too.
    //
    // Selected by label rather than by index into `WIRED_SITES`: a site added
    // or reordered above these two would silently retarget both assertions at
    // the wrong file and leave the test passing.
    let site = |label: &str| {
        WIRED_SITES
            .iter()
            .find(|site| site.label == label)
            .unwrap_or_else(|| panic!("{label} must be a wired site"))
            .source
    };
    let v0 = site("v0 repository create");
    let v1 = site("v1 repository create");
    assert!(
        !v0.contains("reject_unwired_governed_operation("),
        "v0 repository create is wired and must not still refuse governed carriage"
    );
    assert_eq!(
        v1.matches("reject_unwired_governed_operation(").count(),
        1,
        "v1 repository create must refuse governed carriage only on its \
         forwarding branch"
    );

    // CR-032 classifies a repository create as two committed transitions, and
    // both must come from the shared pinned builders rather than a second,
    // seam-local definition of the same classification. Scoped to the seam
    // because that is where the pair is built once for both sites.
    for builder in [
        "outbox_builders::repository_published(",
        "outbox_builders::branch_created(",
    ] {
        assert_eq!(
            GOVERNED_SEAM.matches(builder).count(),
            1,
            "the governed create seam must build {builder} through exactly one \
             call to the shared pinned builder"
        );
    }

    // The events must actually reach the coordinator. Scoped to the
    // `RepositoryCreateInput` literal for the same reason the branch-push pin
    // is scoped to its own: a file-wide check is both unsound and too weak.
    let literal = {
        let start = GOVERNED_SEAM
            .find("let input = RepositoryCreateInput {")
            .expect("the governed create seam must build its coordinator input as a literal");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n        };")
            .expect("the RepositoryCreateInput literal must terminate");
        &rest[..end]
    };
    assert!(
        literal.contains("\n            events,"),
        "the governed create must pass its built events to the coordinator; a \
         literal that sets `events: Vec::new()`, or omits the field, has \
         regressed to an unfed outbox"
    );
    assert!(
        !literal.contains("events: Vec::new()"),
        "the governed create must not regress to an unfed outbox"
    );
}

#[test]
fn the_five_still_unwired_sites_remain_explicitly_guarded() {
    for source in GUARDED_SITES {
        assert!(source.contains("reject_unwired_governed_operation("));
        // A guard without a recorded reason is how "not yet" becomes "nobody
        // remembers". Each of the five carries a BLOCKED marker naming its
        // exact missing artefact. The looser "points at the part that wires it"
        // alternative is gone with Part 3: every remaining guard is blocked on
        // a contract, not on effort.
        assert!(
            source.contains("BLOCKED(WP-116)"),
            "a guarded governed site must record why it is guarded"
        );
    }
}

/// WP-119 Part D: the shared delete seam is complete except its proof.
///
/// A guard whose recorded reason is "not wired yet" decays into "nobody
/// remembers what was missing". This pins the narrower, checkable claim the
/// guard now makes: every input the coordinator needs is built here, one is not
/// derivable, and the seam refuses on exactly that one.
#[test]
fn the_repository_delete_seam_is_complete_except_its_unfrozen_proof() {
    // The one classified event CR-032 assigns to a repository tombstone, built
    // through the shared pinned builder exactly once. More than one call is a
    // second definition of the same classification; zero is an unfed outbox.
    assert_eq!(
        GOVERNED_SEAM
            .matches("outbox_builders::repository_tombstoned(")
            .count(),
        1,
        "the governed delete seam must build repository.tombstoned through \
         exactly one call to the shared pinned builder"
    );
    // CR-032 answers this transition with ONE bounded generation event, not one
    // row per tombstoned branch. A loop or a per-branch builder call here is the
    // superseded reading returning.
    //
    // Scoped to the delete seam's own `input` builder rather than to the whole
    // file: a legitimate `GovernedBranchDelete` seam landing in this same file
    // would build `branch_deleted` correctly and false-fail a file-wide check.
    let delete_input_fn = {
        let start = GOVERNED_SEAM
            .find(
                "        delete_proof: Vec<u8>,\n    ) -> Result<RepositoryDeleteInput, Status> {",
            )
            .expect("the governed delete seam must build its input in one named function");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n    }")
            .expect("the governed delete input builder must terminate");
        &rest[..end]
    };
    assert!(
        !delete_input_fn.contains("outbox_builders::branch_deleted("),
        "a repository tombstone emits one bounded repository-generation event, \
         never one branch.deleted row per hidden branch"
    );
    assert_eq!(
        delete_input_fn
            .matches("outbox_builders::repository_tombstoned(")
            .count(),
        1,
        "the delete input builder must build exactly one classified event"
    );

    // The events must reach the coordinator. Scoped to the
    // `RepositoryDeleteInput` literal for the same reason the create and push
    // pins are scoped to theirs: a file-wide check is both unsound (a fixture
    // elsewhere trips it) and too weak (a `let events = Vec::new();` above the
    // literal satisfies it).
    let literal = {
        let start = GOVERNED_SEAM
            .find("Ok(RepositoryDeleteInput {")
            .expect("the governed delete seam must build its coordinator input as a literal");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n        })")
            .expect("the RepositoryDeleteInput literal must terminate");
        &rest[..end]
    };
    assert!(
        literal.contains("\n            events,"),
        "the governed delete must pass its built event to the coordinator; a \
         literal that sets `events: Vec::new()`, or omits the field, has \
         regressed to an unfed outbox"
    );
    assert!(
        !literal.contains("events: Vec::new()"),
        "the governed delete must not regress to an unfed outbox"
    );

    // The seam reaches the coordinator, so "complete except the proof" is a
    // property of the code rather than of this comment.
    assert!(
        GOVERNED_SEAM.contains(".repository_delete(&self.operation"),
        "the governed delete seam must call the one coordinator method"
    );
    assert!(
        GOVERNED_SEAM.contains("publication.projection()"),
        "the governed delete must commit its projection rows with the tombstone"
    );

    // And the proof is the fence. `bytes()` returning `None` is what refuses;
    // an `Unfrozen` variant that never reaches a refusal would be a comment,
    // not a guard.
    assert!(
        GOVERNED_SEAM.contains("BLOCKED(WP-116): delete_proof derivation unfrozen in CR-029"),
        "the seam must record why it is fenced, in the agreed marker form"
    );
    assert!(
        GOVERNED_SEAM.contains("publication.delete_proof.bytes()"),
        "the seam must fail closed on the proof before it builds anything"
    );
    // The strong form of "the proof is still unfrozen": the enum has exactly one
    // variant. A taboo on one guessed variant NAME would be satisfied by calling
    // the new variant anything else, which is how a naming pin passes while the
    // thing it guards has already happened.
    let proof_variants = {
        let start = GOVERNED_SEAM
            .find("pub enum RepositoryDeleteProof {")
            .expect("the delete proof must stay a closed enum");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n}")
            .expect("the RepositoryDeleteProof body must terminate");
        rest[..end]
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("///") && !line.starts_with("//"))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        proof_variants,
        vec!["Unfrozen,"],
        "RepositoryDeleteProof must carry exactly the one unfrozen variant \
         until CR-029 freezes a delete_proof preimage with golden vectors on \
         both sides; adding any variant here opens the governed delete path"
    );
}

/// WP-119: the shared branch-delete seam is complete except its proof, and its
/// projection is the ONE row the legacy writer touches.
///
/// `branch.deleted` was the last classified event in CR-032's table with no
/// producer anywhere. The producer now exists end to end —
/// `PostgresDomainStore::branch_delete` plus this seam — and the two sites stay
/// guarded for a reason narrower and more checkable than "not wired yet".
#[test]
fn the_branch_delete_seam_is_complete_except_its_unfrozen_proof() {
    // The one classified event CR-032 assigns to a branch tombstone, built
    // through the shared pinned builder exactly once in the whole seam. More
    // than one call is a second definition of the same classification; zero is
    // an unfed outbox.
    assert_eq!(
        GOVERNED_SEAM
            .matches("outbox_builders::branch_deleted(")
            .count(),
        1,
        "the governed branch-delete seam must build branch.deleted through \
         exactly one call to the shared pinned builder"
    );

    // Scoped to the branch-delete seam's own input builder, for the reason every
    // other pin in this file is scoped: `include_str!` pulls in the whole file,
    // and the repository-delete seam legitimately builds a different event a few
    // hundred lines up.
    let branch_input_fn = {
        let start = GOVERNED_SEAM
            .find("        delete_proof: Vec<u8>,\n    ) -> Result<BranchDeleteInput, Status> {")
            .expect("the governed branch-delete seam must build its input in one named function");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n    }")
            .expect("the governed branch-delete input builder must terminate");
        &rest[..end]
    };
    assert_eq!(
        branch_input_fn
            .matches("outbox_builders::branch_deleted(")
            .count(),
        1,
        "the branch-delete input builder must build exactly one classified event"
    );
    // The mirror of the repository seam's pin, in the other direction: a branch
    // tombstone is ONE branch-aggregate row and never a repository-generation
    // row. Emitting `repository.tombstoned` here would tell every consumer the
    // whole repository went away because one branch did.
    assert!(
        !branch_input_fn.contains("outbox_builders::repository_tombstoned("),
        "a branch tombstone emits one branch.deleted row, never a \
         repository-generation event"
    );

    // The event must actually reach the coordinator. Scoped to the
    // `BranchDeleteInput` literal for the same reason the create, push and
    // repository-delete pins are scoped to theirs: a file-wide check is both
    // unsound (a fixture elsewhere trips it) and too weak (a
    // `let events = Vec::new();` above the literal satisfies it).
    let literal = {
        let start = GOVERNED_SEAM
            .find("Ok(BranchDeleteInput {")
            .expect("the governed branch-delete seam must build its input as a literal");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n        })")
            .expect("the BranchDeleteInput literal must terminate");
        &rest[..end]
    };
    assert!(
        literal.contains("\n            events,"),
        "the governed branch delete must pass its built event to the \
         coordinator; a literal that sets `events: Vec::new()`, or omits the \
         field, has regressed to an unfed outbox"
    );
    assert!(
        !literal.contains("events: Vec::new()"),
        "the governed branch delete must not regress to an unfed outbox"
    );
    assert!(
        literal.contains("projection: publication.projection()"),
        "the governed branch delete must commit its projection row with the \
         tombstone"
    );

    // The seam reaches the one coordinator method.
    assert!(
        GOVERNED_SEAM.contains(".branch_delete(&self.operation"),
        "the governed branch-delete seam must call the one coordinator method"
    );

    // The projection is the LOAD-BEARING correctness claim here, and it is the
    // one a reader is most likely to get wrong by analogy with the repository
    // delete. `lore_revision::branch::delete` calls `delete_name_to_id` and
    // nothing else, so a branch delete retires exactly ONE `lore_mutable` row:
    // the live-name key. The branch metadata and latest rows deliberately
    // survive, because the v1 handler builds its idempotent response from them
    // AFTER the delete. Retiring them here would make the governed delete answer
    // differently from the legacy one.
    let branch_projection_fn = {
        let start = GOVERNED_SEAM
            .find("impl BranchDeletePublication<'_> {")
            .expect("the branch-delete publication must have its own impl block");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n}")
            .expect("the BranchDeletePublication impl must terminate");
        &rest[..end]
    };
    assert!(
        !branch_projection_fn.contains("branch::METADATA"),
        "a branch delete must not retire the branch metadata row; the legacy \
         writer leaves it, and the v1 idempotent response reads it after the \
         delete"
    );
    assert!(
        !branch_projection_fn.contains("branch::LATEST"),
        "a branch delete must not retire the branch latest pointer; the legacy \
         writer leaves it"
    );
    assert_eq!(
        branch_projection_fn.matches("ProjectionWrite {").count(),
        1,
        "a branch delete retires exactly one lore_mutable row, the live-name key"
    );
    // The live-name key folds case, because `branch::mutable_name_key` hashes
    // `name.to_lowercase()`. Getting this wrong retires a key nothing wrote and
    // leaves the real one behind, which is invisible until a name is reused.
    assert!(
        branch_projection_fn.contains("self.name.to_lowercase()"),
        "the branch live-name key folds case, unlike the repository name key"
    );

    // The proof is the fence at the seam. `bytes()` returning `None` is what
    // refuses; an `Unfrozen` variant that never reaches a refusal would be a
    // comment, not a guard.
    assert!(
        GOVERNED_SEAM
            .contains("BLOCKED(WP-116): branch delete_proof derivation unfrozen in CR-029"),
        "the branch seam must record why it is fenced, in the agreed marker form"
    );
    // Two seams now fail closed on a proof, and each must keep its own: freezing
    // the repository derivation must not open the branch path.
    assert_eq!(
        GOVERNED_SEAM
            .matches("publication.delete_proof.bytes()")
            .count(),
        2,
        "the repository and branch delete seams must each fail closed on their \
         own proof before building anything"
    );
    // The strong form of "the proof is still unfrozen": the enum has exactly one
    // variant. A taboo on one guessed variant NAME would be satisfied by calling
    // the new variant anything else.
    let proof_variants = {
        let start = GOVERNED_SEAM
            .find("pub enum BranchDeleteProof {")
            .expect("the branch delete proof must stay a closed enum");
        let rest = &GOVERNED_SEAM[start..];
        let end = rest
            .find("\n}")
            .expect("the BranchDeleteProof body must terminate");
        rest[..end]
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("///") && !line.starts_with("//"))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        proof_variants,
        vec!["Unfrozen,"],
        "BranchDeleteProof must carry exactly the one unfrozen variant until \
         CR-029 freezes a branch tombstone-proof preimage with golden vectors \
         on both sides; adding any variant here opens the governed branch \
         delete path"
    );

    // And the second, independent blocker: no handler may call the seam while
    // CR-029 freezes no branch-delete canonical-intent family, because
    // `prepare` takes a digest none of the six frozen families can produce.
    // This is what keeps the two sites at an ENTRY refusal rather than at the
    // seam's own fence.
    // The forwarded entry point is the one branch-delete path with no gate at
    // all. Pinned as an explicit negative so the omission from GUARDED_SITES is
    // a recorded decision, and so this fails the moment the gap closes rather
    // than passing quietly forever.
    assert!(
        !FORWARDED_BRANCH_DELETE.contains("admit_at_entry("),
        "the forwarded v1 branch delete has no domain context and no verified \
         principal, so it is fenced by CR-029's CARRIAGE-02-LORE forwarding \
         contract rather than by a gate. If a gate has landed here, move this \
         site into GUARDED_SITES and delete this pin"
    );

    for source in [GUARDED_SITES[3], GUARDED_SITES[4]] {
        assert!(
            !source.contains("GovernedBranchDelete::prepare("),
            "a branch-delete handler must not reach the seam until CR-029 \
             freezes a CanonicalIntent::BranchDelete family; there is no digest \
             it could pass"
        );
        assert!(
            source.contains("admit_at_entry("),
            "a branch-delete handler must read the domain-operation headers at \
             entry; silently ignoring carriage is the R-BLOCK-2 failure the \
             gate exists to prevent"
        );
    }
    // The second blocker, pinned where it actually lives. Asserting on the
    // seam's text would be unsound: the seam's own doc comment names
    // `CanonicalIntent::BranchDelete` while explaining that no such family
    // exists, so a prose mention would trip the pin and, worse, deleting the
    // explanation would satisfy it. The families are declared in exactly one
    // place, so that is the place to check.
    // Two needles, because each is weak alone. The domain separator is the
    // actual frozen artefact and cannot be spelled any other way, so it catches
    // a family added under a different Rust name. The variant shape catches a
    // family added before its separator is written.
    assert_eq!(
        INTENT_FAMILIES.matches("branch-delete-intent-v1").count(),
        0,
        "a branch-delete canonical-intent domain separator must not exist on \
         the Lore side alone; the preimage is frozen jointly with the platform \
         canonicalizer, with golden vectors computed independently on both sides"
    );
    assert_eq!(
        INTENT_FAMILIES.matches("    BranchDelete {").count(),
        0,
        "a seventh canonical-intent family is a CR-029 amendment with \
         cross-language golden vectors on both sides, not a Lore-side edit; a \
         Lore-only family would fail every admission the platform offered it. \
         When CR-029 freezes one, wire both branch-delete sites in the same \
         change and move them out of GUARDED_SITES"
    );
}

#[test]
fn the_removed_inline_branch_push_definition_cannot_return() {
    const PUSH: &str = include_str!("../src/grpc/handlers/branch_push.rs");
    assert!(!PUSH.contains("blake3::Hasher::new()"));
    assert_eq!(PUSH.matches("CanonicalIntent::BranchPush").count(), 1);
}

/// The ReBAC create callback's proto contract.
///
/// Included as source rather than as a hand-copied field list so the pin below
/// fails when a field is added to the message and left unpopulated — which is
/// exactly the defect this file exists to catch, and exactly what happened to
/// tags 3-21: they were frozen in the proto, generated into
/// `lore-proto/src/grpc/ucs.auth.rs`, verified end to end by `auth-grpc`, and
/// never once written by Lore.
const REBAC_PROTO: &str = include_str!("../../lore-proto/proto/rebac_api.proto");

/// The file that builds the callback request.
const CREATE_HANDLER: &str = include_str!("../src/grpc/handlers/repository_create.rs");

/// Extract one proto message body by name.
fn proto_message(source: &str, name: &str) -> String {
    let header = format!("message {name} {{");
    let start = source
        .find(&header)
        .unwrap_or_else(|| panic!("{name} must exist in rebac_api.proto"))
        + header.len();
    let rest = &source[start..];
    let end = rest
        .find('}')
        .unwrap_or_else(|| panic!("{name} must terminate"));
    rest[..end].to_owned()
}

/// Field names of a proto message at or above `min_tag`, in declaration order.
fn proto_fields_from_tag(body: &str, min_tag: u32) -> Vec<String> {
    let mut fields = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some(statement) = line.strip_suffix(';') else {
            continue;
        };
        let Some((lhs, tag)) = statement.rsplit_once('=') else {
            continue;
        };
        let Ok(tag) = tag.trim().parse::<u32>() else {
            continue;
        };
        let Some(name) = lhs.trim().rsplit(' ').next() else {
            continue;
        };
        if tag >= min_tag {
            fields.push(name.to_owned());
        }
    }
    fields
}

/// Slice one Rust function body out of a source file by its signature prefix.
fn rust_fn_body(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("{signature} must exist"));
    let rest = &source[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{signature} must terminate at column zero"));
    rest[..end].to_owned()
}

/// WP-116: a governed create attaches the COMPLETE platform claim.
///
/// `auth-grpc` decides which of two paths `CreateResource` takes by asking
/// whether any of tags 3-21 is present, and the governed path it then selects is
/// exact-match-or-deny with no fallback. A field left unset is elided by prost,
/// arrives `undefined` under the verifier's `defaults: false` loader, and turns
/// an authorized create into a `PERMISSION_DENIED` that names nothing useful. So
/// "all of them or none of them" is the property, and a partial attachment is
/// worse than no attachment.
///
/// Derived from the proto rather than from a list written here, so a tag added
/// to `CreateResourceRequest` without a matching assignment fails this test
/// instead of shipping as a silently absent field.
#[test]
fn the_governed_create_callback_populates_every_claim_field() {
    let message = proto_message(REBAC_PROTO, "CreateResourceRequest");
    let fields = proto_fields_from_tag(&message, 3);
    assert_eq!(
        fields.len(),
        19,
        "CreateResourceRequest tags 3.. must be the 19 CR-029 claim fields; a \
         changed count means the callback contract moved and this pin, the \
         attach helper, and the platform verifier all need reconciling: {fields:?}"
    );

    let attach = rust_fn_body(
        CREATE_HANDLER,
        "fn attach_create_claim(payload: &mut CreateResourceRequest",
    );
    for field in &fields {
        assert!(
            attach.contains(&format!("payload.{field} =")),
            "the governed create callback must populate `{field}`; an unset \
             field is elided on the wire and denied by the verifier"
        );
    }

    // The method is the platform family constant, not the operation binding's
    // gRPC path. The two wire versions bind different paths, so sourcing it
    // from the binding would fail the verifier's exact match on both.
    assert!(
        attach.contains("payload.method = PLATFORM_METHOD_REPOSITORY_CREATE.to_owned();"),
        "the callback's method must be the platform family constant"
    );
    assert!(
        GOVERNED_SEAM
            .contains("pub const PLATFORM_METHOD_REPOSITORY_CREATE: &str = \"repository.create\";"),
        "the platform family constant must stay `repository.create`, which is \
         what `apps/auth-grpc/src/service-rebac.ts` exact-matches"
    );

    // CR-029 freezes `authorization_id` to the operation UUID and the verifier
    // requires the equality rather than tolerating it, so both fields come from
    // the one value.
    assert_eq!(
        attach
            .matches("witness.operation_id.to_vec().into();")
            .count(),
        2,
        "`operation_id` and `authorization_id` must both carry the operation \
         UUID; CR-029 freezes them equal and the verifier enforces it"
    );
}

/// WP-116: the claim is attached only when there is a claim, and the
/// acknowledgement is required before the mutation.
///
/// Two halves of one contract. A legacy or direct create must leave the request
/// byte-identical to what it sends today, or it trips the verifier's governed
/// branch with no claim to match and loses the catalog path it depends on. And a
/// governed create must not proceed on an unacknowledged claim: the response is
/// the only evidence Lore gets that the platform recognised THIS claim rather
/// than merely permitting A create.
#[test]
fn the_claim_is_attached_only_when_present_and_its_acknowledgement_is_required() {
    let callback = rust_fn_body(
        CREATE_HANDLER,
        "pub(crate) async fn repository_create_auth_resource(",
    );
    assert!(
        callback.contains("if let Some(witness) = witness {\n        attach_create_claim("),
        "the claim must be attached only under a present witness, so an \
         ungoverned create keeps sending resource_id and resource_name alone"
    );
    assert_eq!(
        CREATE_HANDLER.matches("attach_create_claim(").count(),
        2,
        "there must be exactly one definition and one call site of the attach \
         helper; a second call site is a second place a field can be missed"
    );
    assert!(
        callback.contains("verify_create_acknowledgement(response.into_inner(), witness)"),
        "a governed create must verify the acknowledgement before returning"
    );

    let verify = rust_fn_body(CREATE_HANDLER, "fn verify_create_acknowledgement(");
    for field in ["claim_id", "claim_revision", "claim_verification_witness"] {
        assert!(
            verify.contains(&format!("response.{field}")),
            "the acknowledgement check must compare `{field}`; an unchecked \
             field is a field the platform never had to echo"
        );
    }
    let acknowledgement = proto_message(REBAC_PROTO, "CreateResourceResponse");
    assert_eq!(
        proto_fields_from_tag(&acknowledgement, 1).len(),
        3,
        "the acknowledgement is three fields; a fourth needs checking too"
    );

    // An `AlreadyExists` answer carries no claim triple. Treating it as success
    // on the governed path would let the mutation open its transaction with no
    // acknowledgement at all, which is the one ordering this callback exists to
    // establish.
    assert!(
        callback.contains("err.code() == Code::AlreadyExists && witness.is_some()"),
        "a governed create must not read AlreadyExists as an acknowledgement"
    );
}

/// WP-116: the claim witness reaches the callback only through carriage, and
/// only for a mediated operation.
#[test]
fn the_claim_witness_is_mediated_only_and_required_when_mediated() {
    assert!(
        GOVERNED_SEAM.contains("claim-witness carriage requires mediated-scope carriage"),
        "claim-witness carriage must be refused without mediated-scope \
         carriage; it names a platform claim only a mediated operation has"
    );
    assert!(
        GOVERNED_SEAM
            .contains("mediated governed repository create is missing claim-witness carriage"),
        "a mediated governed create must refuse when the claim witness is \
         absent, before the ReBAC callback and before any receipt is consumed"
    );

    // The witness is assembled once, at the seam, so no handler can build a
    // second one from different provenances.
    assert_eq!(
        GOVERNED_SEAM
            .matches("Ok(Some(GovernedCreateWitness {")
            .count(),
        1,
        "the attached claim must be assembled at exactly one place"
    );
    assert!(
        !CREATE_HANDLER.contains("GovernedCreateWitness {"),
        "handlers must consume the assembled witness, never build one"
    );
}

/// WP-116: one method string for a governed create, not two that must agree.
///
/// The regression this pins actually happened, against a live cell. The receipt
/// binding carried the gRPC path and the ReBAC callback carried the platform
/// family constant, so the platform's single stored method could satisfy only
/// one of them: the callback acknowledged and then `ReceiptRow::matches` failed,
/// and the create died at the coordinator with `ADMISSION_REJECTED_V1` after the
/// authorization side effect had already run. The two wire versions also
/// disagreed with each other, so one operation id was consumable only by
/// whichever version the caller happened to reach.
///
/// The fix was to delete the choice rather than correct it, so this pin is about
/// the SHAPE, not the value: `GovernedRepositoryCreate::prepare` must take no
/// method argument, and the seam must bind the same constant it sends.
#[test]
fn a_governed_create_binds_the_same_method_it_sends_on_the_callback() {
    let seam = rust_fn_body(GOVERNED_SEAM, "impl GovernedRepositoryCreate {");
    assert!(
        seam.contains("admitted.into_governed(PLATFORM_METHOD_REPOSITORY_CREATE, digest)"),
        "the create seam must bind the platform family constant; binding a \
         handler-supplied gRPC path is what made the receipt match fail after \
         the callback had already succeeded"
    );

    // A `method` parameter is the mechanism the two values diverged through, so
    // its absence is the property, not merely today's argument being right.
    let signature = {
        let start = seam
            .find("pub fn prepare(")
            .expect("the create seam must expose `prepare`");
        let rest = &seam[start..];
        let end = rest
            .find(") -> Result<Option<Self>, Status> {")
            .expect("`prepare`'s signature must terminate");
        &rest[..end]
    };
    assert!(
        !signature.contains("method"),
        "`GovernedRepositoryCreate::prepare` must take no method argument: both \
         wire versions are one operation family to the platform, and a \
         per-handler argument is how v0 and v1 came to bind different methods \
         for one operation id"
    );

    // Neither create handler may name a method at its `prepare` call.
    for (label, source) in [
        ("v0 repository create", CREATE_HANDLER),
        (
            "v1 repository create",
            include_str!("../src/grpc/repository/v1/repository_create.rs"),
        ),
    ] {
        let start = source
            .find("GovernedRepositoryCreate::prepare(")
            .unwrap_or_else(|| panic!("{label} must call the shared create seam"));
        let rest = &source[start..];
        let end = rest
            .find(")?")
            .unwrap_or_else(|| panic!("{label} call must terminate"));
        let call = &rest[..end];
        assert!(
            !call.contains('"'),
            "{label} must pass no method string to the create seam; found: {call}"
        );
    }
}

/// The governed delete seam binds its method the same way, before it is wired.
///
/// The create seam paid for this lesson against a live cell. Delete has no
/// production call site yet, so there is no defect here to fix — the point is
/// that there is no `method` argument for the wiring change to fill in wrongly.
#[test]
fn the_governed_delete_seam_binds_its_method_by_construction_too() {
    let seam = rust_fn_body(GOVERNED_SEAM, "impl GovernedRepositoryDelete {");
    assert!(
        seam.contains("admitted.into_governed(PLATFORM_METHOD_REPOSITORY_DELETE, digest)"),
        "the delete seam must bind the platform family constant"
    );
    let signature = {
        let start = seam
            .find("pub fn prepare(")
            .expect("the delete seam must expose `prepare`");
        let rest = &seam[start..];
        let end = rest
            .find(") -> Result<Option<Self>, Status> {")
            .expect("`prepare`'s signature must terminate");
        &rest[..end]
    };
    assert!(
        !signature.contains("method"),
        "`GovernedRepositoryDelete::prepare` must take no method argument"
    );
    assert!(
        GOVERNED_SEAM
            .contains("pub const PLATFORM_METHOD_REPOSITORY_DELETE: &str = \"repository.delete\";"),
        "the delete family constant must stay `repository.delete`, which is \
         `REPOSITORY_DELETE_METHOD` in the platform's dispatch module"
    );
}

/// The four metadata-CAS sites still bind their own gRPC path, and this test
/// exists to make that state impossible to forget.
///
/// It is a **tracking** pin, so it is written to fail the moment the gap closes
/// rather than to bless the gap. Two things trip it: a site that stops passing a
/// gRPC-path literal, and a Lore-side platform method constant appearing for
/// either family. Whoever does the fix updates this test as part of it, which is
/// the point.
///
/// # Why these four were not fixed with create and delete
///
/// The defect is identical — `repository_metadata_set` and `branch_metadata_set`
/// each bind one method on v0 and a different one on v1, so one operation id is
/// consumable only by whichever wire version the caller reaches. The value is
/// not. The platform names a method constant per family and today it has exactly
/// two, `repository.create` and `repository.delete`
/// (`packages/control-plane/src/repository-operation-dispatch.ts`). Nothing
/// names a metadata-CAS method, and the intent families in
/// `repository-operation-intent.ts` are canonical-digest domain separators in a
/// different vocabulary, not method strings. Guessing one would produce a
/// mismatch that looks fixed and fails identically at the coordinator, after the
/// authorization side effect — which is exactly how the create defect presented.
///
/// Their shared seam, `GovernedMetadataCas`, genuinely serves two families, so
/// its fix is a constant per family rather than the deleted parameter the
/// single-family seams could take.
///
/// `branch_push` (`branch_push_commit`) and `obliterate` (`begin_obliterate`)
/// are deliberately NOT listed: each binds one string across both wire versions,
/// so neither carries the divergence. Whether those two strings match the
/// platform's authorization rows is a separate, unverified question and not
/// something a source-level pin can answer.
#[test]
fn the_four_metadata_cas_sites_still_bind_a_per_handler_grpc_path() {
    let divergent: [(&str, &str, &str); 4] = [
        (
            "v0 repository metadata set",
            include_str!("../src/grpc/handlers/repository_metadata_set.rs"),
            "\"lore.RepositoryService/RepositoryMetadataSet\"",
        ),
        (
            "v1 repository metadata set",
            include_str!("../src/grpc/repository/v1/repository_metadata_set.rs"),
            "\"lore.repository.v1.RepositoryService/RepositoryMetadataSet\"",
        ),
        (
            "v0 branch metadata set",
            include_str!("../src/grpc/handlers/branch_metadata_set.rs"),
            "\"lore.RevisionService/BranchMetadataSet\"",
        ),
        (
            "v1 branch metadata set",
            include_str!("../src/grpc/revision/v1/branch_metadata_set.rs"),
            "\"lore.revision.v1.RevisionService/BranchMetadataSet\"",
        ),
    ];
    for (label, source, literal) in divergent {
        assert!(
            source.contains(literal),
            "{label} no longer binds {literal}. If you fixed the v0/v1 method \
             divergence, that is the intended outcome and this tracking pin is \
             now stale: update it, and check that its sibling version was fixed \
             in the same change rather than left behind."
        );
    }

    // A Lore-side constant for either family means the platform named the
    // value, which is the one thing that was missing.
    for absent in [
        "PLATFORM_METHOD_REPOSITORY_METADATA",
        "PLATFORM_METHOD_BRANCH_METADATA",
    ] {
        assert!(
            !GOVERNED_SEAM.contains(absent),
            "{absent} exists, so the platform has named this family's method. \
             Bind it at both wire versions and retire this pin; leaving one \
             version on its gRPC path is the defect, not half of a fix."
        );
    }
}

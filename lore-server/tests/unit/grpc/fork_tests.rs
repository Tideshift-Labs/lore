// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the fork's tests of `lore_server::grpc` (its
//! claim-reader gates and the CR-029 domain-error mapping), moved out of the
//! inline `grpc::tests` module when upstream set `[lib] test = false`.

use std::str::FromStr;

use lore_base::types::Context;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::grpc::*;
use tonic::Code;
use tonic::Extensions;
use tonic::Status;

/// Fork extensions carrying one verified token with `resources`.
fn fork_extensions_with(subject: &str, resources: Vec<(&str, &[&str])>) -> Extensions {
    let mut extensions = Extensions::new();
    extensions.insert(AuthorizationToken {
        user_id: subject.to_string(),
        issuer: "issuer".to_string(),
        resources: Some(
            resources
                .into_iter()
                .map(|(resource_id, permissions)| ResourcePermission {
                    resource_id: resource_id.to_string(),
                    permission: permissions.iter().map(|p| p.to_string()).collect(),
                })
                .collect(),
        ),
        ..Default::default()
    });
    extensions
}

const FORK_REPO: &str = "0194b726b34e72b0b45550b88a967076";

fn fork_repo() -> RepositoryId {
    Context::from_str(FORK_REPO).unwrap().into()
}

/// FORK-LOCAL: the branch-creator rule keeps the pre-v0.10.0 reader. Only
/// the FIRST exact `urc-<repo>` entry counts. `urc-*` and later exact
/// entries do not, although upstream's `is_owner_or_admin` now honours both.
#[test]
fn branch_creator_rule_reads_only_the_first_exact_entry() {
    let exact = format!("urc-{FORK_REPO}");
    let other = "urc-0192ae48ccf17060bc1ba9d04f6acb2f";

    let wildcard_owner = fork_extensions_with("s", vec![("urc-*", &["owner"])]);
    assert!(!can_set_branch_creator(&wildcard_owner, fork_repo()));
    assert!(is_owner_or_admin(&wildcard_owner, fork_repo()));

    let later_exact_admin =
        fork_extensions_with("s", vec![(&exact, &["read"]), (&exact, &["admin"])]);
    assert!(!can_set_branch_creator(&later_exact_admin, fork_repo()));
    assert!(is_owner_or_admin(&later_exact_admin, fork_repo()));

    let exact_owner_after_others = fork_extensions_with(
        "s",
        vec![
            ("urc-*", &["read"]),
            (other, &["owner"]),
            (&exact, &["owner"]),
        ],
    );
    assert!(can_set_branch_creator(
        &exact_owner_after_others,
        fork_repo()
    ));

    let exact_admin = fork_extensions_with("s", vec![(&exact, &["admin"])]);
    assert!(can_set_branch_creator(&exact_admin, fork_repo()));

    assert!(!can_set_branch_creator(&Extensions::new(), fork_repo()));
}

/// FORK-LOCAL: the write gate and both force-unlock gates keep their
/// pre-v0.10.0 semantics, which already merged every matching entry and
/// honoured `urc-*`.
#[test]
fn fork_write_and_force_unlock_gates_honour_wildcard_and_merge_entries() {
    let exact = format!("urc-{FORK_REPO}");

    let wildcard = fork_extensions_with("me", vec![("urc-*", &["read", "write", "owner"])]);
    assert!(require_permission(&wildcard, fork_repo(), "write", true).is_ok());
    assert!(can_force_unlock(&wildcard, fork_repo()));
    assert!(is_self_force_unlock(&wildcard, fork_repo(), "me"));

    let split = fork_extensions_with("me", vec![(&exact, &["read"]), (&exact, &["write"])]);
    assert!(require_permission(&split, fork_repo(), "write", true).is_ok());
    assert!(is_self_force_unlock(&split, fork_repo(), "me"));
    assert!(!can_force_unlock(&split, fork_repo()));

    let read_only = fork_extensions_with("me", vec![(&exact, &["read"])]);
    assert_eq!(
        require_permission(&read_only, fork_repo(), "write", true)
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}

mod domain_error_mapping_tests {
    use lore_postgres::domain::DomainError;
    use lore_postgres::domain::coordinator;
    use lore_transport::error::ProtocolError;

    use super::*;

    #[test]
    fn invalid_input_maps_to_invalid_argument() {
        let status = map_domain_error_to_status(&DomainError::InvalidInput("bad".into()));
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn not_ready_maps_to_failed_precondition() {
        let status = map_domain_error_to_status(&DomainError::NotReady("not ready".into()));
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[test]
    fn domain_key_bypass_maps_to_failed_precondition() {
        let status = map_domain_error_to_status(&DomainError::DomainKeyBypass("bypass".into()));
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    // Contention and outcome-unknown share `ABORTED` by CR-029's explicit
    // choice, so the message is the only discriminator a client has — it
    // must be exact-comparable, never the raw SQLSTATE context string the
    // error was constructed with (a client should never have to parse
    // prose to tell "provably rolled back" from "may have committed").
    #[test]
    fn contention_maps_to_aborted_with_the_fixed_detail_not_the_sqlstate_context() {
        let sqlstate_context = "SQLSTATE 40001: could not serialize access";
        let status = map_domain_error_to_status(&DomainError::Contention(sqlstate_context.into()));

        assert_eq!(status.code(), Code::Aborted);
        assert_eq!(status.message(), DOMAIN_CONTENTION_DETAIL);
        assert!(!status.message().contains(sqlstate_context));
    }

    #[test]
    fn transient_maps_to_resource_exhausted_without_leaking_the_inner_detail() {
        let sqlstate_context = "SQLSTATE 08006: connection failure";
        let status = map_domain_error_to_status(&DomainError::Transient(sqlstate_context.into()));

        assert_eq!(status.code(), Code::ResourceExhausted);
        assert!(!status.message().contains(sqlstate_context));
    }

    #[test]
    fn outcome_unknown_maps_to_aborted_with_the_fixed_detail() {
        let status = map_domain_error_to_status(&DomainError::OutcomeUnknown("lost ack".into()));
        assert_eq!(status.code(), Code::Aborted);
        assert_eq!(status.message(), DOMAIN_OUTCOME_UNKNOWN_DETAIL);
    }

    // The two `ABORTED` details must never collide, or a client can no
    // longer tell contention (provably rolled back, safe to retry) from
    // outcome-unknown (may have committed, must refetch first) apart.
    #[test]
    fn domain_contention_detail_and_outcome_unknown_detail_are_distinct() {
        assert_ne!(DOMAIN_CONTENTION_DETAIL, DOMAIN_OUTCOME_UNKNOWN_DETAIL);
    }

    #[test]
    fn internal_maps_to_internal_without_leaking_the_inner_detail() {
        let secret_detail = "connection string password=hunter2";
        let status = map_domain_error_to_status(&DomainError::Internal(secret_detail.into()));
        assert_eq!(status.code(), Code::Internal);
        assert!(!status.message().contains(secret_detail));
    }

    #[test]
    fn generation_and_cas_mismatch_reasons_map_to_aborted() {
        for reason in [
            coordinator::GENERATION_MISMATCH_V1,
            coordinator::CAS_MISMATCH_V1,
        ] {
            let status = map_domain_rejection_to_status(reason);
            assert_eq!(status.code(), Code::Aborted);
        }
    }

    // Indistinguishability is the security property under test: a
    // tombstoned repository and one that never existed must be
    // byte-identical NOT_FOUND responses, or a caller could use the
    // difference to probe for a repository's prior existence.
    #[test]
    fn tombstoned_and_never_existed_are_byte_identical_not_found_responses() {
        let tombstoned = map_domain_rejection_to_status(coordinator::TOMBSTONED_V1);
        let not_found = map_domain_rejection_to_status(coordinator::NOT_FOUND_V1);

        assert_eq!(tombstoned.code(), Code::NotFound);
        assert_eq!(tombstoned.message(), DOMAIN_REPOSITORY_NOT_FOUND_DETAIL);
        assert_eq!(tombstoned.code(), not_found.code());
        assert_eq!(tombstoned.message(), not_found.message());
    }

    #[test]
    fn name_taken_and_fingerprint_mismatch_reasons_map_to_already_exists() {
        for reason in [
            coordinator::NAME_TAKEN_V1,
            coordinator::FINGERPRINT_MISMATCH_V1,
        ] {
            let status = map_domain_rejection_to_status(reason);
            assert_eq!(status.code(), Code::AlreadyExists);
        }
    }

    #[test]
    fn admission_rejected_maps_to_failed_precondition() {
        let status = map_domain_rejection_to_status(coordinator::ADMISSION_REJECTED_V1);
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[test]
    fn unrecognised_reason_maps_to_internal() {
        let status = map_domain_rejection_to_status("SOME_UNKNOWN_REASON_V99");
        assert_eq!(status.code(), Code::Internal);
    }

    // R-BLOCK-1, CR-029: an indeterminate database commit must map to a
    // gRPC code whose `From<tonic::Status>` arm in `lore-transport` is not
    // `Disconnected`. `lore-transport/src/error.rs` folds `Unavailable`
    // AND `Unknown` into `ProtocolError::Disconnected`, and
    // `lore-transport/src/grpc/mod.rs` reissues the operation on exactly
    // that variant (bounded by `MAX_RECONNECTS_PER_OP`) — i.e. it would
    // replay a mutation whose outcome is unknown. This is the most
    // important test in this batch: it is the regression pin for that
    // rule, not merely a mapping check.
    #[test]
    fn outcome_unknown_never_maps_into_the_transport_replay_arm() {
        let status = map_domain_error_to_status(&DomainError::OutcomeUnknown("lost ack".into()));

        let protocol_error = ProtocolError::from(status);

        assert!(!matches!(protocol_error, ProtocolError::Disconnected(_)));

        // The guard that gives the assertion above its teeth: without these
        // two positive checks, the negative assertion would still pass if
        // someone silently changed the transport's own mapping too.
        assert!(matches!(
            ProtocolError::from(Status::new(Code::Unknown, "")),
            ProtocolError::Disconnected(_)
        ));
        assert!(matches!(
            ProtocolError::from(Status::new(Code::Unavailable, "")),
            ProtocolError::Disconnected(_)
        ));
    }
}

/// Owner ruling D8: `ForceUnlock`'s second authorization arm. Follows the
/// `user_permissions_*` fixture style above (build `Extensions`,
/// insert an `AuthorizationToken` directly rather than a real JWT).
///
/// `is_self_force_unlock` takes a `repository: RepositoryId` conjunct too
/// (fail-closed: the caller must hold `read` on THIS repository, or naming
/// oneself against an arbitrary repository id would leak whether fenced
/// routing is armed there via `fenced_call`'s later disclosures). Every
/// case below is explicit about which repository the token's permission
/// grant covers, rather than relying on a wildcard everywhere, so the
/// repository conjunct is actually exercised and not accidentally always
/// satisfied.
mod is_self_force_unlock_tests {
    use super::*;

    fn repository(hex: &str) -> RepositoryId {
        Context::from_str(hex).unwrap().into()
    }

    // The repository the token's grants below are scoped to, unless a case
    // says otherwise.
    fn granted_repository() -> RepositoryId {
        repository("0194b726b34e72b0b45550b88a967076")
    }

    // A different repository the token carries no grant for at all.
    fn ungranted_repository() -> RepositoryId {
        repository("0192ae48ccf17060bc1ba9d04f6acb2f")
    }

    fn extensions_with_token(
        issuer: &str,
        user_id: &str,
        permissions_for_granted_repo: &[&str],
    ) -> Extensions {
        let mut extensions = Extensions::new();
        let mut token = AuthorizationToken {
            issuer: issuer.to_owned(),
            user_id: user_id.to_owned(),
            ..Default::default()
        };
        if !permissions_for_granted_repo.is_empty() {
            token.resources = Some(vec![ResourcePermission {
                resource_id: format!("urc-{}", granted_repository()),
                permission: permissions_for_granted_repo
                    .iter()
                    .map(|p| p.to_string())
                    .collect(),
            }]);
        }
        extensions.insert(token);
        extensions
    }

    #[test]
    fn read_permission_alone_is_enough_without_owner_or_migrate() {
        // The positive half of the repository conjunct: `read` alone --
        // no `owner`, no `migrate` -- is sufficient, because this arm is
        // about owning the lock, not about administrative rank.
        let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
        assert!(is_self_force_unlock(
            &extensions,
            granted_repository(),
            "user-1"
        ));
    }

    #[test]
    fn subject_mismatch_does_not_self_authorize() {
        let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
        assert!(!is_self_force_unlock(
            &extensions,
            granted_repository(),
            "someone-else"
        ));
    }

    #[test]
    fn empty_target_owner_does_not_self_authorize() {
        // The caller carries a real, non-empty subject and read permission
        // on this exact repository -- everything else about the call would
        // otherwise clear the gate -- so an empty `target_owner` is the
        // ONLY reason this must return false. Naming nobody must not be
        // read as naming oneself.
        let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
        assert!(!is_self_force_unlock(&extensions, granted_repository(), ""));
    }

    #[test]
    fn empty_token_user_id_does_not_self_authorize() {
        // Defense in depth over the subject-mismatch case above: a token
        // that carries no subject at all must never self-authorize a named
        // target, whatever that target string is. Read permission is
        // granted here specifically so this test exercises the user_id
        // check itself rather than failing earlier on the permission gate.
        let extensions = extensions_with_token("https://issuer.example", "", &["read"]);
        assert!(!is_self_force_unlock(
            &extensions,
            granted_repository(),
            "someone"
        ));
    }

    #[test]
    fn no_read_permission_on_the_named_repository_does_not_self_authorize() {
        // Regression case for the repository conjunct: the caller names
        // themselves correctly, but the repository passed in is one their
        // token carries NO grant for at all (their `read` grant covers a
        // different repository). Without the `has_required_permission(
        // .., "read")` check, a same-subject match alone would clear this
        // gate for ANY repository id the caller can name, disclosing
        // fenced-routing/cell state for repositories the caller has no
        // standing to be answered about.
        let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
        assert!(!is_self_force_unlock(
            &extensions,
            ungranted_repository(),
            "user-1"
        ));
    }

    #[test]
    fn auth_off_does_not_self_authorize() {
        // No `AuthorizationToken` in extensions at all -- the auth-disabled
        // dev/CI shape. Absence of a verified principal must never be read
        // as "the caller is whoever they name".
        let extensions = Extensions::new();
        assert!(!is_self_force_unlock(
            &extensions,
            granted_repository(),
            "user-1"
        ));
    }
}

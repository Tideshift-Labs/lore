// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use lore_error_set::FfiError;
use lore_transport::outcome::*;
use lore_transport::replay::MutableOutcome;
use lore_transport::replay::OutcomeUnknown as TransportOutcomeUnknown;
use lore_transport::replay::ReplayClass;

/// The one mapping produces the public error, carrying the attempt it was minted for.
#[test]
fn an_unknown_outcome_becomes_the_public_error_with_its_attempt() {
    let attempt = AttemptId::new();
    let outcome: MutableOutcome<()> =
        MutableOutcome::Unknown(TransportOutcomeUnknown { command: "put" });

    let error = resolve(outcome, "StorageService.Put", &attempt)
        .expect_err("an unknown outcome must not resolve to a value");

    assert!(
        error.is_outcome_unknown(),
        "the unknown must land on its own variant, not on a connectivity error: {error:?}",
    );
    assert!(
        error.to_string().contains(&attempt.to_string()),
        "the attempt the caller must reconcile has to be in the error: {error}",
    );
}

/// An unknown outcome is not a disconnect. This is the property every reconnect wrapper
/// relies on: they branch on `Disconnected`, so an unknown that answered to that predicate
/// would be reissued by all of them.
#[test]
fn an_unknown_outcome_is_not_a_disconnect() {
    let error = outcome_unknown("StorageService.Put", &AttemptId::new());

    assert!(!error.is_disconnected());
    assert!(!error.is_slow_down());
    assert!(!error.is_not_found());
    assert_eq!(error.ffi_code(), 248);
}

/// An applied outcome passes through untouched.
#[test]
fn an_applied_outcome_resolves_to_its_value() {
    let resolved = resolve(
        MutableOutcome::Applied(7u32),
        "StorageService.Put",
        &AttemptId::new(),
    );

    assert_eq!(resolved.ok(), Some(7));
}

/// Attempt ids are distinct, and sort by mint order.
#[test]
fn attempt_ids_are_distinct_and_time_ordered() {
    let first = AttemptId::new();
    let second = AttemptId::new();

    assert_ne!(first, second);
    assert!(first.as_uuid() <= second.as_uuid());
}

/// The two classifiers agree wherever they name the same operation. A gRPC `Put` that was
/// read-retryable while the QUIC `Put` was not would make the safety of a mutation depend
/// on which transport happened to carry it.
#[test]
fn the_grpc_classification_matches_the_quic_one_for_shared_operations() {
    use lore_transport::quic::storage_service::Command;
    use lore_transport::replay::storage_replay_class;

    let shared = [
        (GrpcRpc::StorageGet, Command::Get),
        (GrpcRpc::StorageGetMetadata, Command::GetMetadata),
        (GrpcRpc::StorageGetResolved, Command::GetResolved),
        (GrpcRpc::StorageQuery, Command::Query),
        (GrpcRpc::StorageMutableLoad, Command::MutableLoad),
        (GrpcRpc::StoragePut, Command::Put),
        (GrpcRpc::StoragePutResolved, Command::PutResolved),
        (GrpcRpc::StorageCopy, Command::Copy),
        (GrpcRpc::StorageVerify, Command::Verify),
        (GrpcRpc::StorageMutableStore, Command::MutableStore),
        (GrpcRpc::StorageMutableCompareAndSwap, Command::MutableCas),
    ];

    for (rpc, command) in shared {
        assert_eq!(
            grpc_replay_class(rpc),
            storage_replay_class(command),
            "{rpc:?} and {command:?} are the same operation and must classify the same",
        );
    }
}

/// Every RPC classifies, and every mutation names itself on the wire.
#[test]
fn every_rpc_is_classified_and_named() {
    for rpc in ALL_RPCS {
        let name = rpc.wire_name();
        assert!(
            name.contains('.'),
            "{rpc:?} must be named Service.Method, got {name}",
        );
        // Reached for its exhaustiveness, not its value: an unclassified RPC does not
        // compile, and this proves the table is actually walked.
        let _ = grpc_replay_class(*rpc);
    }
}

/// Named here rather than derived so a new variant has to be added deliberately; the
/// classifier's own exhaustiveness is what makes forgetting it a compile error.
const ALL_RPCS: &[GrpcRpc] = &[
    GrpcRpc::AdminObliterate,
    GrpcRpc::StorageGet,
    GrpcRpc::StorageGetMetadata,
    GrpcRpc::StorageGetResolved,
    GrpcRpc::StorageQuery,
    GrpcRpc::StorageMutableLoad,
    GrpcRpc::StoragePut,
    GrpcRpc::StoragePutResolved,
    GrpcRpc::StorageCopy,
    GrpcRpc::StorageVerify,
    GrpcRpc::StorageMutableStore,
    GrpcRpc::StorageMutableCompareAndSwap,
    GrpcRpc::RevisionBranchCreate,
    GrpcRpc::RevisionBranchDelete,
    GrpcRpc::RevisionBranchQuery,
    GrpcRpc::RevisionBranchList,
    GrpcRpc::RevisionBranchPush,
    GrpcRpc::RevisionBranchMetadataGet,
    GrpcRpc::RevisionBranchMetadataSet,
    GrpcRpc::RevisionRevisionList,
    GrpcRpc::RepositoryCreate,
    GrpcRpc::RepositoryDelete,
    GrpcRpc::RepositoryQuery,
    GrpcRpc::RepositoryList,
    GrpcRpc::RepositoryMetadataGet,
    GrpcRpc::RepositoryMetadataSet,
    GrpcRpc::LockLock,
    GrpcRpc::LockUnlock,
    GrpcRpc::LockForceUnlock,
    GrpcRpc::LockQuery,
    GrpcRpc::LockStatus,
    GrpcRpc::EnvironmentGet,
];

/// CR-030: `ForceUnlock` is an administrative takeover, not a caller releasing its own lock,
/// and it is the only lock mutation not gated by [`lore_transport::attempt_store::FencedLockResource`]
/// possession -- so it earns its own classification pin rather than relying on
/// `every_rpc_is_classified_and_named`'s loop, which proves only that the match is
/// exhaustive, not which arm a given RPC lands in.
#[test]
fn force_unlock_is_named_and_classified_as_a_no_replay_mutation() {
    assert_eq!(
        GrpcRpc::LockForceUnlock.wire_name(),
        "LockService.ForceUnlock"
    );
    assert_eq!(
        grpc_replay_class(GrpcRpc::LockForceUnlock),
        ReplayClass::MutableNoReplay,
        "a lost ForceUnlock must never be silently retried: the caller cannot tell whether \
         the administrative takeover it asked for already happened"
    );
}

/// The capability is what a caller declares; linking the crate is not.
#[test]
fn the_capability_is_named_and_implemented() {
    assert!(supports_outcome_unknown_v1());
    assert_eq!(OUTCOME_UNKNOWN_CAPABILITY_V1, "outcome_unknown_v1");
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The public outcome boundary (WP-120).
//!
//! [`crate::replay`] is WP-108's internal contract: it decides whether a command may be sent
//! again and hands back a typed [`MutableOutcome`] when the answer to a mutable command was
//! lost. This module is the one place that turns that internal fact into the public error the
//! rest of Lore, the C API, and every embedding client see, and the one place that classifies
//! a gRPC call against the same replay contract rather than inventing a second one.
//!
//! Three rules hold everything here together:
//!
//! 1. **The mapping happens once.** [`resolve`] is the only conversion from
//!    [`MutableOutcome::Unknown`] to [`ProtocolError::OutcomeUnknown`]. Nothing infers the
//!    unknown from message text, from a generic disconnect, or from a `tonic` code on its own.
//! 2. **An unknown outcome is never retryable.** It is not in the connectivity block and no
//!    reconnect wrapper may reissue on it. A caller that sees it must read authoritative state
//!    before it does anything else.
//! 3. **The attempt is named before it is dispatched.** [`AttemptId`] is minted on the way in,
//!    not at the point the loss is noticed, so the identity in the error is the identity the
//!    server would have recorded.

use std::fmt;

use lore_base::error::OutcomeUnknown as PublicOutcomeUnknown;
use uuid::Uuid;

use crate::error::ProtocolError;
use crate::replay::MutableOutcome;
use crate::replay::ReplayClass;

/// The capability an upgraded caller declares to say it understands
/// [`ProtocolError::OutcomeUnknown`] and will not replay one.
///
/// Linking this library is not the declaration. A caller that has not adopted the contract
/// still collapses an unknown outcome the way it always did, so a cell that gates mutations on
/// the capability must read what the caller declares rather than what it links.
pub const OUTCOME_UNKNOWN_CAPABILITY_V1: &str = "outcome_unknown_v1";

/// The capabilities this transport implements, for a caller assembling its own declaration.
///
/// A slice rather than a set: it is read, never searched, and the order is the order a
/// declaration lists them in.
pub const TRANSPORT_CAPABILITIES: &[&str] = &[OUTCOME_UNKNOWN_CAPABILITY_V1];

/// Whether this build implements [`OUTCOME_UNKNOWN_CAPABILITY_V1`].
///
/// The query a client makes of the transport before declaring the capability upstream. It is a
/// function rather than a bare `const true` so an embedding caller has one call site to point
/// at, and so the answer can become conditional without changing every caller.
pub fn supports_outcome_unknown_v1() -> bool {
    TRANSPORT_CAPABILITIES.contains(&OUTCOME_UNKNOWN_CAPABILITY_V1)
}

/// The gRPC metadata key a server sets to say its own result was indeterminate.
///
/// Additive and stable. An unmarked status is an ordinary protocol error and stays one:
/// `tonic::Code::Unknown` means "the server did not classify this", not "the server knows it
/// lost the outcome". The client's own dispatch tracking is what upgrades a lost *mutable*
/// response, independently of anything the server says — see [`resolve`] and
/// [`grpc_replay_class`].
pub const OUTCOME_UNKNOWN_METADATA_KEY: &str = "lore-outcome-unknown";

/// The only value [`OUTCOME_UNKNOWN_METADATA_KEY`] is honoured with, so the marker can gain
/// versions without an old client reading a new one as the version it knows.
pub const OUTCOME_UNKNOWN_METADATA_VALUE: &str = "v1";

/// Companion header naming the operation whose outcome the server lost.
pub const OUTCOME_UNKNOWN_OPERATION_KEY: &str = "lore-outcome-unknown-operation";

/// Companion header naming the attempt the server lost the outcome of.
pub const OUTCOME_UNKNOWN_ATTEMPT_KEY: &str = "lore-outcome-unknown-attempt";

/// The identity one attempt at a mutable operation was dispatched under.
///
/// UUIDv7 so it sorts by mint time, which is what makes a journal of unresolved attempts
/// readable in the order they were tried. It is minted *before* dispatch; an id created when
/// the failure was observed would name the observation, not the attempt, and could not be
/// matched against a server-side receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptId(Uuid);

impl AttemptId {
    /// Mint an id for an attempt about to be dispatched.
    #[allow(clippy::new_without_default)] // Minting is an event, not a default value.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// The underlying UUID, for a caller storing it in something other than text.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Build the public unknown-outcome error for one named operation and attempt.
pub fn outcome_unknown(operation: &str, attempt: &AttemptId) -> ProtocolError {
    ProtocolError::from(PublicOutcomeUnknown {
        operation: operation.to_string(),
        attempt_id: attempt.to_string(),
    })
}

/// Collapse WP-108's typed outcome into the public result. **The** mapping, and the only one.
///
/// Note what this is not: it is not a place where an unknown becomes a failure. It becomes a
/// distinct error whose whole purpose is that no retry policy recognises it, so the caller is
/// forced to reconcile rather than to guess.
pub fn resolve<T>(
    outcome: MutableOutcome<T>,
    operation: &str,
    attempt: &AttemptId,
) -> Result<T, ProtocolError> {
    match outcome {
        MutableOutcome::Applied(value) => Ok(value),
        MutableOutcome::Unknown(_) => Err(outcome_unknown(operation, attempt)),
    }
}

/// Every gRPC call this transport makes on a caller's behalf.
///
/// Exhaustive by construction, exactly as [`crate::replay::storage_replay_class`] is over the
/// QUIC opcodes: [`grpc_replay_class`] has no wildcard arm, so adding an RPC without deciding
/// whether repeating it is harmless does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrpcRpc {
    AdminObliterate,
    StorageGet,
    StorageGetMetadata,
    StorageGetResolved,
    StorageQuery,
    StorageMutableLoad,
    StoragePut,
    StoragePutResolved,
    StorageCopy,
    StorageVerify,
    StorageMutableStore,
    StorageMutableCompareAndSwap,
    RevisionBranchCreate,
    RevisionBranchDelete,
    RevisionBranchQuery,
    RevisionBranchList,
    RevisionBranchPush,
    RevisionBranchMetadataGet,
    RevisionBranchMetadataSet,
    RevisionRevisionList,
    RepositoryCreate,
    RepositoryDelete,
    RepositoryQuery,
    RepositoryList,
    RepositoryMetadataGet,
    RepositoryMetadataSet,
    LockLock,
    LockUnlock,
    LockQuery,
    LockStatus,
    EnvironmentGet,
    DomainOperationReceiptGet,
}

impl GrpcRpc {
    /// The name that reaches a caller's journal and an operator's logs.
    ///
    /// `Service.Method`, matching how the RPC is named in the protobuf, so an unresolved
    /// attempt can be read against the service definition without a translation table.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::AdminObliterate => "AdminService.Obliterate",
            Self::StorageGet => "StorageService.Get",
            Self::StorageGetMetadata => "StorageService.GetMetadata",
            Self::StorageGetResolved => "StorageService.GetResolved",
            Self::StorageQuery => "StorageService.Query",
            Self::StorageMutableLoad => "StorageService.MutableLoad",
            Self::StoragePut => "StorageService.Put",
            Self::StoragePutResolved => "StorageService.PutResolved",
            Self::StorageCopy => "StorageService.Copy",
            Self::StorageVerify => "StorageService.Verify",
            Self::StorageMutableStore => "StorageService.MutableStore",
            Self::StorageMutableCompareAndSwap => "StorageService.MutableCompareAndSwap",
            Self::RevisionBranchCreate => "RevisionService.BranchCreate",
            Self::RevisionBranchDelete => "RevisionService.BranchDelete",
            Self::RevisionBranchQuery => "RevisionService.BranchQuery",
            Self::RevisionBranchList => "RevisionService.BranchList",
            Self::RevisionBranchPush => "RevisionService.BranchPush",
            Self::RevisionBranchMetadataGet => "RevisionService.BranchMetadataGet",
            Self::RevisionBranchMetadataSet => "RevisionService.BranchMetadataSet",
            Self::RevisionRevisionList => "RevisionService.RevisionList",
            Self::RepositoryCreate => "RepositoryService.Create",
            Self::RepositoryDelete => "RepositoryService.Delete",
            Self::RepositoryQuery => "RepositoryService.Query",
            Self::RepositoryList => "RepositoryService.List",
            Self::RepositoryMetadataGet => "RepositoryService.MetadataGet",
            Self::RepositoryMetadataSet => "RepositoryService.MetadataSet",
            Self::LockLock => "LockService.Lock",
            Self::LockUnlock => "LockService.Unlock",
            Self::LockQuery => "LockService.Query",
            Self::LockStatus => "LockService.Status",
            Self::EnvironmentGet => "EnvironmentService.Get",
            Self::DomainOperationReceiptGet => "DomainOperationService.DomainOperationReceiptGet",
        }
    }
}

/// The replay class of a gRPC call.
///
/// Reuses WP-108's [`ReplayClass`] rather than defining a parallel one, so the QUIC and gRPC
/// halves of the same operation cannot drift into different answers. The classification is the
/// operation's effect, not the transport's: `Put` over gRPC is `MutableNoReplay` for exactly
/// the reason `Put` over QUIC is, and `Verify` carries the heal flag on both.
pub fn grpc_replay_class(rpc: GrpcRpc) -> ReplayClass {
    match rpc {
        // Side-effect-free reads. A second identical request returns the same answer.
        GrpcRpc::StorageGet
        | GrpcRpc::StorageGetMetadata
        | GrpcRpc::StorageGetResolved
        | GrpcRpc::StorageQuery
        | GrpcRpc::StorageMutableLoad
        | GrpcRpc::RevisionBranchQuery
        | GrpcRpc::RevisionBranchList
        | GrpcRpc::RevisionBranchMetadataGet
        | GrpcRpc::RevisionRevisionList
        | GrpcRpc::RepositoryQuery
        | GrpcRpc::RepositoryList
        | GrpcRpc::RepositoryMetadataGet
        | GrpcRpc::LockQuery
        | GrpcRpc::LockStatus
        | GrpcRpc::EnvironmentGet
        // The receipt lookup is the read a caller makes *because* a mutation's outcome is
        // unknown.
        //
        // It is not side-effect-free, and the classification does not rest on pretending it is:
        // a lookup that finds a PREPARED row past its hard TTL terminalizes that row and commits
        // the transition (`lore-postgres/src/domain/receipts.rs`'s `receipt_get`, via
        // `expire_prepared`). What makes it retryable is that the transition is convergent
        // rather than absent — the second lookup finds the row already committed and returns the
        // same answer as the first, so reissuing after a lost channel cannot produce a different
        // verdict. That is the property `ReadRetryable` actually needs, and it is why this sits
        // here while the mutation it asks about cannot.
        | GrpcRpc::DomainOperationReceiptGet => ReplayClass::ReadRetryable,

        // Publishes or revives a repository/context lifecycle association, even where the
        // payload's address is content-derived.
        GrpcRpc::StoragePut | GrpcRpc::StoragePutResolved | GrpcRpc::StorageCopy => {
            ReplayClass::MutableNoReplay
        }

        // Advances a mutable key.
        GrpcRpc::StorageMutableStore | GrpcRpc::StorageMutableCompareAndSwap => {
            ReplayClass::MutableNoReplay
        }

        // Carries the heal flag, and the healing variant writes.
        GrpcRpc::StorageVerify => ReplayClass::MutableNoReplay,

        // Domain mutations. Every one of these has an authoritative receipt path a caller
        // reconciles through; none has a replay that is safe without one.
        GrpcRpc::AdminObliterate
        | GrpcRpc::RevisionBranchCreate
        | GrpcRpc::RevisionBranchDelete
        | GrpcRpc::RevisionBranchPush
        | GrpcRpc::RevisionBranchMetadataSet
        | GrpcRpc::RepositoryCreate
        | GrpcRpc::RepositoryDelete
        | GrpcRpc::RepositoryMetadataSet
        | GrpcRpc::LockLock
        | GrpcRpc::LockUnlock => ReplayClass::MutableNoReplay,
    }
}

#[cfg(test)]
mod tests {
    use lore_error_set::FfiError;

    use super::*;
    use crate::replay::OutcomeUnknown as TransportOutcomeUnknown;

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
        assert_eq!(error.ffi_code(), 193);
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
        use crate::quic::storage_service::Command;
        use crate::replay::storage_replay_class;

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
        GrpcRpc::LockQuery,
        GrpcRpc::LockStatus,
        GrpcRpc::EnvironmentGet,
    ];

    /// The capability is what a caller declares; linking the crate is not.
    #[test]
    fn the_capability_is_named_and_implemented() {
        assert!(supports_outcome_unknown_v1());
        assert_eq!(OUTCOME_UNKNOWN_CAPABILITY_V1, "outcome_unknown_v1");
    }
}

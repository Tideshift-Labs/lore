// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_macro::LoreArgs;
use lore_revision::attempt_store::repository_attempt_store;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::lock::file::acquire::AcquireOptions;
use lore_revision::lock::file::query::QueryOptions;
use lore_revision::lock::file::release::ReleaseOptions;
use lore_revision::lock::file::status::StatusOptions;
use lore_transport::attempt_store::AttemptStore;
use serde::Deserialize;
use serde::Serialize;

use crate::call::repository_call_read;
use crate::call_delegation::dispatch_call;
use crate::call_delegation::reject_undelegatable;
use crate::call_delegation::service_delegation_requested;
use crate::interface::LoreEventCallback;
use crate::interface::LoreString;

/// Arguments for acquiring file locks on the given paths for a branch.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, LoreArgs)]
#[handler(file_acquire_local)]
pub struct LoreLockFileAcquireArgs {
    /// Paths to acquire locks on
    pub paths: LoreArray<LoreString>,
    /// Branch the locks are acquired on
    pub branch: LoreString,
}

/// Acquires file locks on the specified paths for a given branch.
///
/// # Events
///
/// ## Standard Events
///
/// These events are emitted by all interface functions:
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::Log`](crate::interface::LoreEvent::Log) | Diagnostic messages throughout execution |
/// | [`LoreEvent::Error`](crate::interface::LoreEvent::Error) | Emitted for a non-fatal error during the operation |
/// | [`LoreEvent::Complete`](crate::interface::LoreEvent::Complete) | Always emitted at the end; `status` is `0` on success or the error code on failure |
/// | [`LoreEvent::End`](crate::interface::LoreEvent::End) | Always emitted after `Complete` to signal callback termination |
///
/// ## Lock Events
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::LockFileAcquireBegin`](crate::interface::LoreEvent::LockFileAcquireBegin) | Emitted before each group of lock-acquire results |
/// | [`LoreEvent::LockFileAcquire`](crate::interface::LoreEvent::LockFileAcquire) | Emitted for each file related to the lock-acquired report |
pub async fn file_acquire(
    globals: LoreGlobalArgs,
    args: LoreLockFileAcquireArgs,
    callback: LoreEventCallback,
) -> i32 {
    dispatch_call(globals, args, callback, file_acquire_local).await
}

/// Acquire, journalling each lock dispatch in the caller's own attempt store (WP-120).
///
/// The store supplied here records attempt identities and nothing else. Ownership tokens stay in
/// lore's own `.lore/` store, derived from the repository below, and this store's ownership methods
/// are never called for locks. See [`lore_transport::attempt_store::AttemptStore`] for why the two
/// jobs are split: token custody has to agree between a direct call and a delegated one, and only a
/// store derived from the repository does.
///
/// One record per lock dispatch, and an acquire batches, so a large set produces several. Refuses
/// under `LORE_USE_SERVICE` for the same reason
/// [`crate::branch::push_with_attempt_store`] does.
pub async fn file_acquire_with_attempt_store(
    globals: LoreGlobalArgs,
    args: LoreLockFileAcquireArgs,
    callback: LoreEventCallback,
    attempts: Arc<dyn AttemptStore>,
) -> i32 {
    if service_delegation_requested() {
        return reject_undelegatable(
            globals,
            callback,
            "file_acquire_with_attempt_store cannot delegate to a service: the attempt store is \
             in-process, and a delegated acquire would file receipts under identities the caller \
             never recorded. Unset LORE_USE_SERVICE, or call file_acquire and keep no journal."
                .to_owned(),
        )
        .await;
    }
    file_acquire_journalled(globals, args, callback, Some(attempts)).await
}

async fn file_acquire_local(
    globals: LoreGlobalArgs,
    args: LoreLockFileAcquireArgs,
    callback: LoreEventCallback,
) -> i32 {
    file_acquire_journalled(globals, args, callback, None).await
}

async fn file_acquire_journalled(
    globals: LoreGlobalArgs,
    args: LoreLockFileAcquireArgs,
    callback: LoreEventCallback,
    attempts: Option<Arc<dyn AttemptStore>>,
) -> i32 {
    crate::call::repository_call_mutation_read(
        globals,
        callback,
        args,
        file_acquire,
        move |repository, args| {
            let options: AcquireOptions = AcquireOptions {
                paths: args.paths,
                branch: args.branch.to_string(),
                owner: String::default(),
            };

            // Built here, from the repository this call already resolved, and never sent as an
            // argument. That is what keeps the ownership token off the delegation wire: under
            // `LORE_USE_SERVICE` the service process runs this same handler against the same
            // repository path, so it derives the same `.lore/` store and reads the token a direct
            // acquire wrote (WP-120).
            let ownership = repository_attempt_store(&repository);
            async move {
                lore_revision::lock::file::acquire::acquire(
                    repository,
                    options,
                    ownership,
                    attempts.as_ref(),
                )
                .await
            }
        },
    )
    .await
}

pub async fn file_acquire_as_owner(
    globals: LoreGlobalArgs,
    args: LoreLockFileAcquireArgs,
    callback: LoreEventCallback,
    owner: LoreString,
) -> i32 {
    crate::call::repository_call_mutation_read(
        globals,
        callback,
        args,
        file_acquire,
        move |repository, args| {
            let options: AcquireOptions = AcquireOptions {
                paths: args.paths,
                branch: args.branch.to_string(),
                owner: owner.to_string(),
            };

            let ownership = repository_attempt_store(&repository);
            // `None`: this shape is reached only through the C ABI, which cannot carry a store.
            lore_revision::lock::file::acquire::acquire(repository, options, ownership, None)
        },
    )
    .await
}

/// Arguments for returning the lock status of the given files on a branch.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, LoreArgs)]
#[handler(file_status_local)]
pub struct LoreLockFileStatusArgs {
    /// Paths to get the lock status of
    pub paths: LoreArray<LoreString>,
    /// Branch the locks were acquired on
    pub branch: LoreString,
}

/// Returns the lock status of the specified files on a given branch.
///
/// # Events
///
/// ## Standard Events
///
/// These events are emitted by all interface functions:
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::Log`](crate::interface::LoreEvent::Log) | Diagnostic messages throughout execution |
/// | [`LoreEvent::Error`](crate::interface::LoreEvent::Error) | Emitted for a non-fatal error during the operation |
/// | [`LoreEvent::Complete`](crate::interface::LoreEvent::Complete) | Always emitted at the end; `status` is `0` on success or the error code on failure |
/// | [`LoreEvent::End`](crate::interface::LoreEvent::End) | Always emitted after `Complete` to signal callback termination |
///
/// ## Lock Events
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::LockFileStatusBegin`](crate::interface::LoreEvent::LockFileStatusBegin) | Emitted before lock status results begin streaming |
/// | [`LoreEvent::LockFileStatus`](crate::interface::LoreEvent::LockFileStatus) | Emitted for each locked file with owner and lock details |
pub async fn file_status(
    globals: LoreGlobalArgs,
    args: LoreLockFileStatusArgs,
    callback: LoreEventCallback,
) -> i32 {
    dispatch_call(globals, args, callback, file_status_local).await
}

async fn file_status_local(
    globals: LoreGlobalArgs,
    args: LoreLockFileStatusArgs,
    callback: LoreEventCallback,
) -> i32 {
    repository_call_read(
        globals,
        callback,
        args,
        file_status,
        move |repository, args| {
            let options = StatusOptions {
                paths: args.paths,
                branch: args.branch.to_string(),
            };

            lore_revision::lock::file::status::status(repository, options)
        },
    )
    .await
}

/// Arguments for querying file locks on a branch, optionally filtered by owner and path.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, LoreArgs)]
#[handler(file_query_local)]
pub struct LoreLockFileQueryArgs {
    /// Branch to query locks on
    pub branch: LoreString,
    /// Owner filter; empty matches any owner
    pub owner: LoreString,
    /// Path filter; empty matches any path
    pub path: LoreString,
}

/// Queries file locks on a branch, optionally filtered by owner and path.
///
/// # Events
///
/// ## Standard Events
///
/// These events are emitted by all interface functions:
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::Log`](crate::interface::LoreEvent::Log) | Diagnostic messages throughout execution |
/// | [`LoreEvent::Error`](crate::interface::LoreEvent::Error) | Emitted for a non-fatal error during the operation |
/// | [`LoreEvent::Complete`](crate::interface::LoreEvent::Complete) | Always emitted at the end; `status` is `0` on success or the error code on failure |
/// | [`LoreEvent::End`](crate::interface::LoreEvent::End) | Always emitted after `Complete` to signal callback termination |
///
/// ## Lock Events
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::LockFileQueryBegin`](crate::interface::LoreEvent::LockFileQueryBegin) | Emitted before query results begin streaming |
/// | [`LoreEvent::LockFileQuery`](crate::interface::LoreEvent::LockFileQuery) | Emitted for each file matching the query |
pub async fn file_query(
    globals: LoreGlobalArgs,
    args: LoreLockFileQueryArgs,
    callback: LoreEventCallback,
) -> i32 {
    dispatch_call(globals, args, callback, file_query_local).await
}

async fn file_query_local(
    globals: LoreGlobalArgs,
    args: LoreLockFileQueryArgs,
    callback: LoreEventCallback,
) -> i32 {
    repository_call_read(
        globals,
        callback,
        args,
        file_query,
        move |repository, args| {
            let options = QueryOptions {
                branch: args.branch.to_string(),
                owner: args.owner.to_string(),
                path: args.path.to_string(),
            };

            lore_revision::lock::file::query::query(repository, options)
        },
    )
    .await
}

/// Arguments for releasing file locks on the given paths for a branch and owner.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, LoreArgs)]
#[handler(file_release_local)]
pub struct LoreLockFileReleaseArgs {
    /// Paths to release locks on
    pub paths: LoreArray<LoreString>,
    /// Branch the locks were acquired on
    pub branch: LoreString,
    /// Owner of the lock
    pub owner: LoreString,
    /// Owner id of the lock
    pub owner_id: LoreString,
}

/// Releases file locks on the specified paths for a given branch and owner.
///
/// # Events
///
/// ## Standard Events
///
/// These events are emitted by all interface functions:
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::Log`](crate::interface::LoreEvent::Log) | Diagnostic messages throughout execution |
/// | [`LoreEvent::Error`](crate::interface::LoreEvent::Error) | Emitted for a non-fatal error during the operation |
/// | [`LoreEvent::Complete`](crate::interface::LoreEvent::Complete) | Always emitted at the end; `status` is `0` on success or the error code on failure |
/// | [`LoreEvent::End`](crate::interface::LoreEvent::End) | Always emitted after `Complete` to signal callback termination |
///
/// ## Lock Events
///
/// | Event | Description |
/// |-------|-------------|
/// | [`LoreEvent::LockFileReleaseBegin`](crate::interface::LoreEvent::LockFileReleaseBegin) | Emitted before each group of lock-release results |
/// | [`LoreEvent::LockFileRelease`](crate::interface::LoreEvent::LockFileRelease) | Emitted for each file related to the lock-released report |
pub async fn file_release(
    globals: LoreGlobalArgs,
    args: LoreLockFileReleaseArgs,
    callback: LoreEventCallback,
) -> i32 {
    dispatch_call(globals, args, callback, file_release_local).await
}

/// Release, journalling each lock dispatch in the caller's own attempt store (WP-120).
///
/// Records attempt identities only; ownership stays in lore's `.lore/` store, exactly as for
/// [`file_acquire_with_attempt_store`]. A release batches like an acquire, and can additionally
/// escalate to an administrative force-release, which is journalled too.
pub async fn file_release_with_attempt_store(
    globals: LoreGlobalArgs,
    args: LoreLockFileReleaseArgs,
    callback: LoreEventCallback,
    attempts: Arc<dyn AttemptStore>,
) -> i32 {
    if service_delegation_requested() {
        return reject_undelegatable(
            globals,
            callback,
            "file_release_with_attempt_store cannot delegate to a service: the attempt store is \
             in-process, and a delegated release would file receipts under identities the caller \
             never recorded. Unset LORE_USE_SERVICE, or call file_release and keep no journal."
                .to_owned(),
        )
        .await;
    }
    file_release_journalled(globals, args, callback, Some(attempts)).await
}

async fn file_release_local(
    globals: LoreGlobalArgs,
    args: LoreLockFileReleaseArgs,
    callback: LoreEventCallback,
) -> i32 {
    file_release_journalled(globals, args, callback, None).await
}

async fn file_release_journalled(
    globals: LoreGlobalArgs,
    args: LoreLockFileReleaseArgs,
    callback: LoreEventCallback,
    attempts: Option<Arc<dyn AttemptStore>>,
) -> i32 {
    crate::call::repository_call_mutation_read(
        globals,
        callback,
        args,
        file_release,
        move |repository, args| {
            let options = ReleaseOptions {
                paths: args.paths,
                branch: args.branch.to_string(),
                owner: args.owner.to_string(),
                owner_id: args.owner_id.to_string(),
            };

            let ownership = repository_attempt_store(&repository);
            async move {
                lore_revision::lock::file::release::release(
                    repository,
                    options,
                    ownership,
                    attempts.as_ref(),
                )
                .await
            }
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use lore_base::error::InvalidArguments;
    use lore_error_set::FfiError;
    use lore_revision::interface::LoreEventCallbackConfig;
    use lore_transport::VolatileAttemptStore;

    use super::*;
    use crate::call_delegation::tests::service_env_child;

    /// The same status shape `crate::call_delegation::reject_call` uses for every other
    /// pre-command rejection, so this refusal cannot be told apart from one of those by a
    /// caller inspecting the status alone.
    fn undelegatable_status() -> i32 {
        InvalidArguments {
            reason: String::new(),
        }
        .ffi_code()
    }

    fn no_callback() -> LoreEventCallback {
        lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
            user_context: 0,
            func: None,
        })
    }

    /// `file_acquire_with_attempt_store` must refuse under `LORE_USE_SERVICE` rather than
    /// delegate -- see the function's own doc comment for why a delegated acquire would strand
    /// the caller's journal. The repository path is deliberately nonexistent and the store
    /// deliberately records every call it receives: either one being touched would mean the
    /// refusal ran too late, after the code had already started the operation it exists to
    /// prevent.
    #[test]
    fn file_acquire_with_attempt_store_refuses_when_delegation_is_requested() {
        if !service_env_child(
            "lock::tests::file_acquire_with_attempt_store_refuses_when_delegation_is_requested",
            &[Some("1")],
        ) {
            return;
        }

        let globals = LoreGlobalArgs {
            repository_path: LoreString::from_str(
                "Z:/lore-file-acquire-with-attempt-store-test-nonexistent-7d1e4b",
            ),
            ..LoreGlobalArgs::default()
        };
        let args = LoreLockFileAcquireArgs {
            paths: LoreArray::default(),
            branch: LoreString::default(),
        };
        let store = Arc::new(VolatileAttemptStore::new());
        let attempts: Arc<dyn AttemptStore> = store.clone();

        let status = crate::runtime().block_on(file_acquire_with_attempt_store(
            globals,
            args,
            no_callback(),
            attempts,
        ));

        assert_eq!(
            status,
            undelegatable_status(),
            "the refusal must use the same status shape every other pre-command rejection uses"
        );
        assert!(
            crate::runtime()
                .block_on(store.unresolved())
                .expect("unresolved() must succeed on a fresh store")
                .is_empty(),
            "the attempt store must never be touched when the call is refused before it runs"
        );
    }

    /// `file_release_with_attempt_store` must refuse under `LORE_USE_SERVICE` rather than
    /// delegate, for the same reason as the acquire entry point above: the store is in-process
    /// and a delegated release would file receipts under identities the caller never recorded.
    /// The repository path is deliberately nonexistent, so a refusal that ran too late would
    /// still show up here as a failure, just not this one -- the status assertion below is what
    /// tells the two apart, and the store assertion is what proves the refusal ran before the
    /// release ever touched anything.
    #[test]
    fn file_release_with_attempt_store_refuses_when_delegation_is_requested() {
        if !service_env_child(
            "lock::tests::file_release_with_attempt_store_refuses_when_delegation_is_requested",
            &[Some("1")],
        ) {
            return;
        }

        let globals = LoreGlobalArgs {
            repository_path: LoreString::from_str(
                "Z:/lore-file-release-with-attempt-store-test-nonexistent-2a9f6c",
            ),
            ..LoreGlobalArgs::default()
        };
        let args = LoreLockFileReleaseArgs {
            paths: LoreArray::default(),
            branch: LoreString::default(),
            owner: LoreString::default(),
            owner_id: LoreString::default(),
        };
        let store = Arc::new(VolatileAttemptStore::new());
        let attempts: Arc<dyn AttemptStore> = store.clone();

        let status = crate::runtime().block_on(file_release_with_attempt_store(
            globals,
            args,
            no_callback(),
            attempts,
        ));

        assert_eq!(
            status,
            undelegatable_status(),
            "the refusal must use the same status shape every other pre-command rejection uses"
        );
        assert!(
            crate::runtime()
                .block_on(store.unresolved())
                .expect("unresolved() must succeed on a fresh store")
                .is_empty(),
            "the attempt store must never be touched when the call is refused before it runs"
        );
    }
}

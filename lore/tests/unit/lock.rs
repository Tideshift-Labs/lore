// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-120): the attempt-store lock verbs' delegation refusals, moved from
//! `src/lock.rs` with the upstream unit-test relocation.
use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore::interface::LoreString;
use lore::lock::*;
use lore_base::error::InvalidArguments;
use lore_error_set::FfiError;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreGlobalArgs;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;

use crate::call_delegation::service_env_child;

/// The same status shape `lore::call_delegation::reject_call` uses for every other
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
        "lock::file_acquire_with_attempt_store_refuses_when_delegation_is_requested",
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

    let status = lore::runtime().block_on(file_acquire_with_attempt_store(
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
        lore::runtime()
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
        "lock::file_release_with_attempt_store_refuses_when_delegation_is_requested",
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

    let status = lore::runtime().block_on(file_release_with_attempt_store(
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
        lore::runtime()
            .block_on(store.unresolved())
            .expect("unresolved() must succeed on a fresh store")
            .is_empty(),
        "the attempt store must never be touched when the call is refused before it runs"
    );
}

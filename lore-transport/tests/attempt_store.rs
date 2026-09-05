// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// CR-029/CR-030 client attempt-store fixtures (WP-120).
//
// [CLIENT]-class: `lore-transport` is a client-path crate. This file exercises `attempt_store.rs`
// through nothing but the crate's public root, against `VolatileAttemptStore` -- the one in-tree
// implementation, deliberately test-only, gated behind `test_seams` because it violates the
// trait's durability promise (nothing here survives the process). Run with:
//   cargo test -p lore-transport --features test_seams --test attempt_store
// Without the feature this file compiles to zero tests rather than failing the default
// `cargo test -p lore-transport`, since `VolatileAttemptStore` does not exist without it.
//
// These tests pin the *contract* `AttemptStore` states -- record/lookup/unresolved/resolve and
// the ownership side-table -- not the durability promise itself. `VolatileAttemptStore` satisfies
// the trait's shape and deliberately breaks that promise; nothing here proves durability, because
// no durable implementation exists yet (the desktop implements one on its operation journal; a
// `.lore/`-backed CLI store is a separate lane).
#![cfg(feature = "test_seams")]

use bytes::Bytes;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::DomainReceiptQuery;
use lore_transport::LockOwnership;
use lore_transport::VolatileAttemptStore;
use uuid::Uuid;

fn digest(fill: u8) -> Bytes {
    Bytes::from(vec![fill; 32])
}

fn sample_receipt_query() -> DomainReceiptQuery {
    DomainReceiptQuery {
        org_uuid: Uuid::now_v7(),
        initiating_principal_namespace: Bytes::from_static(b"principal-v1\0user"),
        operation_id: Uuid::now_v7(),
        method: "RevisionService.BranchCreate".to_string(),
        scope: Bytes::from_static(b"scope"),
        fingerprint_version: 1,
        fingerprint: digest(0xAA),
        canonical_intent_digest: digest(0xBB),
        authorization_revision: 1,
        consumed_ticket_sha256: digest(0xCC),
    }
}

fn record_at(
    attempt_id: AttemptId,
    state: AttemptState,
    operation: &str,
    repository: RepositoryId,
    recorded_at_unix_millis: i64,
    receipt: Option<DomainReceiptQuery>,
) -> AttemptRecord {
    AttemptRecord {
        attempt_id,
        state,
        operation: operation.to_string(),
        repository,
        recorded_at_unix_millis,
        receipt,
    }
}

fn unresolved_record_at(
    attempt_id: AttemptId,
    operation: &str,
    repository: RepositoryId,
    recorded_at_unix_millis: i64,
) -> AttemptRecord {
    record_at(
        attempt_id,
        AttemptState::Unresolved,
        operation,
        repository,
        recorded_at_unix_millis,
        None,
    )
}

/// A basic round trip: what is recorded is what comes back, field for field.
#[tokio::test]
async fn record_then_lookup_returns_the_exact_record() {
    let store = VolatileAttemptStore::new();
    let attempt = AttemptId::new();
    let record = record_at(
        attempt,
        AttemptState::Unresolved,
        "RevisionService.BranchPush",
        RepositoryId::from([0x01u8; 16]),
        1_000,
        Some(sample_receipt_query()),
    );

    store.record(&record).await.expect("record must succeed");

    let looked_up = store
        .lookup(&attempt)
        .await
        .expect("lookup must succeed")
        .expect("the record must be found");
    assert_eq!(looked_up, record);
}

/// Priority 1, the anti-resurrection property and the single most valuable test here:
/// `resolve()` must not delete the record. A late transport callback or a stale UI event that
/// finds `None` may offer a fresh attempt at a mutation that already applied -- so a resolved
/// attempt must keep reading back as `Some`, carrying the exact resolution.
#[tokio::test]
async fn resolve_then_lookup_returns_some_with_the_resolved_state() {
    let store = VolatileAttemptStore::new();
    let attempt = AttemptId::new();
    store
        .record(&unresolved_record_at(
            attempt,
            "RevisionService.BranchPush",
            RepositoryId::from([0x01u8; 16]),
            1_000,
        ))
        .await
        .unwrap();

    store
        .resolve(&attempt, AttemptResolution::Applied)
        .await
        .unwrap();

    let looked_up = store
        .lookup(&attempt)
        .await
        .unwrap()
        .expect("a resolved attempt must still be found by lookup, never None");
    assert_eq!(
        looked_up.state,
        AttemptState::Resolved(AttemptResolution::Applied),
        "lookup must carry the exact resolution, not merely prove the record survived"
    );
    assert!(!looked_up.state.is_unresolved());
}

/// Priority 2: `resolve()` and `lookup()` deliberately disagree once a record is settled.
/// `unresolved()` is the "what still blocks writes" read and must omit it; `lookup()` is the
/// "what happened to this exact attempt" read and must still find it.
#[tokio::test]
async fn resolve_removes_the_record_from_unresolved_but_not_from_lookup() {
    let store = VolatileAttemptStore::new();
    let attempt = AttemptId::new();
    store
        .record(&unresolved_record_at(
            attempt,
            "RevisionService.BranchPush",
            RepositoryId::from([0x01u8; 16]),
            1_000,
        ))
        .await
        .unwrap();

    store
        .resolve(&attempt, AttemptResolution::NotApplied)
        .await
        .unwrap();

    assert!(
        store
            .unresolved()
            .await
            .unwrap()
            .iter()
            .all(|record| record.attempt_id != attempt),
        "a resolved attempt must not appear in unresolved()"
    );
    assert!(
        store.lookup(&attempt).await.unwrap().is_some(),
        "a resolved attempt must still be found by lookup()"
    );
}

/// Priority 3: the entire argument for `AttemptResolution` having only three variants rests on
/// `AdjudicatedUnknown` NOT being one of them -- it is a distinct `AttemptState` that still
/// blocks writes and still shows up in the boot-recovery read, because its no-old-id-replay
/// marker has to be restored before any new write is admitted. Pinned directly rather than left
/// to follow from the type definitions.
#[tokio::test]
async fn an_adjudicated_unknown_record_still_appears_in_unresolved() {
    let store = VolatileAttemptStore::new();
    let attempt = AttemptId::new();
    store
        .record(&record_at(
            attempt,
            AttemptState::AdjudicatedUnknown,
            "Lock.Lock",
            RepositoryId::from([0x01u8; 16]),
            1_000,
            None,
        ))
        .await
        .unwrap();

    let unresolved = store.unresolved().await.unwrap();
    assert_eq!(
        unresolved.iter().map(|r| r.attempt_id).collect::<Vec<_>>(),
        vec![attempt],
        "AdjudicatedUnknown is not a resolution and must still block writes: {unresolved:?}"
    );
}

/// `AttemptState::is_unresolved()` is the single predicate a caller branches on to decide
/// whether a record still blocks writes. Pin it false only for `Resolved`, whatever the
/// resolution, and true for both remaining states -- a pure, store-independent complement to the
/// two tests above.
#[test]
fn is_unresolved_is_false_only_for_resolved() {
    assert!(AttemptState::Unresolved.is_unresolved());
    assert!(AttemptState::AdjudicatedUnknown.is_unresolved());
    for resolution in [
        AttemptResolution::Applied,
        AttemptResolution::NotApplied,
        AttemptResolution::Conflicted,
    ] {
        assert!(!AttemptState::Resolved(resolution).is_unresolved());
    }
}

/// Priority 4: `resolve()` releases the ownership token the resolved attempt held, and only
/// that one -- a different attempt's held lock must survive.
#[tokio::test]
async fn resolve_clears_the_lock_ownership_that_attempt_held_and_leaves_others_alone() {
    let store = VolatileAttemptStore::new();
    let resolved_attempt = AttemptId::new();
    let other_attempt = AttemptId::new();
    let branch = Context::from([0x11u8; 16]);
    let resolved_resource = Hash::from([0x22u8; 32]);
    let other_resource = Hash::from([0x44u8; 32]);

    store
        .record(&unresolved_record_at(
            resolved_attempt,
            "Lock.Lock",
            RepositoryId::from([0x01u8; 16]),
            1_000,
        ))
        .await
        .unwrap();
    store
        .record_ownership(&LockOwnership {
            attempt_id: resolved_attempt,
            branch,
            resource_hash: resolved_resource,
            token: Bytes::from_static(b"resolved-attempt-token"),
        })
        .await
        .unwrap();
    store
        .record_ownership(&LockOwnership {
            attempt_id: other_attempt,
            branch,
            resource_hash: other_resource,
            token: Bytes::from_static(b"other-attempt-token"),
        })
        .await
        .unwrap();

    store
        .resolve(&resolved_attempt, AttemptResolution::Applied)
        .await
        .unwrap();

    assert_eq!(
        store
            .ownership_for(&branch, &resolved_resource)
            .await
            .unwrap(),
        None,
        "resolving an attempt must clear the ownership it held"
    );
    assert!(
        store
            .ownership_for(&branch, &other_resource)
            .await
            .unwrap()
            .is_some(),
        "resolving one attempt must not clear a lock a different attempt holds"
    );
}

/// Priority 5: ties on `recorded_at_unix_millis` break on the attempt id, so two reads of an
/// unchanged store return the same order even when a client clock repeats a millisecond. Two
/// records are given the identical timestamp; the expected order is derived from the ids'
/// natural (UUIDv7) ordering, not from insertion order, and re-read to prove it is stable.
#[tokio::test]
async fn unresolved_breaks_a_recorded_at_tie_on_attempt_id_and_is_stable_across_reads() {
    let store = VolatileAttemptStore::new();
    let one = AttemptId::new();
    let other = AttemptId::new();
    let (first, second) = if one.as_uuid() < other.as_uuid() {
        (one, other)
    } else {
        (other, one)
    };
    let repository = RepositoryId::from([0x01u8; 16]);

    // Inserted in the opposite order from the expected id-ascending tie-break, so passing here
    // cannot be an accident of insertion order.
    store
        .record(&unresolved_record_at(second, "op", repository, 5_000))
        .await
        .unwrap();
    store
        .record(&unresolved_record_at(first, "op", repository, 5_000))
        .await
        .unwrap();

    for _ in 0..2 {
        let unresolved = store.unresolved().await.unwrap();
        assert_eq!(
            unresolved.iter().map(|r| r.attempt_id).collect::<Vec<_>>(),
            vec![first, second],
            "a tie on recorded_at_unix_millis must break on the attempt id, stably: {unresolved:?}"
        );
    }
}

/// `unresolved()` also orders distinct timestamps oldest first, independent of the tie-break
/// rule above.
#[tokio::test]
async fn unresolved_orders_oldest_first_by_recorded_at_not_by_insertion_order() {
    let store = VolatileAttemptStore::new();
    let repository = RepositoryId::from([0x01u8; 16]);
    let newest = AttemptId::new();
    let oldest = AttemptId::new();
    let middle = AttemptId::new();

    store
        .record(&unresolved_record_at(newest, "op", repository, 300))
        .await
        .unwrap();
    store
        .record(&unresolved_record_at(oldest, "op", repository, 100))
        .await
        .unwrap();
    store
        .record(&unresolved_record_at(middle, "op", repository, 200))
        .await
        .unwrap();

    let unresolved = store.unresolved().await.unwrap();
    assert_eq!(
        unresolved.iter().map(|r| r.attempt_id).collect::<Vec<_>>(),
        vec![oldest, middle, newest],
        "unresolved() must be sorted oldest-first by recorded_at_unix_millis: {unresolved:?}"
    );
}

/// Priority 6: recording the same attempt id twice is the caller retrying its own write, and
/// must overwrite -- including moving the record between states, since the second write is
/// simply the latest truth about that attempt.
#[tokio::test]
async fn recording_the_same_attempt_id_twice_overwrites_and_can_change_state() {
    let store = VolatileAttemptStore::new();
    let attempt = AttemptId::new();
    let repository = RepositoryId::from([0x01u8; 16]);

    store
        .record(&unresolved_record_at(
            attempt,
            "RevisionService.BranchPush",
            repository,
            1_000,
        ))
        .await
        .unwrap();
    store
        .record(&record_at(
            attempt,
            AttemptState::Resolved(AttemptResolution::NotApplied),
            "RevisionService.BranchPush",
            repository,
            2_000,
            None,
        ))
        .await
        .unwrap();

    let looked_up = store.lookup(&attempt).await.unwrap().unwrap();
    assert_eq!(
        looked_up.state,
        AttemptState::Resolved(AttemptResolution::NotApplied),
        "the second write must replace the first's state, not sit beside it"
    );
    assert_eq!(
        looked_up.recorded_at_unix_millis, 2_000,
        "the second write must replace every field, not merge with the first"
    );
    assert!(
        store
            .unresolved()
            .await
            .unwrap()
            .iter()
            .all(|r| r.attempt_id != attempt),
        "one attempt id retried into a resolved state must not still block writes"
    );
}

/// Priority 3 (compile-level half): exactly three variants. An exhaustive match with no
/// wildcard arm fails to compile the moment a variant is added or removed, which is the point --
/// `StillUnknown` and `AdjudicatedUnknown` are deliberately not resolutions (the latter is its
/// own `AttemptState` variant instead, pinned above), and a future edit that quietly reintroduces
/// either of them here must be forced to touch this test.
#[test]
fn attempt_resolution_has_exactly_three_variants() {
    fn name(resolution: AttemptResolution) -> &'static str {
        match resolution {
            AttemptResolution::Applied => "applied",
            AttemptResolution::NotApplied => "not_applied",
            AttemptResolution::Conflicted => "conflicted",
        }
    }

    assert_eq!(name(AttemptResolution::Applied), "applied");
    assert_eq!(name(AttemptResolution::NotApplied), "not_applied");
    assert_eq!(name(AttemptResolution::Conflicted), "conflicted");
}

/// Priority 7: `ownership_for` is keyed by `(branch, resource_hash)`, never by which attempt
/// wrote it. A later attempt overwriting the same resource's ownership must win, and two
/// different resources -- whether by hash or by branch -- must stay independently addressable.
#[tokio::test]
async fn ownership_is_keyed_by_branch_and_resource_not_by_attempt() {
    let store = VolatileAttemptStore::new();
    let branch = Context::from([0x11u8; 16]);
    let other_branch = Context::from([0x33u8; 16]);
    let resource = Hash::from([0x22u8; 32]);
    let other_resource = Hash::from([0x44u8; 32]);

    let first_attempt = AttemptId::new();
    let second_attempt = AttemptId::new();

    // Two different attempts locking the SAME resource: the later write wins, regardless of
    // which attempt id issued it.
    store
        .record_ownership(&LockOwnership {
            attempt_id: first_attempt,
            branch,
            resource_hash: resource,
            token: Bytes::from_static(b"token-from-first-attempt"),
        })
        .await
        .unwrap();
    store
        .record_ownership(&LockOwnership {
            attempt_id: second_attempt,
            branch,
            resource_hash: resource,
            token: Bytes::from_static(b"token-from-second-attempt"),
        })
        .await
        .unwrap();

    let held = store
        .ownership_for(&branch, &resource)
        .await
        .unwrap()
        .expect("a token must be held for this resource");
    assert_eq!(
        held.token,
        Bytes::from_static(b"token-from-second-attempt"),
        "the later write must win regardless of which attempt id issued it"
    );

    // A different resource hash on the same branch is a distinct entry.
    store
        .record_ownership(&LockOwnership {
            attempt_id: first_attempt,
            branch,
            resource_hash: other_resource,
            token: Bytes::from_static(b"token-for-other-resource"),
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .ownership_for(&branch, &other_resource)
            .await
            .unwrap()
            .map(|o| o.token),
        Some(Bytes::from_static(b"token-for-other-resource"))
    );
    assert_eq!(
        store
            .ownership_for(&branch, &resource)
            .await
            .unwrap()
            .map(|o| o.token),
        Some(Bytes::from_static(b"token-from-second-attempt")),
        "writing ownership for a different resource must not disturb the first one"
    );

    // The same resource hash on a different branch is also a distinct entry.
    assert_eq!(
        store.ownership_for(&other_branch, &resource).await.unwrap(),
        None,
        "the same resource hash on a different branch must not be found"
    );
}

/// Priority 8: `receipt: None` is a deliberate statement -- this operation family has no
/// authoritative receipt to look up -- not a stand-in for "not yet known". Nothing enforces
/// that distinction structurally, so this documents both cases surviving a round trip
/// unmodified, distinguishably.
#[tokio::test]
async fn receipt_none_and_receipt_some_both_round_trip_distinguishably() {
    let store = VolatileAttemptStore::new();
    let repository = RepositoryId::from([0x01u8; 16]);

    let no_receipt_family = AttemptId::new();
    let receipted_family = AttemptId::new();
    let receipt = sample_receipt_query();

    store
        .record(&record_at(
            no_receipt_family,
            AttemptState::Unresolved,
            "Lock.Lock",
            repository,
            1_000,
            None,
        ))
        .await
        .unwrap();
    store
        .record(&record_at(
            receipted_family,
            AttemptState::Unresolved,
            "RevisionService.BranchCreate",
            repository,
            1_000,
            Some(receipt.clone()),
        ))
        .await
        .unwrap();

    assert_eq!(
        store
            .lookup(&no_receipt_family)
            .await
            .unwrap()
            .unwrap()
            .receipt,
        None,
        "a family with no authoritative receipt must round-trip as None, not a default value"
    );
    assert_eq!(
        store
            .lookup(&receipted_family)
            .await
            .unwrap()
            .unwrap()
            .receipt,
        Some(receipt),
        "a family with a receipt must round-trip the exact query it was recorded with"
    );
}

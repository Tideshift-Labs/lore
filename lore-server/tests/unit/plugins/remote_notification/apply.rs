// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_postgres::domain::outbox::VersionOrder;
use lore_postgres::domain::outbox::version::AggregateVersion as StoredAggregateVersion;
use lore_server::plugins::remote_notification::apply::*;
use lore_server::plugins::remote_notification::envelope::AggregateVersion;
use lore_server::plugins::remote_notification::envelope::DurableInvalidationBody;

fn repository(byte: u8) -> RepositoryId {
    let mut id = RepositoryId::default();
    *id.data_mut() = [byte; 16];
    id
}

fn body(ordinal: u64, identity: Option<&str>) -> DurableInvalidationBody {
    DurableInvalidationBody {
        payload_version: 1,
        idempotency_key: [3; 32],
        event_kind: "branch.pushed".to_string(),
        repository_generation: 1,
        aggregate_kind: "branch".to_string(),
        aggregate_identity: "0123456789abcdef".to_string(),
        aggregate_version: AggregateVersion {
            ordinal,
            identity: identity.map(str::to_string),
        },
        payload: Bytes::new(),
        committed_at: UNIX_EPOCH,
        actor: None,
    }
}

fn stored(ordinal: u64, identity: Option<&str>) -> StoredAggregateVersion {
    to_stored(&AggregateVersion {
        ordinal,
        identity: identity.map(str::to_string),
    })
    .expect("a short identity encodes")
}

#[test]
fn an_unknown_aggregate_is_the_next_ordinal_not_a_gap() {
    let versions = AppliedVersions::new();
    let key = AggregateKey::of(repository(1), &body(417, None));
    assert_eq!(
        versions.verdict(&key, &stored(417, None)),
        VersionOrder::NextOrdinal,
        "the first event after an authoritative baseline is applied, not refetched"
    );
}

#[test]
fn the_same_version_twice_is_a_duplicate() {
    let mut versions = AppliedVersions::new();
    let key = AggregateKey::of(repository(1), &body(417, Some("abc")));
    versions.record(key.clone(), stored(417, Some("abc")));
    assert_eq!(
        versions.verdict(&key, &stored(417, Some("abc"))),
        VersionOrder::Equal
    );
}

#[test]
fn a_lower_ordinal_is_stale() {
    let mut versions = AppliedVersions::new();
    let key = AggregateKey::of(repository(1), &body(417, None));
    versions.record(key.clone(), stored(417, None));
    assert_eq!(
        versions.verdict(&key, &stored(416, None)),
        VersionOrder::Older
    );
}

#[test]
fn a_skipped_ordinal_is_a_gap_and_the_contiguous_one_is_not() {
    let mut versions = AppliedVersions::new();
    let key = AggregateKey::of(repository(1), &body(417, None));
    versions.record(key.clone(), stored(417, None));
    assert_eq!(
        versions.verdict(&key, &stored(418, None)),
        VersionOrder::NextOrdinal
    );
    assert_eq!(
        versions.verdict(&key, &stored(420, None)),
        VersionOrder::Newer
    );
}

#[test]
fn the_same_ordinal_with_a_different_identity_is_incomparable() {
    let mut versions = AppliedVersions::new();
    let key = AggregateKey::of(repository(1), &body(417, Some("abc")));
    versions.record(key.clone(), stored(417, Some("abc")));
    assert_eq!(
        versions.verdict(&key, &stored(417, Some("def"))),
        VersionOrder::Incomparable
    );
}

/// Two repositories are never one aggregate, however identical the rest of
/// the tuple is.
#[test]
fn the_repository_is_part_of_the_key() {
    let mut versions = AppliedVersions::new();
    let first = AggregateKey::of(repository(1), &body(417, None));
    let second = AggregateKey::of(repository(2), &body(417, None));
    versions.record(first, stored(417, None));
    assert_eq!(
        versions.verdict(&second, &stored(1, None)),
        VersionOrder::NextOrdinal
    );
}

#[test]
fn forgetting_one_repository_leaves_the_others_alone() {
    let mut versions = AppliedVersions::new();
    let first = AggregateKey::of(repository(1), &body(417, None));
    let second = AggregateKey::of(repository(2), &body(417, None));
    versions.record(first, stored(417, None));
    versions.record(second.clone(), stored(417, None));
    versions.forget_repository(repository(1));
    assert_eq!(versions.tracked(), 1);
    assert_eq!(
        versions.verdict(&second, &stored(417, None)),
        VersionOrder::Equal
    );
}

/// The envelope admits a 128-byte identity; the storage encoding admits
/// 120. A value in between is transportable and not storable, so it parks
/// rather than truncating into a different version.
#[test]
fn an_identity_wider_than_the_storage_encoding_is_a_decode_failure() {
    let wide = "x".repeat(121);
    assert_eq!(
        to_stored(&AggregateVersion {
            ordinal: 1,
            identity: Some(wide),
        }),
        Err(VersionDecodeError::IdentityTooWide)
    );
    assert_eq!(
        VersionDecodeError::IdentityTooWide.poison_class(),
        "AGGREGATE_VERSION_IDENTITY_TOO_WIDE"
    );
}

#[tokio::test]
async fn the_recording_target_preserves_call_order() {
    let target = RecordingInvalidationTarget::new();
    target.baseline().await;
    target
        .apply_invalidation(repository(1), &body(417, None))
        .await;
    target.refetch_repository(repository(1)).await;
    assert_eq!(
        target.calls(),
        vec![
            TargetCall::Baseline,
            TargetCall::Apply {
                repository: repository(1),
                event_kind: "branch.pushed".to_string(),
                ordinal: 417,
            },
            TargetCall::Refetch(repository(1)),
        ]
    );
    assert_eq!(target.baselines(), 1);
}

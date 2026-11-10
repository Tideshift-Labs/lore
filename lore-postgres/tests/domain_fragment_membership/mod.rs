// Copyright 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

use super::*;

async fn invalidation(coordinator: &TestFragmentCoordinator, repository: &[u8]) -> i64 {
    coordinator
        .capture_push_witness(repository)
        .await
        .unwrap()
        .unwrap()
        .content_membership_invalidation_generation
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn fresh_exact_keys_preserve_invalidation_but_rebind_and_recreate_advance_it() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let other_repository = create_repository(&store).await;
    let hash = publish_remote_fragment(&coordinator, 11).await;
    let context = random_context();
    let baseline = invalidation(&coordinator, &repository).await;
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline);
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &random_context())
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline);
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline + 1);
    assert_eq!(
        coordinator
            .tombstone_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline + 2);
    assert_eq!(
        coordinator
            .tombstone_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Fenced
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline + 2);
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, baseline + 3);
    assert_eq!(invalidation(&coordinator, &other_repository).await, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn guarded_binding_classifies_absence_and_replacement_and_fenced_calls_change_nothing() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let hash = publish_remote_fragment(&coordinator, 12).await;
    let context = random_context();
    coordinator
        .create_association(&hash, &repository, &context)
        .await
        .unwrap();
    let resolved = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    let witness = expect_readable(&resolved[0]).0;
    let new_context = random_context();
    assert_eq!(
        coordinator
            .create_association_if_current(witness, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 0);
    // A6: a LIVE key re-put under the same readable witness is a no-op.
    assert_eq!(
        coordinator
            .create_association_if_current(witness, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 0);
    coordinator
        .tombstone_association(&hash, &repository, &new_context)
        .await
        .unwrap();
    assert_eq!(invalidation(&coordinator, &repository).await, 1);
    // Recreating a tombstoned key is a replacement and still invalidates.
    assert_eq!(
        coordinator
            .create_association_if_current(witness, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 2);
    let mut stale = witness.clone();
    stale.epoch += 1;
    assert_eq!(
        coordinator
            .create_association_if_current(&stale, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Fenced
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 2);
}

/// A6: two clients write the same fragment, so the second PUT re-binds a key
/// that is already LIVE under the same readable head. That must keep the
/// exact binding (`association_epoch`, `updated_at`) and move no push scalar,
/// so a concurrent push's witness stays valid. The unguarded writer, which
/// can bind against a non-readable head, keeps the conservative rebind.
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn guarded_live_rebind_keeps_the_binding_and_every_push_scalar() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let direct = client(&url).await;
    let hash = publish_remote_fragment(&coordinator, 15).await;
    let context = random_context();
    coordinator
        .create_association(&hash, &repository, &context)
        .await
        .unwrap();
    let resolved = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    let (witness, _, bound_epoch) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    let before_row = association_row(&direct, &hash, &repository, &context).await;
    let before = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published,
        "a same-content live re-put is an idempotent success"
    );

    let after = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after, before,
        "no push scalar moves: not invalidation, not lifecycle, not association"
    );
    assert_eq!(
        association_row(&direct, &hash, &repository, &context).await,
        before_row,
        "the live row is not rewritten"
    );
    let after_resolve = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    assert_eq!(
        after_resolve, resolved,
        "the resolver verdict, association_epoch included, is unchanged"
    );
    assert_eq!(expect_readable(&after_resolve[0]).2, bound_epoch);

    // A different binding still invalidates: the unguarded writer rebinds.
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let rebound = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rebound.content_membership_invalidation_generation,
        before.content_membership_invalidation_generation + 1
    );
    assert_ne!(
        association_row(&direct, &hash, &repository, &context)
            .await
            .0,
        before_row.0
    );
}

/// `(association_epoch, state, repository_generation, updated_at)` of one key.
async fn association_row(
    direct: &Client,
    hash: &[u8],
    repository: &[u8],
    context: &[u8],
) -> (i64, i16, i64, String) {
    let row = direct
        .query_one(
            "SELECT association_epoch, state, repository_generation, updated_at::text \
               FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[&hash, &repository, &context],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

/// A guarded re-put against a key that is not LIVE keeps today's behavior:
/// a tombstoned key recreates and invalidates, and a non-readable head is
/// fenced with no write.
#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn guarded_rebind_of_non_live_states_is_unchanged() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let direct = client(&url).await;
    let hash = publish_remote_fragment(&coordinator, 16).await;
    let context = random_context();
    coordinator
        .create_association(&hash, &repository, &context)
        .await
        .unwrap();
    let resolved = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    let (witness, _, live_epoch) = expect_readable(&resolved[0]);
    let witness = witness.clone();
    coordinator
        .tombstone_association(&hash, &repository, &context)
        .await
        .unwrap();
    let tombstoned = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        coordinator
            .create_association_if_current(&witness, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let recreated = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recreated.content_membership_invalidation_generation,
        tombstoned.content_membership_invalidation_generation + 1,
        "recreating a tombstoned key is a replacement"
    );
    assert_eq!(
        recreated.content_association_generation,
        tombstoned.content_association_generation + 1
    );
    let reresolved = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    assert!(
        expect_readable(&reresolved[0]).2 > live_epoch,
        "recreation takes a fresh association epoch"
    );

    // A head that is no longer readable fences, and writes nothing.
    let current = expect_readable(&reresolved[0]).0.clone();
    assert_eq!(
        coordinator
            .mark_missing(&current, MissingDiagnostic::Absent)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    let before_fence = association_row(&direct, &hash, &repository, &context).await;
    let missing = coordinator
        .capture_push_witness(&repository)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        coordinator
            .create_association_if_current(&current, &repository, &context)
            .await
            .unwrap(),
        CommitVerdict::Fenced
    );
    assert_eq!(
        association_row(&direct, &hash, &repository, &context).await,
        before_fence
    );
    assert_eq!(
        coordinator
            .capture_push_witness(&repository)
            .await
            .unwrap()
            .unwrap(),
        missing
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn both_obliterate_retirement_paths_advance_invalidation_with_retained_payload_control() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    // Arrange the legacy repository before enabling governed metadata admission.
    // Both fragment publication and retirement still run with write claims active.
    enable_write_claims(&url, &coordinator).await;
    let hash = publish_remote_fragment(&coordinator, 13).await;
    let first = random_context();
    let second = random_context();
    coordinator
        .create_association(&hash, &repository, &first)
        .await
        .unwrap();
    coordinator
        .create_association(&hash, &repository, &second)
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .begin_obliterate(&hash, &repository, &first)
            .await
            .unwrap(),
        FragmentObliterateBegin::AssociationOnly
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 1);
    let retained = coordinator
        .resolve(&repository, &second, std::slice::from_ref(&hash))
        .await
        .unwrap();
    expect_readable(&retained[0]);
    let result = coordinator
        .begin_obliterate(&hash, &repository, &second)
        .await
        .unwrap();
    assert!(
        matches!(
            result,
            FragmentObliterateBegin::Ready(_) | FragmentObliterateBegin::Blocked { .. }
        ),
        "{result:?}"
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 2);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn invalidation_overflow_rolls_back_rebind_and_retirement_without_wrapping() {
    let url = pg_url().expect("LORE_TEST_PG_URL");
    let store = store(&url).await;
    let coordinator = store.fragment_coordinator();
    let repository = create_repository(&store).await;
    let hash = publish_remote_fragment(&coordinator, 14).await;
    let context = random_context();
    coordinator
        .create_association(&hash, &repository, &context)
        .await
        .unwrap();
    let direct = client(&url).await;
    direct.execute("UPDATE lore_domain_repositories SET content_membership_invalidation_generation = $2 WHERE repository_id = $1", &[&repository.as_slice(), &i64::MAX]).await.unwrap();
    let before = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    let epoch = expect_readable(&before[0]).2;
    assert!(
        coordinator
            .create_association(&hash, &repository, &context)
            .await
            .is_err()
    );
    assert!(
        coordinator
            .tombstone_association(&hash, &repository, &context)
            .await
            .is_err()
    );
    let after = coordinator
        .resolve(&repository, &context, std::slice::from_ref(&hash))
        .await
        .unwrap();
    assert_eq!(expect_readable(&after[0]).2, epoch);
    assert_eq!(invalidation(&coordinator, &repository).await, i64::MAX);
    assert_eq!(
        coordinator
            .create_association(&hash, &repository, &random_context())
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, i64::MAX);
}

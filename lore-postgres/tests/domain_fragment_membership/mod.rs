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
    assert_eq!(
        coordinator
            .create_association_if_current(witness, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 1);
    coordinator
        .tombstone_association(&hash, &repository, &new_context)
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .create_association_if_current(witness, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Published
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 3);
    let mut stale = witness.clone();
    stale.epoch += 1;
    assert_eq!(
        coordinator
            .create_association_if_current(&stale, &repository, &new_context)
            .await
            .unwrap(),
        CommitVerdict::Fenced
    );
    assert_eq!(invalidation(&coordinator, &repository).await, 3);
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

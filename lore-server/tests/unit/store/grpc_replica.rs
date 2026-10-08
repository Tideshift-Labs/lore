// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
mod stream_error_tests;

use std::sync::Arc;

use lore_base::types::Partition;
use lore_revision::fragment::generate_random;
use lore_server::store::grpc_replica::*;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use mockall::predicate::eq;

#[tokio::test]
async fn test_put() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| Ok(()));

    let store = GrpcReplica::new(client);

    Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_put_fails_with_slowdown() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| Err(ReplicationClientError::SlowDown));

    let store = GrpcReplica::new(client);

    let err = Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await
        .expect_err("should have failed");

    assert!(matches!(err, StoreError::SlowDown(_)));

    Ok(())
}

#[tokio::test]
async fn test_put_fails_with_other_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| {
            Err(ReplicationClientError::RequestFailed(
                tonic::Status::internal("Oh noes"),
            ))
        });

    let store = GrpcReplica::new(client);

    let err = Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await
        .expect_err("should have failed");

    assert!(matches!(err, StoreError::Internal(_)));

    Ok(())
}

/// `GrpcReplica` has no `repository_stats` RPC on its wire protocol, so its
/// explicit override reports `NotSupported` without touching the client.
/// A cell wired to forward through this replica therefore reports
/// `NotSupported` for storage-stats metering even when the store it
/// forwards to could compute the real number; this pins that as the
/// intended behavior rather than inheriting a future trait default. The
/// mock client needs no `.expect_*()` because the override never touches it.
#[tokio::test]
async fn repository_stats_explicit_override_returns_not_supported() {
    let client = MockReplicationClientImpl::default();
    let store = GrpcReplica::new(client);

    let err = Arc::new(store)
        .repository_stats(Partition::default())
        .await
        .expect_err("GrpcReplica explicitly refuses repository_stats");

    assert!(matches!(err, StoreError::NotSupported(_)));
}

/// The replication protocol has no obliterate message, so `GrpcReplica`
/// cannot remove the peer's copy. It must refuse rather than report a
/// success it did not perform, matching its `copy` sibling and
/// `Replica::obliterate`. The mock client needs no `.expect_*()` because
/// the refusal never touches it.
#[tokio::test]
async fn obliterate_refuses_instead_of_reporting_success() {
    use lore_storage::StoreObliterateStats;

    let client = MockReplicationClientImpl::default();
    let store = GrpcReplica::new(client);
    let (_, address, _) = generate_random();

    let err = Arc::new(store)
        .obliterate(
            Partition::default(),
            address,
            Arc::new(StoreObliterateStats::default()),
        )
        .await
        .expect_err("GrpcReplica must not report an obliterate it did not perform");

    assert!(matches!(err, StoreError::NotSupported(_)));
}

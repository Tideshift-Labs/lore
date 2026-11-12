// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::drain_policy::DrainDescriptor;
use lore_object_dispatch::drain_policy::DrainPolicy;
use uuid::Uuid;

fn policy() -> DrainPolicy {
    DrainPolicy {
        boundary: "boundary".into(),
        cell: "cell".into(),
        service: "drain-service".into(),
        revision: "policy-1".into(),
        quota_revision: 1,
        quotas: [[1_048_576, 16, 4, 1024, 1, 1]; 3],
        maximum_ttl_ms: 60_000,
        expires_at_ms: 2_000_000_000_000,
        metadata_max_rows: 32,
        metadata_max_bytes: 1_048_576,
        stage: lore_object_dispatch::drain_policy::DrainStagePolicy {
            max_bytes: 1_048_576,
            max_files: 32,
            max_metadata_bytes: 1_048_576,
            max_metadata_rows: 32,
            prepare_ttl_ms: 60_000,
        },
    }
}

fn descriptor() -> DrainDescriptor {
    DrainDescriptor {
        policy_revision: "policy-1".into(),
        policy_digest: "11".repeat(32),
        boundary: "boundary".into(),
        cell: "cell".into(),
        service: "drain-service".into(),
        logical_request_id: Uuid::parse_str("01900000-0000-7000-8000-000000000001").unwrap(),
        attempt_id: Uuid::parse_str("01900000-0000-7000-8000-000000000002").unwrap(),
        upload_id: Uuid::parse_str("01900000-0000-7000-8000-000000000003").unwrap(),
        spool_object_id: Uuid::parse_str("01900000-0000-7000-8000-000000000004").unwrap(),
        upload_fence: 3,
        source_hash: "22".repeat(32),
        source_epoch: 1,
        source_manifest: "33".repeat(32),
        remote_epoch: 2,
        remote_fence: 3,
        object_key: "22".repeat(32),
        body_digest: "44".repeat(32),
        body_size: 128,
        send_not_after_ms: 2_000_000_000_000,
        hard_not_after_ms: 2_000_000_060_000,
        prepared_ttl_ms: 60_000,
        max_chunk_bytes: 262_144,
        allocation_revision: "allocation-1".into(),
        allocation_fence: 1,
        allocation_expiry_ms: 2_000_000_120_000,
        boundary_digest: "55".repeat(32),
        boundary_token: "boundary-token".into(),
        observation_digest: "66".repeat(32),
    }
}

#[test]
fn descriptor_matches_the_literal_v1_preimage() {
    // Independent network-order fixture, not emitted by the production codec.
    let expected = include_str!("fixtures/fragment-drain-reservation-v1.hex").trim();
    let actual = lore_object_dispatch::drain_policy::hex(&descriptor().canonical_bytes().unwrap());
    assert_eq!(actual, expected);
}

#[test]
fn descriptor_binds_each_source_body_policy_and_attempt_field() {
    let original = descriptor();
    let canonical = original.canonical_bytes().unwrap();
    let mutations: &[fn(&mut DrainDescriptor)] = &[
        |d| d.policy_revision.push('2'),
        |d| d.policy_digest = "aa".repeat(32),
        |d| d.boundary.push('2'),
        |d| d.cell.push('2'),
        |d| d.service.push('2'),
        |d| d.logical_request_id = Uuid::now_v7(),
        |d| d.attempt_id = Uuid::now_v7(),
        |d| d.upload_id = Uuid::now_v7(),
        |d| d.spool_object_id = Uuid::now_v7(),
        |d| d.upload_fence += 1,
        |d| d.source_hash = "aa".repeat(32),
        |d| d.source_epoch += 1,
        |d| d.source_manifest = "aa".repeat(32),
        |d| d.remote_epoch += 1,
        |d| d.remote_fence += 1,
        |d| d.object_key = "aa".repeat(32),
        |d| d.body_digest = "aa".repeat(32),
        |d| d.body_size += 1,
        |d| d.send_not_after_ms += 1,
        |d| d.hard_not_after_ms += 1,
        |d| d.prepared_ttl_ms += 1,
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(
            changed.canonical_bytes().unwrap(),
            canonical,
            "mutation {index}"
        );
    }
    let mut changed = original.clone();
    changed.max_chunk_bytes -= 1;
    assert!(changed.canonical_bytes().is_err());
}

#[test]
fn allocation_renewal_is_excluded_from_the_descriptor_fingerprint() {
    let original = descriptor();
    let mut renewed = original.clone();
    renewed.allocation_revision = "allocation-2".into();
    renewed.allocation_fence += 1;
    renewed.allocation_expiry_ms += 60_000;
    assert_eq!(
        original.canonical_bytes().unwrap(),
        renewed.canonical_bytes().unwrap()
    );
}

#[test]
fn policy_refuses_colliding_scopes_zero_limits_and_consumed_low_water() {
    let original = policy();
    assert!(original.canonical_bytes().is_ok());
    for scope in 0..3 {
        for dimension in 0..3 {
            let mut zero = original.clone();
            zero.quotas[scope][dimension] = 0;
            assert!(zero.canonical_bytes().is_err());
            let mut consumed = original.clone();
            consumed.quotas[scope][dimension + 3] = consumed.quotas[scope][dimension];
            assert!(consumed.canonical_bytes().is_err());
        }
    }
    for (first, second) in [(0, 1), (0, 2), (1, 2)] {
        let mut collision = original.clone();
        let ids = [
            &mut collision.boundary,
            &mut collision.cell,
            &mut collision.service,
        ];
        let value = ids[first].clone();
        *ids[second] = value;
        assert!(collision.canonical_bytes().is_err());
    }
}

#[test]
fn descriptor_rejects_bad_uuid_digest_size_and_deadline() {
    let mutations: &[fn(&mut DrainDescriptor)] = &[
        |d| d.attempt_id = Uuid::nil(),
        |d| d.source_manifest = "ab".repeat(31),
        |d| d.body_digest = "AB".repeat(32),
        |d| d.body_size = 262_145,
        |d| d.upload_fence = 0,
        |d| d.prepared_ttl_ms = 0,
        |d| d.send_not_after_ms = d.hard_not_after_ms + 1,
        |d| d.hard_not_after_ms = u64::MAX,
    ];
    for mutate in mutations {
        let mut invalid = descriptor();
        mutate(&mut invalid);
        assert!(invalid.canonical_bytes().is_err());
    }
}

/// drain-tput2: every drain procedure that writes the cell's hot rows (the quota counters and the
/// drain policy row) takes the hot-row lock first, so racing writers wait instead of aborting.
/// Held by text: dropping the lock from one caller keeps every functional case green and only
/// brings back the serialization failures under load. The live race test
/// (`live_r32_racing_reserves_wait_in_turn_under_the_hot_row_lock`) proves the lock's effect.
#[test]
fn every_hot_row_writer_takes_the_hot_row_lock() {
    let spool = include_str!("../src/drain_spool.rs");
    let policy = include_str!("../src/drain_policy.rs");
    let policy = policy.split("#[cfg(test)]").next().unwrap_or(policy);
    for (source, procedure) in [
        (spool, "drain_cleanup_release_v1"),
        (spool, "drain_cleanup_compact_v3"),
        (spool, "drain_retired_floor_advance_v1"),
        (policy, "drain_reserve_v1"),
    ] {
        let needle = format!("SELECT object_store_retention.{procedure}(");
        assert_eq!(
            source.matches(&needle).count(),
            1,
            "{procedure} has exactly one call"
        );
        let call = source.find(&needle).expect("the call");
        let receiver = &source[call.saturating_sub(80)..call];
        assert!(
            receiver.contains(".query_hot("),
            "{procedure} must run under the hot-row lock (query_hot)"
        );
    }
    // The one hot path: lock, then the SERIALIZABLE transaction, then unlock; and a commit whose
    // unlock failed closes its session instead of returning it to the pool.
    let with = &policy[policy.find("async fn query_with(").expect("query_with")..];
    let with = &with[..with.find("\n    }\n").expect("end of query_with")];
    let lock = with.find("lock_hot_rows(").expect("the lock");
    let begin = with.find(".build_transaction()").expect("the transaction");
    let commit = with.find("tx.commit()").expect("the commit");
    let unlock = with.find("unlock_hot_rows(client)").expect("the unlock");
    assert!(
        lock < begin && begin < commit && commit < unlock,
        "lock, then the SERIALIZABLE transaction, then unlock"
    );
    assert_eq!(with.matches("lease.release().await").count(), 1);
    let release = with.find("Ok(Ok((rows, true))) =>").expect("the clean arm");
    assert!(
        with[release..]
            .find("lease.release().await")
            .is_some_and(|at| at < with[release..].find("Ok(Ok((rows, false)))").unwrap_or(0)),
        "only the clean unlock returns the session to the pool"
    );
    // The lock arms the idle bounds and the unlock resets them.
    let lock_fn = &policy[policy
        .find("async fn lock_hot_rows(")
        .expect("lock_hot_rows")..];
    let lock_fn = &lock_fn[..lock_fn.find("\n}\n").expect("end")];
    for setting in [
        "SET idle_session_timeout",
        "SET idle_in_transaction_session_timeout",
    ] {
        assert!(lock_fn.contains(setting), "the lock arms {setting}");
    }
    let unlock_fn = &policy[policy
        .find("async fn unlock_hot_rows(")
        .expect("unlock_hot_rows")..];
    let unlock_fn = &unlock_fn[..unlock_fn.find("\n}\n").expect("end")];
    for setting in [
        "RESET idle_session_timeout",
        "RESET idle_in_transaction_session_timeout",
    ] {
        assert!(unlock_fn.contains(setting), "the unlock runs {setting}");
    }
}

/// drain-tput5: the stuck-holder read runs after a `ROLLBACK` that dropped the operation's
/// `SET LOCAL` bounds, so it must open its own transaction, bound it on the server, and roll it
/// back. Held by text: the live case (`live_r32_the_hot_row_lock_never_returns_to_the_pool_held`)
/// runs the read but cannot see which `statement_timeout` it ran under.
#[test]
fn the_stuck_holder_read_carries_its_own_server_side_timeout() {
    let policy = include_str!("../src/drain_policy.rs");
    let policy = policy.split("#[cfg(test)]").next().unwrap_or(policy);
    let read = &policy[policy
        .find("pub async fn hot_row_lock_holders(")
        .expect("hot_row_lock_holders")..];
    let read = &read[..read.find("\n}\n").expect("end")];
    let order = [
        "client.transaction().await?",
        "SET LOCAL statement_timeout = '{HOT_ROW_HOLDER_READ_TIMEOUT_MS}ms'",
        "SET LOCAL lock_timeout = '{HOT_ROW_HOLDER_READ_TIMEOUT_MS}ms'",
        ".query(HOT_ROW_HOLDER_SQL,",
        "tx.rollback().await?",
    ];
    let mut at = 0;
    for needle in order {
        let found = read[at..]
            .find(needle)
            .unwrap_or_else(|| panic!("hot_row_lock_holders must run `{needle}` in order"));
        at += found + needle.len();
    }
    assert!(
        !read.contains("client\n        .query(") && !read.contains("client.query("),
        "the holder read must not run outside its bounded transaction"
    );
    assert_eq!(
        lore_object_dispatch::drain_policy::HOT_ROW_HOLDER_READ_TIMEOUT_MS,
        1_000
    );
}

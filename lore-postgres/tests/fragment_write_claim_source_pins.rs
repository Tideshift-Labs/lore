// Copyright Epic Games, Inc. All Rights Reserved.
// Copyright 2026 Tideshift Labs Ltd.
// SPDX-License-Identifier: MIT

fn coordinator_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/domain/fragments/coordinator.rs"
    ))
    .expect("coordinator source")
}

fn immutable_store_source() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/store/immutable_store.rs"
    ))
    .expect("immutable store source")
}

fn function<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).expect("function signature");
    let body = source[start..].find('{').expect("function body") + start;
    let mut depth = 0usize;
    for (offset, byte) in source[body..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {signature}");
}

fn assert_order(source: &str, markers: &[&str]) {
    let mut cursor = 0usize;
    for marker in markers {
        let offset = source[cursor..]
            .find(marker)
            .unwrap_or_else(|| panic!("missing ordered marker {marker}"));
        cursor += offset + marker.len();
    }
}

#[test]
fn claim_creation_locks_head_before_claim_and_uses_one_database_clock_snapshot() {
    let source = coordinator_source();
    let begin = function(&source, "async fn begin_publication(");
    assert_order(
        begin,
        &[
            "lock_fragment_head(&tx, &mut sequence, hash).await?",
            "create_write_claim_locked(",
            "tx.commit().await",
        ],
    );

    let create = function(&source, "async fn create_write_claim_locked(");
    assert!(create.contains("lock_write_claim(tx, sequence, input).await?"));
    assert!(create.contains(
        "write_claim_barrier_locked(tx, sequence, lineage.hash, lineage.epoch, lineage.fence).await?"
    ));
    assert!(create.contains("WITH claim_clock AS (SELECT clock_timestamp() AS now)"));
    assert!(create.contains("claim_clock.now + ($11::bigint * interval '1 millisecond')"));
    assert!(
        create
            .contains("claim_clock.now + (($11::bigint + $12::bigint) * interval '1 millisecond')")
    );
    assert!(create.contains("claim_clock.now"));
    assert!(!create.contains("SystemTime::now"));
}

#[test]
fn authorization_revalidates_lineage_and_claim_before_marking_sending() {
    let source = coordinator_source();
    let authorize = function(&source, "pub async fn authorize_write_claim(");
    assert_order(
        authorize,
        &[
            "lock_fragment_head(&tx, &mut sequence, &claim.hash).await?",
            "let lineage_matches",
            "lock_write_claim_identity(",
            "if locked.claim != *claim",
            "SELECT clock_timestamp()",
            "SET state = $3, authorized_at = clock_timestamp()",
            "tx.commit().await",
        ],
    );
    assert!(authorize.contains("head.state == FragmentLifecycleState::PreparingRemote"));
    assert!(authorize.contains("FragmentWriteSettlement::NoSend"));
    assert!(authorize.contains("fragment_write_lineage_moved"));
    assert!(authorize.contains("claim.send_not_after.duration_since(database_now)"));
    assert!(!authorize.contains("SystemTime::now"));
}

#[test]
fn no_send_is_a_terminal_settlement_but_cannot_publish_an_observation() {
    let source = coordinator_source();
    for (signature, diagnostic) in [
        (
            "pub async fn commit_remote(",
            "a no-send claim cannot publish a remote observation",
        ),
        (
            "pub async fn commit_repair(",
            "a no-send claim cannot publish a repair observation",
        ),
    ] {
        let commit = function(&source, signature);
        assert_order(
            commit,
            &[
                "if settlement == FragmentWriteSettlement::NoSend",
                "DomainError::InvalidInput(",
                diagnostic,
                "self.commit_publication(",
            ],
        );
        let refusal = commit
            .find("if settlement == FragmentWriteSettlement::NoSend")
            .expect("NoSend refusal");
        let publication = commit
            .find("self.commit_publication(")
            .expect("publication call");
        assert!(!commit[refusal..publication].contains("checkout()"));
    }
}

#[test]
fn invalid_settlement_never_clears_a_claim_or_reaches_the_state_update() {
    let source = coordinator_source();
    let settle = function(&source, "async fn settle_write_claim_locked(");
    assert_order(
        settle,
        &[
            "if !valid_transition",
            "fragment_write_claim_invalid_settlement",
            "UPDATE lore_fragment_write_claims",
        ],
    );
    let refusal = settle
        .find("if !valid_transition")
        .expect("invalid-transition refusal");
    let update = settle
        .find("UPDATE lore_fragment_write_claims")
        .expect("settlement update");
    assert!(!settle[refusal..update].contains("return Ok(())"));
}

#[test]
fn hash_wide_inventory_preserves_exact_cleanup_targets_and_uses_database_time() {
    let source = coordinator_source();
    let inventory = function(&source, "async fn write_claim_inventory_locked(");
    assert!(inventory.contains("WHERE hash = $1"));
    assert!(!inventory.contains("WHERE hash = $1 AND epoch"));
    assert_eq!(inventory.matches("SELECT clock_timestamp()").count(), 1);
    for field in [
        "logical_request_id",
        "attempt_id",
        "hash",
        "epoch",
        "fence",
        "authority",
        "object_key",
        "body_blake3",
        "body_size",
    ] {
        assert!(inventory.contains(field), "inventory omitted {field}");
    }
    assert_order(
        inventory,
        &[
            "FragmentWriteClaimState::Prepared",
            "locked.claim.send_not_after > database_now",
            "FragmentWriteClaimState::NoSend.bits()",
            "FragmentWriteClaimState::Sending | FragmentWriteClaimState::Ambiguous",
            "locked.claim.hard_not_after > database_now",
            "cleanup_targets.push(FragmentWriteCleanupTarget",
            "FragmentWriteClaimState::NoSend => {}",
        ],
    );
    assert!(inventory.contains(
        "FragmentWriteClaimState::Sending\n            | FragmentWriteClaimState::Ambiguous\n            | FragmentWriteClaimState::Decisive => {\n                cleanup_targets.push(FragmentWriteCleanupTarget"
    ));
}

#[test]
fn prune_is_bounded_db_clocked_and_requires_exact_decisive_epoch_evidence() {
    let source = coordinator_source();
    let prune = function(&source, "pub async fn prune_terminal_write_claims(");
    assert!(prune.contains("claim.state = $1"));
    assert!(prune.contains("claim.state = $2 AND EXISTS"));
    assert!(prune.contains("FragmentWriteClaimState::Decisive.bits()"));
    assert!(prune.contains("FragmentWriteClaimState::NoSend.bits()"));
    for forbidden in [
        "FragmentWriteClaimState::Prepared.bits()",
        "FragmentWriteClaimState::Sending.bits()",
        "FragmentWriteClaimState::Ambiguous.bits()",
        "SystemTime::now",
    ] {
        assert!(
            !prune.contains(forbidden),
            "prune widened through {forbidden}"
        );
    }
    assert!(prune.contains("settled_at <= clock_timestamp()"));
    assert!(prune.contains("LIMIT $4"));
    assert_order(
        prune,
        &[
            "claim.state = $1",
            "claim.state = $2 AND EXISTS",
            "epoch.provider_body_blake3 = claim.body_blake3",
            "epoch.provider_body_size = claim.body_size",
            "epoch.provider_claim_fence = claim.fence",
            "LIMIT $4",
        ],
    );
    assert_order(
        prune,
        &[
            "lock_fragment_head(&tx, &mut sequence, &candidate.hash).await?",
            "write_claim_inventory_locked(&tx, &mut sequence, &candidate.hash).await?",
            "DELETE FROM lore_fragment_write_claims",
        ],
    );
    for exact in [
        "claim.hash = $3",
        "claim.epoch = $4",
        "claim.fence = $5",
        "claim.authority = $6",
        "claim.object_key = $7",
        "claim.body_blake3 = $8",
        "claim.body_size = $9",
        "epoch.provider_body_blake3 = $8",
        "epoch.provider_body_size = $9",
        "epoch.provider_claim_fence = $5",
    ] {
        assert!(prune.contains(exact), "decisive prune omitted {exact}");
    }
}

#[test]
fn direct_put_claim_is_authorized_immediately_before_the_bounded_send() {
    let source = immutable_store_source();
    let issue = function(&source, "async fn issue_direct_put(");
    assert_order(
        issue,
        &[
            ".admit_put(",
            ".authorize_write_claim(claim)",
            "tokio::time::timeout(",
            "admitted.execute_direct_put(&mut ledger, request.payload)",
        ],
    );
    let authorization = issue
        .find(".authorize_write_claim(claim)")
        .expect("authorization");
    let send = issue
        .find("admitted.execute_direct_put(&mut ledger, request.payload)")
        .expect("direct send");
    let between = &issue[authorization..send];
    for forbidden in ["checkout()", ".transaction()", "lock_fragment_head"] {
        assert!(
            !between.contains(forbidden),
            "database resource crossed the provider send boundary through {forbidden}"
        );
    }
    assert!(issue.contains("FragmentWriteSettlement::NoSend"));
    assert!(issue.contains("FragmentWriteSettlement::Ambiguous"));
    assert!(issue.contains("FragmentWriteSettlement::Decisive"));
    assert!(issue.contains("if authorized.send_budget().is_zero()"));
    assert!(issue.contains("authorized.send_budget(),"));
}

#[test]
fn every_coordinated_direct_put_claims_before_provider_io_while_get_stays_unmetered() {
    let source = immutable_store_source();
    let put = function(&source, "async fn put_coordinated(");
    assert_eq!(put.matches("FragmentWriteClaimInput::new(").count(), 1);
    assert_eq!(put.matches(".begin_direct_write(").count(), 1);
    assert_eq!(put.matches(".issue_direct_put(").count(), 1);
    assert_order(
        put,
        &[
            "FragmentWriteClaimInput::new(",
            ".begin_direct_write(",
            ".issue_direct_put(",
            ".commit_remote(",
        ],
    );

    let get = function(&source, "async fn load_coordinated(");
    for forbidden in [
        "FragmentWriteClaimInput",
        "authorize_write_claim",
        "settle_write_claim",
        "FragmentAttemptLedger",
        "PostgresProviderChargeAuthority",
    ] {
        assert!(!get.contains(forbidden), "GET widened through {forbidden}");
    }
}

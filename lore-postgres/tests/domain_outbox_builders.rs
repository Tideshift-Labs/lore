// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-116 outbox event builders (`lore-postgres/src/domain/outbox/builders.rs`)
//! conformance against the pinned CR-032 value set.
//!
//! Pure, no Postgres: every builder in this module is a pure function with no
//! I/O, so this file proves their output shape directly rather than through a
//! coordinator round trip. `domain_outbox_producers.rs` covers the
//! coordinator-level atomicity/no-row/idempotency-key contract with
//! hand-built `PendingEvent`s; this file is the complementary half that
//! proves the builders themselves emit the pinned strings and the
//! `(aggregate_kind -> ordinal source, identity source)` shape CR-032 PIN-4
//! assigns.
//!
//! Fixture loading follows `domain_outbox_encoding.rs`'s convention: FAIL if
//! the fixture is absent, never skip.

use std::path::PathBuf;

use lore_postgres::domain::coordinator::CommittedOrdinal;
use lore_postgres::domain::coordinator::CommittedVersions;
use lore_postgres::domain::outbox::AggregateVersion;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::builders;
use lore_postgres::domain::outbox::builders::PINNED_AGGREGATE_KINDS;
use lore_postgres::domain::outbox::builders::PINNED_EVENT_KINDS;
use lore_postgres::domain::outbox::idempotency_key;
use serde_json::Value;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lorehub/docs/contracts/fixtures/lore-notification-plane")
        .join(name)
}

fn load_fixture(name: &str) -> Value {
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{name} fixture is required and must not be skipped when absent. Expected it at \
             {}: {error}",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"))
}

fn decode_hex(label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|error| panic!("fixture field {label} is not valid hex: {error}"))
}

fn find_vector<'a>(fixture: &'a Value, id: &str) -> &'a Value {
    fixture["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("idempotency-key.json has no vector with id {id:?}"))
}

// ---------------------------------------------------------------------------
// Value-set conformance
// ---------------------------------------------------------------------------

/// `PINNED_EVENT_KINDS` must be exactly the fixture's 17 `event_kind` values
/// -- no more, no fewer, order-independent. CR-032 makes an unclassified kind
/// fail closed, so a silently grown or shrunk builder set is exactly the way
/// that stops being true.
#[test]
fn pinned_event_kinds_matches_the_fixture_exactly() {
    let fixture = load_fixture("event-kinds.json");
    let mut fixture_kinds: Vec<String> = fixture["aggregate_kinds"]
        .as_array()
        .expect("aggregate_kinds array")
        .iter()
        .flat_map(|k| {
            k["event_kinds"]
                .as_array()
                .expect("event_kinds array")
                .iter()
                .map(|v| v.as_str().expect("event_kind string").to_owned())
        })
        .collect();
    fixture_kinds.sort();

    let mut builder_kinds: Vec<String> = PINNED_EVENT_KINDS.iter().map(|s| s.to_string()).collect();
    builder_kinds.sort();

    assert_eq!(
        builder_kinds, fixture_kinds,
        "builders.rs's PINNED_EVENT_KINDS must match event-kinds.json's event_kinds exactly"
    );
    let count = fixture["counts"]["event_kinds"]
        .as_u64()
        .expect("counts.event_kinds");
    assert_eq!(count as usize, PINNED_EVENT_KINDS.len());
}

/// `PINNED_AGGREGATE_KINDS` must be exactly the fixture's 5 `aggregate_kind`
/// values.
#[test]
fn pinned_aggregate_kinds_matches_the_fixture_exactly() {
    let fixture = load_fixture("event-kinds.json");
    let mut fixture_kinds: Vec<String> = fixture["aggregate_kinds"]
        .as_array()
        .expect("aggregate_kinds array")
        .iter()
        .map(|k| {
            k["aggregate_kind"]
                .as_str()
                .expect("aggregate_kind string")
                .to_owned()
        })
        .collect();
    fixture_kinds.sort();

    let mut builder_kinds: Vec<String> = PINNED_AGGREGATE_KINDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    builder_kinds.sort();

    assert_eq!(builder_kinds, fixture_kinds);
    let count = fixture["counts"]["aggregate_kinds"]
        .as_u64()
        .expect("counts.aggregate_kinds");
    assert_eq!(count as usize, PINNED_AGGREGATE_KINDS.len());
}

/// Every pinned `event_kind`/`aggregate_kind` string fits the contract's
/// 64-UTF-8-byte width (amendment A-14). The fixture separately records the
/// longest of each; cross-check every literal, not only the ones it names.
#[test]
fn every_pinned_kind_string_fits_the_64_byte_width() {
    for kind in PINNED_EVENT_KINDS {
        assert!(
            kind.len() <= 64,
            "event_kind {kind:?} is {} bytes, over the contract's 64-byte width",
            kind.len()
        );
    }
    for kind in PINNED_AGGREGATE_KINDS {
        assert!(
            kind.len() <= 64,
            "aggregate_kind {kind:?} is {} bytes, over the contract's 64-byte width",
            kind.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Repository-kind builders: aggregate_id = 16 repo bytes, ordinal =
// RepositoryGeneration, identity = empty
// ---------------------------------------------------------------------------

fn repo_id() -> [u8; 16] {
    rand::random()
}

#[test]
fn repository_published_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let event =
        builders::repository_published("cell-a", &repository_id, "my-repo", &branch_id, "main")
            .expect("build");
    assert_eq!(event.event_kind, builders::REPOSITORY_PUBLISHED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_REPOSITORY);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(
        event.aggregate_ordinal,
        CommittedOrdinal::RepositoryGeneration
    );
    assert!(event.aggregate_identity.is_empty());
    assert!(event.payload.len() <= 64 * 1024);
    // No fragment content: the payload is built from exactly the identity
    // arguments passed in, hex/JSON-escaped, nothing else.
    let payload_text = String::from_utf8(event.payload).expect("payload is valid UTF-8 JSON-ish");
    assert!(payload_text.contains("my-repo"));
    assert!(payload_text.contains(&hex::encode(repository_id)));
}

#[test]
fn repository_metadata_changed_shape() {
    let repository_id = repo_id();
    let event = builders::repository_metadata_changed(
        "cell-a",
        &repository_id,
        &rand::random::<[u8; 32]>(),
        &rand::random::<[u8; 32]>(),
    )
    .expect("build");
    assert_eq!(event.event_kind, builders::REPOSITORY_METADATA_CHANGED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_REPOSITORY);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(
        event.aggregate_ordinal,
        CommittedOrdinal::RepositoryGeneration
    );
    assert!(event.aggregate_identity.is_empty());
}

#[test]
fn repository_tombstoned_shape() {
    let repository_id = repo_id();
    let event = builders::repository_tombstoned("cell-a", &repository_id).expect("build");
    assert_eq!(event.event_kind, builders::REPOSITORY_TOMBSTONED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_REPOSITORY);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(
        event.aggregate_ordinal,
        CommittedOrdinal::RepositoryGeneration
    );
    assert!(event.aggregate_identity.is_empty());
}

/// CR-032 PIN-3's row: obliterated aggregate_version stays the repository
/// generation (empty identity) even though the payload names the obliterated
/// address.
#[test]
fn repository_obliterated_shape_matches_pin_3() {
    let repository_id = repo_id();
    let address_hash: [u8; 32] = rand::random();
    let address_context: [u8; 16] = rand::random();
    let event =
        builders::repository_obliterated("cell-a", &repository_id, &address_hash, &address_context)
            .expect("build");
    assert_eq!(event.event_kind, builders::REPOSITORY_OBLITERATED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_REPOSITORY);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(
        event.aggregate_ordinal,
        CommittedOrdinal::RepositoryGeneration,
        "PIN-3: the obliteration event's ordinal is the committed repository generation"
    );
    assert!(
        event.aggregate_identity.is_empty(),
        "PIN-3: repository.obliterated carries an empty identity"
    );
}

#[test]
fn repository_default_branch_changed_shape() {
    let repository_id = repo_id();
    let event = builders::repository_default_branch_changed(
        "cell-a",
        &repository_id,
        &rand::random::<[u8; 16]>(),
        &rand::random::<[u8; 16]>(),
    )
    .expect("build");
    assert_eq!(
        event.event_kind,
        builders::REPOSITORY_DEFAULT_BRANCH_CHANGED
    );
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_REPOSITORY);
    assert_eq!(
        event.aggregate_ordinal,
        CommittedOrdinal::RepositoryGeneration
    );
}

// ---------------------------------------------------------------------------
// Branch-kind builders: aggregate_id = the 16 raw branch-id bytes (CR-032's
// 2026-09-03 second amendment to PIN-4 -- the branch NAME travels in the
// bounded payload instead, since Lore admits names up to 1,000 bytes, past
// aggregate_id's 64-byte cap), ordinal = BranchGeneration, identity = exact
// revision hash.
// ---------------------------------------------------------------------------

#[test]
fn branch_pushed_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let previous: [u8; 32] = rand::random();
    let new: [u8; 32] = rand::random();
    let event = builders::branch_pushed(
        "cell-a",
        &repository_id,
        &branch_id,
        "feature/x",
        &previous,
        &new,
    )
    .expect("build");
    assert_eq!(event.event_kind, builders::BRANCH_PUSHED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_BRANCH);
    assert_eq!(
        event.aggregate_id,
        branch_id.to_vec(),
        "branch aggregate_id is the 16 raw branch-id bytes, per the second PIN-4 amendment"
    );
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::BranchGeneration);
    assert_eq!(
        event.aggregate_identity,
        new.to_vec(),
        "identity is the NEW tip, not the previous one"
    );
    // The branch name still travels, just in the payload rather than
    // aggregate_id.
    let payload_text = String::from_utf8(event.payload).expect("payload is UTF-8 JSON-ish");
    assert!(payload_text.contains("feature/x"));
}

#[test]
fn branch_created_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let head: [u8; 32] = rand::random();
    let event = builders::branch_created("cell-a", &repository_id, &branch_id, "main", &head)
        .expect("build");
    assert_eq!(event.event_kind, builders::BRANCH_CREATED);
    assert_eq!(event.aggregate_id, branch_id.to_vec());
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::BranchGeneration);
    assert_eq!(event.aggregate_identity, head.to_vec());
}

#[test]
fn branch_deleted_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let head: [u8; 32] = rand::random();
    let event = builders::branch_deleted("cell-a", &repository_id, &branch_id, "stale", &head)
        .expect("build");
    assert_eq!(event.event_kind, builders::BRANCH_DELETED);
    assert_eq!(event.aggregate_id, branch_id.to_vec());
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::BranchGeneration);
    assert_eq!(event.aggregate_identity, head.to_vec());
}

/// A branch_id that is not exactly 16 bytes is rejected at build time
/// (`checked_id_16`), before any transaction opens.
#[test]
fn branch_id_not_16_bytes_is_rejected_at_build_time() {
    let repository_id = repo_id();
    let head: [u8; 32] = rand::random();
    for wrong_len in [0usize, 15, 17, 32] {
        let bad_branch_id = vec![0u8; wrong_len];
        let result =
            builders::branch_created("cell-a", &repository_id, &bad_branch_id, "main", &head);
        assert!(
            result.is_err(),
            "a {wrong_len}-byte branch_id must be rejected"
        );
    }
    let branch_id: [u8; 16] = rand::random();
    let ok = builders::branch_created("cell-a", &repository_id, &branch_id, "main", &head);
    assert!(ok.is_ok(), "an exact 16-byte branch_id must be accepted");
}

/// The branch NAME is explicitly *not* bounded by `aggregate_id`'s 64-byte
/// cap since the second PIN-4 amendment: it travels unbounded (up to Lore's
/// own `MAX_NAME_LEN`) in the payload instead. A name past the old cap must
/// build successfully now, which is the amendment's whole point -- a legal
/// 1,000-byte branch name had no expressible outbox identity under the old
/// name-as-aggregate_id design.
#[test]
fn a_branch_name_past_the_old_64_byte_aggregate_id_cap_now_builds_successfully() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let head: [u8; 32] = rand::random();
    let long_name = "x".repeat(builders::MAX_AGGREGATE_ID_BYTES + 1);
    let event = builders::branch_created("cell-a", &repository_id, &branch_id, &long_name, &head)
        .expect("a branch name past the old aggregate_id cap must build successfully");
    assert_eq!(
        event.aggregate_id,
        branch_id.to_vec(),
        "aggregate_id is unaffected by name length -- it's the branch id"
    );
    let payload_text = String::from_utf8(event.payload).expect("payload is UTF-8 JSON-ish");
    assert!(
        payload_text.contains(&long_name),
        "the full, untruncated name must appear in the payload"
    );
}

/// The property the second PIN-4 amendment exists to protect: two branches
/// whose names share a 64-byte-or-longer common prefix but whose branch ids
/// differ must produce different `idempotency_key`s. Under the superseded
/// name-as-`aggregate_id` design this would have been a real collision --
/// both names would truncate (or, pre-truncation-rejection, simply be) the
/// same 64-byte `aggregate_id`, and the rest of the seven-field preimage is
/// otherwise identical here, so nothing else would have discriminated them.
/// This is a discriminating check, not just a happy-path assertion: it
/// separately reconstructs what the superseded scheme's `aggregate_id` would
/// have been (the shared 64-byte prefix) and shows that alternate preimage
/// really would collide, so this test cannot pass for the wrong reason.
#[test]
fn two_branches_with_a_shared_64_byte_name_prefix_but_different_ids_produce_different_idempotency_keys()
 {
    let cell_id = "cell-a";
    let repository_id = repo_id();
    let shared_prefix = "release/very-long-shared-branch-name-prefix-used-by-both-branch-";
    assert!(shared_prefix.len() >= builders::MAX_AGGREGATE_ID_BYTES);
    let name_a = format!("{shared_prefix}-a-tail-that-differs");
    let name_b = format!("{shared_prefix}-b-tail-that-differs");
    assert_eq!(
        &name_a[..shared_prefix.len()],
        &name_b[..shared_prefix.len()]
    );

    let branch_id_a: [u8; 16] = rand::random();
    let branch_id_b: [u8; 16] = rand::random();
    let head: [u8; 32] = rand::random();

    let event_a = builders::branch_pushed(
        cell_id,
        &repository_id,
        &branch_id_a,
        &name_a,
        &[0u8; 32],
        &head,
    )
    .expect("build a");
    let event_b = builders::branch_pushed(
        cell_id,
        &repository_id,
        &branch_id_b,
        &name_b,
        &[0u8; 32],
        &head,
    )
    .expect("build b");

    let aggregate_version = AggregateVersion::new(1832, head.to_vec())
        .expect("in-bounds identity")
        .encode();
    let outbox_event_a = OutboxEvent {
        cell_id: &event_a.cell_id,
        repository_id: &repository_id,
        repository_generation: 417,
        event_kind: &event_a.event_kind,
        aggregate_kind: &event_a.aggregate_kind,
        aggregate_id: &event_a.aggregate_id,
        aggregate_version: &aggregate_version,
        payload_schema_version: event_a.payload_schema_version,
        payload: &event_a.payload,
    };
    let outbox_event_b = OutboxEvent {
        cell_id: &event_b.cell_id,
        repository_id: &repository_id,
        repository_generation: 417,
        event_kind: &event_b.event_kind,
        aggregate_kind: &event_b.aggregate_kind,
        aggregate_id: &event_b.aggregate_id,
        aggregate_version: &aggregate_version,
        payload_schema_version: event_b.payload_schema_version,
        payload: &event_b.payload,
    };
    let key_a = idempotency_key(&outbox_event_a);
    let key_b = idempotency_key(&outbox_event_b);
    assert_ne!(
        key_a, key_b,
        "two distinct branches must never share an idempotency_key even when their names \
         share a 64-byte-or-longer prefix"
    );

    // Discriminating half: prove the superseded name-as-aggregate_id scheme
    // really would have collided here, so the positive assertion above isn't
    // vacuously true for an unrelated reason.
    let legacy_aggregate_id_a = name_a.as_bytes()[..builders::MAX_AGGREGATE_ID_BYTES].to_vec();
    let legacy_aggregate_id_b = name_b.as_bytes()[..builders::MAX_AGGREGATE_ID_BYTES].to_vec();
    assert_eq!(
        legacy_aggregate_id_a, legacy_aggregate_id_b,
        "sanity check on the test fixture itself: the shared prefix must be long enough that \
         a 64-byte truncation of both names is identical"
    );
    let legacy_outbox_event_a = OutboxEvent {
        aggregate_id: &legacy_aggregate_id_a,
        ..outbox_event_a
    };
    let legacy_outbox_event_b = OutboxEvent {
        aggregate_id: &legacy_aggregate_id_b,
        ..outbox_event_b
    };
    assert_eq!(
        idempotency_key(&legacy_outbox_event_a),
        idempotency_key(&legacy_outbox_event_b),
        "the superseded name-truncated-to-64-bytes scheme really would have collided here -- \
         this is exactly the defect CR-032's second PIN-4 amendment exists to close"
    );
}

/// An identity over 120 bytes (F-032-4's bound) is rejected at build time,
/// before the coordinator's own `AggregateVersion::new` would reject it
/// mid-transaction.
#[test]
fn lock_identity_over_120_bytes_is_rejected_at_build_time() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let too_long = vec![0u8; 121];
    let result = builders::lock_acquired(
        "cell-a",
        &repository_id,
        &branch_id,
        "assets/characters",
        "urc-7f3a",
        77,
        &too_long,
    );
    assert!(result.is_err(), "a 121-byte owner token must be rejected");

    let at_cap = vec![0u8; 120];
    let ok = builders::lock_acquired(
        "cell-a",
        &repository_id,
        &branch_id,
        "assets/characters",
        "urc-7f3a",
        77,
        &at_cap,
    );
    assert!(ok.is_ok(), "a 120-byte owner token must be accepted");
}

// ---------------------------------------------------------------------------
// Lock-namespace builders: aggregate_id = namespace (UTF-8), ordinal =
// Exact(committed_fence), identity = owner token
// ---------------------------------------------------------------------------

#[test]
fn lock_acquired_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let owner_token = b"urc-7f3a".to_vec();
    let event = builders::lock_acquired(
        "cell-a",
        &repository_id,
        &branch_id,
        "assets/characters",
        "user-123",
        77,
        &owner_token,
    )
    .expect("build");
    assert_eq!(event.event_kind, builders::LOCK_ACQUIRED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_LOCK_NAMESPACE);
    assert_eq!(event.aggregate_id, b"assets/characters".to_vec());
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::Exact(77));
    assert_eq!(event.aggregate_identity, owner_token);
}

/// Reproduces `idempotency-key.json`'s `lock-acquired` vector through
/// `builders::lock_acquired`. `Exact(committed_fence)` resolves independent of
/// any `CommittedVersions`, unlike the repository/branch-generation ordinals
/// the other reproduction tests resolve.
#[test]
fn lock_acquired_builder_reproduces_the_idempotency_key_fixture_vector() {
    let fixture = load_fixture("idempotency-key.json");
    let vector = find_vector(&fixture, "lock-acquired");
    let cell_id = vector["inputs"]["cell_id"].as_str().expect("cell_id");
    let repository_id = decode_hex(
        "repository_hex",
        vector["inputs"]["repository_hex"]
            .as_str()
            .expect("repository_hex"),
    );
    let repository_generation = vector["inputs"]["repository_generation"]
        .as_str()
        .expect("repository_generation")
        .parse::<i64>()
        .expect("repository_generation is a decimal integer");
    let namespace = vector["inputs"]["aggregate_id_utf8"]
        .as_str()
        .expect("aggregate_id_utf8");
    let expected_ordinal = vector["inputs"]["aggregate_version_ordinal"]
        .as_str()
        .expect("aggregate_version_ordinal")
        .parse::<u64>()
        .expect("ordinal is a decimal integer");
    let expected_identity_bytes = vector["inputs"]["aggregate_version_identity_bytes"]
        .as_u64()
        .expect("aggregate_version_identity_bytes");
    let aggregate_version_hex = vector["inputs"]["aggregate_version_hex"]
        .as_str()
        .expect("aggregate_version_hex");
    let full_version_bytes = decode_hex("aggregate_version_hex", aggregate_version_hex);
    assert_eq!(
        full_version_bytes.len(),
        8 + expected_identity_bytes as usize
    );
    let owner_token = full_version_bytes[8..].to_vec();
    let expected_key = decode_hex(
        "idempotency_key_hex",
        vector["idempotency_key_hex"]
            .as_str()
            .expect("idempotency_key_hex"),
    );

    // Arbitrary: neither feeds the idempotency_key preimage. `repository_id`
    // and `branch_id` here are the lock-payload arguments, not the outbox
    // row's own `repository_id` column (bound to the fixture's
    // `repository_hex` below) or the aggregate_id (bound to `namespace`).
    let payload_repository_id = [0x11u8; 16];
    let payload_branch_id = [0x22u8; 16];
    let event = builders::lock_acquired(
        cell_id,
        &payload_repository_id,
        &payload_branch_id,
        namespace,
        "user-123",
        expected_ordinal,
        &owner_token,
    )
    .expect("build lock_acquired");
    assert_eq!(event.aggregate_id, namespace.as_bytes().to_vec());

    let ordinal = event
        .aggregate_ordinal
        .resolve(CommittedVersions {
            repository_generation,
            branch_generation: None,
        })
        .expect("resolve the exact committed fence");
    assert_eq!(ordinal, expected_ordinal);
    let aggregate_version = AggregateVersion::new(ordinal, event.aggregate_identity.clone())
        .expect("in-bounds identity")
        .encode();
    assert_eq!(
        aggregate_version, full_version_bytes,
        "the encoded aggregate_version must equal the fixture's own aggregate_version_hex"
    );

    let outbox_event = OutboxEvent {
        cell_id: &event.cell_id,
        repository_id: &repository_id,
        repository_generation,
        event_kind: &event.event_kind,
        aggregate_kind: &event.aggregate_kind,
        aggregate_id: &event.aggregate_id,
        aggregate_version: &aggregate_version,
        payload_schema_version: event.payload_schema_version,
        payload: &event.payload,
    };
    let key = idempotency_key(&outbox_event);
    assert_eq!(
        key.to_vec(),
        expected_key,
        "builders::lock_acquired must reproduce the fixture's pinned idempotency_key"
    );
}

#[test]
fn lock_renewed_and_released_and_force_released_share_the_lock_shape() {
    let repository_id = repo_id();
    let branch_id: [u8; 16] = rand::random();
    let owner_token = b"urc-abcd".to_vec();
    for (build, expected_kind) in [
        (
            builders::lock_renewed
                as fn(&str, &[u8], &[u8], &str, &str, u64, &[u8]) -> Result<_, _>,
            builders::LOCK_RENEWED,
        ),
        (builders::lock_released, builders::LOCK_RELEASED),
        (builders::lock_force_released, builders::LOCK_FORCE_RELEASED),
        (builders::lock_taken_over, builders::LOCK_TAKEN_OVER),
    ] {
        let event = build(
            "cell-a",
            &repository_id,
            &branch_id,
            "assets/characters",
            "user-123",
            9,
            &owner_token,
        )
        .expect("build");
        assert_eq!(event.event_kind, expected_kind);
        assert_eq!(event.aggregate_kind, builders::AGGREGATE_LOCK_NAMESPACE);
        assert_eq!(event.aggregate_ordinal, CommittedOrdinal::Exact(9));
        assert_eq!(event.aggregate_identity, owner_token);
    }
}

// ---------------------------------------------------------------------------
// Summary builders: aggregate_id = 16 repo bytes, ordinal = Exact(...)
// ---------------------------------------------------------------------------

#[test]
fn fragment_lifecycle_generation_advanced_shape() {
    let repository_id = repo_id();
    let event = builders::fragment_lifecycle_generation_advanced("cell-a", &repository_id, 42)
        .expect("build");
    assert_eq!(
        event.event_kind,
        builders::FRAGMENT_LIFECYCLE_GENERATION_ADVANCED
    );
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_FRAGMENT_LIFECYCLE);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::Exact(42));
    assert!(event.aggregate_identity.is_empty());
}

// ---------------------------------------------------------------------------
// Builder-to-fixture end-to-end idempotency-key conformance
//
// The tests above pin builder *shape* (which kind, which aggregate_id, which
// CommittedOrdinal variant). These two go further: build a real event through
// a real builder, resolve its ordinal exactly the way a coordinator would
// (CommittedOrdinal::resolve against a CommittedVersions the transaction
// would have committed), encode aggregate_version, and run the production
// idempotency_key function -- then compare the result to
// idempotency-key.json's own frozen hex, byte for byte. This is the one place
// that proves a builder's specific field choices (which string literal, which
// bytes go in aggregate_id vs. aggregate_identity) reproduce a vector nobody
// hand-typed into this file -- domain_outbox_encoding.rs already proves the
// idempotency_key algorithm's internal consistency; this proves these two
// builders feed it correctly.
// ---------------------------------------------------------------------------

/// Reproduces `idempotency-key.json`'s `repository-obliterated` vector
/// through `builders::repository_obliterated`.
#[test]
fn repository_obliterated_builder_reproduces_the_idempotency_key_fixture_vector() {
    let fixture = load_fixture("idempotency-key.json");
    let vector = find_vector(&fixture, "repository-obliterated");
    let cell_id = vector["inputs"]["cell_id"].as_str().expect("cell_id");
    let repository_id = decode_hex(
        "repository_hex",
        vector["inputs"]["repository_hex"]
            .as_str()
            .expect("repository_hex"),
    );
    let repository_generation = vector["inputs"]["repository_generation"]
        .as_str()
        .expect("repository_generation")
        .parse::<i64>()
        .expect("repository_generation is a decimal integer");
    let expected_ordinal = vector["inputs"]["aggregate_version_ordinal"]
        .as_str()
        .expect("aggregate_version_ordinal")
        .parse::<u64>()
        .expect("ordinal is a decimal integer");
    assert_eq!(
        expected_ordinal as i64, repository_generation,
        "the fixture's own vector ties the obliterated ordinal to the repository generation"
    );
    let expected_key = decode_hex(
        "idempotency_key_hex",
        vector["idempotency_key_hex"]
            .as_str()
            .expect("idempotency_key_hex"),
    );

    // Arbitrary: the address is payload-only and excluded from
    // idempotency_key's input set.
    let address_hash = [0xAAu8; 32];
    let address_context = [0xBBu8; 16];
    let event =
        builders::repository_obliterated(cell_id, &repository_id, &address_hash, &address_context)
            .expect("build repository_obliterated");

    let ordinal = event
        .aggregate_ordinal
        .resolve(CommittedVersions {
            repository_generation,
            branch_generation: None,
        })
        .expect("resolve the committed repository generation");
    assert_eq!(ordinal, expected_ordinal);
    let aggregate_version = AggregateVersion::new(ordinal, event.aggregate_identity.clone())
        .expect("in-bounds identity")
        .encode();

    let outbox_event = OutboxEvent {
        cell_id: &event.cell_id,
        repository_id: &repository_id,
        repository_generation,
        event_kind: &event.event_kind,
        aggregate_kind: &event.aggregate_kind,
        aggregate_id: &event.aggregate_id,
        aggregate_version: &aggregate_version,
        payload_schema_version: event.payload_schema_version,
        payload: &event.payload,
    };
    let key = idempotency_key(&outbox_event);
    assert_eq!(
        key.to_vec(),
        expected_key,
        "builders::repository_obliterated must reproduce the fixture's pinned idempotency_key"
    );
}

/// Reproduces `idempotency-key.json`'s `branch-pushed` vector through
/// `builders::branch_pushed`.
#[test]
fn branch_pushed_builder_reproduces_the_idempotency_key_fixture_vector() {
    let fixture = load_fixture("idempotency-key.json");
    let vector = find_vector(&fixture, "branch-pushed");
    let cell_id = vector["inputs"]["cell_id"].as_str().expect("cell_id");
    let repository_id = decode_hex(
        "repository_hex",
        vector["inputs"]["repository_hex"]
            .as_str()
            .expect("repository_hex"),
    );
    let repository_generation = vector["inputs"]["repository_generation"]
        .as_str()
        .expect("repository_generation")
        .parse::<i64>()
        .expect("repository_generation is a decimal integer");
    let branch_id = decode_hex(
        "aggregate_id_hex",
        vector["inputs"]["aggregate_id_hex"]
            .as_str()
            .expect("aggregate_id_hex"),
    );
    let expected_ordinal = vector["inputs"]["aggregate_version_ordinal"]
        .as_str()
        .expect("aggregate_version_ordinal")
        .parse::<u64>()
        .expect("ordinal is a decimal integer");
    let expected_identity_bytes = vector["inputs"]["aggregate_version_identity_bytes"]
        .as_u64()
        .expect("aggregate_version_identity_bytes");
    // The identity is the tail of the encoded aggregate_version_hex, after the
    // 8-byte big-endian ordinal (16 hex chars).
    let aggregate_version_hex = vector["inputs"]["aggregate_version_hex"]
        .as_str()
        .expect("aggregate_version_hex");
    let full_version_bytes = decode_hex("aggregate_version_hex", aggregate_version_hex);
    assert_eq!(
        full_version_bytes.len(),
        8 + expected_identity_bytes as usize
    );
    let new_latest_hash = full_version_bytes[8..].to_vec();
    let expected_key = decode_hex(
        "idempotency_key_hex",
        vector["idempotency_key_hex"]
            .as_str()
            .expect("idempotency_key_hex"),
    );

    // Arbitrary: unused by the idempotency_key preimage since the second
    // PIN-4 amendment (2026-09-03) moved the branch name out of aggregate_id
    // and into the payload-only side. previous_hash is excluded the same way
    // payload is.
    let branch_name = "feature/some-long-lived-branch";
    let previous_hash = [0xDDu8; 32];
    let event = builders::branch_pushed(
        cell_id,
        &repository_id,
        &branch_id,
        branch_name,
        &previous_hash,
        &new_latest_hash,
    )
    .expect("build branch_pushed");
    assert_eq!(
        event.aggregate_id, branch_id,
        "aggregate_id must be the 16 raw branch-id bytes, matching the fixture's aggregate_id_hex \
         (second PIN-4 amendment)"
    );

    let ordinal = event
        .aggregate_ordinal
        .resolve(CommittedVersions {
            repository_generation,
            branch_generation: Some(expected_ordinal as i64),
        })
        .expect("resolve the committed branch generation");
    assert_eq!(ordinal, expected_ordinal);
    let aggregate_version = AggregateVersion::new(ordinal, event.aggregate_identity.clone())
        .expect("in-bounds identity")
        .encode();
    assert_eq!(
        aggregate_version, full_version_bytes,
        "the encoded aggregate_version must equal the fixture's own aggregate_version_hex"
    );

    let outbox_event = OutboxEvent {
        cell_id: &event.cell_id,
        repository_id: &repository_id,
        repository_generation,
        event_kind: &event.event_kind,
        aggregate_kind: &event.aggregate_kind,
        aggregate_id: &event.aggregate_id,
        aggregate_version: &aggregate_version,
        payload_schema_version: event.payload_schema_version,
        payload: &event.payload,
    };
    let key = idempotency_key(&outbox_event);
    assert_eq!(
        key.to_vec(),
        expected_key,
        "builders::branch_pushed must reproduce the fixture's pinned idempotency_key"
    );
}

#[test]
fn association_generation_advanced_shape() {
    let repository_id = repo_id();
    let epoch = rand::random::<[u8; 8]>().to_vec();
    let event = builders::association_generation_advanced("cell-a", &repository_id, 5, &epoch)
        .expect("build");
    assert_eq!(event.event_kind, builders::ASSOCIATION_GENERATION_ADVANCED);
    assert_eq!(event.aggregate_kind, builders::AGGREGATE_ASSOCIATION);
    assert_eq!(event.aggregate_id, repository_id.to_vec());
    assert_eq!(event.aggregate_ordinal, CommittedOrdinal::Exact(5));
    assert_eq!(event.aggregate_identity, epoch);
}

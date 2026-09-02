// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Structural controls for Phase 6B's authoritative lifecycle metering rebuild.

const COORDINATOR: &str = include_str!("../src/domain/fragments/coordinator.rs");
const IMMUTABLE_STORE: &str = include_str!("../src/store/immutable_store.rs");

fn function<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker {marker:?}"));
    let tail = &source[start..];
    let opening = tail.find('{').expect("function opening brace");
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes()[opening..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {marker:?}")
}

fn position(source: &str, marker: &str) -> usize {
    source
        .find(marker)
        .unwrap_or_else(|| panic!("missing marker {marker:?}"))
}

#[test]
fn rebuild_uses_one_serialized_transaction_and_the_documented_lock_order() {
    let rebuild = function(COORDINATOR, "pub async fn rebuild_metering_projection(");
    assert_eq!(rebuild.matches(".transaction()").count(), 1);
    assert_eq!(rebuild.matches("tx.commit()").count(), 1);

    let lifecycle = position(
        rebuild,
        "LOCK TABLE lore_fragment_lifecycle IN EXCLUSIVE MODE",
    );
    let epochs = position(rebuild, "LOCK TABLE lore_fragment_epochs IN SHARE MODE");
    let associations = position(
        rebuild,
        "LOCK TABLE lore_fragment_associations IN SHARE MODE",
    );
    let projection = position(
        rebuild,
        "LOCK TABLE lore_fragment_lifecycle_metering IN SHARE ROW EXCLUSIVE MODE",
    );
    assert!(lifecycle < epochs && epochs < associations && associations < projection);
    assert!(projection < position(rebuild, "CREATE TEMPORARY TABLE"));

    for forbidden in ["head_fragment", "self.s3", "put_object", "get_object"] {
        assert!(!rebuild.contains(forbidden));
    }
}

#[test]
fn one_canonical_projection_drives_upsert_stale_delete_and_exact_verification() {
    let rebuild = function(COORDINATOR, "pub async fn rebuild_metering_projection(");
    assert_eq!(
        rebuild
            .matches("CREATE TEMPORARY TABLE lore_fragment_metering_rebuild")
            .count(),
        1
    );
    assert!(rebuild.contains("e.hash = l.hash AND e.epoch = l.current_epoch"));
    assert!(rebuild.contains("e.disposition = $1"));
    assert!(rebuild.contains("l.state = ANY($2) AND l.manifest_id = e.manifest_id"));
    assert!(rebuild.contains("FragmentLifecycleState::Missing.bits()"));
    assert!(rebuild.contains("FragmentLifecycleState::DeletingChildren.bits()"));
    assert!(rebuild.contains("FragmentLifecycleState::DeletingPayload.bits()"));

    for marker in [
        "fragment metering rebuild upserted",
        "fragment metering rebuild removed",
        "fragment metering rebuild retained",
        "fragment metering rebuild verification found a projection mismatch",
    ] {
        assert!(
            rebuild.contains(marker),
            "missing fail-closed check {marker:?}"
        );
    }
    assert_eq!(rebuild.matches("lore_fragment_metering_rebuild").count(), 6);
}

#[test]
fn coordinated_store_delegates_before_legacy_database_or_provider_work() {
    let rebuild = function(IMMUTABLE_STORE, "pub async fn rebuild_metering_projection(");
    let coordinated = position(rebuild, "FragmentLifecycleRoute::Coordinated");
    let delegated = position(rebuild, "return coordinator");
    let legacy_checkout = position(rebuild, "self.pool.get()");
    let legacy_head = position(rebuild, "self.head_fragment(hash).await?");
    assert!(
        coordinated < delegated && delegated < legacy_checkout && legacy_checkout < legacy_head
    );
}

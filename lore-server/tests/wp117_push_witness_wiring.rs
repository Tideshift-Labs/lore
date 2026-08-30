// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-level wiring fixture for WP-117's unconditional push-witness capture.
//!
//! `prepare_governed_push` is crate-private and requires a full server context, so this fixture pins
//! the two handler call sites and the ordering seam that executable Postgres component tests cannot
//! observe. Behavioral capture and transaction-local revalidation are exercised by
//! `lore-postgres/tests/domain_lock_fencing.rs`.

const V0_HANDLER: &str = include_str!("../src/grpc/handlers/branch_push.rs");
const V1_HANDLER: &str = include_str!("../src/grpc/revision/v1/branch_push.rs");
const CR019_GUARD: &str = include_str!("../src/grpc/handlers/push_lock_guard.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("fixture start must exist");
    let remainder = &source[start..];
    let end = remainder.find(end).expect("fixture end must exist");
    &remainder[..end]
}

fn assert_precedes(source: &str, first: &str, second: &str) {
    let first_offset = source.find(first).expect("first wiring marker must exist");
    let second_offset = source
        .find(second)
        .expect("second wiring marker must exist");
    assert!(
        first_offset < second_offset,
        "`{first}` must precede `{second}`"
    );
}

#[test]
fn capture_precedes_the_no_governed_operation_early_return() {
    let prepare = between(
        V0_HANDLER,
        "pub(crate) async fn prepare_governed_push(",
        "impl GovernedPushCommit",
    );

    assert_precedes(
        prepare,
        ".capture_push_witness(repository_id.as_ref(), branch_id.as_ref())",
        "let Some(admitted) = admitted else",
    );
    assert!(
        !prepare.contains("lock_enforcement"),
        "witness capture must not depend on CR-019 carriage"
    );
}

#[test]
fn both_wire_generations_capture_before_the_optional_cr019_guard() {
    for (generation, handler) in [("v0", V0_HANDLER), ("v1", V1_HANDLER)] {
        let request_path = between(
            handler,
            "let governed_push = prepare_governed_push(",
            "let PushResult {",
        );
        assert_precedes(
            request_path,
            "let governed_push = prepare_governed_push(",
            "if let Some(lock_store) = lock_enforcement",
        );
        assert!(
            handler.contains("governed_push.as_ref(),"),
            "{generation} must carry the prepared witness to the final-push path"
        );
    }
}

#[test]
fn cr019_no_foreign_locks_short_circuit_remains_after_witness_capture() {
    assert!(
        CR019_GUARD.contains("if other_locks.is_empty()"),
        "fixture must continue to cover CR-019's no-change early return"
    );
    for handler in [V0_HANDLER, V1_HANDLER] {
        assert_precedes(
            handler,
            "let governed_push = prepare_governed_push(",
            "crate::grpc::handlers::push_lock_guard::enforce_push_locks(",
        );
    }
}

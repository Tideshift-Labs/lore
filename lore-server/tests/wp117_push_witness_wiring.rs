// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-level wiring fixture for WP-117's unconditional push-witness capture
//! and CR-030's fenced push-lock routing.
//!
//! `prepare_governed_push` is crate-private and requires a full server context, so this fixture pins
//! the two handler call sites and the ordering seams that executable Postgres component tests cannot
//! observe. Behavioral capture and transaction-local revalidation are exercised by
//! `lore-postgres/tests/domain_lock_fencing.rs`; the fenced push comparison itself by
//! `lore-server/src/grpc/handlers/branch_push/governed_tests.rs`.

use std::path::Path;

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
        "/// Reject a push that touches a resource locked by another",
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
            "} else if let Some(enforcement) = lock_enforcement",
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
            "push_lock_guard::enforce_push_locks(",
        );
    }
}

/// A fenced cell routes EVERY push through the coordinator, governed or not.
///
/// The legacy guard reads subject-only owners out of the legacy store, so it
/// cannot answer the owner-pair question on a fenced cell. Leaving it as the
/// fallback for an ungoverned push was INV-EE P1-1's second leg: enforcement
/// off meant `admit` returned `Ok(None)`, so no pair comparison ran at all.
#[test]
fn a_fenced_cell_checks_every_push_and_never_falls_back_to_the_legacy_guard() {
    for (generation, handler) in [("v0", V0_HANDLER), ("v1", V1_HANDLER)] {
        let request_path = between(
            handler,
            "let fenced_coordinator = domain_context",
            "let PushResult {",
        );
        assert!(
            request_path.contains("if let Some(coordinator) = fenced_coordinator.as_ref()"),
            "{generation} must consult the fenced coordinator when one is present"
        );
        assert!(
            request_path.contains("} else if let Some(enforcement) = lock_enforcement"),
            "{generation} must reach the legacy guard only when no coordinator exists"
        );
        assert_precedes(
            request_path,
            "if let Some(coordinator) = fenced_coordinator.as_ref()",
            "} else if let Some(enforcement) = lock_enforcement",
        );
    }
}

/// Request validation precedes the witness read on both generations (P2-10).
#[test]
fn a_zero_revision_is_rejected_before_any_witness_capture() {
    for (generation, handler) in [("v0", V0_HANDLER), ("v1", V1_HANDLER)] {
        let request_path = between(
            handler,
            "let admitted = admit_at_entry(",
            "let PushResult {",
        );
        assert_precedes(
            request_path,
            "if revision.is_zero()",
            "let governed_push = prepare_governed_push(",
        );
        assert!(
            !request_path.is_empty(),
            "{generation} request path must be readable"
        );
    }
}

/// The WP-120 arming gate has exactly one bypass, and only tests use it.
///
/// `enable_fencing_for_component_fixture` skips the public-contract refusal so
/// the armed state stays reachable under test. If production code ever calls
/// it, the refusal in `enable_fencing` is decorative.
#[test]
fn only_tests_bypass_the_public_mutation_contract_gate() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lore-server must sit inside the workspace root");
    let mut offenders = Vec::new();
    for crate_name in ["lore-server", "lore-postgres"] {
        collect_fixture_arming_callers(&workspace.join(crate_name).join("src"), &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "enable_fencing_for_component_fixture is a test-only bypass, but it is called from: {}",
        offenders.join(", ")
    );
}

fn collect_fixture_arming_callers(directory: &Path, offenders: &mut Vec<String>) {
    let entries = std::fs::read_dir(directory).expect("source directory must be readable");
    for entry in entries {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_fixture_arming_callers(&path, offenders);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("source file must be readable");
        // The definition itself, its doc comment, and this fixture's own name
        // are not call sites.
        let calls = source
            .lines()
            .filter(|line| line.contains(".enable_fencing_for_component_fixture("))
            .count();
        if calls != 0 {
            offenders.push(path.display().to_string());
        }
    }
}

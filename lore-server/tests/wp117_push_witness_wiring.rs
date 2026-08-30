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
    for handler in [V0_HANDLER, V1_HANDLER] {
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
    }
}

/// The WP-120 arming gate has exactly one bypass, and only tests use it.
///
/// `enable_fencing_for_component_fixture` skips the public-contract refusal so
/// the armed state stays reachable under test. If production code ever named
/// it, the refusal in `enable_fencing` would be decorative.
///
/// Matching the whole identifier rather than a `.method(` call shape is
/// deliberate: UFCS (`PostgresLockCoordinator::enable_fencing_for_component_fixture(..)`),
/// a function-pointer binding, and a call split across lines all reach the
/// bypass without ever writing `.name(`.
///
/// Files that are themselves test code — declared `#[cfg(test)] mod <name>;` by
/// a parent module, like `branch_push/governed_tests.rs` — are excluded, since
/// a bypass call there is exactly what the bypass is for.
#[test]
fn only_tests_bypass_the_public_mutation_contract_gate() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lore-server must sit inside the workspace root");
    let roots =
        ["lore-server", "lore-postgres"].map(|crate_name| workspace.join(crate_name).join("src"));

    let mut test_only = Vec::new();
    for root in &roots {
        collect_test_only_module_files(root, &mut test_only);
    }
    // Without this, a detector that silently stopped resolving module paths
    // would excuse every file rather than none, and the gate would pass by
    // scanning nothing.
    assert!(
        test_only
            .iter()
            .any(|path| path.ends_with("branch_push/governed_tests.rs")),
        "the test-only module detector resolved no path for a known whole-file test module, so \
         its exclusions cannot be trusted; found: {test_only:?}"
    );

    let mut offenders = Vec::new();
    for root in &roots {
        collect_fixture_arming_references(root, &test_only, &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "enable_fencing_for_component_fixture is a test-only bypass, but non-test source names \
         it at: {}",
        offenders.join(", ")
    );
}

/// Files declared `#[cfg(test)] mod <name>;` by some module in `directory`.
///
/// Resolved from that declaration rather than a hardcoded path list, and
/// deliberately not by counting braces around an *inline* `#[cfg(test)] mod` —
/// brace counting drifts on format strings, and a drifting scanner silently
/// stops covering production code, which is the one failure this gate cannot
/// have. An inline test module that needs the bypass therefore still trips the
/// gate; move the call into a whole-file test module rather than loosening the
/// identifier match.
fn collect_test_only_module_files(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
    let entries = std::fs::read_dir(directory).expect("source directory must be readable");
    for entry in entries {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_test_only_module_files(&path, found);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("source file must be readable");
        let mut cfg_test_pending = false;
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "#[cfg(test)]" {
                cfg_test_pending = true;
                continue;
            }
            if cfg_test_pending
                && let Some(name) = trimmed
                    .strip_prefix("mod ")
                    .and_then(|rest| rest.strip_suffix(';'))
            {
                // Exactly ONE candidate, never a fallback. In the 2018 module
                // system `mod bar;` inside `foo.rs` resolves to `foo/bar.rs`
                // and nothing else; only a `mod.rs` or crate root resolves to
                // the sibling `<dir>/bar.rs`. Trying both would silently excuse
                // a production `<dir>/bar.rs` whenever a `foo/bar.rs` test
                // module shares its name — and over-excluding is the one
                // direction this gate cannot fail in.
                let stem = path.file_stem().unwrap_or_default();
                let parent = path.parent().unwrap_or(Path::new(""));
                let candidate = if stem == "mod" || stem == "lib" || stem == "main" {
                    parent.join(format!("{name}.rs"))
                } else {
                    parent.join(stem).join(format!("{name}.rs"))
                };
                if candidate.is_file() {
                    found.push(candidate);
                }
            }
            cfg_test_pending = false;
        }
    }
}

/// The detector must actually detect. Without this, a matcher that silently
/// stops matching reads as "no offenders" forever.
#[test]
fn the_bypass_detector_flags_every_spelling_of_a_call() {
    for planted in [
        "    coordinator.enable_fencing_for_component_fixture(false).await?;",
        "    PostgresLockCoordinator::enable_fencing_for_component_fixture(&coordinator, false);",
        "    let arm = PostgresLockCoordinator::enable_fencing_for_component_fixture;",
        "    coordinator\n        .enable_fencing_for_component_fixture(false)\n        .await?;",
    ] {
        assert_eq!(
            fixture_arming_reference_count(planted),
            1,
            "the detector missed a real call spelled as: {planted}"
        );
    }
    // The definition site and its documentation are not call sites.
    let definition = "/// See [`enable_fencing`](Self::enable_fencing).\n\
                      #[doc(hidden)]\n\
                      pub async fn enable_fencing_for_component_fixture(\n";
    assert_eq!(fixture_arming_reference_count(definition), 0);
}

/// Lines that name the bypass, excluding its own definition and documentation.
fn fixture_arming_reference_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
                && !trimmed.starts_with("pub async fn enable_fencing_for_component_fixture")
                && line.contains("enable_fencing_for_component_fixture")
        })
        .count()
}

fn collect_fixture_arming_references(
    directory: &Path,
    test_only: &[std::path::PathBuf],
    offenders: &mut Vec<String>,
) {
    let entries = std::fs::read_dir(directory).expect("source directory must be readable");
    for entry in entries {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_fixture_arming_references(&path, test_only, offenders);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        if test_only.contains(&path) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("source file must be readable");
        if fixture_arming_reference_count(&source) != 0 {
            offenders.push(path.display().to_string());
        }
    }
}

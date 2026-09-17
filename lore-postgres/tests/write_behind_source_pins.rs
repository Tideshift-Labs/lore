// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Structural pins for the WP-114 CD-6/CD-7 write-behind store adapter seam.
//!
//! Cross-platform and infrastructure-free: these are text scans over the
//! source tree, so they run identically on the Windows dev rig and in CI --
//! unlike `write_behind_stage.rs`'s functional cases, which are Unix-only.
//!
//! # What a structural pin here does NOT prove
//!
//! Two cases in this file (D11 fallback, the staged-read integration) can only
//! be reached live through `store/immutable_store.rs`'s `Coordinated` route,
//! which requires a real `FragmentProviderEntry` -- a live S3-compatible
//! endpoint, a dispatch pool, cell-schema-install migrations. No test in this
//! crate constructs that today; it is `lore-server` composition. A structural
//! pin proves the CONTROL FLOW is correct (an impossible-to-violate match
//! shape, a call order) but not that a real PUT/GET round-trips real bytes
//! through it. Both live round trips are **REQUIRED-DEFERRED to round-3
//! activation** (the disposable governed two-replica cell on slot 52), which
//! names both explicitly as gates. Do not read a green run here as "D11
//! proven" or "the staged read proven end to end" -- read it as "the routing
//! that a live proof will exercise cannot silently do the wrong thing."

use std::path::Path;
use std::path::PathBuf;

fn read_source(relative: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

/// Extract one brace-delimited function body by its `fn` signature prefix.
/// Copied from the same helper already proven in
/// `fragment_write_claim_source_pins.rs` and `immutable_store_provider_routing.rs`.
fn function<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing function signature {signature:?}"));
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
    panic!("unterminated function {signature:?}")
}

fn assert_order(source: &str, markers: &[&str]) {
    let mut cursor = 0usize;
    for marker in markers {
        let offset = source[cursor..]
            .find(marker)
            .unwrap_or_else(|| panic!("missing ordered marker {marker:?}"));
        cursor += offset + marker.len();
    }
}

fn write_behind_source_files() -> Vec<PathBuf> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store/write_behind");
    let mut files = Vec::new();
    collect_rs_files(&directory, &mut files);
    assert!(
        !files.is_empty(),
        "expected at least one source file under {directory:?} -- this pin has nothing to check"
    );
    files
}

fn collect_rs_files(directory: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// U7 (L2 plan §6). Nothing under `store/write_behind/` may hold a database
/// resource across file I/O -- the module's own header states this as a
/// compile-time property, not a review convention, and this pin is what makes
/// that claim checked rather than aspirational.
///
/// Forbidden strings are call/type *shapes*, not bare capitalized words,
/// deliberately: `mod.rs`'s own doc comment says "a `Pool`, a `Transaction`,
/// or a connection checkout" in prose, and a naive scan for the words `Pool`
/// or `Transaction` would trip on its own documentation. `.transaction()`,
/// `pool.get(`, and `deadpool_postgres::` do not appear in that prose and do
/// not appear anywhere else by accident.
#[test]
fn write_behind_never_names_a_transaction_pool_checkout_or_deadpool_type() {
    let forbidden = [
        ".transaction()",
        "pool.get(",
        "deadpool_postgres::",
        "tokio_postgres::Transaction",
        ": Pool",
        "<Pool>",
    ];
    for file in write_behind_source_files() {
        let source = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "{} names {needle:?}; write_behind must hold no database resource across file I/O",
                file.display()
            );
        }
    }
}

/// U8 (L2 plan §6). `put`'s fragment-size validation must precede the
/// coordinated-route branch, so an oversized payload is refused before the
/// staged/direct split ever runs -- and, per the L2 plan, write-behind does
/// not change this bound or this ordering.
#[test]
fn put_validates_fragment_size_before_branching_on_the_coordinated_route() {
    let source = read_source("src/store/immutable_store.rs");
    let put = function(&source, "async fn put(\n");

    let metadata_at = put
        .find("lore_storage::validate_fragment_metadata(&fragment)?;")
        .expect("put must validate fragment metadata");
    let payload_at = put
        .find("lore_storage::validate_fragment_payload(&fragment, payload.len())?;")
        .expect("put must validate an in-band payload's size");
    let size_at = put
        .find("lore_storage::validate_fragment_size(&fragment)?;")
        .expect("put must validate a sizes-only request");
    let route_at = put
        .find("FragmentLifecycleRoute::Coordinated")
        .expect("put must still branch on the coordinated route");

    assert!(
        metadata_at < route_at && payload_at < route_at && size_at < route_at,
        "size/metadata validation must precede the route branch, not follow it"
    );
}

/// D11 fallback, structural half. `put_coordinated`'s route match is the only
/// place `put_staged` and `upload_coordinated_representation` can be called
/// for one PUT, and Rust's match semantics make running both an impossible
/// program, not merely an untested one. This is what a live proof cannot add
/// to: reaching the same code through a real `Coordinated` route needs a live
/// `FragmentProviderEntry`, which no test in this crate constructs today (see
/// `testing-fork-delta-inventory.md`'s write-behind entry) -- this pin is the
/// evidence available without that infrastructure, not a placeholder for it.
#[test]
fn d11_fallback_and_staging_are_mutually_exclusive_and_reach_one_shared_acknowledgement() {
    let source = read_source("src/store/immutable_store.rs");
    let put_coordinated = function(&source, "async fn put_coordinated(");

    // Exactly one call site for each route arm's action, inside one `match`
    // whose scrutinee is `self.write_behind.as_ref().map(|stage| (stage,
    // stage.mode()))` -- so the two calls below are different arms of the
    // same match, not two independent `if`s that could both run.
    let scrutinee_at = put_coordinated
        .find(".write_behind\n            .as_ref()\n            .map(|stage| (stage, stage.mode()))")
        .expect("the route decision must read write_behind's mode through one match scrutinee");
    let staged_arm_at = put_coordinated
        .find("Some((stage, StagingMode::Stage)) => {")
        .expect("Stage must be its own match arm");
    let staged_call_at = put_coordinated
        .find(".put_staged(coordinator, stage, address, fragment, payload)")
        .expect("the Stage arm must call put_staged");
    let fallback_arm_at = put_coordinated
        .find("Some((_, StagingMode::DirectFallback)) | None => {")
        .expect("DirectFallback and no-staging-tier must share one arm, unioned with `|`");
    let fallback_call_at = put_coordinated
        .find(".upload_coordinated_representation(")
        .expect("the fallback arm must call the pre-existing direct upload, unchanged");
    let refuse_arm_at = put_coordinated
        .find("Some((_, StagingMode::Refuse | StagingMode::Unready)) => {")
        .expect("Refuse and Unready must share one arm, unioned with `|`, and neither writes");

    assert!(
        scrutinee_at < staged_arm_at
            && staged_arm_at < staged_call_at
            && staged_call_at < fallback_arm_at
            && fallback_arm_at < fallback_call_at,
        "expected source order: scrutinee, Stage arm (put_staged), then the fallback arm \
         (upload_coordinated_representation) -- got a reordering that would need re-checking \
         which arm each call now belongs to"
    );
    assert!(
        !put_coordinated.contains("put_staged") || put_coordinated.matches("put_staged").count() == 1,
        "put_staged must be called from exactly the Stage arm, not duplicated into another arm"
    );

    // Both routes must feed the SAME association commit, so neither can
    // silently acknowledge without it: the witness both arms of the route
    // match produce binds one local `let witness = match { .. }`, and
    // `create_association_if_current` is called exactly once, after that
    // binding, not inside either arm.
    let witness_binding_at = put_coordinated
        .find("let witness = match self")
        .expect("both routes must produce one shared witness binding");
    let association_at = put_coordinated
        .find(".create_association_if_current(&witness, repository.data(), address.context.data())")
        .expect("the shared association commit must exist");
    assert_eq!(
        put_coordinated
            .matches(".create_association_if_current(&witness, repository.data(), address.context.data())")
            .count(),
        1,
        "there must be exactly one association commit shared by both routes, not one per arm"
    );
    assert!(
        witness_binding_at < association_at,
        "the association commit must run after the route match produces its witness, not inside it"
    );
    assert!(
        association_at > refuse_arm_at,
        "the shared association commit must be reachable only after the route match, so Refuse/Unready's early return skips it entirely rather than racing it"
    );
}

/// The store-level half of THE CASE THAT MATTERS MOST. `write_behind_stage.rs`
/// proves `WriteBehindStage::read_staged` itself never answers `Absent` for an
/// unavailable root. This proves the caller -- `load_coordinated`'s staged
/// read arm -- respects that distinction rather than re-collapsing it:
/// `StagedRead::Absent` is the only arm that may reach
/// `mark_coordinated_missing`, and `StagedRead::Unavailable` must release its
/// lease and return `SlowDown` without ever reaching it. Reaching this arm at
/// all needs a live `EpochAuthority::Staged` head served through the real
/// `Coordinated` route, which -- like D11 below -- needs a live
/// `FragmentProviderEntry` (`load_coordinated` takes `provider:
/// &FragmentProviderEntry` unconditionally, even though a `Staged`-authority
/// read never calls it). So this, too, is a structural pin, and the live
/// round trip is the same REQUIRED-DEFERRED as D11's.
#[test]
fn staged_read_never_lets_an_unavailable_root_reach_the_missing_publication() {
    let source = read_source("src/store/immutable_store.rs");
    let load_coordinated = function(&source, "async fn load_coordinated(");

    let staged_arm_at = load_coordinated
        .find("EpochAuthority::Staged => {")
        .expect("the staged authority must still be its own match arm");
    let found_arm_at = load_coordinated
        .find("StagedRead::Found(bytes) => {")
        .expect("Found must be its own arm");
    let absent_arm_at = load_coordinated
        .find("StagedRead::Absent => Err(MissingDiagnostic::Absent),")
        .expect("Absent must map directly to the missing diagnostic, unwrapped");
    let unavailable_arm_at = load_coordinated
        .find("StagedRead::Unavailable(_) => {")
        .expect("Unavailable must be its own arm, distinct from Absent");
    let unavailable_body = &load_coordinated[unavailable_arm_at..];
    let release_at = unavailable_arm_at
        + unavailable_body
            .find(".release_staged_lease(&lease_id)")
            .expect("Unavailable must release the staged lease before returning");
    let slowdown_at = unavailable_arm_at
        + unavailable_body
            .find("return Err(StoreError::from(SlowDown));")
            .expect("Unavailable must return SlowDown directly, never reaching mark_coordinated_missing");
    assert!(
        release_at < slowdown_at,
        "the lease must be released before the early return, not leaked on the SlowDown path"
    );

    // The decisive structural claim: within the STAGED arm specifically,
    // exactly one call to mark_coordinated_missing exists (the Remote arm
    // above it has its own, separate call to the same helper -- this scopes
    // to the staged arm's own sub-source so that sibling call cannot inflate
    // the count), and it is reachable only after the Found/Absent match on
    // `result` -- not inside the Unavailable arm's early return, which
    // happens earlier in the source and already left the function via
    // `return`.
    let staged_body = &load_coordinated[staged_arm_at..];
    let missing_calls = staged_body
        .matches("mark_coordinated_missing(coordinator, &witness, diagnostic)")
        .count();
    assert_eq!(
        missing_calls, 1,
        "exactly one call site in the staged arm may demote to Missing"
    );
    let missing_call_at = staged_arm_at
        + staged_body
            .find("mark_coordinated_missing(coordinator, &witness, diagnostic)")
            .expect("located above");
    assert!(
        staged_arm_at < found_arm_at
            && found_arm_at < absent_arm_at
            && absent_arm_at < unavailable_arm_at
            && unavailable_arm_at < slowdown_at
            && slowdown_at < missing_call_at,
        "expected source order: staged arm, Found, Absent (direct Err), Unavailable (release+SlowDown, \
         an early return), THEN the single mark_coordinated_missing call downstream of both -- so \
         Unavailable's `return` provably never reaches it"
    );
}

/// Durable finalization ordering, structural half. No userspace test can prove
/// bytes survive a real power loss; what a source pin CAN prove is that the
/// operations ADR-00027 requires before the authoritative `Staged` commit
/// happen in the documented order, so a crash window analysis reasoning about
/// "before the rename" / "after the rename" is reasoning about what the code
/// actually does. The live recovery half (what a crash between each of these
/// steps leaves, and that a retry converges) is
/// `write_behind_staging_lifecycle.rs`'s job, against a real Postgres.
#[test]
fn finalize_creates_and_fsyncs_fanout_directories_before_the_rename_and_fsyncs_the_leaf_after() {
    let source = read_source("src/store/write_behind/finalize.rs");
    let finalize_blocking = function(&source, "fn finalize_blocking(");
    assert_order(
        finalize_blocking,
        &[
            // Step 1: fan-out directories exist and are durable before anything
            // is written under incoming/, let alone renamed.
            "root.ensure_parent(resolved)?;",
            // Step 2: the payload lands in incoming/, never directly at its
            // final staged path.
            ".create_new(true)",
            ".open(&temporary)",
            "file.write_all(payload.as_ref())",
            // Step 3: contents AND metadata are durable before the rename that
            // publishes them.
            "file.sync_all()",
            // Step 4: atomic rename onto the content-derived identity.
            "fs::rename(&temporary, resolved.path())",
            // Step 5: the leaf directory entry is durable only after this.
            "sync_directory(resolved.parent())",
        ],
    );
}

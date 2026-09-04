// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The handful of WP-118 Phase 4 rules a crate boundary does not express.
//!
//! # What this file is, after the split
//!
//! Most of what its predecessor checked is now structural and these tests were
//! deleted rather than carried:
//!
//! - "only the seam reaches the governed client" and "the seam publishes no
//!   route to it" — `lore-postgres` does not depend on `lore-object-dispatch`,
//!   and the client is erased behind [`AttemptSink`], so a caller there cannot
//!   construct `execute`'s arguments and no accessor can hand it anything
//!   callable. A scan for aliases and accessors was guarding a property the
//!   compiler now holds. (Narrow wording on purpose: a call expression with
//!   divergent arguments is still writable and panics, and a *deliberate*
//!   forwarding method written here would widen the boundary. See the crate
//!   docs for where the line is.)
//! - "the package builds no private provider client" — for *this* crate that is
//!   the dependency graph. The four files still in `lore-postgres` keep a
//!   reduced version of that scan, in that crate's own pins file.
//! - The scanner scaffolding those needed — the file-list check, the
//!   `include!`/`#[path]` refusal, the alias resolver, the four-placement
//!   self-proof — went with them, except what the rules below still need.
//!
//! Five rules remain, and each is here because nothing else holds it: no
//! publication of the eighteen types the re-export assessment depends on, the
//! erasure trait staying private, no AWS SDK in the manifest, no filesystem
//! access, and the constructor signature.
//!
//! # Known limit, recorded rather than fixed
//!
//! `shipped_code`'s walk from a `#[cfg(test)]` attribute to its item is not a
//! Rust parser. A `{`, `}` or `;` inside a string literal between the attribute
//! and the item's opening brace desynchronises it, and a later literal can
//! resynchronise it — hiding code in between from the scans below. That was
//! reported as a real evasion of the previous, much larger tier.
//!
//! The walker is **not fixed**, deliberately. Hardening a scanner that no
//! longer carries properties 2 or 3 is the wrong direction: every previous
//! patch produced another evasion, and the properties that matter moved to the
//! compiler.
//!
//! What was done instead is narrower and worth stating exactly, because it
//! changes which rules the limit reaches. The filesystem rule — the one with
//! real safety content, since CR-031's no-pre-admission-spool rule has no
//! compiler-checked form — was **taken off the walker entirely**: it scans the
//! whole comment-stripped file, so nothing the walker mis-parses can hide from
//! it. Verified by reproducing the desync against it.
//!
//! The limit therefore still reaches exactly two checks, both about the *shape*
//! of declarations rather than about reaching a provider:
//! [`only_a_real_readback_can_mint_a_cell_schema_attestation`]'s use of shipped
//! code, and [`the_seam_addresses_only_its_own_boundary`]. Hiding a widened
//! `verify_installed_layers` or a `target` field behind a desynchronising
//! string literal is possible and would not be caught here. Recorded, not
//! fixed; a reader should treat this file as regression detection over one
//! file, not as a proof.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Filesystem access. The seam must have none: CR-031 removed the pre-admission
/// body spool, and a crate boundary does not prevent `std::fs`.
const FILESYSTEM_TOKENS: [&str; 7] = [
    "std::fs",
    "tokio::fs",
    "OpenOptions",
    "create_dir",
    "read_to_string",
    "File::",
    "fs::",
];

/// WP-114 retains durable PUT reservation/spooling, but WP-118's bounded
/// fragment seam must not import, project, call, or publish that capability.
const PHASE5_DURABLE_PUT_TOKENS: [&str; 12] = [
    "FragmentReservePutQuota",
    "FragmentReservePutRequest",
    "FragmentPutSpoolReady",
    "ReservedFragmentPutAttempt",
    "ReadyFragmentPutAttempt",
    "ReservePutRequest",
    "PutSpoolReadyRequest",
    "bind_durable_put_body_from_ready",
    "reserve_put(",
    "put_spool_ready(",
    "SpoolLayout",
    "DurablePutSpoolExpectation",
];

/// Every entry is a type whose publication would falsify a named claim in the
/// seam's authorised re-export assessment, paired with the claim it protects.
///
/// **Three spellings, because an earlier revision checked only one.** The pin
/// used to match lines containing `pub use `. A reviewer published both of
/// `execute`'s parameter types with `pub type PublicLedger =
/// ProviderAttemptLedger;` instead — not a `pub use`, and beyond
/// `private_interfaces`, which cannot object to aliasing a type that is
/// legitimately public upstream. So this covers `pub use`, `pub type`
/// right-hand sides, and `pub fn` signatures.
///
/// **What carries claim 1 is the [`AttemptSink`] erasure, not this pin.** With
/// the client boxed behind a private trait, no accessor can hand out anything
/// callable, so publishing its parameter types buys an outside caller nothing.
/// Claims 2 through 4 have no such backstop: they rest on these names being
/// absent and on nothing else, which is why the list is the whole of their
/// enforcement.
///
/// **Built by asking, for each claim, "what would have to be re-exported to
/// make this false, and is that type covered?"** That sweep found the list had
/// been two entries covering one claim, while three further claims rested on
/// types nothing checked — including `DispatchRuntimePool`, the single type that
/// turns `DispatchRuntimeClient` from a bound into a capability and thereby
/// unlocks the rest. A claim resting on something nobody checks is the shape
/// every finding in this campaign has taken.
const FORBIDDEN_REEXPORTS: [(&str, &str); 19] = [
    // Claim 1: `execute`'s parameters are unnameable outside this crate, so no
    // caller elsewhere can construct them. This is property 2 itself.
    (
        "ProviderAttemptLedger",
        "execute's parameters stay unnameable",
    ),
    (
        "ProviderAttemptRequest",
        "execute's parameters stay unnameable",
    ),
    (
        "MeteredProviderAttemptRequest",
        "the charged execute capability stays behind AttemptSink",
    ),
    (
        "ProviderDirectPutAttemptRequest",
        "the raw direct PUT dispatch capability stays behind AttemptSink",
    ),
    (
        "ProviderGetAttemptRequest",
        "the raw GET dispatch capability stays behind AttemptSink",
    ),
    // Claim 2: `DispatchRuntimeClient` is a *bound*, not a capability. It rests
    // on the pool being unnameable, so nothing outside can construct a client —
    // and on the four request types being unnameable, so none of the mutations
    // can be called on one that is handed in. `DispatchMaintenanceClient` takes
    // the same pool and is listed with them.
    (
        "DispatchRuntimePool",
        "a dispatch client cannot be constructed",
    ),
    (
        "DispatchMaintenanceClient",
        "a dispatch client cannot be constructed",
    ),
    ("ReservePutRequest", "dispatch mutations cannot be called"),
    (
        "PutUploadProgressRequest",
        "dispatch mutations cannot be called",
    ),
    (
        "PutSpoolReadyRequest",
        "dispatch mutations cannot be called",
    ),
    (
        "RegisterDispatcherRequest",
        "dispatch mutations cannot be called",
    ),
    // Claim 3: `ProviderTransport` is nameable as a bound but unimplementable
    // outside this crate, so no other crate can inject a transport — which would
    // be a private provider client under another name.
    (
        "AuthorizedProviderAttempt",
        "ProviderTransport stays unimplementable",
    ),
    (
        "AuthorizedProviderGet",
        "ProviderGetTransport stays unimplementable",
    ),
    (
        "ProviderAttemptReport",
        "ProviderTransport stays unimplementable",
    ),
    (
        "ProviderTransportRefusal",
        "ProviderTransport stays unimplementable",
    ),
    (
        "ProviderGetTransport",
        "the raw GET transport stays unavailable outside the seam",
    ),
    // Claim 4: the same for `ProviderChargeAuthority`, so the only gateway
    // another crate can build is the unwired one.
    (
        "ProviderChargeRequest",
        "ProviderChargeAuthority stays unimplementable",
    ),
    (
        "ProviderChargeGrant",
        "ProviderChargeAuthority stays unimplementable",
    ),
    (
        "ProviderChargeError",
        "ProviderChargeAuthority stays unimplementable",
    ),
];

/// Just the type names, for scanning.
fn forbidden_reexport_names() -> Vec<&'static str> {
    FORBIDDEN_REEXPORTS.iter().map(|(name, _)| *name).collect()
}

/// The claim an offending type would falsify, for the failure message.
fn claim_for(name: &str) -> &'static str {
    match FORBIDDEN_REEXPORTS.iter().find(|(ty, _)| *ty == name) {
        Some((_, claim)) => claim,
        None => "an unrecorded claim",
    }
}

/// Crates whose presence in `[dependencies]` would end property 3's structural
/// form. `lore-aws` is permitted as a **dev-dependency**: `masks.rs`'s
/// `PAYLOAD_FLAGS` comparison lives in `lore-postgres`, but a future test here
/// may want the same vocabulary, and a dev-dependency reaches no shipped graph.
const FORBIDDEN_SHIPPED_DEPS: [&str; 5] = [
    "aws-sdk-s3",
    "aws-config",
    "aws-smithy",
    "lore-aws",
    "lore-postgres",
];

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(relative: &str) -> String {
    let path = crate_root().join(relative);
    match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => panic!("{} must be readable: {error}", path.display()),
    }
}

/// Removes `//`-to-end-of-line comments, conservatively.
///
/// This crate's prose legitimately names the forbidden tokens, so a scan that
/// did not strip comments would force the documentation to be vaguer than the
/// rule. A line containing a `"` is kept whole rather than cut at its first
/// `//`, because a naive cut lets `let s = "//"; use std::fs;` hide real code
/// behind a string literal.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                return "";
            }
            if line.contains('"') {
                return line;
            }
            match line.find("//") {
                Some(index) => &line[..index],
                None => line,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Comments stripped, and every `#[cfg(test)]`-attributed item removed by
/// structure so that code after the test module stays visible. See the module
/// docs for this walk's known limit.
fn shipped_code(text: &str) -> String {
    let stripped = strip_line_comments(text);
    let mut out = String::with_capacity(stripped.len());
    let mut rest = stripped.as_str();
    while let Some(index) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..index]);
        rest = skip_attributed_item(&rest[index..]).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

fn skip_attributed_item(text: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            ';' if depth == 0 => return Some(&text[index + 1..]),
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[index + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

fn hits<'a>(haystack: &str, tokens: &[&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .copied()
        .filter(|token| haystack.contains(token))
        .collect()
}

fn block_after(text: &str, opening: &str, open: char, close: char) -> String {
    let Some(start) = text.find(opening) else {
        panic!("expected to find {opening:?}");
    };
    let rest = &text[start..];
    let mut depth = 0usize;
    for (index, character) in rest.char_indices() {
        if character == open {
            depth += 1;
        } else if character == close {
            depth -= 1;
            if depth == 0 {
                return rest[..=index].to_string();
            }
        }
    }
    panic!("unbalanced block starting at {opening:?}");
}

// ---------------------------------------------------------------------------
// The scanner's own two checks — kept because four rules rest on them
// ---------------------------------------------------------------------------

/// The stripper must drop a documented mention and keep the code around it, and
/// `shipped_code` must remove the test module without hiding what follows it.
/// Both are checked against the real file, and the second is the one an earlier
/// truncating version got wrong.
#[test]
fn the_scanner_strips_comments_and_tests_without_hiding_what_follows() {
    let seam = read("src/lib.rs");
    assert!(
        seam.contains("aws-sdk-s3"),
        "the crate docs are expected to name the SDK in prose; if that prose \
         went away this check has stopped proving anything",
    );
    let shipped = shipped_code(&seam);
    assert!(
        !shipped.contains("aws-sdk-s3"),
        "a documented mention must be stripped",
    );
    assert!(
        shipped.contains("GovernedProviderClient"),
        "the code being scanned must survive",
    );
    assert!(
        !shipped.contains("fn a_granted_charge_binds_exactly_one_issued_attempt"),
        "the test module must be removed",
    );
    assert!(
        !shipped.contains("fn for_tests"),
        "a #[cfg(test)] item nested in an impl must be removed too",
    );

    let appended = format!("{seam}\nuse std::fs::OpenOptions;\n");
    assert!(
        shipped_code(&appended).contains("OpenOptions"),
        "code after the test module must remain visible",
    );
}

/// The stripper is blind to `/* */`, so the scanned file may not have one.
#[test]
fn the_seam_uses_no_block_comment() {
    assert!(
        !read("src/lib.rs").contains("/*"),
        "a block comment is something the line-based scanner cannot see through",
    );
}

// ---------------------------------------------------------------------------
// Rule 1: property 2's one remaining textual dependency
// ---------------------------------------------------------------------------

/// `execute`'s parameter types must never be re-exported.
///
/// The whole of property 2 is that a caller outside this crate cannot name
/// them. One `pub use` line would end that, and it is the only way to end it
/// short of adding `lore-object-dispatch` to another crate's manifest.
#[test]
fn the_seam_never_re_exports_the_types_execute_takes() {
    let shipped = shipped_code(&read("src/lib.rs"));

    // Spelling 1: a `pub use`, whether direct or aliased with `as`.
    for line in shipped.lines().filter(|line| line.contains("pub use ")) {
        let found = hits(line, &forbidden_reexport_names());
        assert!(
            found.is_empty(),
            "re-exporting {found:?} falsifies \"{}\": {line}",
            claim_for(found.first().copied().unwrap_or_default()),
        );
    }

    // Spelling 2: a public type alias. Collected as whole statements, because
    // rustfmt wraps a long right-hand side onto the next line and a line-scoped
    // scan would read only `pub type X =`.
    let mut aliases = 0;
    for statement in public_type_aliases(&shipped) {
        aliases += 1;
        let found = hits(&statement, &forbidden_reexport_names());
        assert!(
            found.is_empty(),
            "a public type alias publishes {found:?} and falsifies \"{}\" — the \
             spelling a `pub use` scan missed: {statement}",
            claim_for(found.first().copied().unwrap_or_default()),
        );
    }

    // Spelling 3: a public function signature naming one of them.
    for signature in public_fn_signatures(&shipped) {
        let found = hits(&signature, &forbidden_reexport_names());
        assert!(
            found.is_empty(),
            "a public signature names {found:?} and falsifies \"{}\": {signature}",
            claim_for(found.first().copied().unwrap_or_default()),
        );
    }

    assert!(
        shipped.contains("pub use lore_object_dispatch::"),
        "the re-export block must still exist, or this check scans nothing",
    );
    assert!(
        aliases + shipped.matches("pub fn ").count() > 0,
        "the alias and signature scans found nothing to scan, so they prove nothing",
    );
}

/// Every `pub type ... ;` statement, collected whole across rustfmt's wrapping.
fn public_type_aliases(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut rest = text;
    while let Some(offset) = rest.find("pub type ") {
        let tail = &rest[offset..];
        let Some(end) = tail.find(';') else {
            break;
        };
        statements.push(tail[..=end].to_string());
        rest = &tail[end + 1..];
    }
    statements
}

/// Every `pub fn`/`pub async fn` signature, from the keyword to its opening
/// brace, so a wrapped return type is scanned with the rest of it.
fn public_fn_signatures(text: &str) -> Vec<String> {
    let mut signatures = Vec::new();
    let mut rest = text;
    while let Some(offset) = rest.find("pub fn ").or_else(|| rest.find("pub async fn ")) {
        let tail = &rest[offset..];
        let Some(end) = tail.find('{') else {
            break;
        };
        signatures.push(tail[..end].to_string());
        rest = &tail[end + 1..];
    }
    signatures
}

/// `AttemptSink` must stay private, because one word is the whole difference.
///
/// **Claim protected: no accessor can hand out anything callable.** That rests
/// entirely on the trait being private — `private_interfaces` refuses
/// `pub fn inner(&self) -> &dyn AttemptSink` only while it is. Adding `pub` to
/// the declaration is a single token that silently removes the erasure's entire
/// protection: clippy stays at zero errors, this suite stayed at 9/9, and the
/// exploit builds.
///
/// This is the same class as every other finding in this campaign — a property
/// resting on something nobody checks — and the cheapest possible edit to make
/// by accident, which is exactly why it is worth a pin.
#[test]
fn the_erasure_trait_stays_private() {
    let shipped = shipped_code(&read("src/lib.rs"));
    assert!(
        shipped.contains("\ntrait AttemptSink"),
        "AttemptSink must be declared, and declared private",
    );
    for widened in [
        "pub trait AttemptSink",
        "pub(crate) trait AttemptSink",
        "pub(super) trait AttemptSink",
    ] {
        assert!(
            !shipped.contains(widened),
            "AttemptSink is declared as `{widened}`, which falsifies \"no accessor \
             can hand out anything callable\": `private_interfaces` refuses an \
             accessor returning it only while the trait is private",
        );
    }
}

#[test]
fn raw_direct_put_request_construction_stays_inside_the_admitted_put_execution() {
    let shipped = shipped_code(&read("src/lib.rs"));
    assert_eq!(
        shipped.matches("ProviderDirectPutAttemptRequest {").count(),
        1,
        "the raw direct PUT request must have exactly one construction site"
    );
    let admitted = block_after(&shipped, "impl AdmittedFragmentPutAttempt<'_>", '{', '}');
    assert!(admitted.contains("ProviderDirectPutAttemptRequest {"));

    let opaque = block_after(
        &shipped,
        "pub struct FragmentDirectPutRequest<'a>",
        '{',
        '}',
    );
    assert!(!opaque.contains("pub authorized:"));
    assert!(!opaque.contains("pub operation:"));
}

// ---------------------------------------------------------------------------
// Rule 2: property 3's structural form depends on a manifest
// ---------------------------------------------------------------------------

/// The AWS SDK must stay out of this crate's shipped dependencies.
///
/// Property 3 is structural only while that holds, and a manifest edit is a
/// one-line way to end it silently. `[dev-dependencies]` is exempt: those reach
/// no shipped graph.
#[test]
fn the_seam_manifest_admits_no_provider_sdk() {
    let manifest = read("Cargo.toml");
    let shipped_section = match manifest.split_once("[dev-dependencies]") {
        Some((before, _)) => before,
        None => manifest.as_str(),
    };
    let stripped: String = shipped_section
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let found = hits(&stripped, &FORBIDDEN_SHIPPED_DEPS);
    assert!(
        found.is_empty(),
        "shipped dependencies name {found:?}; property 3's structural form and \
         the acyclic graph both rest on their absence",
    );
    assert!(
        stripped.contains("lore-object-dispatch"),
        "the seam must still depend on the dispatch crate, or this scans nothing",
    );
}

// ---------------------------------------------------------------------------
// Rule 3: no pre-body spool gate
// ---------------------------------------------------------------------------

/// A crate boundary does not prevent `std::fs`, and CR-031's no-pre-admission-spool
/// rule needs it to. The seam supplies no durable body of its own; the caller
/// brings one.
///
/// **A corroborating lint exists, narrowly.** `clippy::items_after_test_module`
/// also catches code appended *below* the test module, but only under
/// `--all-targets`: the lint fires on the lib **test** target, and without that
/// flag there is no test module for anything to be after. It is easy to miss
/// even then, because `dead_code` fails the lib target first and cargo stops
/// before printing it — which is why an earlier attempt to reproduce it saw
/// only `dead_code` and wrongly concluded it did not fire. Both observations
/// were right; they were about different targets.
///
/// It says nothing about the same code placed *above* the tests, so this pin
/// remains the real guard and the lint is corroboration, not a second one.
///
/// **This rule deliberately does not use [`shipped_code`].** It scans the whole
/// comment-stripped file, tests included, so the `#[cfg(test)]` walk — and the
/// desynchronisation recorded as this file's known limit — cannot hide anything
/// from it. That costs nothing here: the seam's own tests touch no filesystem
/// either.
#[test]
fn the_seam_performs_no_filesystem_work() {
    let whole_file = strip_line_comments(&read("src/lib.rs"));
    let found = hits(&whole_file, &FILESYSTEM_TOKENS);
    assert!(
        found.is_empty(),
        "the seam names {found:?} somewhere in the file; CR-031 adds no \
         pre-admission body spool",
    );
}

#[test]
fn the_phase5_seam_has_no_durable_reservation_or_spool_capability() {
    let found = hits(
        &shipped_code(&read("src/lib.rs")),
        &PHASE5_DURABLE_PUT_TOKENS,
    );
    assert!(
        found.is_empty(),
        "the bounded fragment seam names WP-114 durable PUT capability {found:?}",
    );
}

/// The filesystem rule scans one file, so the crate must be one file, and it
/// must not splice in another.
///
/// Kept when the rest of the scanner scaffolding was deleted, because it is the
/// only thing standing between the rule above and a second module or an
/// `include!` — neither of which the crate boundary says anything about.
#[test]
fn the_seam_is_the_only_source_file_and_splices_in_nothing() {
    let sources = crate_root().join("src");
    let entries = match fs::read_dir(&sources) {
        Ok(entries) => entries,
        Err(error) => panic!("{} must be readable: {error}", sources.display()),
    };
    let mut found: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec!["lib.rs".to_string()],
        "the seam is scanned as one file, so src/ must hold exactly lib.rs",
    );

    let spliced = hits(
        &strip_line_comments(&read("src/lib.rs")),
        &["include!", "#[path"],
    );
    assert!(
        spliced.is_empty(),
        "the seam names {spliced:?}, which compiles source this guard never reads",
    );
}

// ---------------------------------------------------------------------------
// Rule 4: the constructor's signature
// ---------------------------------------------------------------------------

/// The constructor takes neither a retry policy nor a second boundary.
///
/// Nothing structural stops a later edit adding either: a retry parameter would
/// compile, and so would a boundary argument that disagrees with the
/// attestation's. Both are one-line regressions in a signature, which is
/// exactly what a signature pin is for.
#[test]
fn the_gateway_constructor_takes_neither_a_retry_policy_nor_a_second_boundary() {
    let shipped = shipped_code(&read("src/lib.rs"));
    let signature = block_after(&shipped, "pub fn new<C, T>(", '(', ')');
    assert!(
        !signature.to_ascii_lowercase().contains("retry"),
        "FragmentProviderGateway::new must not accept a retry setting, got {signature}",
    );
    assert!(
        !signature.contains("CellProviderBoundary"),
        "the boundary must come from the attestation, not a second argument, got {signature}",
    );
    for expected in [
        "attestation: CellSchemaAttestation",
        "bound: InFlightPutBound",
    ] {
        assert!(
            signature.contains(expected),
            "FragmentProviderGateway::new must still require {expected}, got {signature}",
        );
    }
}

/// The attestation stays unforgeable: the comparison private, the test-only
/// constructor test-only, and no public field or deserialization path.
///
/// Kept because none of it is structural — every one of these is a one-word
/// widening that compiles, and `attest_cell_schema` being the only way to mint
/// an attestation is what makes a gateway mean anything.
#[test]
fn only_a_real_readback_can_mint_a_cell_schema_attestation() {
    let raw = strip_line_comments(&read("src/lib.rs"));
    let shipped = shipped_code(&read("src/lib.rs"));

    assert!(
        shipped.contains("\nfn verify_installed_layers("),
        "the layer comparison must be private to the seam",
    );
    for widened in [
        "pub fn verify_installed_layers(",
        "pub(crate) fn verify_installed_layers(",
        "pub(super) fn verify_installed_layers(",
    ] {
        assert!(
            !shipped.contains(widened),
            "the comparison is visible as {widened}, which mints an attestation with no cell",
        );
    }
    assert!(
        shipped.contains("pub async fn attest_cell_schema("),
        "the one public constructor must still exist",
    );

    let Some(index) = raw.find("fn for_tests(") else {
        panic!("the test-only constructor must still exist");
    };
    assert!(
        raw[index.saturating_sub(200)..index].contains("#[cfg(test)]"),
        "for_tests must carry #[cfg(test)]",
    );
    assert!(
        !raw.contains("pub fn for_tests"),
        "for_tests must not be public outside the crate",
    );

    let declaration = block_after(&shipped, "pub struct CellSchemaAttestation {", '{', '}');
    let Some(body) = declaration.split_once('{').map(|(_, body)| body) else {
        panic!("the attestation declaration must have a body, got {declaration}");
    };
    assert!(
        !body.contains("pub "),
        "an attestation with a public field is constructible by anyone, got {declaration}",
    );
    assert!(
        body.contains("attested_layers"),
        "the extracted declaration must be the real one, got {declaration}",
    );
    for forgeable in ["impl Default for CellSchemaAttestation", "Deserialize"] {
        assert!(
            !shipped.contains(forgeable),
            "the seam names {forgeable}, which opens another way to build an attestation",
        );
    }
}

/// A caller cannot name a target, and the request builder that runs no checks is
/// not public. Property 5's two textual halves; the type system holds neither.
#[test]
fn the_seam_addresses_only_its_own_boundary() {
    let shipped = shipped_code(&read("src/lib.rs"));

    let declaration = block_after(&shipped, "pub struct FragmentProviderAttempt {", '{', '}');
    for forbidden in ["target", "bucket", "region", "endpoint"] {
        assert!(
            !declaration.contains(forbidden),
            "FragmentProviderAttempt must not let a caller name a {forbidden}, got {declaration}",
        );
    }
    assert!(
        declaration.contains("pub attempt_class: ProviderAttemptClass"),
        "the extracted declaration must be the real one, got {declaration}",
    );

    assert!(
        !shipped.contains("pub fn build_request"),
        "build_request runs neither the class allowlist nor the ingress cap, \
         so it must not be public",
    );
    let builder = block_after(
        &shipped,
        "fn build_request(&self, attempt: &FragmentProviderAttempt) -> ProviderAttemptRequest {",
        '{',
        '}',
    );
    assert!(
        builder.contains("target: self.client.boundary().target().clone()"),
        "build_request must take its target from this gateway's boundary, got {builder}",
    );
    assert_eq!(
        builder.matches("target:").count(),
        1,
        "exactly one line may supply the target, got {builder}",
    );
}

/// WP-114 CD-8 publishes exactly one dispatch type the forbidden list does not
/// cover, and this records why that is permitted and pins what it buys.
///
/// `FragmentProviderEntry::cell_retention` hands out a `CellRetentionClient`
/// built on the entry's own pool, because `lore-server` schedules the retention
/// pass and the pool cannot cross `lore-postgres` as itself. That does not
/// falsify claim 2: the client's pool field is private with no accessor, so a
/// holder cannot recover the pool, cannot construct a `DispatchRuntimeClient`,
/// and cannot reach any of the four dispatch mutations — whose request types
/// remain unnameable regardless.
///
/// **That reasoning is about the client's method set, and nothing else checked
/// it.** A later `pub fn pool(&self)` on `CellRetentionClient`, or a new
/// mutation on it, would widen this seam with no test failing anywhere. So the
/// set is pinned here, against the dispatch crate's own source. A deliberate
/// addition updates this list and states what it costs; an accidental one is a
/// failure.
#[test]
fn the_cell_retention_client_buys_only_the_retention_procedures() {
    const RETENTION_CLIENT: &str = include_str!("../../lore-object-dispatch/src/cell_retention.rs");
    const PERMITTED: [&str; 4] = ["new", "read_state", "prune_once", "backlog"];

    let shipped = shipped_code(&read("src/lib.rs"));
    assert!(
        shipped.contains("pub fn cell_retention("),
        "this pin describes an accessor that no longer exists",
    );
    // The forbidden names must still be absent from that accessor's own
    // signature and from the handle it returns.
    for signature in public_fn_signatures(&shipped) {
        assert!(
            hits(&signature, &forbidden_reexport_names()).is_empty(),
            "the retention accessor must publish no forbidden type: {signature}"
        );
    }

    let client_impl = block_after(RETENTION_CLIENT, "impl CellRetentionClient {", '{', '}');
    let mut methods = Vec::new();
    let mut rest = strip_line_comments(&client_impl);
    while let Some(offset) = rest.find("pub fn ").or_else(|| rest.find("pub async fn ")) {
        let tail = rest[offset..]
            .trim_start_matches("pub ")
            .trim_start_matches("async ")
            .trim_start_matches("fn ");
        let end = tail.find(['(', '<']).expect("a method name ends somewhere");
        methods.push(tail[..end].trim().to_string());
        rest = rest[offset + 7..].to_string();
    }
    // Equality, not containment. A containment check passes just as happily
    // when the scan has quietly stopped seeing methods, which is the failure
    // mode that makes a source scan look like coverage while proving nothing.
    methods.sort();
    let mut permitted: Vec<String> = PERMITTED.iter().map(|name| (*name).to_string()).collect();
    permitted.sort();
    assert_eq!(
        methods, permitted,
        "CellRetentionClient's public method set changed. A new method is one \
         this seam's authorised export was assessed without: either it is safe \
         to hand a `lore-postgres`-crossing holder, in which case add it here \
         and say why, or the accessor must stop handing out this client. A \
         missing one means the scan stopped seeing methods and is proving \
         nothing.",
    );
    // The reasoning above rests on the pool being unrecoverable from the client.
    assert!(
        !methods.iter().any(|method| method == "pool"),
        "a pool accessor on CellRetentionClient falsifies \"a dispatch client cannot be constructed\"",
    );
}

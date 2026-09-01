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
//!   route to it" — `lore-postgres` does not depend on `lore-object-dispatch`
//!   and this crate does not re-export `execute`'s parameter types, so a caller
//!   there cannot make the call. A scan for aliases, accessors and re-exports
//!   was guarding a property the compiler now holds.
//! - "the package builds no private provider client" — for *this* crate that is
//!   the dependency graph. The four files still in `lore-postgres` keep a
//!   reduced version of that scan, in that crate's own pins file.
//! - The scanner scaffolding those needed — the file-list check, the
//!   `include!`/`#[path]` refusal, the alias resolver, the four-placement
//!   self-proof — went with them, except what the rules below still need.
//!
//! Four rules remain, and each is here because nothing else holds it.
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
const FILESYSTEM_TOKENS: [&str; 8] = [
    "std::fs",
    "tokio::fs",
    "OpenOptions",
    "create_dir",
    "read_to_string",
    "SpoolLayout",
    "File::",
    "fs::",
];

/// The two types `GovernedProviderClient::execute` takes.
///
/// **This is the load-bearing rule in this file.** Property 2 is structural
/// because no crate outside this one can name these, so a `pub use` of either
/// would hand the whole property away in one line — and unlike the dependency
/// on `lore-object-dispatch`, which a reviewer would notice in a manifest, a
/// re-export hides in an import block.
const FORBIDDEN_REEXPORTS: [&str; 2] = ["ProviderAttemptLedger", "ProviderAttemptRequest"];

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
    for line in shipped.lines().filter(|line| line.contains("pub use ")) {
        let found = hits(line, &FORBIDDEN_REEXPORTS);
        assert!(
            found.is_empty(),
            "re-exporting {found:?} lets a caller elsewhere name execute's \
             arguments, which is the entire property: {line}",
        );
    }
    assert!(
        shipped.contains("pub use lore_object_dispatch::"),
        "the re-export block must still exist, or this check scans nothing",
    );
    // Belt and braces: neither type may be re-exported under an alias either.
    for forbidden in FORBIDDEN_REEXPORTS {
        let aliased = format!("pub use lore_object_dispatch::{forbidden}");
        assert!(
            !shipped.contains(&aliased),
            "{forbidden} must not be re-exported, aliased or otherwise",
        );
    }
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
/// **This rule deliberately does not use [`shipped_code`].** It scans the whole
/// comment-stripped file, tests included, so the `#[cfg(test)]` walk — and the
/// desynchronisation recorded as this file's known limit — cannot hide anything
/// from it. That costs nothing here: the seam's own tests touch no filesystem
/// either. `SpoolLayout` is the one exception, because the put-body fixture
/// constructs one to derive a path without opening anything, so it is checked
/// against shipped code alone and named as the exception rather than dropped.
#[test]
fn the_seam_performs_no_filesystem_work() {
    let whole_file = strip_line_comments(&read("src/lib.rs"));
    let unconditional: Vec<&str> = FILESYSTEM_TOKENS
        .iter()
        .copied()
        .filter(|token| *token != "SpoolLayout")
        .collect();
    let found = hits(&whole_file, &unconditional);
    assert!(
        found.is_empty(),
        "the seam names {found:?} somewhere in the file; CR-031 adds no \
         pre-admission body spool",
    );

    assert!(
        whole_file.contains("SpoolLayout"),
        "the put-body fixture is expected to name SpoolLayout; if it stopped, \
         drop the exception below rather than leaving it unexplained",
    );
    assert!(
        !shipped_code(&read("src/lib.rs")).contains("SpoolLayout"),
        "shipped code must not derive a spool path",
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
    let Some(start) = shipped.find("impl<C, T> FragmentProviderGateway<C, T>") else {
        panic!("the generic gateway impl block must exist");
    };
    let signature = block_after(&shipped[start..], "pub fn new(", '(', ')');
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
        builder.contains("target: self.client.0.boundary().target().clone()"),
        "build_request must take its target from this gateway's boundary, got {builder}",
    );
    assert_eq!(
        builder.matches("target:").count(),
        1,
        "exactly one line may supply the target, got {builder}",
    );
}

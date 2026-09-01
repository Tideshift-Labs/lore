// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Source pins for the two WP-118 Phase 4 properties that cannot be structural.
//!
//! CR-031 forbids this package from building a second provider client and from
//! enabling SDK automatic retries. Neither can be enforced by the type system
//! inside `lore-postgres`:
//!
//! - `lore-postgres` legitimately depends on the AWS S3 SDK for the legacy
//!   CR-007 immutable store, so a crate-level absence is not available as
//!   evidence. The rule is therefore scoped to `src/domain/fragments/`, which is
//!   the package CR-031 actually governs.
//! - The retry setting is structural at the *seam*
//!   (`FragmentProviderGateway::new` takes no retry parameter), but nothing
//!   stops a later edit from adding one. That signature is pinned here.
//!
//! These are guards over source text, and a guard over source text is only as
//! good as its scanner. Every check below is therefore run against a mutated
//! copy of the real file as well as the real file, so a scanner that has
//! quietly stopped matching fails this suite instead of passing it.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Every file in the WP-118 package.
const PACKAGE_FILES: [&str; 6] = [
    "coordinator.rs",
    "masks.rs",
    "mod.rs",
    "provider.rs",
    "schema.rs",
    "states.rs",
];

/// A provider SDK or bucket client. None of these may appear in the package's
/// code, in any file, because CR-031's no-second-provider-client rule is what
/// keeps WP-114's governed client the only route to a bucket.
///
/// **`lore_aws` as a whole is deliberately not on this list, and that carve-out
/// is load-bearing.** `masks.rs` reads `lore_aws::store::object_metadata::
/// PAYLOAD_FLAGS`, which is the shared payload-flag vocabulary CR-031's two
/// masks are defined against — a constant, not a client, and a pre-existing
/// dependency this package inherited rather than introduced. Forbidding the
/// crate outright would have failed on that line and invited the guard to be
/// weakened wholesale. The client surface is named instead, so a use that could
/// actually reach a bucket is what fails.
const PRIVATE_CLIENT_TOKENS: [&str; 9] = [
    "aws_sdk_s3",
    "aws-sdk-s3",
    "aws_smithy",
    "aws_config",
    "lore_aws::clients",
    "lore_aws::s3",
    "S3Impl",
    "ObjectStoreSettings",
    "PostgresImmutableStore",
];

/// The governed-client surface. These may appear only in `provider.rs`, which is
/// the package's single provider seam; anywhere else means a second route.
const GOVERNED_CLIENT_TOKENS: [&str; 6] = [
    "GovernedProviderClient",
    "ProviderTransport",
    "ProviderChargeAuthority",
    "ProviderAttemptRequest",
    "AuthorizedProviderAttempt",
    "lore_object_dispatch",
];

/// The subset of [`GOVERNED_CLIENT_TOKENS`] that shipped code must actually
/// contain, so "only provider.rs names these" cannot be satisfied by a
/// provider.rs that stopped being the seam.
///
/// `AuthorizedProviderAttempt` is deliberately absent: it is the value CD-5
/// hands a transport, and this seam ships no transport, so it appears only in
/// this package's test doubles.
const SEAM_REQUIRED_TOKENS: [&str; 5] = [
    "GovernedProviderClient",
    "ProviderTransport",
    "ProviderChargeAuthority",
    "ProviderAttemptRequest",
    "lore_object_dispatch",
];

/// Filesystem access. `provider.rs` must have none: CR-031 removed the
/// pre-admission body spool, and a seam that can open a file is a seam that can
/// grow one back.
const FILESYSTEM_TOKENS: [&str; 7] = [
    "std::fs",
    "tokio::fs",
    "OpenOptions",
    "create_dir",
    "read_to_string",
    "SpoolLayout",
    "File::",
];

fn package_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/domain/fragments")
}

fn read(file: &str) -> String {
    let path = package_dir().join(file);
    match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => panic!("{} must be readable: {error}", path.display()),
    }
}

/// Removes `//`-to-end-of-line comments, conservatively.
///
/// The package's prose legitimately names the forbidden tokens — this very
/// file's module docs do — so a scan that did not strip comments would flag
/// documentation and force the documentation to be vaguer than the rule.
///
/// Three rules, in order, and the middle one is the important one:
///
/// 1. A line whose first non-whitespace is `//` is a comment line and is
///    dropped whole.
/// 2. **A line containing a `"` is kept whole**, because a naive cut at the
///    first `//` would let `let s = "//"; use aws_sdk_s3::X;` hide real code
///    behind a string literal. That was a live evasion in an earlier revision
///    of this file. Keeping the line is conservative in the safe direction: the
///    worst case is that a forbidden token in a trailing comment on a
///    string-bearing line trips the guard, which is a false alarm a reviewer
///    resolves by moving the comment.
/// 3. Otherwise cut at the first `//`.
///
/// The stripper is line-based and therefore blind to `/* */`, so
/// [`no_scanned_file_uses_a_block_comment`] refuses any file that has one rather
/// than letting a block comment hide code from the scan.
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

/// The part of a file that ships, excluding its `#[cfg(test)]` module.
///
/// Test code legitimately names the transport trait and the spool layout: it has
/// to, to build the doubles that prove the seam behaves. The rules here are
/// about shipped code.
fn shipped_code(text: &str) -> String {
    let stripped = strip_line_comments(text);
    match stripped.find("\n#[cfg(test)]") {
        Some(index) => stripped[..index].to_string(),
        None => stripped,
    }
}

/// The tokens `haystack` contains, in the order they were searched for.
fn hits<'a>(haystack: &str, tokens: &[&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .copied()
        .filter(|token| haystack.contains(token))
        .collect()
}

/// [`hits`], but each match must start a Rust identifier.
///
/// Substring matching is the right default for the file-level scans: it is
/// conservative, and a false alarm there is cheap. It is wrong for the type-alias
/// scan, because `UnwiredProviderTransport` — the shipped, correct alias's own
/// right-hand side — contains `ProviderTransport`, and a substring rule would
/// flag the very shape the seam is supposed to have.
fn hits_as_identifier<'a>(haystack: &str, tokens: &[&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .copied()
        .filter(|token| {
            haystack.match_indices(token).any(|(index, _)| {
                index == 0
                    || !haystack.as_bytes()[index - 1].is_ascii_alphanumeric()
                        && haystack.as_bytes()[index - 1] != b'_'
            })
        })
        .collect()
}

/// Extracts the balanced `{ ... }` or `( ... )` block that starts at the first
/// occurrence of `opening`.
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
// The scanner proves itself first
// ---------------------------------------------------------------------------

/// The line-comment stripper is what every other check rests on, so it is
/// checked against the real file rather than a toy string: it must remove a
/// documented mention and keep the code around it.
#[test]
fn the_stripper_removes_comments_and_keeps_code() {
    let provider = read("provider.rs");
    assert!(
        provider.contains("aws-sdk-s3"),
        "provider.rs's module docs are expected to name the SDK in prose; \
         if that prose was removed this guard has stopped proving anything",
    );
    let shipped = shipped_code(&provider);
    assert!(
        !shipped.contains("aws-sdk-s3"),
        "the stripper must remove a documented mention",
    );
    assert!(
        shipped.contains("GovernedProviderClient"),
        "the stripper must keep the code it is scanning",
    );
    assert!(
        !shipped.contains("fn a_granted_charge_binds_exactly_one_issued_attempt"),
        "shipped_code must stop at the #[cfg(test)] module",
    );
}

/// The stripper is blind to `/* */`, so no scanned file may have one. Without
/// this, a block comment could hide a forbidden token from every check below.
#[test]
fn no_scanned_file_uses_a_block_comment() {
    for file in PACKAGE_FILES {
        assert!(
            !read(file).contains("/*"),
            "{file} uses a block comment, which the line-based scanner cannot see through",
        );
    }
}

/// Every forbidden token, injected into the real shipped source as code, must be
/// caught; injected as a comment, it must not be. Driving the loop from the
/// token tables rather than a hand-picked example means a token added to a table
/// without a working match fails here.
#[test]
fn the_scanner_catches_every_forbidden_token_it_claims_to() {
    let provider = shipped_code(&read("provider.rs"));
    for token in PRIVATE_CLIENT_TOKENS
        .iter()
        .chain(GOVERNED_CLIENT_TOKENS.iter())
        .chain(FILESYSTEM_TOKENS.iter())
    {
        // Four placements, not one. The last two are the evasions a naive
        // first-`//` cut lets through, and both were live before this file's
        // stripper grew rule 2.
        for (placement, injected) in [
            ("a plain code line", format!("use {token};")),
            ("code after a doc line", format!("/// docs\nuse {token};")),
            (
                "code after a string containing a comment marker",
                format!("let marker = \"//\"; use {token};"),
            ),
            (
                "code trailing a string literal",
                format!("let name = \"x\"; use {token};"),
            ),
        ] {
            let mutated = format!("{provider}\n{injected}\n");
            let stripped = strip_line_comments(&mutated);
            // Assert on the *injected* line, not on the whole text. Several of
            // these tokens already occur in `provider.rs` legitimately, so
            // `stripped.contains(token)` is true whatever the stripper does — an
            // earlier revision of this test made exactly that mistake and proved
            // nothing for five of the six governed-client tokens.
            let survivor = stripped
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default();
            assert!(
                survivor.contains(*token),
                "the scanner must catch {token} as {placement}; \
                 the injected line survived stripping as {survivor:?}",
            );
        }

        // A distinctive sentinel, for the same reason: the token itself occurs
        // elsewhere in the file, so a whole-text check would be meaningless.
        let as_comment = format!("{provider}\n// mentions {token} SENTINELXYZ\n");
        assert!(
            !strip_line_comments(&as_comment).contains("SENTINELXYZ"),
            "the scanner must ignore {token} written in a comment",
        );
    }
}

/// The seam must not hand its own package a way around
/// [`only_the_provider_seam_reaches_the_governed_client`]. A `pub use` or a
/// public type alias in `provider.rs` would let a sibling name the governed
/// client as `provider::Something` and satisfy every check above.
#[test]
fn the_seam_re_exports_no_part_of_the_governed_client() {
    let provider = shipped_code(&read("provider.rs"));
    assert!(
        !provider.contains("pub use lore_object_dispatch"),
        "provider.rs must not re-export the dispatch crate",
    );
    // Scan each alias as a whole *statement*, not as a line. rustfmt wraps a
    // long alias onto the next line — `UnwiredFragmentProviderGateway` in this
    // very file is that shape — so a line-scoped check reads only `pub type
    // Seam =` and never sees the type it names. That was a live bypass.
    let mut aliases = 0;
    for statement in type_alias_statements(&provider) {
        aliases += 1;
        let found = hits_as_identifier(&statement, &GOVERNED_CLIENT_TOKENS);
        assert!(
            found.is_empty(),
            "a public type alias names {found:?}, which re-opens the seam: {statement}",
        );
    }
    assert!(
        aliases >= 1,
        "the alias scan found nothing to scan, so it proves nothing",
    );
}

/// Every `pub type ... ;` statement in `text`, each collected whole across the
/// line breaks rustfmt may have inserted.
fn type_alias_statements(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("pub type ") {
        let tail = &rest[start..];
        let end = match tail.find(';') {
            Some(end) => end + 1,
            None => panic!("unterminated `pub type` statement: {tail}"),
        };
        statements.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    statements
}

/// The file list this suite scans must be the directory's actual contents, so a
/// new file cannot be added to the package and silently escape every rule.
#[test]
fn the_scanned_file_list_is_the_whole_package() {
    let entries = match fs::read_dir(package_dir()) {
        Ok(entries) => entries,
        Err(error) => panic!("the package directory must be readable: {error}"),
    };
    let mut found = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        // The listing is not recursive, so a subdirectory would carry files no
        // rule here reaches. Refuse one rather than walk it: the package has a
        // flat shape and a nested module is a design change, not a file move.
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                panic!("domain/fragments/ has a subdirectory ({name}); these guards are flat")
            }
            _ => {}
        }
        if name.ends_with(".rs") {
            found.push(name);
        }
    }
    found.sort();
    assert_eq!(
        found,
        PACKAGE_FILES.map(str::to_string).to_vec(),
        "every .rs file in domain/fragments/ must be listed in PACKAGE_FILES",
    );
}

// ---------------------------------------------------------------------------
// Property 3: no private S3 client, no SDK automatic retries
// ---------------------------------------------------------------------------

#[test]
fn the_package_builds_no_private_provider_client() {
    for file in PACKAGE_FILES {
        let found = hits(&strip_line_comments(&read(file)), &PRIVATE_CLIENT_TOKENS);
        assert!(
            found.is_empty(),
            "{file} names {found:?}; WP-114's governed client is the only route to a bucket",
        );
    }
}

#[test]
fn only_the_provider_seam_reaches_the_governed_client() {
    for file in PACKAGE_FILES {
        if file == "provider.rs" {
            continue;
        }
        let found = hits(&strip_line_comments(&read(file)), &GOVERNED_CLIENT_TOKENS);
        assert!(
            found.is_empty(),
            "{file} names {found:?}; provider.rs is the package's only provider seam",
        );
    }
    let seam = shipped_code(&read("provider.rs"));
    for token in SEAM_REQUIRED_TOKENS {
        assert!(
            seam.contains(token),
            "provider.rs must actually be the seam it claims to be, but does not name {token}",
        );
    }
}

/// Every `ProviderRetryPolicy::` in the file must be `::disabled`. Anything else
/// would be a second retry setting, which is what CR-031 forbids.
#[test]
fn the_seam_states_exactly_one_retry_setting_and_it_is_disabled() {
    let provider = strip_line_comments(&read("provider.rs"));
    let mut constructions = 0;
    for (index, _) in provider.match_indices("ProviderRetryPolicy::") {
        constructions += 1;
        let tail = &provider[index + "ProviderRetryPolicy::".len()..];
        assert!(
            tail.starts_with("disabled"),
            "ProviderRetryPolicy is constructed as something other than disabled()",
        );
    }
    assert!(
        constructions >= 1,
        "the seam must state its retry setting explicitly",
    );
}

/// The constructor takes neither a retry policy nor a second boundary, so a
/// retrying client cannot be configured through this seam and a gateway cannot
/// address a cell other than the one its attestation was minted for.
#[test]
fn the_gateway_constructor_takes_neither_a_retry_policy_nor_a_second_boundary() {
    let provider = shipped_code(&read("provider.rs"));
    // Anchored inside the generic impl block, because `InFlightPutBound::new`
    // occurs earlier in the file and would otherwise be the match.
    let Some(start) = provider.find("impl<C, T> FragmentProviderGateway<C, T>") else {
        panic!("the generic gateway impl block must exist");
    };
    let signature = block_after(&provider[start..], "pub fn new(", '(', ')');
    assert!(
        !signature.to_ascii_lowercase().contains("retry"),
        "FragmentProviderGateway::new must not accept a retry setting, got {signature}",
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
    // The boundary must NOT be a separate argument: it travels inside the
    // attestation so the two cannot be paired wrongly. See
    // `only_a_real_readback_can_mint_a_cell_schema_attestation`.
    assert!(
        !signature.contains("CellProviderBoundary"),
        "the boundary must come from the attestation, not from a second argument, got {signature}",
    );
}

// ---------------------------------------------------------------------------
// Property 1: only a real readback can mint an attestation
// ---------------------------------------------------------------------------

/// `CellSchemaAttestation` is the gate on constructing a gateway at all, so
/// "only a real cell readback can mint one" has to stay true.
///
/// The comparison it rests on takes a `DispatcherIdentityState`, whose fields
/// are all public, against `CELL_SCHEMA_LAYERS`, which is public too — so
/// exposing the comparison at all hands any caller a way to mint an attestation
/// from a hand-built state with no cell behind it. An earlier revision did
/// exactly that. The compiler enforces the current shape; this fails loudly if
/// someone widens it back for convenience.
#[test]
fn only_a_real_readback_can_mint_a_cell_schema_attestation() {
    let provider = shipped_code(&read("provider.rs"));
    assert!(
        provider.contains("\nfn verify_installed_layers("),
        "the layer comparison must be private to the seam",
    );
    for widened in [
        "pub fn verify_installed_layers(",
        "pub(crate) fn verify_installed_layers(",
        "pub(super) fn verify_installed_layers(",
    ] {
        assert!(
            !provider.contains(widened),
            "the layer comparison is visible as {widened}, which mints an attestation with no cell",
        );
    }
    assert!(
        provider.contains("pub async fn attest_cell_schema("),
        "the one public constructor must still exist",
    );
    assert!(
        !strip_line_comments(&read("mod.rs")).contains("verify_installed_layers"),
        "the layer comparison must not be re-exported",
    );

    let declaration = block_after(&provider, "pub struct CellSchemaAttestation {", '{', '}');
    // The extracted block opens with `pub struct ...`, so the body is what is
    // scanned for a public field.
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
    for forgeable in [
        "impl Default for CellSchemaAttestation",
        "Deserialize",
        "serde",
    ] {
        assert!(
            !provider.contains(forgeable),
            "provider.rs names {forgeable}, which opens another way to build an attestation",
        );
    }
}

// ---------------------------------------------------------------------------
// Property 4: no pre-body spool gate
// ---------------------------------------------------------------------------

#[test]
fn the_seam_performs_no_filesystem_work() {
    let provider = shipped_code(&read("provider.rs"));
    let found = hits(&provider, &FILESYSTEM_TOKENS);
    assert!(
        found.is_empty(),
        "provider.rs names {found:?}; CR-031 adds no pre-admission body spool, \
         and a durable body is the caller's to supply",
    );
}

// ---------------------------------------------------------------------------
// Property 5: the cell's own region and nothing else
// ---------------------------------------------------------------------------

/// A caller cannot name a target, because the type has nowhere to put one.
#[test]
fn a_caller_supplied_attempt_carries_no_provider_target() {
    let provider = shipped_code(&read("provider.rs"));
    let declaration = block_after(&provider, "pub struct FragmentProviderAttempt {", '{', '}');
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
}

/// The one line that supplies the target reads it from the gateway's own
/// boundary. If a future edit moves it, this fails rather than the property
/// silently weakening.
#[test]
fn the_seam_sources_its_target_only_from_its_own_boundary() {
    let provider = shipped_code(&read("provider.rs"));
    let builder = block_after(
        &provider,
        "pub fn build_request(&self, attempt: &FragmentProviderAttempt) -> ProviderAttemptRequest {",
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

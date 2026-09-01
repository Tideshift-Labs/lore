// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Source pins for the WP-118 Phase 4 properties that cannot be structural.
//!
//! # What these are, and what they are not
//!
//! CR-031 forbids this package from building a second provider client and from
//! enabling SDK automatic retries. Neither can be enforced by the type system
//! inside `lore-postgres`:
//!
//! - `lore-postgres` legitimately depends on the AWS S3 SDK for the legacy
//!   CR-007 immutable store, so a crate-level absence is not available as
//!   evidence. The rule is scoped to `src/domain/fragments/`, which is the
//!   package CR-031 actually governs.
//! - The retry setting is structural at the *seam* — `FragmentProviderGateway::new`
//!   takes no retry parameter — but nothing stops a later edit from adding one.
//!   That signature is pinned here.
//!
//! **These are a speed bump and a regression detector, not a proof.** A scan
//! over source text cannot express reachability, and an independent reviewer
//! beat an earlier version of this file three separate ways in one sitting: by
//! appending code below the test module, by chaining a private type alias, and
//! by `include!`ing a file outside the scanned directory. Those three root
//! causes are closed below and each has a test that reproduces the evasion. A
//! fourth is not ruled out. A dependency-graph fix — a crate that cannot depend
//! on `aws-sdk-s3` at all — is the only thing that would make "not expressible"
//! true, and it is not this file.
//!
//! Every check runs against a mutated copy of the real source as well as the
//! real source, so a scanner that has quietly stopped matching fails this suite
//! instead of passing it.

use std::collections::BTreeSet;
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

/// The governed-client surface, as a coarse substring set. These may appear only
/// in `provider.rs`.
///
/// The alias and signature checks do **not** use this list — they derive the
/// dispatch surface from `provider.rs`'s own imports instead, because a hand
/// list is a guess at the population and an earlier revision's list was missing
/// `ProviderRetryPolicy` and `ProviderCapabilities`, which was one of the three
/// evasions a reviewer used.
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

/// Compile-time source splicing. Every check here reads files from
/// `domain/fragments/`, so a Rust item pulled in from outside it would be
/// compiled and unscanned. That was one of the three reviewer evasions.
///
/// **`include_str!` and `include_bytes!` are deliberately absent.** They embed
/// *data*, not code — nothing they name is compiled as Rust — and `schema.rs`
/// legitimately uses `include_str!` to read `migrations/0001_init.sql` so its
/// tests can compare the migration against the runtime DDL const. Banning them
/// would have failed on that and invited the whole guard to be relaxed.
const SPLICING_TOKENS: [&str; 2] = ["include!", "#[path"];

/// Public type aliases in `provider.rs` that legitimately name a dispatch type,
/// each with the reason it is safe.
///
/// The alias scan resolves chains transitively and refuses every tainted public
/// alias not listed here, so adding one is a deliberate act that lands in this
/// table with a justification rather than passing silently.
const PERMITTED_GOVERNED_ALIASES: [(&str, &str); 1] = [(
    "UnwiredFragmentProviderGateway",
    "names only the two fail-closed defaults, which can neither charge nor send",
)];

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

/// The part of a file that ships: comments stripped, and every
/// `#[cfg(test)]`-attributed item removed **by structure**.
///
/// **This function is the root cause a reviewer exploited, and the fix is the
/// word "every".** It used to truncate the file at the first column-0
/// `#[cfg(test)]`, which made *everything below the test module invisible to
/// every check built on it* — a reviewer appended a filesystem import, a direct
/// governed-client re-export, and a spooling method below the tests and left
/// all thirteen pins green. Removing each attributed item and continuing past it
/// means there is no "below" to hide in.
///
/// Removal walks from the attribute to the item's first `{` or `;` at the top
/// level and takes the balanced block or the statement. That covers `mod`, `fn`,
/// `impl`, `use`, and `const`. It is not a Rust parser: a `{`, `}` or `;` inside
/// a string literal between the attribute and its item's opening brace would
/// misparse. [`the_test_module_remover_keeps_everything_around_it`] pins the
/// behaviour against the real files.
fn shipped_code(text: &str) -> String {
    let stripped = strip_line_comments(text);
    let mut out = String::with_capacity(stripped.len());
    let mut rest = stripped.as_str();
    while let Some(index) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..index]);
        let tail = &rest[index..];
        // An unterminated item means the tail is all test code.
        rest = skip_attributed_item(tail).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

/// Given text starting at an attribute, returns the text after the item it
/// attaches to.
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

/// The tokens `haystack` contains, in the order they were searched for.
fn hits<'a>(haystack: &str, tokens: &[&'a str]) -> Vec<&'a str> {
    tokens
        .iter()
        .copied()
        .filter(|token| haystack.contains(token))
        .collect()
}

/// Every identifier `provider.rs` imports from `lore_object_dispatch`.
///
/// Derived rather than hand-listed. A hand list is a guess at the population it
/// ranges over, and the earlier hand list was missing two identifiers a reviewer
/// then used to escape. Anything the seam imports from the dispatch crate is by
/// definition part of the surface a sibling must not reach through it.
fn dispatch_identifiers(provider: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in provider.lines() {
        let trimmed = line.trim();
        let Some(path) = trimmed.strip_prefix("use lore_object_dispatch::") else {
            continue;
        };
        let Some(path) = path.strip_suffix(';') else {
            continue;
        };
        // `use a::b::C as D;` contributes both C and D.
        for part in path.split(" as ") {
            if let Some(last) = part.rsplit("::").next() {
                let last = last.trim();
                if !last.is_empty() {
                    names.insert(last.to_string());
                }
            }
        }
    }
    assert!(
        names.contains("GovernedProviderClient"),
        "the derived dispatch surface must include the governed client; \
         the import parser has stopped working",
    );
    names
}

/// One `type` alias: its name, whether it is public, and its right-hand side.
struct TypeAlias {
    name: String,
    public: bool,
    rhs: String,
}

/// Every `type ... = ...;` statement in `text`, public or private, each
/// collected whole across the line breaks rustfmt may have inserted.
///
/// A line-scoped scan reads only `pub type Seam =` and never sees the type it
/// names; `UnwiredFragmentProviderGateway` in `provider.rs` is exactly that
/// shape. Private aliases are collected too, because the chain
/// `type Inner = Governed…;` then `pub type Escape = Inner;` was a reviewer
/// evasion: neither statement alone names a forbidden identifier publicly.
fn type_aliases(text: &str) -> Vec<TypeAlias> {
    let mut aliases = Vec::new();
    let mut rest = text;
    while let Some(offset) = rest.find("type ") {
        let public = rest[..offset].trim_end().ends_with("pub");
        let tail = &rest[offset + "type ".len()..];
        let Some(end) = tail.find(';') else {
            break;
        };
        let statement = &tail[..end];
        if let Some((left, right)) = statement.split_once('=') {
            let name = left
                .split(['<', ' ', '\n'])
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            if !name.is_empty() {
                aliases.push(TypeAlias {
                    name,
                    public,
                    rhs: right.to_string(),
                });
            }
        }
        rest = &tail[end + 1..];
    }
    aliases
}

/// The alias names whose expansion transitively reaches a dispatch identifier.
fn tainted_aliases(aliases: &[TypeAlias], dispatch: &BTreeSet<String>) -> BTreeSet<String> {
    let mut tainted: BTreeSet<String> = BTreeSet::new();
    // Bounded fixpoint: each pass can only add, and there are finitely many
    // aliases, so `aliases.len()` passes reach the fixpoint.
    for _ in 0..=aliases.len() {
        let before = tainted.len();
        for alias in aliases {
            if tainted.contains(&alias.name) {
                continue;
            }
            let reaches_dispatch = dispatch
                .iter()
                .any(|identifier| names_identifier(&alias.rhs, identifier));
            // The transitive step. Without it, `type Inner = Governed…;` plus
            // `pub type Escape = Inner<…>;` publishes the client while neither
            // statement names it publicly — a reviewer's evasion.
            let reaches_tainted = tainted
                .iter()
                .any(|name| names_identifier(&alias.rhs, name));
            if reaches_dispatch || reaches_tainted {
                tainted.insert(alias.name.clone());
            }
        }
        if tainted.len() == before {
            break;
        }
    }
    tainted
}

/// Whether `haystack` names `identifier` as a whole Rust identifier.
///
/// Substring matching is wrong here: `UnwiredProviderTransport` — the shipped,
/// correct alias's own right-hand side — contains `ProviderTransport`, and a
/// substring rule would flag the very shape the seam is supposed to have.
fn names_identifier(haystack: &str, identifier: &str) -> bool {
    haystack.match_indices(identifier).any(|(index, _)| {
        let before_ok = index == 0 || !is_identifier_byte(haystack.as_bytes()[index - 1]);
        let after = index + identifier.len();
        let after_ok = after >= haystack.len() || !is_identifier_byte(haystack.as_bytes()[after]);
        before_ok && after_ok
    })
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
}

/// **The evasion this replaced a truncation to close.**
///
/// `shipped_code` must remove the test module and keep going, so that code
/// appended below it is still scanned. The two assertions are a pair: dropping
/// the tests, and keeping what follows them.
#[test]
fn the_test_module_remover_keeps_everything_around_it() {
    let provider = read("provider.rs");
    let shipped = shipped_code(&provider);
    assert!(
        !shipped.contains("fn a_granted_charge_binds_exactly_one_issued_attempt"),
        "the test module must be removed",
    );
    assert!(
        shipped.contains("pub async fn attest_cell_schema"),
        "shipped items before the test module must survive",
    );
    assert!(
        !shipped.contains("fn for_tests"),
        "a #[cfg(test)] item nested inside an impl must be removed too",
    );

    let appended = format!("{provider}\nuse std::fs::OpenOptions;\n");
    assert!(
        shipped_code(&appended).contains("OpenOptions"),
        "code appended below the test module must remain visible to the scan",
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

/// Every forbidden token, injected into the real shipped source, must be caught
/// in each of five placements; injected as a comment, it must not be. Driving
/// the loop from the token tables rather than a hand-picked example means a
/// token added to a table without a working match fails here.
#[test]
fn the_scanner_catches_every_forbidden_token_it_claims_to() {
    let provider = shipped_code(&read("provider.rs"));
    for token in PRIVATE_CLIENT_TOKENS
        .iter()
        .chain(GOVERNED_CLIENT_TOKENS.iter())
        .chain(FILESYSTEM_TOKENS.iter())
    {
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
            (
                "code wrapped across two lines",
                format!("type Wrapped =\n    {token};"),
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

/// The scanned file list must be what is actually compiled, so a file cannot be
/// added to the package and escape every rule.
///
/// Three things have to agree: the directory's contents, `mod.rs`'s module
/// declarations, and [`PACKAGE_FILES`]. The middle one is what a bare directory
/// listing misses — a file present but undeclared compiles into nothing, and a
/// module declared but sourced from elsewhere compiles from a path no rule here
/// reads.
#[test]
fn the_scanned_file_list_is_what_the_package_actually_compiles() {
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

    let mut declared: Vec<String> = shipped_code(&read("mod.rs"))
        .lines()
        .filter_map(|line| {
            let trimmed = line
                .trim()
                .strip_prefix("pub mod ")
                .or(line.trim().strip_prefix("mod "))?;
            trimmed.strip_suffix(';').map(|name| format!("{name}.rs"))
        })
        .collect();
    declared.push("mod.rs".to_string());
    declared.sort();
    assert_eq!(
        declared,
        PACKAGE_FILES.map(str::to_string).to_vec(),
        "mod.rs's module declarations must match the scanned file list exactly",
    );
}

/// **The evasion that reached outside the directory entirely.**
///
/// `include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/domain/elsewhere.rs"))`
/// compiles a file no check here reads. So does `#[path = "..."] mod`. Neither
/// has any legitimate use in this package.
#[test]
fn the_package_splices_in_no_source_from_outside_itself() {
    for file in PACKAGE_FILES {
        let found = hits(&strip_line_comments(&read(file)), &SPLICING_TOKENS);
        assert!(
            found.is_empty(),
            "{file} names {found:?}, which compiles source these guards never read",
        );
    }
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

/// The test-only constructor must stay test-only.
///
/// `for_tests` mints an attestation with no cell. Its `#[cfg(test)]` is what
/// keeps that unreachable from a shipped binary, and an attribute is exactly the
/// kind of thing a later edit drops without noticing: changing it to `pub fn`
/// left every other pin green.
#[test]
fn the_test_only_attestation_constructor_stays_test_only() {
    let raw = strip_line_comments(&read("provider.rs"));
    let Some(index) = raw.find("fn for_tests(") else {
        panic!("the test-only constructor must still exist");
    };
    let preceding = &raw[index.saturating_sub(200)..index];
    assert!(
        preceding.contains("#[cfg(test)]"),
        "for_tests must carry #[cfg(test)], got the preceding text {preceding:?}",
    );
    assert!(
        !raw.contains("pub fn for_tests"),
        "for_tests must not be public outside the crate",
    );
    // And it must be gone from the shipped view, which is the same fact seen
    // from the other side.
    assert!(
        !shipped_code(&read("provider.rs")).contains("fn for_tests"),
        "for_tests must not appear in shipped code",
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

/// **The evasion that chained a private alias.**
///
/// `type Inner<C,T> = GovernedProviderClient<C,T>;` followed by
/// `pub type Escape = Inner<A,B>;` publishes the governed client without either
/// statement publicly naming it, and a sibling then builds a second client
/// through `provider::Escape`. The scan therefore collects private aliases too
/// and resolves the chain transitively, and it derives the dispatch surface from
/// `provider.rs`'s own imports rather than from a hand list that was missing two
/// of the identifiers the reviewer used.
#[test]
fn the_seam_publishes_no_route_to_the_governed_client() {
    let provider = shipped_code(&read("provider.rs"));
    assert!(
        !provider.contains("pub use lore_object_dispatch"),
        "provider.rs must not re-export the dispatch crate",
    );

    let dispatch = dispatch_identifiers(&provider);
    let aliases = type_aliases(&provider);
    assert!(
        !aliases.is_empty(),
        "the alias scan found nothing to scan, so it proves nothing",
    );
    let tainted = tainted_aliases(&aliases, &dispatch);
    let permitted: BTreeSet<&str> = PERMITTED_GOVERNED_ALIASES
        .iter()
        .map(|(name, _)| *name)
        .collect();
    for alias in &aliases {
        if !alias.public || !tainted.contains(&alias.name) {
            continue;
        }
        assert!(
            permitted.contains(alias.name.as_str()),
            "public alias {} reaches the dispatch surface and is not in \
             PERMITTED_GOVERNED_ALIASES; add it there with a reason or remove it",
            alias.name,
        );
    }
    // The allowlist must describe reality, or it is a stale exemption.
    for (name, _) in PERMITTED_GOVERNED_ALIASES {
        assert!(
            aliases.iter().any(|alias| alias.name == name),
            "PERMITTED_GOVERNED_ALIASES names {name}, which no longer exists",
        );
    }

    // A public function that hands back the governed client is the same escape
    // with a different spelling.
    for line in provider.lines().filter(|line| line.contains("pub fn ")) {
        assert!(
            !names_identifier(line, "GovernedProviderClient"),
            "a public function exposes the governed client: {line}",
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
    // attestation so the two cannot be re-paired after minting.
    assert!(
        !signature.contains("CellProviderBoundary"),
        "the boundary must come from the attestation, not from a second argument, got {signature}",
    );
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
/// boundary, and the builder that runs no checks is not public.
#[test]
fn the_seam_sources_its_target_only_from_its_own_boundary() {
    let provider = shipped_code(&read("provider.rs"));
    assert!(
        !provider.contains("pub fn build_request"),
        "build_request runs neither the class allowlist nor the ingress cap, \
         so it must not be public",
    );
    let builder = block_after(
        &provider,
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

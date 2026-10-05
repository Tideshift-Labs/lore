// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source pins for WP-115 row 80 idea 3: the hot Postgres statements run
//! through a per-connection prepared-statement cache, which is safe only
//! because every pooled connection runs `plan_cache_mode = force_custom_plan`.
//!
//! Nothing here needs a database. The live half (the setting on each pooled
//! connection, the generic-plan EXPLAIN gate, cache behaviour) is
//! `statement_cache_live.rs`.
//!
//! The inventory is read from the `*_cached(` call sites themselves
//! (`common/cached_sql.rs`), so a statement added to the cache later fails the
//! one-to-one pin check below until someone pins it and says which partial
//! index it depends on.

#[path = "common/cached_sql.rs"]
mod cached_sql;

use cached_sql::CachedSite;
use cached_sql::PINS;
use cached_sql::cached_sites;
use cached_sql::distinct_sites;
use cached_sql::normalize;
use cached_sql::pin_matches;

fn src(relative: &str) -> String {
    std::fs::read_to_string(format!("{}/src/{relative}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|error| panic!("read src/{relative}: {error}"))
}

/// Source with `//` comment lines removed, so a forbidden spelling quoted in
/// prose (the module docs explain `DISCARD ALL`) is not mistaken for code.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn function<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("function signature {signature}"));
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
    panic!("unterminated function {signature}");
}

fn describe(sites: &[CachedSite]) -> String {
    sites
        .iter()
        .map(|site| format!("  {}: {}", site.file, site.normalized()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_cached_statement_list_is_non_empty_and_every_text_is_unique() {
    let sites = cached_sites();
    assert!(
        !sites.is_empty(),
        "no `*_cached(` call site was found under src/; the extractor or the change is gone"
    );
    let mut seen = std::collections::BTreeMap::<String, &str>::new();
    for site in &sites {
        assert!(
            !site.sql.trim().is_empty(),
            "{}: an empty cached statement",
            site.file
        );
        // Identical text at two call sites is one cache entry, harmless for a
        // parameterless read such as the clock. A parameterised duplicate is
        // copy-paste drift waiting to happen: one site gets edited, one not.
        if let Some(first) = seen.insert(site.normalized(), site.file.as_str())
            && site.sql.contains('$')
        {
            panic!(
                "the same parameterised statement is cached from two call sites ({first} and {}): {}",
                site.file,
                site.normalized()
            );
        }
    }
}

#[test]
fn every_cached_statement_matches_exactly_one_pin_and_every_pin_matches_exactly_one_statement() {
    let sites = distinct_sites();
    for site in &sites {
        let matching: Vec<&str> = PINS
            .iter()
            .filter(|pin| pin_matches(pin, site))
            .map(|pin| pin.name)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "{} cached statement matches {matching:?}; add or tighten a pin in \
             tests/common/cached_sql.rs (and name its partial index, if any).\n{}",
            site.file,
            site.normalized()
        );
    }
    for pin in PINS {
        let matching: Vec<&CachedSite> = sites.iter().filter(|s| pin_matches(pin, s)).collect();
        assert_eq!(
            matching.len(),
            1,
            "pin {} must describe exactly one cached statement, found {}.\nStatements:\n{}",
            pin.name,
            matching.len(),
            describe(&sites)
        );
    }
}

/// Negatives first: a revert that re-spells the state list as a bound
/// parameter violates both the forbidden spellings and the literal pins, and
/// whichever assertion stands first aborts the test. Negatives first leaves
/// every one of them demonstrated on a probe that went red.
#[test]
fn a_cached_statement_with_a_partial_index_keeps_its_state_list_as_literals() {
    let sites = cached_sites();
    let mut checked = 0;
    for pin in PINS.iter().filter(|pin| !pin.indexes.is_empty()) {
        let site = sites
            .iter()
            .find(|site| pin_matches(pin, site))
            .unwrap_or_else(|| panic!("pin {} matches no cached statement", pin.name));
        let text = site.normalized();
        for spelling in pin.forbidden {
            assert!(
                !text.contains(spelling),
                "{}: the cached statement spells a state as a bound parameter ({spelling}); a \
                 generic plan cannot prove it implies the partial index predicate: {text}",
                pin.name
            );
        }
        for needle in pin.needles {
            assert!(
                text.contains(needle),
                "{}: missing {needle:?}: {text}",
                pin.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 1, "no pin names a partial index");
}

/// The pins above are only worth having if each half can fail alone. Probe the
/// real drain statement with three revert shapes, none of which touches source.
#[test]
fn the_literal_pins_and_the_forbidden_spellings_each_detect_a_bound_state_revert() {
    let pin = PINS
        .iter()
        .find(|pin| pin.name == "staged_drain_candidates_after")
        .expect("drain pin");
    let real = cached_sites()
        .into_iter()
        .find(|site| pin_matches(pin, site))
        .expect("drain statement");
    let forbidden_hit = |text: &str| pin.forbidden.iter().any(|spelling| text.contains(spelling));

    // Negatives first, on the unmodified statement.
    assert!(
        !forbidden_hit(&real.normalized()),
        "the real statement already spells a bound state"
    );

    // 1. Appending a bound spelling keeps every needle: only `forbidden` sees it.
    let appended = CachedSite {
        file: real.file.clone(),
        sql: format!("{} -- AND l.state = $9", real.sql),
    };
    assert!(pin_matches(pin, &appended), "the needles must still match");
    assert!(forbidden_hit(&appended.normalized()), "forbidden missed it");

    // 2. Re-spelling the barrier's state list loses a needle: only the literal
    //    pin sees it, and the forbidden spelling sees it too.
    let respelled = CachedSite {
        file: real.file.clone(),
        sql: real
            .sql
            .replace("active.state IN (0, 1, 3)", "active.state = ANY($3)"),
    };
    assert_ne!(respelled.sql, real.sql, "the probe must change the text");
    assert!(!pin_matches(pin, &respelled), "the literal pin missed it");
    assert!(
        forbidden_hit(&respelled.normalized()),
        "forbidden missed it"
    );

    // 3. Re-spelling the head state alone: a needle goes, no `ANY(`.
    let head = CachedSite {
        file: real.file.clone(),
        sql: real.sql.replace("l.state = 3", "l.state = $3"),
    };
    assert_ne!(head.sql, real.sql, "the probe must change the text");
    assert!(!pin_matches(pin, &head), "the literal pin missed it");
    assert!(forbidden_hit(&head.normalized()), "forbidden missed it");
}

#[test]
fn the_plan_cache_mode_constant_and_the_set_statement_agree() {
    let source = src("statement_cache.rs");
    assert!(
        source.contains("pub const PLAN_CACHE_MODE: &str = \"force_custom_plan\";"),
        "the mode every pooled connection must report changed"
    );
    assert!(
        source.contains(
            "const SET_PLAN_CACHE_MODE: &str = \"SET plan_cache_mode = force_custom_plan\";"
        ),
        "the SET statement no longer matches PLAN_CACHE_MODE"
    );
    // The SET is read back with SHOW, so a server that ignores it fails loudly.
    let apply = function(&source, "pub async fn apply_plan_cache_mode(");
    assert!(
        normalize(apply).contains("show_plan_cache_mode(client)") && apply.contains("return Err("),
        "apply_plan_cache_mode must read the setting back and fail on a mismatch"
    );
    assert!(
        source.contains("\"SHOW plan_cache_mode\""),
        "the read-back statement changed"
    );
}

#[test]
fn every_pool_the_cell_builds_applies_the_mode_on_creation_and_the_domain_store_verifies_it_first()
{
    let pool = src("pool.rs");
    let build = function(&pool, "pub fn build_pool_named(");
    assert!(
        build.contains(".post_create(")
            && build.contains("crate::statement_cache::apply_plan_cache_mode(client)"),
        "build_pool_named must set the mode in a post_create hook"
    );
    assert!(
        build.contains("RecyclingMethod::Fast"),
        "build_pool_named recycling changed; re-derive whether the session setting survives it"
    );
    let verify = function(&pool, "pub async fn verify_plan_cache_mode(");
    assert!(
        verify.contains("show_plan_cache_mode(") && verify.contains("PLAN_CACHE_MODE"),
        "verify_plan_cache_mode must compare the live setting to PLAN_CACHE_MODE"
    );

    let store = src("domain/store.rs");
    let connect = function(&store, "pub async fn connect_with_layout(");
    let verified = connect
        .find("verify_plan_cache_mode(&pool)")
        .expect("connect_with_layout must verify the plan cache mode");
    let first_schema = connect
        .find("ensure_schema_online(")
        .expect("connect_with_layout installs schema");
    assert!(
        verified < first_schema,
        "the mode is verified before any schema work or serving"
    );
    assert!(
        connect[verified..first_schema].contains('?'),
        "a failed verification must abort pool init with `?`, not be swallowed"
    );
}

/// A recycled connection must keep the setting. `RecyclingMethod::Clean` runs
/// `DISCARD ALL`, which resets it, and the hook runs only on creation, so the
/// loss would be silent. Nothing may reset it by hand either.
#[test]
fn nothing_in_the_crate_resets_session_state_that_would_drop_the_plan_cache_mode() {
    let mut files = Vec::new();
    collect(
        std::path::Path::new(&format!("{}/src", env!("CARGO_MANIFEST_DIR"))),
        &mut files,
    );
    assert!(files.len() > 10, "source walk found {} files", files.len());
    for path in files {
        let code = code_only(&std::fs::read_to_string(&path).expect("read source"));
        for forbidden in [
            "RecyclingMethod::Clean",
            "DISCARD ALL",
            "RESET ALL",
            "RESET plan_cache_mode",
            "plan_cache_mode = auto",
            "plan_cache_mode=auto",
            "force_generic_plan",
        ] {
            assert!(
                !code.contains(forbidden),
                "{} contains {forbidden:?}, which would drop or defeat the pinned plan cache mode",
                path.display()
            );
        }
    }
}

fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The observer pool is built apart from `build_pool_named` and does not run
/// the post-create hook. It is safe only while the observer never runs a
/// cached statement; this fails the day it does.
#[test]
fn the_stage_observer_never_runs_a_cached_statement() {
    let source = src("domain/fragments/coordinator.rs");
    let start = source
        .find("pub struct FragmentStageObserver")
        .expect("FragmentStageObserver");
    let end = source[start..]
        .find("pub fn fragment_stage_observer(")
        .expect("fragment_stage_observer constructor")
        + start;
    assert!(end > start && end - start < 20_000, "observer region moved");
    let region = &source[start..end];
    assert!(
        !region.contains("_cached("),
        "the stage observer runs on build_observer_pool, which does not apply the mode"
    );
}

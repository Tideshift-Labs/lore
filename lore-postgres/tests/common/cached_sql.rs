// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-level discovery of every statement the crate runs through the
//! `*_cached` methods of `statement_cache::CachedStatements`.
//!
//! The statements are literals at their call sites, so the call sites ARE the
//! inventory. Reading them from source (rather than keeping a second list in a
//! test) means a statement added later is seen by both the source pins and the
//! live EXPLAIN gate without anyone remembering to register it.
//!
//! Shared by `statement_cache_source_pins.rs` and `statement_cache_live.rs`,
//! each its own test binary, through `#[path]`.

use std::path::Path;
use std::path::PathBuf;

/// One `*_cached(` call site whose first argument is a string literal.
#[derive(Debug, Clone)]
pub struct CachedSite {
    /// The source file, relative to `lore-postgres/src`.
    pub file: String,
    /// The literal, unescaped exactly as rustc would: the bytes sent to the server.
    pub sql: String,
}

impl CachedSite {
    /// The statement with every run of whitespace collapsed, so a pin does not
    /// also pin `rustfmt`'s wrapping or a line continuation's indentation.
    pub fn normalized(&self) -> String {
        normalize(&self.sql)
    }
}

pub fn normalize(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A load-bearing fragment of one cached statement.
///
/// A statement is pinned when every needle is in its normalized text. Needles
/// are written in normalized form (single spaces). `indexes` names the partial
/// indexes the live EXPLAIN gate requires in the statement's GENERIC plan;
/// every statement must additionally avoid a `Seq Scan` on the lifecycle and
/// write-claims tables, whether or not it names an index.
#[allow(
    dead_code,
    reason = "each test binary reads a different subset of the pin"
)]
pub struct Pin {
    pub name: &'static str,
    pub needles: &'static [&'static str],
    /// Spellings that must NOT appear in the statement. A bound state
    /// parameter cannot reach a partial index under a generic plan (INV-FJ).
    pub forbidden: &'static [&'static str],
    pub indexes: &'static [&'static str],
}

pub const PINS: &[Pin] = &[
    Pin {
        name: "resolve_scoped",
        needles: &[
            "WITH requested AS ( SELECT request.hash, request.context, request.ordinality",
            "AND l.state = ANY($7)",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "database_clock",
        needles: &["=SELECT clock_timestamp()"],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "authorize_write_claim",
        needles: &[
            "UPDATE lore_fragment_write_claims SET state = $3, authorized_at = clock_timestamp() \
             WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $4",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "promotion_exact_source",
        needles: &[
            "SELECT 1 FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2 AND manifest_id = $3 AND object_key = $4",
            "FROM lore_fragment_stage_custody c WHERE c.hash=$1 AND c.epoch=$2",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "promotion_ownership_stamp",
        needles: &[
            "UPDATE lore_fragment_lifecycle SET last_fence = $2, active_operation = $3, updated_at = clock_timestamp() WHERE hash = $1",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "promotion_abandon_fence_stamp",
        needles: &[
            "UPDATE lore_fragment_lifecycle SET last_fence = $2, active_operation = NULL, updated_at = clock_timestamp() WHERE hash = $1",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "staged_drain_candidates_after",
        needles: &[
            "FROM lore_fragment_lifecycle AS l JOIN lore_fragment_epochs AS e",
            "WHERE l.state = 3 AND (l.active_operation IS NULL OR l.active_operation = decode('77703131352d70726f6d6f74652d7631','hex'))",
            "AND l.hash > $2",
            "active.state IN (0, 1, 3)",
            "ORDER BY l.hash LIMIT $1",
        ],
        forbidden: &["ANY($", "state = $", "state=$", "state IN ($"],
        indexes: &[
            "lore_fragment_stage_drain_recovery",
            "lore_fragment_write_claims_barrier",
        ],
    },
    Pin {
        name: "stage_preparation_owner",
        needles: &[
            "SELECT 1 FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2 AND state=0 AND prepare_deadline>clock_timestamp()",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "first_publication_intent_insert",
        needles: &[
            "INSERT INTO lore_fragment_lifecycle ( hash, current_epoch, state, manifest_id, last_fence, active_operation ) VALUES ($1, $2, $3, NULL, $4, $5) ON CONFLICT (hash) DO NOTHING",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "publication_intent_upsert",
        needles: &[
            "INSERT INTO lore_fragment_lifecycle ( hash, current_epoch, state, manifest_id, last_fence, active_operation ) VALUES ($1, $2, $3, NULL, $4, $5) ON CONFLICT (hash) DO UPDATE SET current_epoch = EXCLUDED.current_epoch",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "publication_epoch_insert",
        needles: &[
            "INSERT INTO lore_fragment_epochs ( hash, epoch, authority, object_key, manifest_id",
            "ON CONFLICT (hash, epoch) DO NOTHING",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "publication_predecessor_quarantine",
        needles: &[
            "UPDATE lore_fragment_epochs SET disposition = $3 WHERE hash = $1 AND epoch < $2 AND disposition = $4",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "publication_head_update",
        needles: &[
            "UPDATE lore_fragment_lifecycle SET current_epoch = $2, state = $3, manifest_id = $4, last_fence = $5, active_operation = NULL, diagnostic_class = 0, updated_at = clock_timestamp() WHERE hash = $1",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "publication_metering_upsert",
        needles: &[
            "INSERT INTO lore_fragment_lifecycle_metering ( hash, epoch, payload_flags, size_payload, size_content, authority ) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (hash) DO UPDATE",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "stage_custody_reserve",
        needles: &[
            "INSERT INTO lore_fragment_stage_custody (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes) SELECT $1,$2,$3,$4,$5,",
            "FROM lore_fragment_stage_policy WHERE singleton AND expires_at > clock_timestamp()",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "stage_capacity_reserve",
        needles: &["UPDATE lore_fragment_stage_usage AS u SET live_bytes=u.live_bytes+$1"],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "stage_custody_publication",
        needles: &[
            "UPDATE lore_fragment_stage_custody SET state=1 WHERE hash=$1 AND epoch=$2 AND operation_fence=$3 AND state=0",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "claim_creation_insert",
        needles: &[
            "WITH claim_clock AS (SELECT clock_timestamp() AS now) INSERT INTO lore_fragment_write_claims (",
            "RETURNING send_not_after, hard_not_after",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "head_lock_for_update",
        needles: &[
            "=SELECT current_epoch, state, manifest_id, last_fence, active_operation FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "write_claim_barrier_lock",
        needles: &[
            "SELECT state, send_not_after, hard_not_after FROM lore_fragment_write_claims WHERE hash = $1 AND state IN (0, 1, 3) AND hard_not_after > $5",
            "FOR UPDATE",
        ],
        forbidden: &["ANY($", "state = $", "state=$", "state IN ($"],
        indexes: &["lore_fragment_write_claims_barrier"],
    },
    Pin {
        name: "write_claim_by_identity_lock",
        needles: &[
            "hard_not_after > clock_timestamp() AS unexpired FROM lore_fragment_write_claims WHERE logical_request_id = $1 AND attempt_id = $2 FOR UPDATE",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "write_claim_settle",
        needles: &[
            "UPDATE lore_fragment_write_claims SET state = $3, settled_at = clock_timestamp() WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $4",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "fence_allocation",
        needles: &["=SELECT nextval('lore_fragment_fence_seq')::bigint"],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "lifecycle_fanout_plan",
        needles: &[
            "=SELECT repository_id FROM lore_fragment_associations WHERE hash = $1 AND state = $2 ORDER BY repository_id",
        ],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "repository_row_lock",
        needles: &["=SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE"],
        forbidden: &[],
        indexes: &[],
    },
    Pin {
        name: "repository_generation_bump",
        needles: &[
            "UPDATE lore_domain_repositories SET fragment_lifecycle_generation = fragment_lifecycle_generation + 1 WHERE repository_id = ANY($1) RETURNING",
        ],
        forbidden: &[],
        indexes: &[],
    },
];

/// Whether `pin` describes `site`. A needle starting with `=` must equal the
/// whole normalized statement; any other needle must be contained in it.
pub fn pin_matches(pin: &Pin, site: &CachedSite) -> bool {
    let text = site.normalized();
    pin.needles
        .iter()
        .all(|needle| match needle.strip_prefix('=') {
            Some(whole) => text == whole,
            None => text.contains(needle),
        })
}

/// One site per distinct statement text, first occurrence kept. A parameterless
/// read (the clock) may legitimately appear at several call sites; those share
/// one cache entry.
pub fn distinct_sites() -> Vec<CachedSite> {
    let mut seen = std::collections::BTreeSet::new();
    cached_sites()
        .into_iter()
        .filter(|site| seen.insert(site.normalized()))
        .collect()
}

const METHODS: [&str; 4] = ["query", "query_one", "query_opt", "execute"];

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            source_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every `.query_cached(`, `.query_one_cached(`, `.query_opt_cached(` and
/// `.execute_cached(` call under `src/`, outside `statement_cache.rs` itself
/// (which defines them). A call whose first argument is not a string literal
/// panics: a constant or a variable there would hide the statement from every
/// gate that reads this list, so a person must decide how to pin it.
pub fn cached_sites() -> Vec<CachedSite> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&src, &mut files);
    files.sort();
    let mut sites = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "statement_cache.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source file");
        let mut from = 0;
        while let Some(found) = text[from..].find("_cached(") {
            let call = from + found;
            from = call + "_cached(".len();
            let before = &text[..call];
            let Some(method) = METHODS.iter().find(|method| before.ends_with(**method)) else {
                continue;
            };
            let name_start = call - method.len();
            if !text[..name_start].ends_with('.')
                && !text[..name_start].ends_with(char::is_whitespace)
            {
                continue;
            }
            let rest = text[from..].trim_start();
            assert!(
                rest.starts_with('"'),
                "{relative}: `{method}_cached(` at byte {call} is not given a string literal; \
                 the cached-statement gates read literals from source. Next text: {:?}",
                &rest[..rest.len().min(60)]
            );
            sites.push(CachedSite {
                file: relative.clone(),
                sql: unescape_literal(&rest[1..], &relative),
            });
        }
    }
    sites
}

/// Read a Rust string literal body up to its closing quote.
fn unescape_literal(body: &str, file: &str) -> String {
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => return out,
            '\\' => match chars.next() {
                Some('\n' | '\r') => {
                    while chars.peek().is_some_and(|next| next.is_whitespace()) {
                        chars.next();
                    }
                }
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\'') => out.push('\''),
                other => panic!("{file}: unsupported escape \\{other:?} in a cached statement"),
            },
            _ => out.push(c),
        }
    }
    panic!("{file}: unterminated string literal in a cached statement");
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The environment gate, and the NOT-RUN discipline WP-109 requires of it.
//!
//! # Why this panics instead of returning
//!
//! A live case that returns early when its environment is unset is counted
//! `passed` by Rust's harness, and WP-109 Phase 2 is explicit that a
//! setup-skipped body is **NOT RUN**, never passing evidence. Every accessor
//! here therefore panics, and every panic message starts with
//! [`NOT_RUN_MARKER`] so `run-active-active-shared-backend-live.ps1` can tell
//! "this environment was absent" (NOT RUN) from "this race failed" (FAIL)
//! without guessing from an exit code.
//!
//! This mirrors `domain_obliterate_fence.rs` and `domain_lock_fencing.rs`,
//! which already panic on an unset `LORE_TEST_PG_URL`, and deliberately does
//! **not** mirror `domain_outbox_producers.rs`, which returns.

#![allow(dead_code)]

use std::path::PathBuf;

/// Prefix on every panic this module raises. The runner greps for it.
///
/// It has to be a *panic* rather than an ordinary log line: a log line on a
/// case that returned still leaves the harness reporting `1 passed`.
pub const NOT_RUN_MARKER: &str = "WP109-NOT-RUN:";

/// Postgres reachable by both coordinator sets. One database per case; the
/// runner creates and drops it.
pub const PG_URL_VAR: &str = "LORE_TEST_PG_URL";
/// S3-compatible endpoint (MinIO locally).
pub const S3_ENDPOINT_VAR: &str = "LORE_TEST_S3_ENDPOINT";
/// Region handed to the SDK. Optional; MinIO ignores it.
pub const S3_REGION_VAR: &str = "LORE_TEST_S3_REGION";
/// Access key. Read by the AWS SDK itself, checked here so a missing
/// credential is NOT RUN rather than an opaque SDK error mid-race.
pub const S3_ACCESS_KEY_VAR: &str = "AWS_ACCESS_KEY_ID";
/// Secret key, same reasoning.
pub const S3_SECRET_KEY_VAR: &str = "AWS_SECRET_ACCESS_KEY";
/// The failpoint rendezvous directory (`domain/fragments/failpoints.rs`).
pub const FAILPOINT_DIR_VAR: &str = "LORE_FRAGMENT_FAILPOINT_DIR";
/// The failpoint specification itself.
pub const FAILPOINT_SPEC_VAR: &str = "LORE_FRAGMENT_FAILPOINTS";
/// Optional identity seed, so a failing race replays with the same identities.
pub const SEED_VAR: &str = "LORE_TEST_SEED";

fn not_run(message: &str) -> ! {
    panic!("{NOT_RUN_MARKER} {message}");
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => not_run(&format!(
            "{name} is unset; this case needs the shared backend and cannot be counted as a pass"
        )),
    }
}

/// The Postgres half. Every case needs it.
pub fn pg_url() -> String {
    required(PG_URL_VAR)
}

/// The object-store half, for the cases that put real bytes in a real bucket.
#[derive(Debug, Clone)]
pub struct ObjectStoreEnv {
    /// S3 endpoint URL.
    pub endpoint: String,
    /// Region string handed to the SDK.
    pub region: String,
}

/// Require a reachable S3-compatible endpoint and credentials.
///
/// Deliberately does **not** require `LORE_TEST_S3_BUCKET`: this harness mints
/// one bucket per case (see [`super::bucket`]), which is the "unique bucket"
/// arm of WP-109's namespace rule, so a shared pre-created bucket name would be
/// unused and its absence must not gate a case.
pub fn object_store() -> ObjectStoreEnv {
    let endpoint = required(S3_ENDPOINT_VAR);
    let _ = required(S3_ACCESS_KEY_VAR);
    let _ = required(S3_SECRET_KEY_VAR);
    let region = std::env::var(S3_REGION_VAR)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "us-east-1".to_owned());
    ObjectStoreEnv { endpoint, region }
}

/// Require the process to have been started with exactly the failpoint
/// configuration this case drives.
///
/// `domain/fragments/failpoints.rs` reads `LORE_FRAGMENT_FAILPOINTS` **once**,
/// through a `LazyLock`, so a case cannot arm its own anchors: the runner must
/// have set them before the process started. Checking the exact spec here is
/// what stops a case from silently degrading into "no failpoint" and passing on
/// a race that never had a barrier.
///
/// Returns the rendezvous directory, creating it if the runner named one that
/// does not exist yet.
pub fn failpoints(expected_spec: &str) -> PathBuf {
    let spec = required(FAILPOINT_SPEC_VAR);
    if spec.trim() != expected_spec {
        not_run(&format!(
            "{FAILPOINT_SPEC_VAR} is {spec:?} but this case needs exactly {expected_spec:?}; \
             the anchor configuration is read once per process and cannot be set from here"
        ));
    }
    let dir = PathBuf::from(required(FAILPOINT_DIR_VAR));
    if let Err(error) = std::fs::create_dir_all(&dir) {
        not_run(&format!(
            "{FAILPOINT_DIR_VAR}={} could not be created: {error}",
            dir.display()
        ));
    }
    dir
}

/// This run's identity seed.
///
/// Every repository id, branch id, name, content hash, and cell id in a case is
/// derived from it, so a failed race is replayable byte-for-byte by re-running
/// with the same `LORE_TEST_SEED`. It is **not** a scheduling seed: nothing here
/// controls thread interleaving, and claiming otherwise would be a lie about
/// what a rerun reproduces.
pub fn seed() -> u64 {
    match std::env::var(SEED_VAR) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u64>().unwrap_or_else(|_| {
            not_run(&format!(
                "{SEED_VAR}={value:?} is not a u64; refusing to run with an unrecorded seed"
            ))
        }),
        _ => rand::random::<u64>(),
    }
}

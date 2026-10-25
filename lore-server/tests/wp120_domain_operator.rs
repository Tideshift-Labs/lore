// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-120 domain operator entry point: `loreserver domain status|cutover`.
//!
//! Covers, offline (no infra, part of a plain `cargo test -p lore-server`):
//!
//! - CLI argument parsing through [`lore_server::server::Cli`] (`domain
//!   status`, `domain cutover` and its four flags, and that `loreserver` with
//!   no arguments still parses with `command == None` — the serving path must
//!   stay unchanged).
//! - [`lore_server::domain::operator::run`] refusing a non-Postgres cell, and
//!   the order `Cutover` checks its preconditions in.
//! - [`lore_server::domain::lock_fencing_settings_preconditions`].
//!
//! `parse_legacy_lock_issuers` and the backfill fingerprint are deliberately
//! NOT covered here — `operator.rs`'s own inline `mod tests` already owns
//! them; see the note above section 2 below.
//!
//! Live, `#[ignore]`-gated (`cargo test -p lore-server -- --ignored`), each
//! case its own disposable database on the server named by `LORE_TEST_PG_URL`
//! — **never** point that at `postgres-cell-a` or the `lorehub` control-plane
//! database. `LORE_TEST_S3_ENDPOINT` / `LORE_TEST_S3_BUCKET` (+ optional
//! `LORE_TEST_S3_REGION`) gate the cases that need a real immutable store,
//! following `lore-postgres/tests/immutable_store.rs`'s convention. A case
//! whose gate variable is unset prints a notice and returns — under `#[ignore]`
//! that is an operator opting into a live tier without configuring it, not a
//! disguised skip: the default `cargo test` run already reports these as
//! `ignored`, never as `passed`.
//!
//! No container is started, stopped, or recreated here.

use clap::Parser;
use lore_server::domain::backfill_source::CellBackfillSource;
use lore_server::domain::lock_fencing_settings_preconditions;
use lore_server::domain::operator::DomainCommand;
use lore_server::domain::operator::run;
use lore_server::server::Cli;
use lore_server::settings::AuthSettings;
use lore_server::settings::LockStoreSettings;
use lore_server::settings::Settings;

// ─── 1. CLI argument parsing ───────────────────────────────────────────────
//
// The exact shape of the new `MaintenanceCommand::Domain` variant (tuple vs.
// struct-with-named-field, matching the existing `Outbox { command }`
// precedent or not) is an implementation choice this contract doesn't fix.
// Asserting against `format!("{:?}", cli.command)` proves every flag parsed
// to the right value without depending on that shape, since `MaintenanceCommand`
// and `DomainCommand` both derive `Debug`.

fn parsed_command_debug(args: &[&str]) -> String {
    let cli = Cli::try_parse_from(args)
        .unwrap_or_else(|error| panic!("expected {args:?} to parse: {error}"));
    format!("{:?}", cli.command)
}

#[test]
fn bare_invocation_still_parses_with_no_maintenance_command() {
    let cli = Cli::try_parse_from(["loreserver"]).expect("bare invocation must parse");
    assert!(
        cli.command.is_none(),
        "adding `domain` must not change the no-argument serving path"
    );
}

#[test]
fn domain_status_parses() {
    let debug = parsed_command_debug(&["loreserver", "domain", "status"]);
    assert!(debug.contains("Status"), "debug: {debug}");
    assert!(debug.contains("json: false"), "debug: {debug}");
}

#[test]
fn domain_status_json_parses() {
    let debug = parsed_command_debug(&["loreserver", "domain", "status", "--json"]);
    assert!(debug.contains("Status"), "debug: {debug}");
    assert!(debug.contains("json: true"), "debug: {debug}");
}

#[test]
fn domain_cutover_defaults_parse() {
    let debug = parsed_command_debug(&["loreserver", "domain", "cutover"]);
    assert!(debug.contains("Cutover"), "debug: {debug}");
    assert!(debug.contains("dry_run: false"), "debug: {debug}");
    assert!(
        debug.contains("force_release_legacy_locks: false"),
        "debug: {debug}"
    );
    assert!(debug.contains("json: false"), "debug: {debug}");
}

#[test]
fn domain_cutover_dry_run_parses() {
    let debug = parsed_command_debug(&["loreserver", "domain", "cutover", "--dry-run"]);
    assert!(debug.contains("dry_run: true"), "debug: {debug}");
}

#[test]
fn domain_cutover_force_release_legacy_locks_parses() {
    let debug = parsed_command_debug(&[
        "loreserver",
        "domain",
        "cutover",
        "--force-release-legacy-locks",
    ]);
    assert!(
        debug.contains("force_release_legacy_locks: true"),
        "debug: {debug}"
    );
}

#[test]
fn domain_cutover_json_parses() {
    let debug = parsed_command_debug(&["loreserver", "domain", "cutover", "--json"]);
    assert!(debug.contains("json: true"), "debug: {debug}");
}

#[test]
fn domain_cutover_collects_repeated_legacy_lock_issuer_values() {
    let debug = parsed_command_debug(&[
        "loreserver",
        "domain",
        "cutover",
        "--legacy-lock-issuer",
        "a=b",
        "--legacy-lock-issuer",
        "c=d",
    ]);
    assert!(
        debug.contains(r#"["a=b", "c=d"]"#),
        "expected both repeated values collected in order, debug: {debug}"
    );
}

// ─── 2. `run` refuses a non-Postgres cell ──────────────────────────────────
//
// `parse_legacy_lock_issuers` and the backfill fingerprint
// (`BACKFILL_FINGERPRINT_VERSION`, `backfill_repository_fingerprint`,
// `backfill_branch_fingerprint`) are deliberately NOT re-tested here:
// `operator.rs`'s own inline `mod tests` already pins the first-`=` split,
// the three malformed shapes, the one-subject-two-issuers refusal (plus the
// identical-repeat non-conflict), per-component sensitivity, the
// length-prefix boundary-shift measurement, domain separation between the
// repository and branch fingerprints, and version ≠ 1. Duplicating that here
// would just be two copies to keep in sync.

fn cutover_defaults() -> DomainCommand {
    DomainCommand::Cutover {
        dry_run: false,
        force_release_legacy_locks: false,
        legacy_lock_issuer: Vec::new(),
        json: false,
    }
}

#[tokio::test]
async fn run_status_refuses_a_non_postgres_cell() {
    let (settings, _hash) = Settings::load(None, None).expect("built-in defaults must load");
    assert_eq!(
        settings.mutable_store.mode, "local",
        "fixture default must stay non-Postgres to prove the guard"
    );

    let error = run(&DomainCommand::Status { json: false }, &settings)
        .await
        .expect_err("a non-Postgres cell must refuse `domain status`");
    let message = error.to_string();
    assert!(
        message.contains("mutable_store.mode = postgres"),
        "message must name the requirement: {message}"
    );
    assert!(
        message.contains("'local'"),
        "message must name the effective mode 'local': {message}"
    );
}

/// `Cutover` calls [`lock_fencing_settings_preconditions`] BEFORE opening any
/// connection (see the next test for that ordering itself), so a bare
/// default `Settings` would trip the fencing precondition first rather than
/// this test's target. Give the settings a complete auth + postgres
/// lock-store block so the postgres-mode refusal is actually what's reached.
#[tokio::test]
async fn run_cutover_refuses_a_non_postgres_cell_once_fencing_preconditions_are_satisfied() {
    let (mut settings, _hash) = Settings::load(None, None).expect("built-in defaults must load");
    settings.server.auth = Some(valid_auth_settings());
    settings.lock_store = Some(LockStoreSettings {
        mode: "postgres".to_string(),
    });
    assert_eq!(
        settings.mutable_store.mode, "local",
        "fixture default must stay non-Postgres to prove the guard"
    );

    let error = run(&cutover_defaults(), &settings)
        .await
        .expect_err("a non-Postgres cell must refuse `domain cutover`");
    let message = error.to_string();
    assert!(
        message.contains("mutable_store.mode = postgres"),
        "message must name the requirement: {message}"
    );
    assert!(
        message.contains("'local'"),
        "message must name the effective mode 'local': {message}"
    );
}

/// The ordering claim itself: on a bare-default cell (no `[server.auth]` at
/// all, so `mutable_store.mode` is ALSO not postgres), `cutover` must refuse
/// via the fencing precondition, not the postgres-mode check — proving
/// `run` checks `lock_fencing_settings_preconditions` first, before it opens
/// any connection.
#[tokio::test]
async fn run_cutover_checks_lock_fencing_preconditions_before_opening_any_connection() {
    let (settings, _hash) = Settings::load(None, None).expect("built-in defaults must load");
    assert!(settings.server.auth.is_none(), "fixture must have no auth");
    assert_eq!(settings.mutable_store.mode, "local");

    let error = run(&cutover_defaults(), &settings)
        .await
        .expect_err("cutover on a bare-default cell must refuse");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("auth"),
        "cutover must trip the fencing precondition before the postgres-mode check: {message}"
    );
    assert!(
        !message.contains("mutable_store.mode"),
        "the postgres-mode refusal must not be reached: {message}"
    );
}

// ─── 3. `lock_fencing_settings_preconditions` ──────────────────────────────

fn valid_auth_settings() -> AuthSettings {
    // Upstream v0.10.0 makes jwt_issuer/jwt_audience mandatory; resource_claim keeps the fork's
    // GlobalGrants refusal out of the way. enforce_write_permission defaults to true.
    let mut auth: AuthSettings = toml::from_str(
        "jwt_issuer = 'https://issuer.invalid'\njwt_audience = ['lore']\nresource_claim = 'resources'",
    )
    .expect("auth fixture must parse");
    auth.jwk = Some(lore_server::auth::jwk::JWKServiceSettings {
        endpoint: Some("https://issuer.invalid/jwks".into()),
    });
    assert!(auth.enforce_write_permission);
    auth
}

fn settings_with_valid_lock_fencing_preconditions() -> Settings {
    let (mut settings, _hash) = Settings::load(None, None).expect("built-in defaults must load");
    settings.server.auth = Some(valid_auth_settings());
    settings.lock_store = Some(LockStoreSettings {
        mode: "postgres".to_string(),
    });
    settings
}

#[test]
fn lock_fencing_settings_preconditions_accepts_a_fully_configured_cell() {
    let settings = settings_with_valid_lock_fencing_preconditions();
    lock_fencing_settings_preconditions(&settings)
        .expect("a fully configured cell's settings must be accepted");
}

/// Each refusal below asserts a keyword unique to its OWN offending
/// condition, not just that the call returned `Err`. This is what makes the
/// assertion measure the guard: a transposed check (e.g. reporting the
/// `enforce_write_permission` condition while jwk is what's actually missing)
/// would produce a message containing a DIFFERENT keyword and fail here, even
/// though it would still pass a bare `is_err()` check.
#[test]
fn lock_fencing_settings_preconditions_refuses_absent_auth_section() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings.server.auth = None;
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("an absent [server.auth] section must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("auth"),
        "message must name the missing auth configuration: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_absent_jwk() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings
        .server
        .auth
        .as_mut()
        .expect("fixture must carry auth")
        .jwk = None;
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("an absent jwk verifier must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("jwk"),
        "message must name the missing JWK verifier: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_absent_jwt_issuer() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings
        .server
        .auth
        .as_mut()
        .expect("fixture must carry auth")
        .jwt_issuer = Vec::new();
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("an absent jwt_issuer must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("issuer"),
        "message must name the missing JWT issuer policy: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_empty_jwt_issuer() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings
        .server
        .auth
        .as_mut()
        .expect("fixture must carry auth")
        .jwt_issuer = vec![String::new()];
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("an empty jwt_issuer must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("issuer"),
        "message must name the missing JWT issuer policy: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_enforce_write_permission_false() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings
        .server
        .auth
        .as_mut()
        .expect("fixture must carry auth")
        .enforce_write_permission = false;
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("enforce_write_permission = false must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("enforce_write_permission"),
        "message must name the disabled write-permission enforcement: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_non_postgres_lock_store() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings.lock_store = Some(LockStoreSettings {
        mode: "local".to_string(),
    });
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("a non-Postgres lock store must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("postgres") || message.contains("lock store"),
        "message must name the lock store condition: {message}"
    );
}

#[test]
fn lock_fencing_settings_preconditions_refuses_absent_lock_store() {
    let mut settings = settings_with_valid_lock_fencing_preconditions();
    settings.lock_store = None;
    let error = lock_fencing_settings_preconditions(&settings)
        .expect_err("an absent lock store must be refused");
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("postgres") || message.contains("lock store"),
        "message must name the lock store condition: {message}"
    );
}

// ─── 4. Live: a disposable Postgres (+ S3) cell ────────────────────────────
//
// Every case below builds its OWN fresh database on the server named by
// `LORE_TEST_PG_URL` and drops it when done, following
// `lore-postgres/tests/domain_backfill.rs`'s established pattern. `cutover`
// arms both CR-029 domain enforcement AND CR-030 lock fencing together, and
// opens a real `ImmutableStore` to build `CellBackfillSource` — confirmed by
// the landed `operator.rs` (`status` needs no immutable store; `cutover`
// does), so every case here also gates on the S3 env
// `lore-postgres/tests/immutable_store.rs` uses.
//
// Independent verification reads go through `lore-postgres`'s own typed store
// API (`PostgresDomainStore::schema_state`,
// `PostgresLockCoordinator::readiness`) against a second connection to the
// SAME database, rather than parsing anything `run` prints — that satisfies
// "assert against the database rows" more robustly than hand-written SQL,
// since it can't drift from what the column names actually mean.

mod live {
    use std::sync::Arc;

    use lore_base::types::KeyType;
    use lore_base::types::RepositoryId;
    use lore_postgres::domain::DomainSchemaState;
    use lore_postgres::domain::PostgresDomainStore;
    use lore_postgres::domain::backfill::DomainBackfillSource;
    use lore_postgres::domain::errors::DomainError;
    use lore_postgres::domain::fragments::FragmentLifecycleState;
    use lore_postgres::domain::locks::LockFencingReadiness;
    use lore_postgres::domain::schema as domain_schema;
    use lore_postgres::pool::TlsConfig;
    use lore_postgres::pool::build_pool;
    use lore_postgres::store::immutable_store::ObjectStoreSettings;
    use lore_postgres::store::immutable_store::PostgresImmutableStore;
    use lore_postgres::store::lock_store::PostgresLockStore;
    use lore_postgres::store::mutable_store::PostgresMutableStore;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_server::domain::operator::BackfillFailure;
    use lore_server::domain::operator::CutoverRefusal;
    use lore_storage::Hash;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_storage::Partition;
    use tokio_postgres::NoTls;

    use super::CellBackfillSource;
    use super::DomainCommand;
    use super::Settings;
    use super::cutover_defaults;
    use super::run;
    use super::valid_auth_settings;

    struct S3Env {
        endpoint: String,
        bucket: String,
        region: String,
    }

    fn pg_admin_url() -> Option<String> {
        std::env::var("LORE_TEST_PG_URL").ok()
    }

    fn s3_env() -> Option<S3Env> {
        let endpoint = std::env::var("LORE_TEST_S3_ENDPOINT").ok()?;
        let bucket = std::env::var("LORE_TEST_S3_BUCKET").ok()?;
        let region =
            std::env::var("LORE_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        Some(S3Env {
            endpoint,
            bucket,
            region,
        })
    }

    /// `None` when either gate is unset, with a notice naming which one.
    /// Every live test funnels through this so the "opted in but not
    /// configured" notice is worded once.
    fn live_env(case: &str) -> Option<(String, S3Env)> {
        let Some(admin_url) = pg_admin_url() else {
            eprintln!("[{case}] LORE_TEST_PG_URL unset; live test cannot run");
            return None;
        };
        let Some(s3) = s3_env() else {
            eprintln!(
                "[{case}] LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET unset; live test cannot run"
            );
            return None;
        };
        Some((admin_url, s3))
    }

    async fn pg_client(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, NoTls)
            .await
            .expect("connect for direct test setup");
        lore_base::lore_spawn!(async move {
            if let Err(error) = connection.await {
                eprintln!("direct postgres connection error: {error}");
            }
        });
        client
    }

    fn replace_dbname(url: &str, db_name: &str) -> String {
        let (base, query) = match url.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (url, None),
        };
        let last_slash = base
            .rfind('/')
            .expect("postgres URL must have a /dbname path");
        let mut new_url = format!("{}/{}", &base[..last_slash], db_name);
        if let Some(q) = query {
            new_url.push('?');
            new_url.push_str(q);
        }
        new_url
    }

    async fn create_throwaway_database(admin_url: &str, label: &str) -> (String, String) {
        let client = pg_client(admin_url).await;
        let suffix: u64 = rand::random();
        let db_name = format!("lore_wp120_operator_{label}_{suffix:016x}");
        client
            .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
            .await
            .expect("create throwaway database");
        (db_name.clone(), replace_dbname(admin_url, &db_name))
    }

    async fn drop_throwaway_database(admin_url: &str, db_name: &str) {
        let client = pg_client(admin_url).await;
        let _ = client
            .execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[&db_name],
            )
            .await;
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
            .await
            .expect("drop throwaway database");
    }

    /// A cell configured to fully arm on `cutover`: Postgres immutable,
    /// mutable, and lock stores all pointed at `url`, plus the auth settings
    /// `lock_fencing_settings_preconditions` requires.
    fn armed_settings(url: &str, s3: &S3Env) -> Settings {
        let mut settings: Settings = toml::from_str(include_str!("../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        settings.immutable_store.mode = "postgres".to_string();
        settings.mutable_store.mode = "postgres".to_string();
        settings.lock_store = Some(super::LockStoreSettings {
            mode: "postgres".to_string(),
        });
        settings.server.auth = Some(valid_auth_settings());
        let plugin_toml = format!(
            "url = {url:?}\npool_max = 4\ndomain_pool_max = 4\n\n[object_store]\n\
             bucket = {bucket:?}\nendpoint_url = {endpoint:?}\nregion = {region:?}\n\
             force_path_style = true\n",
            url = url,
            bucket = s3.bucket,
            endpoint = s3.endpoint,
            region = s3.region,
        );
        settings.plugins.insert(
            "postgres".to_string(),
            toml::from_str(&plugin_toml).expect("postgres plugin fixture config must parse"),
        );
        settings
    }

    async fn independent_domain_state(url: &str) -> DomainSchemaState {
        let store = PostgresDomainStore::connect(url, 2, &TlsConfig::default())
            .await
            .expect("independent verification connection must bootstrap");
        store
            .schema_state()
            .await
            .expect("read domain schema state")
    }

    async fn independent_lock_readiness(url: &str) -> LockFencingReadiness {
        let store = PostgresDomainStore::connect(url, 2, &TlsConfig::default())
            .await
            .expect("independent verification connection must bootstrap");
        store
            .lock_coordinator()
            .readiness()
            .await
            .expect("read lock fencing readiness")
    }

    // ── 6. cutover arms an empty disposable cell end to end ──────────────

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_arms_an_empty_disposable_cell_end_to_end() {
        let Some((admin_url, s3)) = live_env("cutover_arms_an_empty_disposable_cell_end_to_end")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "cutover_e2e").await;
        let settings = armed_settings(&db_url, &s3);

        let outcome = run(&cutover_defaults(), &settings).await;
        // Independent verification runs even on an `Err`, so a partial-arming
        // defect is not hidden by an early return before cleanup.
        let domain_state = independent_domain_state(&db_url).await;
        let lock_readiness = independent_lock_readiness(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        outcome.expect("cutover of an empty disposable cell must succeed");
        assert_eq!(domain_state.backfill_state, domain_schema::BACKFILL_CUTOVER);
        assert!(domain_state.residue_classified);
        assert!(domain_state.cutover_at.is_some());
        assert!(domain_state.enforcement_enabled);
        assert!(lock_readiness.fencing_enabled);
        assert!(!lock_readiness.lease_enabled);
    }

    // ── 7. cutover is idempotent / restartable ────────────────────────────

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_run_twice_is_idempotent() {
        let Some((admin_url, s3)) = live_env("cutover_run_twice_is_idempotent") else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "cutover_twice").await;
        let settings = armed_settings(&db_url, &s3);

        run(&cutover_defaults(), &settings)
            .await
            .expect("first cutover must succeed");
        let first = independent_domain_state(&db_url).await;

        let second_outcome = run(&cutover_defaults(), &settings).await;
        let second = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        second_outcome.expect("a second cutover on an already-armed cell must succeed");
        assert_eq!(
            first, second,
            "a restart cutover against an already-armed cell must change nothing"
        );
    }

    // ── 8. --dry-run changes no row ───────────────────────────────────────

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn dry_run_cutover_changes_no_row_on_a_fresh_database() {
        let Some((admin_url, s3)) = live_env("dry_run_cutover_changes_no_row_on_a_fresh_database")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "dry_run").await;
        let settings = armed_settings(&db_url, &s3);

        let before = independent_domain_state(&db_url).await;
        let outcome = run(
            &DomainCommand::Cutover {
                dry_run: true,
                force_release_legacy_locks: false,
                legacy_lock_issuer: Vec::new(),
                json: false,
            },
            &settings,
        )
        .await;
        let after = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        outcome.expect("a --dry-run must not itself fail");
        assert_eq!(
            before.backfill_state,
            domain_schema::BACKFILL_NOT_STARTED,
            "fixture must start from an unbackfilled cell to prove the guard"
        );
        assert_eq!(
            after.backfill_state, before.backfill_state,
            "--dry-run must not advance backfill_state"
        );
        assert_eq!(
            after.enforcement_enabled, before.enforcement_enabled,
            "--dry-run must not enable enforcement"
        );
        assert!(!after.enforcement_enabled);
    }

    // ── 9. a legacy (owner_issuer IS NULL) lock blocks cutover ───────────

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_legacy_lock_without_force_and_completes_with_it() {
        let Some((admin_url, s3)) =
            live_env("cutover_refuses_a_legacy_lock_without_force_and_completes_with_it")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "legacy_lock").await;

        // Seed the pre-SCHEMA-117 legacy lock schema and one subject-only row
        // (no `owner_issuer`, matching a lock acquired before fencing ever
        // ran). `PostgresLockStore::connect` bootstraps the legacy CR-007
        // table; SCHEMA-117's own migration later adds `owner_issuer` as a
        // nullable column, so this seeded row lands with it NULL.
        let legacy_store = PostgresLockStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the legacy CR-007 lock schema");
        drop(legacy_store);
        let seed_client = pg_client(&db_url).await;
        let repository: Vec<u8> = vec![1u8; 16];
        let branch: Vec<u8> = vec![2u8; 16];
        let hash: Vec<u8> = vec![3u8; 32];
        seed_client
            .execute(
                "INSERT INTO lore_locks (repository, branch, hash, owner, description, \
                 locked_at) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &repository,
                    &branch,
                    &hash,
                    &"legacy-subject",
                    &"pre-fencing lock",
                    &0i64,
                ],
            )
            .await
            .expect("seed one legacy (owner_issuer IS NULL) lock row");

        let settings = armed_settings(&db_url, &s3);
        let refusal = run(&cutover_defaults(), &settings).await;
        let force_outcome = run(
            &DomainCommand::Cutover {
                dry_run: false,
                force_release_legacy_locks: true,
                legacy_lock_issuer: Vec::new(),
                json: false,
            },
            &settings,
        )
        .await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        let error = refusal.expect_err("one legacy lock with no force/issuer must refuse cutover");
        let message = error.to_string();
        // The refusal names the SUBJECT count (one distinct `owner` with no
        // reviewed issuer), not a row count — they happen to coincide here
        // because this fixture seeds exactly one row for one subject, so the
        // wording is asserted explicitly rather than just checking for '1'.
        assert!(
            message.contains("1 legacy lock subject"),
            "refusal must name the legacy-lock SUBJECT count: {message}"
        );
        assert!(
            message.contains("legacy-subject"),
            "refusal must name the offending subject: {message}"
        );
        force_outcome.expect("--force-release-legacy-locks must complete the same cutover");
        assert!(final_state.enforcement_enabled);
    }

    // ── 10. CellBackfillSource against a live cell ────────────────────────
    //
    // GAP (reported, not silently dropped): the "one repository and one
    // branch written through `lore_revision`'s own create path" and
    // "snapshot_token changes after a mutable write" sub-cases from the spec
    // are NOT covered here. `lore_revision::repository::create_with_metadata`
    // drives a full client/server round trip (`protocol::connect`, a real
    // loreserver) rather than writing directly against an `ImmutableStore` +
    // `MutableStore` pair — the same class of heavy fixture the testing guide
    // already documents deferring for `State::tree`'s remote-fetch case, for
    // the same reason (no cheap harness for it exists in this crate or
    // `lore-integration-tests` today). Reproducing `CellBackfillSource`'s own
    // key derivation by hand here would test my guess at its internals, not
    // its real contract. What IS covered without that fixture: the two
    // baseline properties requiring no repository/branch at all, plus the
    // one raw-write orphan case that IS reachable without it.
    //
    // SECOND CORRECTION (the first one, using `KeyType::RepositoryMetadata`,
    // was itself invalidated by a later fix round): `domain_key_types()` is
    // now derived from `bypass::is_domain_owned`, which includes `Instance` —
    // reachable only through the generic mutable RPCs, with no server writer
    // — so an `Instance` row IS scanned and classifies as
    // `ResidueClass::ForeignDomainKeyWrite`, the one class
    // `DomainBackfill::complete` refuses cutover on. `Instance` is also the
    // right choice for a reason `RepositoryMetadata` no longer is:
    // `CellBackfillSource` now unions the name-map walk with every partition
    // holding a `RepositoryMetadata` row, so a raw `RepositoryMetadata` write
    // gets WALKED as a candidate repository rather than staying simple
    // orphan residue. A raw `Instance` write is not discovered as a
    // repository at all, so it stays exactly what this case wants to prove.
    // The case now asserts the refusal outright, rather than passing for an
    // incidental reason.
    //
    // Every fallible call below is captured as a `Result` and every
    // assertion runs AFTER `drop_throwaway_database`, so a genuine assertion
    // failure never leaks the disposable database.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cell_backfill_source_flags_a_foreign_instance_key_and_cutover_refuses_on_it() {
        let Some((admin_url, s3)) =
            live_env("cell_backfill_source_flags_a_foreign_instance_key_and_cutover_refuses_on_it")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "backfill_source").await;

        let object = ObjectStoreSettings {
            bucket: s3.bucket.clone(),
            endpoint_url: Some(s3.endpoint.clone()),
            region: Some(s3.region.clone()),
            force_path_style: true,
            slow_operation_threshold_millis: u64::MAX,
            timeout_millis: 5_000,
            validate_bucket_on_startup: true,
        };
        let immutable_store =
            PostgresImmutableStore::connect(&db_url, 2, &TlsConfig::default(), object)
                .await
                .expect("bootstrap the disposable immutable store");
        let mutable_store = PostgresMutableStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the disposable mutable store");
        let pool = build_pool(&db_url, 2, &TlsConfig::default())
            .expect("build the disposable backfill-source pool");

        let immutable: Arc<dyn ImmutableStore> = Arc::new(immutable_store);
        let mutable: Arc<dyn MutableStore> = Arc::new(mutable_store);
        let source = CellBackfillSource::new(pool, immutable, mutable.clone());

        let repositories_result = source.list_repositories().await;
        let branches_result = source.list_branches(&[0u8; 16]).await;
        let orphans_before_result = source.orphan_projection_keys().await;

        let orphan_partition = Partition::from([9u8; 16]);
        let orphan_key = Hash::from([9u8; 32]);
        let write_result = mutable
            .clone()
            .store(
                orphan_partition,
                orphan_key,
                Hash::from([1u8; 32]),
                KeyType::Instance,
            )
            .await;

        let orphans_after_result = source.orphan_projection_keys().await;

        // Against the SAME cell: a full `cutover` must refuse once this
        // residue exists, not merely report it.
        let settings = armed_settings(&db_url, &s3);
        let cutover_outcome = run(&cutover_defaults(), &settings).await;

        drop_throwaway_database(&admin_url, &db_name).await;

        let repositories =
            repositories_result.expect("list_repositories must succeed on a clean cell");
        assert!(
            repositories.is_empty(),
            "a clean cell must report no repositories"
        );

        let branches = branches_result
            .expect("list_branches must succeed for a repository that doesn't exist");
        assert!(branches.is_empty());

        let orphans_before =
            orphans_before_result.expect("orphan_projection_keys must succeed on a clean cell");
        assert!(
            orphans_before.is_empty(),
            "a clean cell must report no orphan keys"
        );

        write_result.expect("write one raw Instance-typed key directly into lore_mutable");

        let orphans_after =
            orphans_after_result.expect("orphan_projection_keys must succeed after the raw write");
        assert_eq!(
            orphans_after.len(),
            1,
            "the raw Instance-typed key must be reported as exactly one orphan: \
             {orphans_after:?}"
        );
        let reported = &orphans_after[0];
        assert_eq!(reported.key_type, KeyType::Instance as i16);
        assert_eq!(reported.partition, orphan_partition.as_ref().to_vec());
        assert_eq!(reported.key, orphan_key.as_ref().to_vec());

        let error = cutover_outcome.expect_err(
            "a ForeignDomainKeyWrite (the Instance row) must refuse cutover outright, not pass \
             for an incidental reason",
        );
        let message = error.to_string();
        assert!(
            message.contains(
                "domain-typed key(s) in this cell were written through the generic mutable path"
            ),
            "refusal must name the ForeignDomainKeyWrite class: {message}"
        );
        assert!(
            message.contains('1'),
            "refusal must name the count: {message}"
        );
    }

    // ── 11. resume from a cell hand-stranded at BACKFILL_VERIFIED ─────────
    //
    // `DomainBackfill::complete` is now one transaction (see the module docs
    // above and the dispatching session's note), so no cutover this build
    // performs can leave a cell durably at VERIFIED without CUTOVER any
    // more — that combination is reachable today only as a historical
    // artefact of an older, non-transactional build. There is no code path
    // in this build that produces it, so it is simulated directly against
    // the schema (never through any code path under test, and never by
    // calling `DomainBackfill` methods out of order) rather than faked by
    // weakening the assertion below.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_resumes_at_verify_complete_from_a_cell_hand_stranded_at_verified() {
        let Some((admin_url, s3)) =
            live_env("cutover_resumes_at_verify_complete_from_a_cell_hand_stranded_at_verified")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "verified_resume").await;

        let bootstrap_store = PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the disposable domain schema");
        drop(bootstrap_store);
        let seed_client = pg_client(&db_url).await;
        let seed_result = seed_client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_state = $1, residue_classified = true, \
                     updated_at = clock_timestamp() \
                 WHERE id = 1",
                &[&domain_schema::BACKFILL_VERIFIED],
            )
            .await;

        let settings = armed_settings(&db_url, &s3);
        let outcome = run(&cutover_defaults(), &settings).await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        seed_result.expect("hand-place the cell at BACKFILL_VERIFIED");
        outcome.expect("cutover must resume a cell stranded at VERIFIED and complete it");
        assert_eq!(
            final_state.backfill_state,
            domain_schema::BACKFILL_CUTOVER,
            "resuming from VERIFIED must still reach CUTOVER"
        );
        assert!(final_state.enforcement_enabled);
    }

    // ── 12. a failed lock backfill leaves enforcement off ─────────────────
    //
    // `enable_enforcement` now runs LAST, after the lock backfill and
    // `enable_fencing`, so a lock backfill failure must leave the domain
    // side already at CUTOVER (it ran and committed first) while
    // enforcement itself stays off.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn a_failed_lock_backfill_completes_the_domain_cutover_but_leaves_enforcement_off() {
        let Some((admin_url, s3)) = live_env(
            "a_failed_lock_backfill_completes_the_domain_cutover_but_leaves_enforcement_off",
        ) else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "fencing_window").await;

        // A legacy lock row pointing at a repository/branch this cell never
        // creates. A correct `--legacy-lock-issuer` mapping for its subject
        // clears the pre-flight `refuse_uncovered_legacy_locks` precondition,
        // but the lock backfill itself still quarantines the row once it
        // tries to convert it, because no domain row exists for that
        // repository/branch.
        let legacy_store = PostgresLockStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the legacy CR-007 lock schema");
        drop(legacy_store);
        let seed_client = pg_client(&db_url).await;
        let repository: Vec<u8> = vec![9u8; 16];
        let branch: Vec<u8> = vec![8u8; 16];
        let hash: Vec<u8> = vec![7u8; 32];
        let seed_result = seed_client
            .execute(
                "INSERT INTO lore_locks (repository, branch, hash, owner, description, \
                 locked_at) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &repository,
                    &branch,
                    &hash,
                    &"orphan-lock-subject",
                    &"points at a repository/branch this cell never creates",
                    &0i64,
                ],
            )
            .await;

        let settings = armed_settings(&db_url, &s3);
        let outcome = run(
            &DomainCommand::Cutover {
                dry_run: false,
                force_release_legacy_locks: false,
                legacy_lock_issuer: vec!["orphan-lock-subject=https://issuer.invalid".to_string()],
                json: false,
            },
            &settings,
        )
        .await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        seed_result.expect("seed one legacy lock row pointing at a nonexistent repository/branch");
        let error = outcome.expect_err(
            "a legacy lock row with no matching domain repository/branch must quarantine and \
             fail the cutover",
        );
        assert!(
            error.to_string().contains("quarantined"),
            "refusal must name the quarantine: {error}"
        );
        assert_eq!(
            final_state.backfill_state,
            domain_schema::BACKFILL_CUTOVER,
            "the domain backfill must have already committed its cutover marker before the \
             lock backfill failed"
        );
        assert!(
            !final_state.enforcement_enabled,
            "enforcement must stay off when the lock backfill fails, since it now runs last"
        );
    }

    // ── 13. any fragment lifecycle head refuses a cutover not yet done ───
    //
    // `cutover` opens the immutable store on the legacy route, which reads
    // only the legacy fragment tables. A coordinated-route write never writes
    // them, so every coordinated-route blob — Staged, or Remote at any key —
    // reads as absent to the backfill. The supported order is domain cutover
    // first, then `initialize-fragments`, so a cell holding any lifecycle head
    // before its backfill finishes is outside that design. The command must
    // refuse, before it changes any lifecycle state and on `--dry-run` too,
    // whatever state the head is in, and the refusal must be typed.
    //
    // The control is the same cell with the head deleted: an installed but
    // empty lifecycle table must cut over, so the refusal is shown to be
    // caused by the head and not by the table.

    /// Install SCHEMA-118 through the coordinator's own bootstrap, then insert
    /// one lifecycle head in `state`.
    async fn seed_lifecycle_head(
        store: &PostgresDomainStore,
        db_url: &str,
        state: i16,
    ) -> Result<(), String> {
        store
            .fragment_coordinator()
            .bootstrap()
            .await
            .map_err(|error| format!("fragment schema bootstrap: {error}"))?;
        pg_client(db_url)
            .await
            .execute(
                "INSERT INTO lore_fragment_lifecycle \
                 (hash, current_epoch, state, manifest_id, last_fence) \
                 VALUES ($1, 1, $2, $3, 1)",
                &[&vec![0x5au8; 32], &state, &vec![0x5bu8; 32]],
            )
            .await
            .map_err(|error| format!("insert the lifecycle head: {error}"))?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_cell_holding_a_staged_fragment_head() {
        let case = "cutover_refuses_a_cell_holding_a_staged_fragment_head";
        Box::pin(assert_lifecycle_head_refuses_cutover(
            case,
            FragmentLifecycleState::Staged,
        ))
        .await;
    }

    /// A `Remote` head is the case a Staged-only check missed: a promoted or
    /// repaired blob is still a coordinated-route blob the legacy backfill
    /// cannot read.
    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_cell_holding_a_remote_fragment_head() {
        let case = "cutover_refuses_a_cell_holding_a_remote_fragment_head";
        Box::pin(assert_lifecycle_head_refuses_cutover(
            case,
            FragmentLifecycleState::Remote,
        ))
        .await;
    }

    async fn assert_lifecycle_head_refuses_cutover(case: &str, state: FragmentLifecycleState) {
        let Some((admin_url, s3)) = live_env(case) else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "lifecycle_head").await;

        let bootstrap_store = PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the disposable domain schema");
        let seed_result = seed_lifecycle_head(&bootstrap_store, &db_url, state.bits()).await;
        drop(bootstrap_store);

        let settings = armed_settings(&db_url, &s3);
        let dry_run_outcome = run(
            &DomainCommand::Cutover {
                dry_run: true,
                force_release_legacy_locks: false,
                legacy_lock_issuer: Vec::new(),
                json: false,
            },
            &settings,
        )
        .await;
        let refused_outcome = run(&cutover_defaults(), &settings).await;
        let refused_state = independent_domain_state(&db_url).await;

        // The control: the same cell, its lifecycle table installed but empty.
        let empty_result = pg_client(&db_url)
            .await
            .execute("DELETE FROM lore_fragment_lifecycle", &[])
            .await;
        let control_outcome = run(&cutover_defaults(), &settings).await;
        let control_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        seed_result.expect("seed one lifecycle head");
        let expected = CutoverRefusal::FragmentLifecyclePresent {
            heads: 1,
            first: vec![hex::encode([0x5au8; 32])],
        };
        let dry_run_error = dry_run_outcome.expect_err("a --dry-run must report the refusal too");
        assert_eq!(
            dry_run_error.downcast_ref::<CutoverRefusal>(),
            Some(&expected),
            "the dry-run refusal must be typed: {dry_run_error}"
        );
        let error = refused_outcome.expect_err("a lifecycle head must refuse cutover");
        assert_eq!(
            error.downcast_ref::<CutoverRefusal>(),
            Some(&expected),
            "the refusal must be typed: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("1 fragment lifecycle head(s)")
                && message.contains("initialize-fragments"),
            "the refusal must name the count and the supported order: {message}"
        );
        assert!(
            !message.contains("drain"),
            "the refusal must not offer a drain recovery the cell cannot use: {message}"
        );
        assert_eq!(
            refused_state.backfill_state,
            domain_schema::BACKFILL_NOT_STARTED,
            "a refusal must not start the domain backfill"
        );
        assert!(!refused_state.enforcement_enabled);

        empty_result.expect("empty the lifecycle table");
        control_outcome.expect("the same cell with an empty lifecycle table must cut over");
        assert_eq!(
            control_state.backfill_state,
            domain_schema::BACKFILL_CUTOVER
        );
        assert!(control_state.enforcement_enabled);
    }

    // ── 13b. a lifecycle head refuses a backfill left RUNNING or VERIFIED ─
    //
    // The refusal is gated on "backfill not finished", not on "backfill not
    // started". A cell hand-placed at RUNNING or VERIFIED (the latter as in
    // case 11) still has to run or resume a backfill step that reads through
    // the legacy route, so a lifecycle head must refuse there too, and the
    // refusal must leave the seeded backfill state exactly as it was.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_lifecycle_head_while_the_backfill_is_running() {
        let case = "cutover_refuses_a_lifecycle_head_while_the_backfill_is_running";
        Box::pin(assert_lifecycle_head_refuses_unfinished_backfill(
            case,
            domain_schema::BACKFILL_RUNNING,
            false,
        ))
        .await;
    }

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_lifecycle_head_while_the_backfill_is_verified() {
        let case = "cutover_refuses_a_lifecycle_head_while_the_backfill_is_verified";
        Box::pin(assert_lifecycle_head_refuses_unfinished_backfill(
            case,
            domain_schema::BACKFILL_VERIFIED,
            true,
        ))
        .await;
    }

    async fn assert_lifecycle_head_refuses_unfinished_backfill(
        case: &str,
        backfill_state: i16,
        residue_classified: bool,
    ) {
        let Some((admin_url, s3)) = live_env(case) else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "unfinished_head").await;

        let bootstrap_store = PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the disposable domain schema");
        let head_result = seed_lifecycle_head(
            &bootstrap_store,
            &db_url,
            FragmentLifecycleState::Remote.bits(),
        )
        .await;
        drop(bootstrap_store);
        let state_result = pg_client(&db_url)
            .await
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_state = $1, residue_classified = $2, \
                     updated_at = clock_timestamp() \
                 WHERE id = 1",
                &[&backfill_state, &residue_classified],
            )
            .await;

        let settings = armed_settings(&db_url, &s3);
        let outcome = run(&cutover_defaults(), &settings).await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        head_result.expect("seed one lifecycle head");
        assert_eq!(
            state_result.expect("hand-place the backfill state"),
            1,
            "the seed must move the one schema-state row, or this case tests nothing"
        );
        let error = outcome.expect_err("a lifecycle head must refuse an unfinished backfill");
        assert_eq!(
            error.downcast_ref::<CutoverRefusal>(),
            Some(&CutoverRefusal::FragmentLifecyclePresent {
                heads: 1,
                first: vec![hex::encode([0x5au8; 32])],
            }),
            "the refusal must be typed: {error}"
        );
        assert_eq!(
            final_state.backfill_state, backfill_state,
            "a refusal must leave the seeded backfill state unchanged"
        );
        assert!(!final_state.enforcement_enabled);
    }

    // ── 14. a metadata-row repository with an absent blob refuses ────────
    //
    // A repository found only by its `RepositoryMetadata` row, whose blob the
    // object store reports absent, used to be skipped as delete residue. No
    // writer produces that shape: create stores the blob before the row, and
    // delete removes the rows and never the blob. So every instance is lost
    // data (an unpromoted or lost write-behind blob, an obliterated blob, a
    // wrong bucket), and the skip dropped the repository from the projection
    // with only a warning. The cutover must refuse and name the partition.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_refuses_a_metadata_row_repository_whose_blob_is_absent() {
        let Some((admin_url, s3)) =
            live_env("cutover_refuses_a_metadata_row_repository_whose_blob_is_absent")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "absent_blob").await;

        let object = ObjectStoreSettings {
            bucket: s3.bucket.clone(),
            endpoint_url: Some(s3.endpoint.clone()),
            region: Some(s3.region.clone()),
            force_path_style: true,
            slow_operation_threshold_millis: u64::MAX,
            timeout_millis: 5_000,
            validate_bucket_on_startup: true,
        };
        let immutable_store =
            PostgresImmutableStore::connect(&db_url, 2, &TlsConfig::default(), object)
                .await
                .expect("bootstrap the disposable immutable store");
        let mutable_store = PostgresMutableStore::connect(&db_url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap the disposable mutable store");
        let immutable: Arc<dyn ImmutableStore> = Arc::new(immutable_store);
        let mutable: Arc<dyn MutableStore> = Arc::new(mutable_store);

        // The exact key `repository::metadata_hash` reads, pointing at a blob
        // that was never written.
        let mut repository_id = RepositoryId::default();
        *repository_id.data_mut() = [0x6cu8; 16];
        let base = RepositoryContext::new_null_context(immutable, mutable.clone());
        let (key, key_type) =
            repository::mutable_key(base.salt(), repository::METADATA, repository_id);
        let write_result = mutable
            .clone()
            .store(
                Partition::from(*repository_id.data()),
                key,
                Hash::from([0x6du8; 32]),
                key_type,
            )
            .await;

        let settings = armed_settings(&db_url, &s3);
        let outcome = run(&cutover_defaults(), &settings).await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        write_result.expect("write one repository metadata row with no blob behind it");
        assert_eq!(key_type, KeyType::RepositoryMetadata);
        let error = outcome.expect_err(
            "a metadata-row repository whose blob is absent must refuse cutover, not be skipped",
        );
        // Typed, so a caller can tell this refusal from a database failure
        // without matching on message text.
        assert!(
            matches!(
                error
                    .downcast_ref::<BackfillFailure>()
                    .map(BackfillFailure::cause),
                Some(DomainError::NotReady(_))
            ),
            "the refusal must be a recoverable DomainError::NotReady: {error:?}"
        );
        // The whole chain, as the CLI prints it. `NotReady`'s own prefix says
        // "enforcement requested before cutover", which is not what happened.
        let chain = format!("{error:?}");
        assert!(
            !chain.contains("requested before cutover"),
            "the refusal must not claim enforcement was requested: {chain}"
        );
        let message = error.to_string();
        assert!(
            message.contains("missing from the legacy store"),
            "the refusal must say where the blob is missing: {message}"
        );
        assert!(
            message.contains(&hex::encode([0x6cu8; 16])),
            "the refusal must name the repository partition: {message}"
        );
        assert!(
            !final_state.enforcement_enabled,
            "a refused backfill must leave enforcement off"
        );
        assert_ne!(
            final_state.backfill_state,
            domain_schema::BACKFILL_CUTOVER,
            "a refused backfill must not reach cutover"
        );
    }

    // ── 15. a Staged head on an already cut-over cell does not refuse ────
    //
    // The lifecycle-head refusal guards the domain backfill, the one step that
    // reads metadata blobs. A cell already at cutover skips that step, and on
    // such a cell a Staged head is ordinary live write-behind traffic. A rerun
    // must still pass, or every restart of an armed write-behind cell's
    // cutover would refuse.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_rerun_on_a_cut_over_cell_passes_with_a_staged_fragment_head() {
        let Some((admin_url, s3)) =
            live_env("cutover_rerun_on_a_cut_over_cell_passes_with_a_staged_fragment_head")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "staged_rerun").await;
        let settings = armed_settings(&db_url, &s3);

        let first_outcome = run(&cutover_defaults(), &settings).await;
        let seed_result = match PostgresDomainStore::connect(&db_url, 2, &TlsConfig::default())
            .await
        {
            Ok(store) => {
                seed_lifecycle_head(&store, &db_url, FragmentLifecycleState::Staged.bits()).await
            }
            Err(error) => Err(format!("connect the seeding store: {error}")),
        };
        let rerun_outcome = run(&cutover_defaults(), &settings).await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        first_outcome.expect("the first cutover of an empty cell must succeed");
        seed_result.expect("seed one Staged lifecycle head after cutover");
        rerun_outcome.expect("a rerun on a cut-over cell must not refuse on a Staged head");
        assert_eq!(final_state.backfill_state, domain_schema::BACKFILL_CUTOVER);
        assert!(final_state.enforcement_enabled);
    }

    // ── 16. no lifecycle table at all does not refuse ────────────────────
    //
    // A cell that never installed SCHEMA-118 has never staged anything. The
    // probe must read the missing relation as "nothing staged" rather than
    // fail the query against a table that does not exist.

    #[tokio::test]
    #[ignore = "requires LORE_TEST_PG_URL + LORE_TEST_S3_ENDPOINT/LORE_TEST_S3_BUCKET"]
    async fn cutover_passes_on_a_cell_with_no_fragment_lifecycle_table() {
        let Some((admin_url, s3)) =
            live_env("cutover_passes_on_a_cell_with_no_fragment_lifecycle_table")
        else {
            return;
        };
        let (db_name, db_url) = create_throwaway_database(&admin_url, "no_lifecycle").await;
        let settings = armed_settings(&db_url, &s3);

        let probe = "SELECT to_regclass('lore_fragment_lifecycle') IS NOT NULL AS present";
        let absent_before = pg_client(&db_url).await.query_one(probe, &[]).await;
        let outcome = run(&cutover_defaults(), &settings).await;
        let absent_after = pg_client(&db_url).await.query_one(probe, &[]).await;
        let final_state = independent_domain_state(&db_url).await;
        drop_throwaway_database(&admin_url, &db_name).await;

        let present: bool = absent_before
            .expect("probe the lifecycle relation before cutover")
            .get("present");
        assert!(
            !present,
            "the fixture must start with no lifecycle table, or this case tests nothing"
        );
        outcome.expect("a cell with no lifecycle table must cut over");
        let present: bool = absent_after
            .expect("probe the lifecycle relation after cutover")
            .get("present");
        assert!(
            !present,
            "the probe ran against a missing relation, and cutover must not create it"
        );
        assert_eq!(final_state.backfill_state, domain_schema::BACKFILL_CUTOVER);
        assert!(final_state.enforcement_enabled);
    }
}

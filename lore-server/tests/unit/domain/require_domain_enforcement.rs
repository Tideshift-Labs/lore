// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `[mutable_store] require_domain_enforcement`, the
//! boot refusal for a cell that must not serve with CR-029 enforcement unarmed.

use lore_server::domain::require_armed_domain_enforcement;
use lore_server::settings::Settings;

/// `Settings` deserializes with a `'static` bound, so the assembled TOML is
/// leaked; each test builds one.
fn settings(mode: &str, require: Option<bool>) -> Settings {
    let require = require
        .map(|value| format!("require_domain_enforcement = {value}"))
        .unwrap_or_default();
    let config = format!(
        r#"
            [server]
            runtime_shutdown_timeout_seconds = 0

            [immutable_store]
            mode = "local"

            [mutable_store]
            mode = "{mode}"
            {require}
        "#
    );
    toml::from_str(Box::leak(config.into_boxed_str())).expect("settings deserialize")
}

// --- settings --------------------------------------------------------------

#[test]
fn the_setting_defaults_to_off() {
    assert!(
        !settings("local", None)
            .mutable_store
            .require_domain_enforcement
    );
    assert!(
        !settings("postgres", None)
            .mutable_store
            .require_domain_enforcement
    );
}

#[test]
fn the_setting_can_be_turned_on_or_off_explicitly() {
    assert!(
        settings("postgres", Some(true))
            .mutable_store
            .require_domain_enforcement
    );
    assert!(
        !settings("postgres", Some(false))
            .mutable_store
            .require_domain_enforcement
    );
}

// --- the refusal -----------------------------------------------------------

#[test]
fn off_never_refuses_whether_or_not_enforcement_is_armed() {
    for mode in ["local", "postgres", "aws"] {
        for settings in [settings(mode, None), settings(mode, Some(false))] {
            for armed in [false, true] {
                assert!(
                    require_armed_domain_enforcement(&settings, armed).is_ok(),
                    "off must pass: mode {mode}, armed {armed}"
                );
            }
        }
    }
}

#[test]
fn on_and_armed_boots() {
    assert!(require_armed_domain_enforcement(&settings("postgres", Some(true)), true).is_ok());
}

#[test]
fn on_and_unarmed_on_postgres_refuses_and_names_the_cutover() {
    let error = require_armed_domain_enforcement(&settings("postgres", Some(true)), false)
        .expect_err("an unarmed cell must refuse to serve");
    let text = format!("{error:#}");
    assert!(
        text.contains("domain cutover"),
        "the refusal must point at `loreserver domain cutover`, got {text:?}"
    );
    assert!(
        text.contains("require_domain_enforcement"),
        "the refusal must name the setting, got {text:?}"
    );
}

#[test]
fn on_with_a_non_postgres_store_refuses_and_names_the_mode() {
    for mode in ["local", "aws"] {
        // Armed is irrelevant here in practice (only Postgres arms), but the
        // unarmed answer is the one a non-Postgres cell always gets.
        let error = require_armed_domain_enforcement(&settings(mode, Some(true)), false)
            .expect_err("a non-Postgres cell can never be armed");
        let text = format!("{error:#}");
        assert!(
            text.contains(&format!("{mode:?}")),
            "the refusal must name mode {mode:?}, got {text:?}"
        );
        assert!(
            text.contains("postgres"),
            "the refusal must say what mode is needed, got {text:?}"
        );
        assert!(
            !text.contains("domain cutover"),
            "a cutover cannot fix a non-Postgres mode, got {text:?}"
        );
    }
}

// --- wiring ----------------------------------------------------------------

const SERVER: &str = include_str!("../../../src/server.rs");
const OPERATOR: &str = include_str!("../../../src/domain/operator.rs");

/// `//` comment lines removed, so prose that names a function is not a call.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The serving path calls the refusal once, after the domain context is
/// configured and before any listener starts, and propagates its error.
#[test]
fn async_main_refuses_after_configuring_the_domain_and_before_any_listener() {
    let server = code_only(SERVER);
    let body_start = server
        .find("async fn async_main(")
        .expect("async_main must exist");
    let body = &server[body_start..];

    let call = "require_armed_domain_enforcement(";
    assert_eq!(
        server.matches(call).count(),
        1,
        "exactly one call site, in async_main"
    );
    let call_at = body.find(call).expect("async_main must call the refusal");

    let configured_at = body
        .rfind("configure_domain_context(")
        .expect("async_main must configure the domain context");
    assert!(
        configured_at < call_at,
        "the refusal must follow the last configure_domain_context call"
    );

    for listener in [
        "launch_grpc_server(",
        "launch_grpc_internal_server(",
        "launch_quinn_server(",
        "launch_http_server(",
        "launch_maintenance_grpc_server(",
    ] {
        let listener_at = body
            .find(listener)
            .unwrap_or_else(|| panic!("async_main must start {listener}"));
        assert!(
            call_at < listener_at,
            "the refusal must precede {listener} (call at {call_at}, listener at {listener_at})"
        );
    }

    // The error propagates, and the armed flag is what the mutable store was
    // given, not a literal.
    let call_text = &body[call_at..];
    let end = call_text.find(";").expect("statement end");
    let call_text = &call_text[..end];
    assert!(
        call_text.ends_with(")?"),
        "the error must propagate: {call_text}"
    );
    assert!(
        call_text.contains("mutable_enforcement") && call_text.contains("is_enabled"),
        "armed must be the mutable store's enforcement flag: {call_text}"
    );
}

/// `loreserver domain cutover` is how the setting is satisfied, so the
/// operator path must never be gated by it.
#[test]
fn the_operator_path_does_not_call_the_refusal() {
    assert!(
        !code_only(OPERATOR).contains("require_armed_domain_enforcement"),
        "the maintenance subcommands must not be blocked by the setting they clear"
    );
}

// --- live ------------------------------------------------------------------

/// An unmigrated Postgres cell boots with enforcement configured but not
/// enabled; the refusal reads that real state.
#[tokio::test]
#[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
async fn an_unarmed_postgres_cell_is_refused_when_enforcement_is_required() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");

    let mut settings: Settings = toml::from_str(include_str!("../../../config/default.toml"))
        .expect("built-in settings fixture must deserialize");
    settings.mutable_store.mode = "postgres".to_owned();
    settings.plugins.insert(
        "postgres".to_owned(),
        toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
            .expect("Postgres plugin fixture config"),
    );

    let configured = lore_server::domain::configure_domain_context(&settings)
        .await
        .expect("an unmigrated cell must configure rather than abort");
    let armed = configured
        .mutable_enforcement
        .as_ref()
        .is_some_and(lore_postgres::domain::bypass::DomainEnforcement::is_enabled);
    assert!(!armed, "a never-cutover database must not arm enforcement");

    settings.mutable_store.require_domain_enforcement = false;
    assert!(require_armed_domain_enforcement(&settings, armed).is_ok());

    settings.mutable_store.require_domain_enforcement = true;
    let error = require_armed_domain_enforcement(&settings, armed)
        .expect_err("the unarmed cell must refuse when enforcement is required");
    assert!(format!("{error:#}").contains("domain cutover"), "{error:#}");
}

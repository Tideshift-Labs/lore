// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source controls for Phase 6B's provider-free coordinated metering rebuild.

const SERVER: &str = include_str!("../src/server.rs");

fn function<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker {marker:?}"));
    let tail = &source[start..];
    let opening = tail.find('{').expect("function opening brace");
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes()[opening..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {marker:?}")
}

fn assert_precedes(source: &str, first: &str, second: &str) {
    let first = source.find(first).expect("first marker must exist");
    let second = source.find(second).expect("second marker must exist");
    assert!(first < second, "{first} must precede {second}");
}

#[test]
fn enabled_rebuild_validates_then_uses_only_the_domain_coordinator() {
    let rebuild = function(SERVER, "async fn rebuild_postgres_metering(");
    let enabled_start = rebuild
        .find("if fragment_provider_enabled")
        .expect("enabled branch");
    let legacy_start = rebuild[enabled_start..]
        .find("let store = plugins::postgres::connect_immutable_store")
        .map(|offset| enabled_start + offset)
        .expect("legacy branch");
    let enabled = &rebuild[enabled_start..legacy_start];

    assert_precedes(enabled, "process_pool_inventory", ".validate()");
    assert_precedes(
        enabled,
        ".validate()",
        "configure_domain_context(settings).await?",
    );
    assert_precedes(
        enabled,
        "configure_domain_context(settings).await?",
        ".fragment_coordinator",
    );
    assert_precedes(
        enabled,
        ".fragment_coordinator",
        ".rebuild_metering_projection()",
    );

    for forbidden in [
        "connect_immutable_store",
        "configure_immutable_store_via_plugin",
        "FragmentProviderEntry",
        "with_fragment_provider",
        "DispatchRuntime",
        "PostgresImmutableStore",
    ] {
        assert!(
            !enabled.contains(forbidden),
            "enabled rebuild must not construct provider path token {forbidden:?}"
        );
    }
}

#[test]
fn absent_or_disabled_rebuild_preserves_the_legacy_store_path() {
    let rebuild = function(SERVER, "async fn rebuild_postgres_metering(");
    let legacy = rebuild
        .split("let store = plugins::postgres::connect_immutable_store")
        .nth(1)
        .expect("legacy store branch");

    assert!(legacy.contains("(&plugin_config, None)"));
    assert!(legacy.contains("store\n        .rebuild_metering_projection()"));
    assert_eq!(
        rebuild.matches(".rebuild_metering_projection()").count(),
        2,
        "enabled coordinator and legacy store must remain distinct rebuild routes"
    );
}

#[test]
fn normal_enabled_activation_still_requires_the_provider_composition_path() {
    let startup = function(SERVER, "async fn async_main(");
    assert!(startup.contains("FragmentProviderActivation::new("));
    assert!(startup.contains("configure_immutable_store_via_plugin("));
    assert!(startup.contains(
        "enabled fragment_provider requires the Postgres fragment lifecycle coordinator"
    ));
    assert!(
        !function(SERVER, "async fn rebuild_postgres_metering(")
            .contains("FragmentProviderActivation::new(")
    );
}

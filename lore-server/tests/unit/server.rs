// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
/// Covers where the local store ends up on disk, and whether that location
/// survives a reboot.
mod local_store_path_resolution {
    use lore_server::server::is_path_configured;
    use lore_server::server::local_data_dir;
    use lore_server::server::local_store_path;
    use lore_server::util::local_store_monitor::is_temporary_path;

    #[test]
    fn a_path_counts_as_configured_only_when_it_names_something() {
        assert!(is_path_configured("/srv/lore/store"));
        assert!(!is_path_configured(""));
        assert!(!is_path_configured("   "));
    }

    #[test]
    fn an_unconfigured_path_falls_back_under_the_temp_dir() {
        let path = local_store_path("");

        assert_eq!(path, local_data_dir());
        assert!(is_temporary_path(&path));
    }

    #[test]
    fn a_blank_path_falls_back_under_the_temp_dir() {
        assert_eq!(local_store_path("   "), local_data_dir());
    }

    /// Sourced from the temporary directory, which is absolute however the
    /// platform spells one.
    #[test]
    fn a_configured_absolute_path_is_taken_as_given() {
        let path = std::env::temp_dir().join("lore-configured-store");
        let configured = path.to_str().expect("temporary directory path is UTF-8");

        assert_eq!(local_store_path(configured), path);
    }

    /// The storage layer creates a relative path against the working
    /// directory, so the reported location must match.
    // The process directory is the assertion, not a carried one.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn a_relative_path_is_resolved_against_the_working_directory() {
        let current = std::env::current_dir().expect("working directory");

        assert_eq!(local_store_path("store"), current.join("store"));
    }

    /// `./` is what the shipped `gha.toml` configures.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn a_working_directory_path_resolves_to_the_working_directory() {
        let current = std::env::current_dir().expect("working directory");

        assert_eq!(local_store_path("./"), current);
    }

    /// Classification is lexical, so a first start decides as a later one
    /// does.
    #[test]
    fn a_temporary_path_is_classified_before_it_exists() {
        let path = std::env::temp_dir().join("lore-server-classified-before-it-exists");

        assert!(!path.exists());
        assert!(is_temporary_path(&path));
    }

    /// The shipped `local.toml` names a path under the temporary
    /// directory, so being configured says nothing about surviving a
    /// reboot.
    #[test]
    fn a_configured_temporary_path_is_configured_and_temporary() {
        let path = std::env::temp_dir().join("lore-server");
        let configured = path.to_str().expect("temporary directory path is UTF-8");

        assert!(is_path_configured(configured));
        assert!(is_temporary_path(&local_store_path(configured)));
    }

    #[test]
    fn a_configured_persistent_path_is_neither() {
        assert!(is_path_configured("/srv/lore/store"));
        assert!(!is_temporary_path(&local_store_path("/srv/lore/store")));
    }

    /// Both conditions hold for the zero-configuration default.
    #[test]
    fn an_unconfigured_path_is_neither_configured_nor_persistent() {
        assert!(!is_path_configured(""));
        assert!(is_temporary_path(&local_store_path("")));
    }
}

/// Covers which local stores are reported and given to the disk space
/// monitor.
mod local_stores {
    use std::path::PathBuf;

    use lore_server::server::LocalStoreLocation;
    use lore_server::server::local_data_dir;
    use lore_server::server::local_store_locations;
    use lore_server::server::local_store_path;
    use lore_server::server::monitored_local_store_paths;
    use lore_server::settings::ImmutableStoreSettings;
    use lore_server::settings::MutableStoreSettings;

    const LOCAL_IMMUTABLE: &str = r#"
            mode = "local"
            [local]
            flush_delay_seconds = 10
            path = "/tmp/lore-server"
        "#;

    const LOCAL_MUTABLE: &str = r#"
            mode = "local"
            [local]
            flush_delay_seconds = 10
            path = "/tmp/lore-server"
        "#;

    const REMOTE_MUTABLE: &str = r#"
            mode = "remote"
        "#;

    const COMPOSITE_WITH_LOCAL_TIER: &str = r#"
            mode = "composite"
            [composite.local]
            mode = "local"
            [composite.local.local]
            flush_delay_seconds = 10
            path = "/tmp/lore-server"
        "#;

    const COMPOSITE_WITHOUT_LOCAL_TIER: &str = r#"
            mode = "composite"
            [composite.local]
            mode = "local"
        "#;

    /// Only the first local tier reaches disk.
    const COMPOSITE_WITH_EVERY_TIER_LOCAL: &str = r#"
            mode = "composite"

            [composite.local]
            mode = "local"

            [composite.local.local]
            flush_delay_seconds = 10
            path = "/var/lore/cache"

            [composite.durable]
            mode = "local"

            [composite.durable.local]
            flush_delay_seconds = 10
            path = "/var/lore/durable"

            [[composite.replica]]
            mode = "local"

            [composite.replica.local]
            flush_delay_seconds = 10
            path = "/var/lore/replica"
        "#;

    const UNCONFIGURED_IMMUTABLE: &str = r#"
            mode = "local"
            [local]
            flush_delay_seconds = 10
            path = ""
        "#;

    fn immutable(config: &'static str) -> ImmutableStoreSettings {
        toml::from_str(config).expect("[immutable_store] should deserialize")
    }

    fn mutable(config: &'static str) -> MutableStoreSettings {
        toml::from_str(config).expect("[mutable_store] should deserialize")
    }

    fn locations(
        immutable_config: &'static str,
        mutable_config: &'static str,
    ) -> Vec<LocalStoreLocation> {
        local_store_locations(&immutable(immutable_config), &mutable(mutable_config))
    }

    fn watched(immutable_config: &'static str, mutable_config: &'static str) -> Vec<PathBuf> {
        monitored_local_store_paths(locations(immutable_config, mutable_config))
    }

    fn reaches_disk(stores: &[LocalStoreLocation]) -> Vec<bool> {
        stores.iter().map(|store| store.reaches_disk).collect()
    }

    fn labels(stores: &[LocalStoreLocation]) -> Vec<&'static str> {
        stores.iter().map(|store| store.label).collect()
    }

    #[test]
    fn both_local_stores_are_watched() {
        assert_eq!(
            watched(LOCAL_IMMUTABLE, LOCAL_MUTABLE),
            vec![local_store_path("/tmp/lore-server"); 2]
        );
    }

    #[test]
    fn each_store_is_named_by_what_it_is() {
        assert_eq!(
            labels(&locations(LOCAL_IMMUTABLE, LOCAL_MUTABLE)),
            vec!["immutable", "mutable"]
        );
    }

    /// A `[local]` block left in a remote deployment's config names a
    /// directory the server never writes to.
    #[test]
    fn a_store_that_is_not_local_is_not_listed() {
        let remote_immutable = r#"
                mode = "remote"
                [local]
                flush_delay_seconds = 10
                path = "/tmp/lore-server"
            "#;

        assert!(locations(remote_immutable, REMOTE_MUTABLE).is_empty());
    }

    #[test]
    fn a_composite_local_tier_is_watched() {
        assert_eq!(
            watched(COMPOSITE_WITH_LOCAL_TIER, REMOTE_MUTABLE),
            vec![local_store_path("/tmp/lore-server")]
        );
    }

    /// A second local tier never gets a store at its own path.
    #[test]
    fn only_the_first_local_composite_tier_is_watched() {
        assert_eq!(
            watched(COMPOSITE_WITH_EVERY_TIER_LOCAL, REMOTE_MUTABLE),
            vec![local_store_path("/var/lore/cache")]
        );
    }

    /// The tiers that reach no disk are still listed, so the paths they
    /// name can be reported as unused.
    #[test]
    fn every_local_composite_tier_is_listed() {
        let stores = locations(COMPOSITE_WITH_EVERY_TIER_LOCAL, REMOTE_MUTABLE);

        assert_eq!(
            labels(&stores),
            vec![
                "immutable composite local",
                "immutable composite durable",
                "immutable composite replica"
            ]
        );
        assert_eq!(reaches_disk(&stores), vec![true, false, false]);
    }

    /// A later tier naming the first tier's path shares the store standing
    /// there, so it is written at and must not be reported as unused.
    #[test]
    fn a_composite_tier_repeating_the_first_path_is_written_at() {
        let tiers_share_a_path = r#"
                mode = "composite"

                [composite.local]
                mode = "local"

                [composite.local.local]
                flush_delay_seconds = 10
                path = "/var/lore/store"

                [composite.durable]
                mode = "local"

                [composite.durable.local]
                flush_delay_seconds = 10
                path = "/var/lore/store"
            "#;

        let stores = locations(tiers_share_a_path, REMOTE_MUTABLE);

        assert_eq!(reaches_disk(&stores), vec![true, true]);
    }

    /// The mutable store is its own store, not a tier handed the immutable
    /// one.
    #[test]
    fn the_mutable_store_reaches_disk_beside_a_composite_tier() {
        let stores = locations(COMPOSITE_WITH_LOCAL_TIER, LOCAL_MUTABLE);

        assert_eq!(reaches_disk(&stores), vec![true, true]);
    }

    /// First in build order, not the cache tier by name.
    #[test]
    fn the_first_local_tier_is_watched_whichever_tier_that_is() {
        let cache_is_remote = r#"
                mode = "composite"

                [composite.local]
                mode = "remote"

                [composite.durable]
                mode = "local"

                [composite.durable.local]
                flush_delay_seconds = 10
                path = "/var/lore/durable"
            "#;

        assert_eq!(
            watched(cache_is_remote, REMOTE_MUTABLE),
            vec![local_store_path("/var/lore/durable")]
        );
    }

    #[test]
    fn a_composite_store_with_no_local_tier_settings_is_not_listed() {
        assert!(locations(COMPOSITE_WITHOUT_LOCAL_TIER, REMOTE_MUTABLE).is_empty());
    }

    #[test]
    fn an_unconfigured_local_store_is_watched_where_it_falls_back_to() {
        assert_eq!(
            watched(UNCONFIGURED_IMMUTABLE, REMOTE_MUTABLE),
            vec![local_data_dir()]
        );
    }

    #[test]
    fn an_unconfigured_local_store_is_recorded_as_unconfigured() {
        let stores = locations(UNCONFIGURED_IMMUTABLE, REMOTE_MUTABLE);

        assert_eq!(
            stores
                .iter()
                .map(|store| store.configured)
                .collect::<Vec<_>>(),
            vec![false]
        );
    }

    #[test]
    fn a_configured_local_store_is_recorded_as_configured() {
        let stores = locations(LOCAL_IMMUTABLE, REMOTE_MUTABLE);

        assert_eq!(
            stores
                .iter()
                .map(|store| store.configured)
                .collect::<Vec<_>>(),
            vec![true]
        );
    }
}

/// Covers the `[server.http]` to `LoreHttpServerSettings` mapping, the one seam
/// between config deserialization and the HTTP server's own settings.
mod http_settings_mapping {
    use std::sync::Arc;

    use lore_server::server::build_lore_http_settings;
    use lore_server::settings::HttpSettings;

    fn http_settings(extra_keys: &str) -> HttpSettings {
        let config = format!(
            r#"
                enabled = true
                host = "127.0.0.1"
                max_file_size = 1024
                port = 8080
                request_timeout_seconds = 30
                request_body_timeout_seconds = 30
                available_interval_seconds = 5
                available_timeout_seconds = 30
                store_health_check = false
                {extra_keys}
                "#
        );
        toml::from_str(&config).expect("[server.http] should deserialize")
    }

    /// The whole read path: TOML to the policy the allowlist is built from.
    #[test]
    fn content_type_policy_is_carried_from_config() {
        let settings = build_lore_http_settings(
            &http_settings(
                r#"
                    presigned_url_extra_content_types = ["application/zip"]
                    presigned_url_denied_content_types = ["application/pdf"]
                    "#,
            ),
            Arc::default(),
        );

        assert_eq!(
            settings.presign.content_type_policy.extra,
            ["application/zip"]
        );
        assert_eq!(
            settings.presign.content_type_policy.denied,
            ["application/pdf"]
        );
    }

    /// Absent keys give an empty policy, which resolves to the built-in set.
    #[test]
    fn absent_content_type_keys_give_an_empty_policy() {
        let settings = build_lore_http_settings(&http_settings(""), Arc::default());

        assert!(settings.presign.content_type_policy.extra.is_empty());
        assert!(settings.presign.content_type_policy.denied.is_empty());
    }

    /// Guards against a copy-paste slip putting the wrong source field on a
    /// neighbouring target field.
    #[test]
    fn presign_ttl_and_key_are_carried_from_config() {
        let settings = build_lore_http_settings(
            &http_settings(
                r#"
                    presigned_url_hmac_key = "abcdef"
                    presigned_url_min_ttl_seconds = 5
                    presigned_url_default_ttl_seconds = 60
                    presigned_url_max_ttl_seconds = 600
                    "#,
            ),
            Arc::default(),
        );

        assert_eq!(settings.presign.hmac_key.as_deref(), Some("abcdef"));
        assert_eq!(settings.presign.min_ttl_seconds, 5);
        assert_eq!(settings.presign.default_ttl_seconds, 60);
        assert_eq!(settings.presign.max_ttl_seconds, 600);
    }
}

mod validate_endpoint_security {
    use std::path::PathBuf;

    use lore_server::server::EndpointSecurity;
    use lore_server::server::validate_endpoint_security;
    use lore_server::tls::CertificateSettings;

    const LABEL: &str = "[server.test]";

    fn mtls_triple() -> CertificateSettings {
        CertificateSettings {
            cert_file: PathBuf::from("cert.pem"),
            pkey_file: PathBuf::from("key.pem"),
            cert_chain: Some(PathBuf::from("ca.pem")),
        }
    }

    fn no_chain() -> CertificateSettings {
        CertificateSettings {
            cert_file: PathBuf::from("cert.pem"),
            pkey_file: PathBuf::from("key.pem"),
            cert_chain: None,
        }
    }

    #[test]
    fn full_mtls_triple_with_verify_yields_mtls() {
        let cert = mtls_triple();
        let security = validate_endpoint_security(LABEL, Some(&cert), true)
            .expect("full mTLS triple should be accepted");
        assert_eq!(security, EndpointSecurity::Mtls);
    }

    #[test]
    fn verify_off_yields_untrusted_even_with_full_triple() {
        // verify_client_certs is the operator's expressed intent; an
        // explicit `false` opts out regardless of what certs are
        // sitting on disk. The caller is expected to emit a startup
        // warning.
        let cert = mtls_triple();
        let security = validate_endpoint_security(LABEL, Some(&cert), false)
            .expect("verify_client_certs=false is always accepted");
        assert_eq!(security, EndpointSecurity::Untrusted);
    }

    #[test]
    fn verify_off_with_no_certs_yields_untrusted() {
        let security = validate_endpoint_security(LABEL, None, false)
            .expect("verify_client_certs=false is always accepted");
        assert_eq!(security, EndpointSecurity::Untrusted);
    }

    #[test]
    fn verify_on_with_no_certs_is_rejected() {
        let err = validate_endpoint_security(LABEL, None, true)
            .expect_err("default policy must refuse to start without mTLS");
        let message = err.to_string();
        assert!(message.contains(LABEL), "label must appear: {message}");
        assert!(message.contains("requires mTLS"), "got: {message}");
        assert!(
            message.contains("verify_client_certs"),
            "error must name the opt-out flag; got: {message}"
        );
    }

    #[test]
    fn verify_on_with_partial_cert_is_rejected() {
        // server-only TLS (no client-CA chain) is not mTLS. Don't
        // silently downgrade — refuse the config and name the missing
        // field so the operator can fix it.
        let cert = no_chain();
        let err = validate_endpoint_security(LABEL, Some(&cert), true)
            .expect_err("partial mTLS (no CA chain) must be rejected");
        let message = err.to_string();
        assert!(message.contains(LABEL), "label must appear: {message}");
        assert!(message.contains("partially configured"), "got: {message}");
        assert!(message.contains("cert_chain"), "got: {message}");
    }
}

// FORK-LOCAL (Tideshift): the fork's `server` tests, moved out of the inline
// `server::tests` module when upstream set `[lib] test = false`.

/// WP-109 D3. The internal QUIC server's `ImmutableLocal*` opcodes must
/// reach a local store, the property the gRPC internal server enforces at
/// construction. With no local store they are refused, never routed to a
/// non-local main store.
#[tokio::test]
async fn internal_quic_refuses_a_non_local_store_for_immutable_local_opcodes() {
    use std::sync::Arc;

    use lore_server::store::grpc_replica::GrpcReplica;
    use lore_server::store::grpc_replica::ReplicationClient;
    use lore_storage::ImmutableStore;

    let non_local: Arc<dyn ImmutableStore> =
        Arc::new(GrpcReplica::new(ReplicationClient::default()));

    assert!(
        lore_server::server::internal_quic_local_store(None, &non_local).is_none(),
        "no local store and a non-local main store must not serve ImmutableLocal* opcodes"
    );
    assert!(
        lore_server::server::internal_quic_local_store(Some(non_local.clone()), &non_local)
            .is_none(),
        "a non-local store must not serve ImmutableLocal* opcodes"
    );
}

/// A local store serves `ImmutableLocal*` opcodes, and so does a main store
/// that is itself local.
#[tokio::test]
async fn internal_quic_accepts_a_local_store() -> Result<(), lore_storage::StoreError> {
    use std::sync::Arc;

    use lore_server::store::grpc_replica::GrpcReplica;
    use lore_server::store::grpc_replica::ReplicationClient;
    use lore_storage::ImmutableStore;

    let (local, _mutable, _execution) = crate::store::test_support::test_store_create().await?;
    let non_local: Arc<dyn ImmutableStore> =
        Arc::new(GrpcReplica::new(ReplicationClient::default()));

    assert!(
        lore_server::server::internal_quic_local_store(Some(local.clone()), &non_local).is_some()
    );
    assert!(lore_server::server::internal_quic_local_store(None, &local).is_some());
    Ok(())
}

#[test]
fn compiled_features_advertise_domain_rails_only_when_service_is_available() {
    let enabled = lore_server::server::compiled_features(true, true);
    let disabled = lore_server::server::compiled_features(false, false);

    for capability in [
        "domain_operation_receipt_v2",
        "domain_operation_proof_namespace_lifecycle_v1",
    ] {
        assert_eq!(
            enabled
                .iter()
                .filter(|feature| *feature == capability)
                .count(),
            1,
            "active domain capability must be advertised exactly once: {capability}"
        );
        assert!(
            !disabled.iter().any(|feature| feature == capability),
            "unavailable domain service must not advertise {capability}"
        );
    }
}

/// WP-120. A mounted service on an unarmed cell advertised
/// `domain_operation_receipt_v2`, so a client expected receipts the cell
/// files none of. The proof-namespace capability keeps the mount condition,
/// because that rail does not depend on enforcement.
#[test]
fn the_receipt_capability_additionally_requires_enforcement() {
    let unenforcing = lore_server::server::compiled_features(true, false);
    assert!(
        !unenforcing
            .iter()
            .any(|feature| feature == "domain_operation_receipt_v2"),
        "a cell with enforcement off files no receipt and must not advertise the rail"
    );
    assert!(
        unenforcing
            .iter()
            .any(|feature| feature == "domain_operation_proof_namespace_lifecycle_v1"),
        "the proof-namespace rail is mounted and reachable without enforcement"
    );

    // Enforcement alone is not enough either: with no service mounted there
    // is nothing to look a receipt up through.
    let unmounted = lore_server::server::compiled_features(false, true);
    assert!(
        !unmounted
            .iter()
            .any(|feature| feature.starts_with("domain_operation_")),
        "an unmounted service advertises neither domain rail"
    );
}

#[test]
fn the_receipt_capability_predicate_needs_both_halves() {
    use lore_server::grpc::server::domain_operation_receipt_capability_available;

    for (service, enforcement, expected) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        assert_eq!(
            domain_operation_receipt_capability_available(service, enforcement),
            expected,
            "service={service} enforcement={enforcement}"
        );
    }
}

#[test]
fn domain_operation_service_availability_requires_every_runtime_dependency() {
    use lore_server::grpc::server::domain_operation_service_available;

    for (name, has_domain_context, auth_url, auth_enabled, expected) in [
        (
            "enabled",
            true,
            Some("https://auth-grpc.example"),
            true,
            true,
        ),
        (
            "missing domain context",
            false,
            Some("https://auth-grpc.example"),
            true,
            false,
        ),
        ("missing auth URL", true, None, true, false),
        (
            "authentication disabled",
            true,
            Some("https://auth-grpc.example"),
            false,
            false,
        ),
    ] {
        assert_eq!(
            domain_operation_service_available(has_domain_context, auth_url, auth_enabled),
            expected,
            "availability mismatch for {name}"
        );
    }
}

mod maintenance_cli {
    use clap::Parser;
    use lore_server::server::Cli;
    use lore_server::server::ensure_postgres_rebuild_mode;

    #[test]
    fn parses_rebuild_postgres_metering_flag() {
        let cli = Cli::try_parse_from(["loreserver", "--rebuild-postgres-metering"])
            .expect("maintenance flag should parse");

        assert!(cli.rebuild_postgres_metering);
    }

    #[test]
    fn rebuild_postgres_metering_defaults_off() {
        let cli = Cli::try_parse_from(["loreserver"]).expect("default CLI should parse");

        assert!(!cli.rebuild_postgres_metering);
    }

    #[test]
    fn rebuild_refuses_non_postgres_immutable_mode() {
        let error = ensure_postgres_rebuild_mode("local")
            .expect_err("maintenance must fail closed for non-Postgres modes");

        assert!(error.to_string().contains("effective mode is 'local'"));
    }

    #[test]
    fn rebuild_accepts_postgres_immutable_mode() {
        ensure_postgres_rebuild_mode("postgres")
            .expect("Postgres immutable mode should be accepted");
    }
}

mod wait_for_shutdown_tests {
    use std::time::Duration;

    use lore_server::server::wait_for_shutdown;
    use tokio::sync::watch;
    use tokio::task::JoinSet;

    /// CR-009 default-off regression: `Some(timeout)` — today's behavior
    /// (`connection_close_timeout_seconds`, unaffected by `graceful_drain`)
    /// — must still force-abort a stuck endpoint once the timeout elapses,
    /// not before and not never.
    #[tokio::test(start_paused = true)]
    async fn bounded_timeout_force_aborts_a_stuck_endpoint() {
        let (shutdown_tx, _rx) = watch::channel(false);
        let mut endpoints: JoinSet<anyhow::Result<()>> = JoinSet::new();
        lore_base::lore_spawn!(endpoints, async {
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok(())
        });

        shutdown_tx.send(true).expect("receiver still alive");

        let start = tokio::time::Instant::now();
        wait_for_shutdown(endpoints, shutdown_tx, Some(Duration::from_secs(2)))
            .await
            .expect("wait_for_shutdown should not error even when force-aborting");

        assert!(
            tokio::time::Instant::now() - start >= Duration::from_secs(2),
            "must wait out the full connection_close_timeout before force-aborting"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_timeout_returns_early_once_endpoint_finishes_on_its_own() {
        let (shutdown_tx, _rx) = watch::channel(false);
        let mut endpoints: JoinSet<anyhow::Result<()>> = JoinSet::new();
        lore_base::lore_spawn!(endpoints, async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok(())
        });

        shutdown_tx.send(true).expect("receiver still alive");

        tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_shutdown(endpoints, shutdown_tx, Some(Duration::from_secs(30))),
        )
        .await
        .expect(
            "wait_for_shutdown should return once the endpoint finishes, \
             well before the 30s ceiling",
        )
        .expect("wait_for_shutdown returned an error");
    }

    /// The new unbounded mode (`drain_timeout_seconds = 0` -> `None`):
    /// must outlast a transfer longer than the old hard-coded 5s default
    /// instead of force-aborting it.
    #[tokio::test(start_paused = true)]
    async fn unbounded_none_timeout_waits_for_a_slow_endpoint_instead_of_force_aborting() {
        let (shutdown_tx, _rx) = watch::channel(false);
        let mut endpoints: JoinSet<anyhow::Result<()>> = JoinSet::new();
        lore_base::lore_spawn!(endpoints, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        });

        shutdown_tx.send(true).expect("receiver still alive");

        tokio::time::timeout(
            Duration::from_secs(30),
            wait_for_shutdown(endpoints, shutdown_tx, None),
        )
        .await
        .expect("wait_for_shutdown should eventually return once the slow endpoint finishes")
        .expect("wait_for_shutdown returned an error");
    }
}

/// FORK-LOCAL (Tideshift): WP-120 public-QUIC caller-capability wiring.
mod quic_caller_capability_wiring;

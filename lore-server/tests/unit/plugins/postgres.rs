// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lore_base::types::KeyType;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_postgres::domain::DomainPoolLayout;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
use lore_postgres::domain::fragments::FragmentProcessPoolInventory;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::write_behind::drain_reserve::DrainReserveSettings;
use lore_server::plugins::ImmutableStorePluginFactory;
use lore_server::plugins::LockStorePluginFactory;
use lore_server::plugins::MutableStorePluginContext;
use lore_server::plugins::MutableStorePluginFactory;
use lore_server::plugins::PluginError;
use lore_server::plugins::postgres::*;
use lore_server::settings::Settings;
use lore_storage::Hash;
use lore_storage::ImmutableStore;
use lore_storage::Partition;

/// Real startup construction must bind the initialized object namespace before
/// dispatch setup. Live-only (#[ignore]); driven by
/// lore-postgres/tests/run-fragment-clean-init-live.ps1.
#[path = "../../common/clean_init_construction.rs"]
mod clean_init_construction_tests;

/// The `oodle` Cargo feature must reach `lore-postgres`, not only
/// `lore-revision`.
///
/// `lore-postgres`'s copy gates no codec of its own. It gates a
/// **diagnostic**: CR-031's coordinator distinguishes a damaged payload
/// (repairable in band) from an intact one this build has no codec for
/// (needs a differently-built binary). A server whose codec is enabled but
/// whose coordinator does not know it would report a perfectly decodable
/// legacy Oodle2 object as unrepairable, sending an operator hunting for
/// damage that is not there.
///
/// Cargo cannot express "these two features move together", so this is the
/// guard. It compiles in both configurations and fails only when the two
/// disagree, which is exactly the drift a hand-edited feature list produces.
#[test]
fn the_oodle_feature_chain_reaches_lore_postgres() {
    use lore_base::types::FragmentFlags;
    use lore_postgres::domain::fragments::DecodeSupport;
    use lore_postgres::domain::fragments::decodable_encoding;

    let verdict = decodable_encoding(FragmentFlags::PayloadCompressedOodle2.bits());
    let expected = if cfg!(feature = "oodle") {
        DecodeSupport::Supported
    } else {
        DecodeSupport::RecognizedUnsupported
    };
    assert_eq!(
        verdict, expected,
        "lore-server's `oodle` feature must forward to lore-postgres/oodle; \
         without it the coordinator misreports a decodable Oodle2 object as unrepairable"
    );
}

/// The `failure_generator` Cargo feature must reach `lore-postgres`, not
/// only `lore-storage`.
///
/// WP-118 Phase 9's failpoints live in `lore-postgres`'s fragment lifecycle
/// coordinator, and WP-109's two-process proof drives its races through
/// them. If `lore-server/failure_generator` forwarded only to
/// `lore-storage`, the coordinator's failpoint module would not be
/// compiled: every `LORE_FRAGMENT_FAILPOINTS` anchor would be a silent
/// no-op, and the proof would report green having raced nothing. That is a
/// worse failure than a build error, because it looks like evidence.
///
/// Env marker that turns a re-executed copy of this test binary into the
/// child half of [`the_failpoint_boot_banner_actually_reaches_stderr`].
const BANNER_CHILD_MARKER: &str = "LORE_TEST_FRAGMENT_FAILPOINT_BANNER_CHILD";

/// The boot banner must actually be emitted, not merely be present in
/// source.
///
/// This is an executed proof on purpose. The previous version of this
/// warning used `tracing::warn!` and was correct-looking, unreachable, and
/// shipped: `register_all_plugins` runs before the telemetry subscriber is
/// installed, so the event went nowhere. A source-ordering argument is what
/// produced that defect, so it cannot be what closes it.
///
/// The child re-executes this same test binary with a marker in its
/// environment, runs the real [`register_all_plugins`] path against a fresh
/// registry, and exits. The parent asserts on its stderr — which needs no
/// subscriber, no configuration file, and no server boot.
///
/// It asserts in **both** directions: the banner is present in a
/// `failure_generator` build and absent in a default one. The second half
/// is what pins that an ordinary production binary stays silent.
#[test]
fn the_failpoint_boot_banner_actually_reaches_stderr() {
    if std::env::var(BANNER_CHILD_MARKER).is_ok() {
        // Child: exercise the real registration path and let the banner (if
        // this build has one) go to the inherited stderr.
        let mut registry = lore_server::plugins::PluginRegistry::new();
        lore_server::plugins::register_all_plugins(&mut registry);
        return;
    }

    let exe = std::env::current_exe().expect("the test binary must know its own path");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "plugins::postgres::the_failpoint_boot_banner_actually_reaches_stderr",
            "--nocapture",
        ])
        .env(BANNER_CHILD_MARKER, "1")
        .output()
        .expect("the child test process must run");
    let stderr = String::from_utf8_lossy(&output.stderr);

    if cfg!(feature = "failure_generator") {
        assert!(
            stderr.contains(FRAGMENT_FAILPOINTS_COMPILED_BANNER),
            "a failure_generator build must announce its failpoints on stderr at plugin \
             registration, because that runs before any tracing subscriber exists. \
             stderr was:\n{stderr}"
        );
    } else {
        assert!(
            !stderr.contains("failure_generator"),
            "a default build must not announce failpoints it does not carry. \
             stderr was:\n{stderr}"
        );
    }
}

/// Second instance of the same guard shape as the `oodle` chain above, for
/// the same reason: Cargo cannot express "these two features move
/// together", so a hand-edited feature list is the drift and a test
/// compiled in both configurations is the only thing that sees it.
#[test]
fn the_failpoint_feature_chain_reaches_lore_postgres() {
    assert_eq!(
        lore_postgres::domain::fragments::failpoints_compiled(),
        cfg!(feature = "failure_generator"),
        "lore-server's `failure_generator` feature must forward to \
         lore-postgres/failure_generator; without it WP-109's failpoints are inert and its \
         barriers race nothing"
    );
}

// CR-031's in-flight put bound. Validation is the only live behavior here —
// no gateway is constructed until Phase 5 — so these pin that an impossible
// bound is refused at startup and that the default is the seam's own.

fn immutable_config(extra: &str) -> toml::Value {
    // The extra keys go above the `[object_store]` header on purpose: a TOML
    // key after a table header belongs to that table, so appending would
    // have set `object_store.fragment_in_flight_puts` and proved nothing.
    let text = format!(
        r#"
url = "postgres://localhost/lore"
{extra}
[object_store]
bucket = "fragments"
"#
    );
    match toml::from_str(&text) {
        Ok(config) => config,
        Err(error) => panic!("fixture config must parse: {error}"),
    }
}

#[test]
fn the_fragment_in_flight_put_bound_defaults_to_the_seams_own_default() {
    let parsed: PostgresStoreConfig = match immutable_config("").try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    assert_eq!(
        parsed.fragment_in_flight_puts,
        lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_PUTS,
    );
    assert!(validate_fragment_put_bound(PLUGIN_NAME, &parsed).is_ok());
}

/// The bad values, and the strings that must name them.
const IMPOSSIBLE_PUT_BOUNDS: [&str; 3] = [
    "fragment_in_flight_puts = 0",
    "fragment_in_flight_puts = 100000",
    "fragment_put_admission_wait_millis = 0",
];

const ADMISSION_REFUSAL: &str = "fragment lifecycle provider admission config";

/// `validate_config` refuses an impossible bound in every factory. The field
/// lives on `PostgresStoreConfig`, so an operator can put it under any of
/// the three `[plugins.postgres.*]` sections.
#[test]
fn an_impossible_fragment_put_bound_is_refused_by_every_validate_config() {
    type ValidateFn<'a> = &'a dyn Fn(&toml::Value) -> Result<(), PluginError>;

    let factories: [(&str, ValidateFn<'_>); 3] = [
        ("immutable", &|config| {
            PostgresImmutableStorePluginFactory.validate_config(config)
        }),
        ("mutable", &|config| {
            PostgresMutableStorePluginFactory.validate_config(config)
        }),
        ("lock", &|config| {
            PostgresLockStorePluginFactory.validate_config(config)
        }),
    ];
    for extra in IMPOSSIBLE_PUT_BOUNDS {
        let config = immutable_config(extra);
        for (label, validate) in &factories {
            let error =
                validate(&config).expect_err("an impossible in-flight put bound must be refused");
            assert!(
                format!("{error}").contains(ADMISSION_REFUSAL),
                "{extra} must be refused by name in the {label} factory, got {error}",
            );
        }
    }
}

/// **This is the one that matters, and it is the one that was missing.**
///
/// `validate_config` is not on loreserver's boot path: `server.rs` reaches
/// `create()` directly, and the trait method's only callers live in
/// `settings.rs`'s own tests. A cell configured with
/// `fragment_in_flight_puts = 0` therefore booted clean while this file's
/// docs said it was refused at startup. The check now lives in
/// `parse_config`, which every `create()` runs.
///
/// No database is needed: the refusal happens while parsing, before any
/// connection is attempted, which is also why it is a startup refusal
/// rather than a first-write one. The URL below points nowhere on purpose —
/// if the refusal ever moved after the connect, this test would hang or
/// fail with a connection error instead of the admission message.
#[test]
fn an_impossible_fragment_put_bound_refuses_the_construction_path() {
    for extra in IMPOSSIBLE_PUT_BOUNDS {
        let config = immutable_config(extra);

        match PostgresLockStorePluginFactory.create(&config) {
            Err(error) => assert!(
                format!("{error}").contains(ADMISSION_REFUSAL),
                "{extra} must be refused by the lock store's create(), got {error}",
            ),
            Ok(_) => panic!("{extra} must not produce a lock store"),
        }

        // The immutable store's construction path is shared with offline
        // maintenance, so it is checked at that seam rather than through
        // the plugin trait's `create`, which additionally builds an S3
        // client.
        let immutable = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(connect_immutable_store(&config, None, None)));
        match immutable {
            Ok(Err(error)) => assert!(
                format!("{error}").contains(ADMISSION_REFUSAL),
                "{extra} must be refused by connect_immutable_store, got {error}",
            ),
            Ok(Ok(_)) => panic!("{extra} must not produce an immutable store"),
            Err(error) => panic!("the test runtime must build: {error}"),
        }
    }
}

#[test]
fn a_valid_fragment_put_bound_passes_config_validation() {
    let config =
        immutable_config("fragment_in_flight_puts = 16\nfragment_put_admission_wait_millis = 250");
    assert!(
        PostgresImmutableStorePluginFactory
            .validate_config(&config)
            .is_ok()
    );
    let parsed: PostgresStoreConfig = match config.try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    let bound = match validate_fragment_put_bound(PLUGIN_NAME, &parsed) {
        Ok(bound) => bound,
        Err(error) => panic!("a valid bound must validate: {error}"),
    };
    assert_eq!(bound.permits(), 16);
    assert_eq!(
        bound.acquire_timeout(),
        std::time::Duration::from_millis(250)
    );
}

// The charge-admission bound (CR-033 charge authority pool exhaustion).
// Same fixture shape as the in-flight-put-bound tests directly above --
// `fragment_in_flight_charges`/`fragment_charge_admission_wait_millis` sit
// on the same shared `PostgresStoreConfig`.

#[test]
fn the_fragment_in_flight_charge_bound_defaults_to_the_seams_own_default() {
    let parsed: PostgresStoreConfig = match immutable_config("").try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    assert_eq!(
        parsed.fragment_in_flight_charges,
        lore_postgres::domain::fragments::DEFAULT_IN_FLIGHT_CHARGES,
    );
    assert!(validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok());
}

/// The bad values, and the strings that must name them.
const IMPOSSIBLE_CHARGE_BOUNDS: [&str; 3] = [
    "fragment_in_flight_charges = 0",
    "fragment_in_flight_charges = 100000",
    "fragment_charge_admission_wait_millis = 0",
];

const CHARGE_ADMISSION_REFUSAL: &str = "fragment lifecycle provider charge-admission config";

/// Mirrors `an_impossible_fragment_put_bound_is_refused_by_every_validate_config`
/// exactly. The field lives on the same `PostgresStoreConfig` as the put
/// bound, so the same claim -- any of the three `[plugins.postgres.*]`
/// sections gets refused by name -- should hold for it too.
#[test]
fn an_impossible_fragment_charge_bound_is_refused_by_every_validate_config() {
    type ValidateFn<'a> = &'a dyn Fn(&toml::Value) -> Result<(), PluginError>;

    let factories: [(&str, ValidateFn<'_>); 3] = [
        ("immutable", &|config| {
            PostgresImmutableStorePluginFactory.validate_config(config)
        }),
        ("mutable", &|config| {
            PostgresMutableStorePluginFactory.validate_config(config)
        }),
        ("lock", &|config| {
            PostgresLockStorePluginFactory.validate_config(config)
        }),
    ];
    for extra in IMPOSSIBLE_CHARGE_BOUNDS {
        let config = immutable_config(extra);
        for (label, validate) in &factories {
            let error = validate(&config)
                .expect_err("an impossible in-flight charge bound must be refused");
            assert!(
                format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                "{extra} must be refused by name in the {label} factory, got {error}",
            );
        }
    }
}

/// Mirrors `an_impossible_fragment_put_bound_refuses_the_construction_path`:
/// the lock store's `create()` (no database needed -- the URL points
/// nowhere) and the immutable store's shared `connect_immutable_store`
/// path must both refuse before any connection is attempted.
#[test]
fn an_impossible_fragment_charge_bound_refuses_the_construction_path() {
    for extra in IMPOSSIBLE_CHARGE_BOUNDS {
        let config = immutable_config(extra);

        match PostgresLockStorePluginFactory.create(&config) {
            Err(error) => assert!(
                format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                "{extra} must be refused by the lock store's create(), got {error}",
            ),
            Ok(_) => panic!("{extra} must not produce a lock store"),
        }

        let immutable = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(connect_immutable_store(&config, None, None)));
        match immutable {
            Ok(Err(error)) => assert!(
                format!("{error}").contains(CHARGE_ADMISSION_REFUSAL),
                "{extra} must be refused by connect_immutable_store, got {error}",
            ),
            Ok(Ok(_)) => panic!("{extra} must not produce an immutable store"),
            Err(error) => panic!("the test runtime must build: {error}"),
        }
    }
}

#[test]
fn a_valid_fragment_charge_bound_passes_config_validation() {
    let config = immutable_config(
        "fragment_in_flight_charges = 8\nfragment_charge_admission_wait_millis = 1500",
    );
    assert!(
        PostgresImmutableStorePluginFactory
            .validate_config(&config)
            .is_ok()
    );
    let parsed: PostgresStoreConfig = match config.try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    let bound = match validate_fragment_charge_bound(PLUGIN_NAME, &parsed) {
        Ok(bound) => bound,
        Err(error) => panic!("a valid bound must validate: {error}"),
    };
    assert_eq!(bound.permits(), 8);
    assert_eq!(
        bound.acquire_timeout(),
        std::time::Duration::from_millis(1500)
    );
}

// The horizon guard (`validate_fragment_charge_bound`'s own refusal, on top
// of the impossible-bound checks above): `fragment_charge_admission_wait_millis`
// plus `object_store.timeout_millis` must fit inside
// `FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS`, because `admit_operation`
// shifts a queued attempt's deadline forward by exactly the wait, but the
// horizon is anchored to the attempt id's timestamp minted before that
// wait. `immutable_config`'s object-store block always deserializes with
// the seam's own `default_timeout()` (5_000ms) for `timeout_millis`, so
// these three pin the sum at, one over, and without that contribution at
// all.

#[test]
fn a_fragment_charge_bound_exactly_at_the_deadline_horizon_passes_config_validation() {
    let wait_millis = FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS - default_timeout();
    let config = immutable_config(&format!(
        "fragment_charge_admission_wait_millis = {wait_millis}"
    ));
    let parsed: PostgresStoreConfig = match config.try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    assert_eq!(
        parsed
            .object_store
            .as_ref()
            .map(|object_store| object_store.timeout_millis),
        Some(default_timeout()),
        "fixture must exercise the seam's own default object_store timeout"
    );
    assert_eq!(
        wait_millis + default_timeout(),
        FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS,
        "fixture arithmetic must land exactly on the horizon"
    );
    assert!(
        validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok(),
        "a combination exactly equal to the horizon must be admitted, not refused"
    );
}

#[test]
fn a_fragment_charge_bound_one_millisecond_over_the_horizon_is_refused_naming_both_keys() {
    let wait_millis = FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS - default_timeout() + 1;
    let config = immutable_config(&format!(
        "fragment_charge_admission_wait_millis = {wait_millis}"
    ));
    let parsed: PostgresStoreConfig = match config.try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    let error = validate_fragment_charge_bound(PLUGIN_NAME, &parsed)
        .expect_err("one millisecond over the horizon must be refused");
    let message = format!("{error}");
    assert!(
        message.contains("fragment_charge_admission_wait_millis"),
        "error must name fragment_charge_admission_wait_millis, got {message}"
    );
    assert!(
        message.contains("object_store.timeout_millis"),
        "error must name object_store.timeout_millis, got {message}"
    );
}

/// An absent `[object_store]` block contributes 0 to the horizon sum, not
/// some other default. Pinned by proving the full horizon is still
/// admissible as a wait alone when the block is entirely absent -- if
/// absence contributed any nonzero amount (e.g. the seam's own
/// `default_timeout()`), this combination would be refused.
#[test]
fn an_absent_object_store_block_contributes_zero_to_the_charge_bound_horizon_sum() {
    let text = format!(
        "url = \"postgres://localhost/lore\"\n\
         fragment_charge_admission_wait_millis = {FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS}\n"
    );
    let config: toml::Value = match toml::from_str(&text) {
        Ok(config) => config,
        Err(error) => panic!("fixture config must parse: {error}"),
    };
    let parsed: PostgresStoreConfig = match config.try_into() {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    };
    assert!(
        parsed.object_store.is_none(),
        "fixture must exercise the truly-absent case, not a present-but-default block"
    );
    assert!(
        validate_fragment_charge_bound(PLUGIN_NAME, &parsed).is_ok(),
        "a wait equal to the full horizon must be admitted when object_store is absent, \
         proving the absent block contributes 0 to the sum rather than some nonzero default"
    );
}

/// `fragment_in_flight_charges`/`fragment_charge_admission_wait_millis`
/// live on the shared `PostgresStoreConfig`, not on
/// `FragmentProviderConfig` -- which is `#[serde(deny_unknown_fields)]`.
/// Putting either key under `[fragment_provider]` instead of the
/// top-level table must be a hard deserialization refusal naming the
/// misplaced key, not a silently-ignored value.
#[test]
fn a_charge_bound_key_under_fragment_provider_is_an_unknown_field() {
    let config = enabled_fragment_provider_config("fragment_in_flight_charges = 8");
    let parsed: Result<PostgresStoreConfig, _> = config.try_into();
    let error = match parsed {
        Err(error) => error,
        Ok(_) => {
            panic!("fragment_in_flight_charges under [fragment_provider] must not deserialize")
        }
    };
    assert!(
        format!("{error}").contains("fragment_in_flight_charges"),
        "the deserialization error must name the misplaced key, got {error}",
    );
}

// WP-114 CD-6/CD-8's settings-mapping wiring. `fragment_prune_settings` and
// `cell_retention_settings` are `pub(crate)`, so nothing outside this file
// can exercise them directly; both are covered here, in the same fixture
// style as the in-flight-put-bound tests above. Neither had a same-file
// unit test before this pass (`fragment_prune_settings` had none at all).

/// A fully valid, `enabled = true` `[fragment_provider]` block (every
/// field `enabled_fragment_provider_config` requires, mirroring
/// `heterogeneous_store_configuration_builds_the_exact_five_pool_inventory`'s
/// fixture below), with `extra` appended inside that same table.
///
/// `parse_config` runs `enabled_fragment_provider_config` unconditionally
/// once `enabled = true`, regardless of which sub-feature a test actually
/// means to exercise, so a prune/retention-only test still needs every
/// dispatch/boundary/budget key present or it fails on
/// `dispatch_pool_max` before ever reaching the field under test.
fn enabled_fragment_provider_config(extra: &str) -> toml::Value {
    let text = format!(
        r#"
url = "postgresql://immutable@db.example/cell"
pool_max = 1
[object_store]
bucket = "fragments"
endpoint_url = "http://minio:9000"
region = "us-test-1"
timeout_millis = 5000
[fragment_provider]
enabled = true
dispatch_postgres_url = "postgresql://dispatcher@db-alias.example/cell?sslmode=require"
dispatch_ca_cert_path = "C:/secrets/dispatch-ca.pem"
dispatch_pool_max = 5
dispatch_connect_timeout_millis = 1000
dispatch_acquire_timeout_millis = 1000
dispatch_statement_timeout_millis = 2000
dispatch_lock_timeout_millis = 3000
provider_boundary_id = "cell.primary"
endpoint_host = "minio"
region = "us-test-1"
budget_revision = "budget-v1"
budget_fence = 7
provider_late_effect_bound_millis = 60000
{extra}
"#
    );
    match toml::from_str(&text) {
        Ok(config) => config,
        Err(error) => panic!("fixture config must parse: {error}"),
    }
}

#[test]
fn fragment_prune_settings_is_none_when_fragment_provider_is_absent() {
    let config = immutable_config("");
    assert!(
        fragment_prune_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

#[test]
fn fragment_prune_settings_is_none_when_fragment_provider_is_disabled() {
    let config = immutable_config("[fragment_provider]\nenabled = false\n");
    assert!(
        fragment_prune_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

#[test]
fn fragment_prune_settings_is_none_when_prune_enabled_is_false() {
    let config = enabled_fragment_provider_config("prune_enabled = false");
    assert!(
        fragment_prune_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

/// `prune_enabled` omitted (as opposed to explicitly `false`) means
/// enabled, and every other key omitted takes the scheduler's own
/// defaults.
#[test]
fn fragment_prune_settings_defaults_when_enabled_with_no_other_keys() {
    let config = enabled_fragment_provider_config("");
    let settings = fragment_prune_settings(&config)
        .expect("must not error")
        .expect("an enabled block with no prune_enabled must produce settings");
    assert_eq!(
        settings,
        lore_server::fragment_prune::FragmentPruneSettings::default()
    );
}

/// Every explicit key lands on the field its name says, not a
/// transposed neighbor.
#[test]
fn fragment_prune_settings_threads_explicit_values_in_the_right_positions() {
    let config = enabled_fragment_provider_config(
        "prune_interval_millis = 5000\nprune_batch = 77\n\
         prune_terminal_retention_millis = 90000\nprune_stall_ticks = 5",
    );
    let settings = fragment_prune_settings(&config)
        .expect("must not error")
        .expect("enabled settings must produce a value");
    assert_eq!(settings.interval, Duration::from_millis(5_000));
    assert_eq!(settings.batch, 77);
    assert_eq!(settings.terminal_retention, Duration::from_millis(90_000));
    assert_eq!(settings.stall_ticks, 5);
}

/// Each out-of-bounds key is refused, and named by its own field --
/// proves the four constructor arguments were not transposed en route
/// from the parsed config to `FragmentPruneSettings::new`.
#[test]
fn fragment_prune_settings_out_of_bounds_values_name_their_own_field() {
    let cases = [
        (
            "prune_interval_millis = 999",
            "fragment_provider.prune_interval_millis",
        ),
        ("prune_batch = 0", "fragment_provider.prune_batch"),
        (
            "prune_terminal_retention_millis = 0",
            "fragment_provider.prune_terminal_retention_millis",
        ),
        (
            "prune_stall_ticks = 0",
            "fragment_provider.prune_stall_ticks",
        ),
    ];
    for (bad_key, expected_field) in cases {
        let config = enabled_fragment_provider_config(bad_key);
        let error =
            fragment_prune_settings(&config).expect_err(&format!("{bad_key} must be refused"));
        assert!(
            error.to_string().contains(expected_field),
            "{bad_key} must be refused by name ({expected_field}), got {error}"
        );
    }
}

#[test]
fn cell_retention_settings_is_none_when_fragment_provider_is_absent() {
    let config = immutable_config("");
    assert!(
        cell_retention_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

#[test]
fn cell_retention_settings_is_none_when_fragment_provider_is_disabled() {
    let config = immutable_config("[fragment_provider]\nenabled = false\n");
    assert!(
        cell_retention_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

/// Distinct from an absent `fragment_provider` block and from omitting
/// the key entirely: an operator's explicit opt-out, which
/// `cell_retention_settings` checks with `== Some(false)`, not a falsy
/// coercion of `Option<bool>`.
#[test]
fn cell_retention_settings_is_none_when_cell_retention_enabled_is_false() {
    let config = enabled_fragment_provider_config("cell_retention_enabled = false");
    assert!(
        cell_retention_settings(&config)
            .expect("must not error")
            .is_none()
    );
}

/// `cell_retention_enabled` omitted means enabled, on the same reasoning
/// as `prune_enabled` above, and every other key omitted takes
/// `CellRetentionSettings`' own defaults.
#[test]
fn cell_retention_settings_defaults_when_enabled_with_no_other_keys() {
    let config = enabled_fragment_provider_config("");
    let settings = cell_retention_settings(&config)
        .expect("must not error")
        .expect("an enabled block with no cell_retention_enabled must produce settings");
    assert_eq!(settings, CellRetentionSettings::default());
}

/// Every explicit key lands on the field its name says, not a
/// transposed neighbor.
#[test]
fn cell_retention_settings_threads_explicit_values_in_the_right_positions() {
    let config = enabled_fragment_provider_config(
        "cell_retention_enabled = true\ncell_retention_interval_millis = 5000\n\
         cell_retention_batch = 50\ncell_retention_terminal_retention_millis = 120000\n\
         cell_retention_stall_ticks = 4",
    );
    let settings = cell_retention_settings(&config)
        .expect("must not error")
        .expect("enabled settings must produce a value");
    assert_eq!(settings.interval, Duration::from_millis(5_000));
    assert_eq!(settings.batch, 50);
    assert_eq!(settings.terminal_retention, Duration::from_millis(120_000));
    assert_eq!(settings.stall_ticks, 4);
}

/// Each out-of-bounds key is refused, and named by its own field --
/// proves the four constructor arguments were not transposed en route
/// from the parsed config to `CellRetentionSettings::new`.
#[test]
fn cell_retention_settings_out_of_bounds_values_name_their_own_field() {
    let cases = [
        (
            "cell_retention_interval_millis = 999",
            "cell_retention.interval_millis",
        ),
        ("cell_retention_batch = 0", "cell_retention.batch"),
        (
            "cell_retention_terminal_retention_millis = 0",
            "cell_retention.terminal_retention_millis",
        ),
        (
            "cell_retention_stall_ticks = 0",
            "cell_retention.stall_ticks",
        ),
    ];
    for (bad_key, expected_field) in cases {
        let config = enabled_fragment_provider_config(bad_key);
        let error =
            cell_retention_settings(&config).expect_err(&format!("{bad_key} must be refused"));
        assert!(
            error.to_string().contains(expected_field),
            "{bad_key} must be refused by name ({expected_field}), got {error}"
        );
    }
}

#[test]
fn heterogeneous_store_configuration_builds_the_exact_five_pool_inventory() {
    let immutable: toml::Value = toml::from_str(
        r#"
url = "postgresql://immutable@db.example/cell"
pool_max = 1
[object_store]
bucket = "fragments"
endpoint_url = "http://minio:9000"
region = "us-test-1"
timeout_millis = 5000
[fragment_provider]
enabled = true
dispatch_postgres_url = "postgresql://dispatcher@db-alias.example/cell?sslmode=require"
dispatch_ca_cert_path = "C:/secrets/dispatch-ca.pem"
dispatch_pool_max = 5
dispatch_connect_timeout_millis = 1000
dispatch_acquire_timeout_millis = 1000
dispatch_statement_timeout_millis = 2000
dispatch_lock_timeout_millis = 3000
provider_boundary_id = "cell.primary"
endpoint_host = "minio"
region = "us-test-1"
budget_revision = "budget-v1"
budget_fence = 7
provider_late_effect_bound_millis = 60000
"#,
    )
    .expect("immutable config");
    let mutable: toml::Value = toml::from_str(
        r#"
url = "postgresql://mutable@db.example/cell"
pool_max = 2
domain_pool_max = 4
"#,
    )
    .expect("mutable config");
    let lock: toml::Value = toml::from_str(
        r#"
url = "postgresql://lock@db.example/cell"
pool_max = 3
"#,
    )
    .expect("lock config");

    let inventory = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), false)
        .expect("valid inventory");
    assert_eq!(
        inventory,
        FragmentProcessPoolInventory {
            immutable_pool_max: 1,
            mutable_pool_max: 2,
            lock_pool_max: 3,
            domain_pool_max: 4,
            dispatch_pool_max: 5,
            relay_pool_max: 0,
        }
    );

    // The relay flag decides presence, not size. With `[outbox_relay]` on,
    // the same three store configurations must reserve CR-032's whole pool
    // and nothing else about the inventory may move.
    let with_relay = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), true)
        .expect("valid inventory");
    assert_eq!(
        with_relay,
        FragmentProcessPoolInventory {
            relay_pool_max: lore_server::event_relay::wiring::RELAY_POOL_MAX,
            ..inventory
        }
    );
}

/// The escape this closes: a cell with NO fragment provider still opens the
/// four store and domain pools, and CR-032's relay pool when the relay is
/// on. It used to get no inventory at all, so nothing evaluated the
/// ceiling for it. Now it gets one whose dispatch component is zero.
#[test]
fn a_provider_disabled_cell_still_declares_an_inventory_and_is_held_to_the_ceiling() {
    let immutable: toml::Value = toml::from_str(
        r#"
url = "postgresql://immutable@db.example/cell"
pool_max = 5
"#,
    )
    .expect("immutable config");
    let mutable: toml::Value = toml::from_str(
        r#"
url = "postgresql://mutable@db.example/cell"
pool_max = 5
domain_pool_max = 4
"#,
    )
    .expect("mutable config");
    let lock: toml::Value = toml::from_str(
        r#"
url = "postgresql://lock@db.example/cell"
pool_max = 5
"#,
    )
    .expect("lock config");

    // Relay off: no dispatch pool, no relay pool, 19 connections. Inside
    // the ceiling, and it validates.
    let relay_off = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), false)
        .expect("valid inventory");
    assert_eq!(relay_off.dispatch_pool_max, 0);
    assert_eq!(relay_off.relay_pool_max, 0);
    let validated = relay_off.validate().expect("19 is inside the ceiling");
    assert!(
        !validated.budget().opens_dispatch_pool(),
        "a provider-disabled cell must not look like one that opens a dispatch pool"
    );
    assert_eq!(validated.budget().connections_per_replica(), 19);

    // Relay on: the same cell is 24 and must now refuse, which is exactly
    // the staging shape and exactly what used to pass unevaluated.
    let relay_on = fragment_process_pool_inventory(&immutable, &mutable, Some(&lock), true)
        .expect("valid inventory");
    assert_eq!(
        relay_on.relay_pool_max,
        lore_server::event_relay::wiring::RELAY_POOL_MAX
    );
    assert!(
        relay_on.validate().is_err(),
        "24 connections must be refused on a provider-disabled cell too"
    );

    // A lock store that is not in Postgres mode opens no lock pool, so it
    // is declared as zero rather than skipping the ceiling. Without this
    // the same cell escaped at 10 + 10 + 4 + 5 = 29 against a limit of 20,
    // which is the escape this closes wearing a different hat.
    let no_lock_store =
        fragment_process_pool_inventory(&immutable, &mutable, None, true).expect("valid inventory");
    assert_eq!(no_lock_store.lock_pool_max, 0);
    assert_eq!(
        no_lock_store
            .validate()
            .expect("5 + 5 + 4 + 5 is inside the ceiling")
            .budget()
            .connections_per_replica(),
        19
    );
}

async fn direct_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct schema-state client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

// `domain_pool_max` is deliberately its own knob, not inherited from
// `pool_max` — see the field's own doc comment. These three pin that
// independence at the config-parsing boundary.

#[test]
fn domain_pool_max_defaults_to_four_when_absent() {
    let config: toml::Value = toml::from_str(r#"url = "postgres://localhost/lore""#).unwrap();
    let parsed: PostgresStoreConfig = config.try_into().unwrap();

    assert_eq!(parsed.domain_pool_max, 4);
}

#[test]
fn domain_pool_max_explicit_value_is_honoured() {
    let config: toml::Value = toml::from_str(
        r#"
        url = "postgres://localhost/lore"
        domain_pool_max = 20
        "#,
    )
    .unwrap();
    let parsed: PostgresStoreConfig = config.try_into().unwrap();

    assert_eq!(parsed.domain_pool_max, 20);
}

#[test]
fn pool_max_alone_does_not_change_domain_pool_max() {
    let config: toml::Value = toml::from_str(
        r#"
        url = "postgres://localhost/lore"
        pool_max = 50
        "#,
    )
    .unwrap();
    let parsed: PostgresStoreConfig = config.try_into().unwrap();

    assert_eq!(parsed.pool_max, 50);
    assert_eq!(
        parsed.domain_pool_max, 4,
        "domain_pool_max must not inherit pool_max"
    );
}

// WP-114 CD-7 / WP-122 L5: the `[write_behind]` block.
//
// Every case below is executed on both platforms except the two that name a
// platform in their own title. That is why `enabled_write_behind_settings`
// runs its content and coupling checks *before* D13's Unix gate: with the
// gate first, none of this would ever run on the rig this fork is written
// on.

/// An absolute path on the host running the test.
///
/// The `cfg!(windows)` fork is load-bearing, not cosmetic, and it is the
/// same trap that made all seven of `lore-fragment-provider`'s drain cases
/// fail on Linux while passing here: a `C:\` literal is not `is_absolute()`
/// on Linux, and a `/var/...` literal is not `is_absolute()` on Windows, so
/// a single literal makes the valid fixture invalid on one of the two
/// platforms — and production is the Linux one.
fn staging_root() -> &'static str {
    if cfg!(windows) {
        "C:/lore/staging"
    } else {
        "/var/lib/loreserver/staging"
    }
}

/// The object-dispatch spool root, on the same platform fork and for the
/// same reason as [`staging_root`].
///
/// A sibling of the staging root rather than a child of it, because D15's
/// whole point is that these are two trees. A fixture that nested them
/// would be refused by the separateness check and every case built on it
/// would fail for the wrong reason.
fn spool_root() -> &'static str {
    if cfg!(windows) {
        "C:/lore/spool"
    } else {
        "/var/lib/loreserver/spool"
    }
}

/// A `[write_behind]` block with every required key present and coherent.
fn valid_write_behind_block() -> String {
    format!(
        r#"
[write_behind]
enabled = true
root = "{}"
spool_root = "{}"
low_bytes = 1000
high_bytes = 2000
hard_bytes = 3000
low_count = 10
high_count = 20
hard_count = 30
min_free_bytes = 4096
drain_stale_after_millis = 30000
sample_interval_millis = 5000
cell_id = "fixture-cell"
policy_revision = "fixture-policy-v1"
policy_digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        staging_root(),
        spool_root()
    )
}

/// The raw block, parsed out of a config that also enables a provider, so
/// the coupling check has something to find.
fn parsed_config_with(write_behind: &str) -> PostgresStoreConfig {
    let text = format!(
        r#"
url = "postgres://localhost/lore"
[object_store]
bucket = "fragments"
[fragment_provider]
enabled = true
{write_behind}
"#
    );
    match toml::from_str::<toml::Value>(&text).and_then(toml::Value::try_into) {
        Ok(parsed) => parsed,
        Err(error) => panic!("fixture config must deserialize: {error}"),
    }
}

fn raw_write_behind(write_behind: &str) -> WriteBehindConfig {
    match parsed_config_with(write_behind).write_behind {
        Some(raw) => raw,
        None => panic!("fixture must carry a write_behind block"),
    }
}

/// The content half, end to end: a complete block becomes exactly the
/// settings the staging tier takes, with no value invented or rounded.
#[test]
fn a_complete_write_behind_block_converts_to_the_stages_own_settings() {
    let raw = raw_write_behind(&valid_write_behind_block());
    let composition = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
        Ok(composition) => composition,
        Err(error) => panic!("a complete block must validate: {error}"),
    };
    let settings = composition.settings;

    assert_eq!(settings.root, PathBuf::from(staging_root()));
    // D15's two roots arrive as two distinct values from the one block. The
    // inequality is asserted as well as each value, because the failure this
    // guards is not a wrong path but the SAME path arriving twice.
    assert_eq!(
        composition.shared_spool_root,
        PathBuf::from(spool_root()),
        "the spool root must be the spool_root key, not the staging root",
    );
    assert_ne!(composition.shared_spool_root, settings.root);
    assert_eq!(settings.watermarks.low_bytes, 1000);
    assert_eq!(settings.watermarks.high_bytes, 2000);
    assert_eq!(settings.watermarks.hard_bytes, 3000);
    assert_eq!(settings.watermarks.low_count, 10);
    assert_eq!(settings.watermarks.high_count, 20);
    assert_eq!(settings.watermarks.hard_count, 30);
    assert_eq!(settings.watermarks.min_free_bytes, 4096);
    assert_eq!(settings.drain_stale_after, Duration::from_millis(30_000));
    assert_eq!(settings.sample_interval, Duration::from_millis(5_000));
}

/// Absence and `enabled = false` are the two inert cases, and neither is an
/// error: they leave every PUT on the synchronous object-store path.
#[test]
fn an_absent_or_disabled_write_behind_block_opens_no_staging_tier() {
    let absent = parsed_config_with("");
    assert!(matches!(
        enabled_write_behind_settings(PLUGIN_NAME, &absent),
        Ok(None)
    ));

    let disabled = parsed_config_with("[write_behind]\nenabled = false\n");
    assert!(matches!(
        enabled_write_behind_settings(PLUGIN_NAME, &disabled),
        Ok(None)
    ));

    // And the same two through the real boot door, for all three factories.
    for extra in ["", "[write_behind]\nenabled = false\n"] {
        let config = immutable_config(extra);
        assert!(parse_config(PLUGIN_NAME, &config).is_ok());
    }
}

/// There are no defaults, deliberately, so each omitted key must be refused
/// **by name**. A refusal that does not name the key sends an operator
/// looking through a block of twelve of them.
#[test]
fn every_omitted_write_behind_key_is_refused_by_its_own_name() {
    const REQUIRED: [&str; 14] = [
        "root",
        "spool_root",
        "low_bytes",
        "high_bytes",
        "hard_bytes",
        "low_count",
        "high_count",
        "hard_count",
        "min_free_bytes",
        "drain_stale_after_millis",
        "sample_interval_millis",
        "cell_id",
        "policy_revision",
        "policy_digest",
    ];
    let complete = valid_write_behind_block();
    for key in REQUIRED {
        let without = complete
            .lines()
            .filter(|line| !line.starts_with(&format!("{key} =")))
            .collect::<Vec<_>>()
            .join("\n");
        assert_ne!(
            without, complete,
            "the fixture must actually contain {key}, or this case removes nothing"
        );
        let raw = raw_write_behind(&without);
        let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
            Ok(_) => panic!("a block missing {key} must be refused"),
            Err(error) => error.to_string(),
        };
        let named = if key == "root" { "root" } else { key };
        assert!(
            error.contains(named),
            "the refusal for a missing {key} must name it; got {error}"
        );
    }
}

/// An unknown key is a typo, and a typo in a block with no defaults would
/// otherwise be reported as the *adjacent* key being missing.
#[test]
fn an_unknown_write_behind_key_is_refused_rather_than_ignored() {
    let text = format!(
        r#"
url = "postgres://localhost/lore"
{}
staging_root = "/var/lib/loreserver/staging"
"#,
        valid_write_behind_block()
    );
    let value: toml::Value = match toml::from_str(&text) {
        Ok(value) => value,
        Err(error) => panic!("fixture must parse as TOML: {error}"),
    };
    let error = match value.try_into::<PostgresStoreConfig>() {
        Ok(_) => panic!("an unknown write_behind key must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("staging_root"),
        "the refusal must name the unknown key; got {error}"
    );
}

/// The values that are individually present and jointly impossible.
///
/// Each of these produces no error anywhere in the staging tier itself. A
/// mis-ordered pair yields a hysteresis latch that can never clear, which
/// reads as a cell permanently in direct fallback with nothing to explain
/// it; a zero ceiling refuses every PUT the moment occupancy is observed at
/// all, because the watermark comparison is `>=`.
#[test]
fn incoherent_write_behind_thresholds_are_refused_at_configuration_time() {
    // Each case is a set of substitutions, because a zero ceiling on its
    // own also breaks the ordering rule and would be refused by the wrong
    // check — which would leave the positivity check itself unproved.
    const CASES: [(&[(&str, &str)], &str); 7] = [
        (
            &[("low_bytes = 1000", "low_bytes = 2500")],
            "low_bytes <= high_bytes",
        ),
        (
            &[("high_bytes = 2000", "high_bytes = 4000")],
            "high_bytes <= hard_bytes",
        ),
        (
            &[("low_count = 10", "low_count = 25")],
            "low_count <= high_count",
        ),
        (
            &[("high_count = 20", "high_count = 40")],
            "high_count <= hard_count",
        ),
        (
            &[
                ("low_bytes = 1000", "low_bytes = 0"),
                ("high_bytes = 2000", "high_bytes = 0"),
                ("hard_bytes = 3000", "hard_bytes = 0"),
            ],
            "positive",
        ),
        (
            &[
                ("low_count = 10", "low_count = 0"),
                ("high_count = 20", "high_count = 0"),
                ("hard_count = 30", "hard_count = 0"),
            ],
            "positive",
        ),
        (
            &[("min_free_bytes = 4096", "min_free_bytes = 0")],
            "positive",
        ),
    ];
    let complete = valid_write_behind_block();
    for (substitutions, expected) in CASES {
        let mut mutated = complete.clone();
        for (from, to) in substitutions {
            let next = mutated.replace(from, to);
            assert_ne!(
                next, mutated,
                "the fixture must contain `{from}`, or this case mutates nothing"
            );
            mutated = next;
        }
        let raw = raw_write_behind(&mutated);
        let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
            Ok(_) => panic!("{substitutions:?} must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(expected),
            "{substitutions:?} must be refused naming {expected}; got {error}"
        );
    }
}

/// A relative root resolves against the process working directory, which is
/// an operator-invisible input: the same configuration would stage into
/// different filesystems depending on how the unit was launched.
#[test]
fn a_relative_or_empty_staging_root_is_refused() {
    let complete = valid_write_behind_block();
    // Both keys, because `spool_root` is a second absolute path with the
    // same working-directory hazard and nothing about the first key's
    // coverage carries over to it.
    for (key, configured) in [("root", staging_root()), ("spool_root", spool_root())] {
        for (root, expected) in [
            ("staging", "absolute"),
            ("", "non-empty"),
            ("   ", "non-empty"),
        ] {
            let mutated = complete.replace(
                &format!(r#"{key} = "{configured}""#),
                &format!(r#"{key} = "{root}""#),
            );
            assert_ne!(
                mutated, complete,
                "the fixture must contain `{key} = \"{configured}\"`"
            );
            let raw = raw_write_behind(&mutated);
            let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
                Ok(_) => panic!("{key} `{root}` must be refused"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains(expected) && error.contains(key),
                "{key} `{root}` must be refused naming {expected} and {key}; got {error}"
            );
        }
    }
}

/// Owner ruling D15: the staging root and the spool root are two separate
/// trees, and a configuration that merges them is refused rather than
/// honoured.
///
/// This is a correctness refusal, not tidiness. Contract C2's orphan
/// reclaimer enumerates the staging tree and reclaims what the coordinator
/// confirms absent from the epoch table — and a spool file legitimately has
/// no epoch row. So a spool root at, or under, the staging root puts
/// in-flight upload bytes inside the reclaimer's delete set. The reverse
/// nesting is refused too, because it puts a foreign writer inside the tree
/// `ConfinedRoot` fsyncs on every staged write.
///
/// All three shapes are covered — equal, spool under staging, staging under
/// spool — because an equality-only check passes the two that matter.
#[test]
fn a_spool_root_sharing_the_staging_tree_is_refused() {
    let complete = valid_write_behind_block();
    let nested_spool = format!("{}/spool", staging_root());
    let parent_spool = match PathBuf::from(staging_root()).parent() {
        Some(parent) => parent.to_string_lossy().replace('\\', "/"),
        None => panic!("the staging-root fixture must have a parent"),
    };
    for (label, spool) in [
        ("equal", staging_root().to_owned()),
        ("spool under staging", nested_spool),
        ("staging under spool", parent_spool),
    ] {
        let mutated = complete.replace(
            &format!(r#"spool_root = "{}""#, spool_root()),
            &format!(r#"spool_root = "{spool}""#),
        );
        assert_ne!(
            mutated, complete,
            "the {label} case must mutate the fixture"
        );
        let raw = raw_write_behind(&mutated);
        let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
            Ok(_) => panic!("a {label} spool root must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("separate trees"),
            "the {label} case must be refused naming the separateness rule; got {error}"
        );
    }
}

/// The lower bound is not tidiness. The sampler builds a
/// `tokio::time::interval` from `sample_interval_millis`, and that
/// constructor **panics** on a zero period, so without this refusal a
/// zero would be a panicking background task rather than a config error.
/// The upper bound catches the unit mistake: a milliseconds field filled in
/// as if it were seconds.
#[test]
fn out_of_range_write_behind_intervals_are_refused() {
    let complete = valid_write_behind_block();
    const CASES: [(&str, &str); 4] = [
        (
            "sample_interval_millis = 5000",
            "sample_interval_millis = 0",
        ),
        (
            "sample_interval_millis = 5000",
            "sample_interval_millis = 3600001",
        ),
        (
            "drain_stale_after_millis = 30000",
            "drain_stale_after_millis = 0",
        ),
        (
            "drain_stale_after_millis = 30000",
            "drain_stale_after_millis = 3600001",
        ),
    ];
    for (from, to) in CASES {
        let mutated = complete.replace(from, to);
        assert_ne!(mutated, complete, "the fixture must contain `{from}`");
        let raw = raw_write_behind(&mutated);
        let field = to.split(' ').next().unwrap_or_default();
        let error = match validated_write_behind_settings(PLUGIN_NAME, &raw) {
            Ok(_) => panic!("`{to}` must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains(field) && error.contains("between 1 and 3600000"),
            "`{to}` must be refused naming {field} and its bounds; got {error}"
        );
    }
}

/// Row 76: optional, unlike the thresholds, defaulting to the 1 s wait,
/// and capped so a unit mistake cannot park PUTs for minutes.
#[test]
fn stage_io_wait_defaults_to_one_second_and_is_bounded() {
    let complete = valid_write_behind_block();
    let wait = |text: &str| {
        validated_write_behind_settings(PLUGIN_NAME, &raw_write_behind(text))
            .map(|composition| composition.settings.stage_io_wait)
    };
    let with = |millis: u64| {
        let mutated = complete.replace(
            "sample_interval_millis = 5000",
            &format!("sample_interval_millis = 5000\nstage_io_wait_millis = {millis}"),
        );
        assert_ne!(
            mutated, complete,
            "the fixture must set sample_interval_millis"
        );
        mutated
    };
    assert_eq!(wait(&complete).unwrap(), Duration::from_secs(1));
    assert_eq!(wait(&with(0)).unwrap(), Duration::ZERO);
    assert_eq!(wait(&with(10_000)).unwrap(), Duration::from_secs(10));
    let error = match wait(&with(10_001)) {
        Ok(_) => panic!("10001 ms must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("stage_io_wait_millis") && error.contains("between 0 and 10000"),
        "got {error}"
    );
}

/// Row 80 follow-up: the GET read wait is optional, defaults to 250 ms,
/// accepts zero (refuse at once), is bounded like the PUT knob, and is
/// independent of it.
#[test]
fn stage_read_wait_defaults_to_250_ms_and_is_bounded_like_the_put_wait() {
    let complete = valid_write_behind_block();
    let settings = |text: &str| {
        validated_write_behind_settings(PLUGIN_NAME, &raw_write_behind(text))
            .map(|composition| composition.settings)
    };
    let with = |line: &str| {
        let mutated = complete.replace(
            "sample_interval_millis = 5000",
            &format!("sample_interval_millis = 5000\n{line}"),
        );
        assert_ne!(
            mutated, complete,
            "the fixture must set sample_interval_millis"
        );
        mutated
    };
    let defaulted = settings(&complete).unwrap();
    assert_eq!(defaulted.stage_read_wait, Duration::from_millis(250));
    assert_eq!(defaulted.stage_io_wait, Duration::from_secs(1));
    assert_eq!(
        settings(&with("stage_read_wait_millis = 0"))
            .unwrap()
            .stage_read_wait,
        Duration::ZERO
    );
    let tuned = settings(&with("stage_read_wait_millis = 10000")).unwrap();
    assert_eq!(tuned.stage_read_wait, Duration::from_secs(10));
    assert_eq!(
        tuned.stage_io_wait,
        Duration::from_secs(1),
        "the read knob must not move the put knob"
    );
    let error = match settings(&with("stage_read_wait_millis = 10001")) {
        Ok(_) => panic!("10001 ms must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("stage_read_wait_millis") && error.contains("between 0 and 10000"),
        "got {error}"
    );
    // The PUT knob's own bound still names the PUT field.
    let error = match settings(&with("stage_io_wait_millis = 10001")) {
        Ok(_) => panic!("10001 ms must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("stage_io_wait_millis"), "got {error}");
}

/// Row 80 reserve contention: the reserve permit and retry keys are
/// optional, default to one permit and five tries, and refuse zero
/// permits and out-of-range values by name.
#[test]
fn drain_reserve_keys_default_to_one_permit_and_five_tries_and_are_bounded() {
    let complete = valid_write_behind_block();
    let settings = |text: &str| {
        validated_write_behind_settings(PLUGIN_NAME, &raw_write_behind(text))
            .map(|composition| composition.settings.drain_reserve)
    };
    let with = |lines: &str| {
        let mutated = complete.replace(
            "sample_interval_millis = 5000",
            &format!("sample_interval_millis = 5000\n{lines}"),
        );
        assert_ne!(
            mutated, complete,
            "the fixture must set sample_interval_millis"
        );
        mutated
    };
    assert_eq!(
        settings(&complete).unwrap(),
        DrainReserveSettings::default()
    );
    let tuned = settings(&with(
        "drain_reserve_permits = 2\ndrain_reserve_permit_wait_millis = 300\n\
         drain_reserve_attempts = 3\ndrain_reserve_backoff_base_millis = 10\n\
         drain_reserve_backoff_cap_millis = 40",
    ))
    .unwrap();
    assert_eq!(
        tuned,
        DrainReserveSettings {
            permits: 2,
            permit_wait: Duration::from_millis(300),
            attempts: 3,
            backoff_base: Duration::from_millis(10),
            backoff_cap: Duration::from_millis(40),
        }
    );
    // A base above the default cap raises the defaulted cap with it.
    let raised = settings(&with("drain_reserve_backoff_base_millis = 200")).unwrap();
    assert_eq!(raised.backoff_cap, Duration::from_millis(200));
    for (line, field) in [
        ("drain_reserve_permits = 0", "drain_reserve_permits"),
        ("drain_reserve_permits = 9", "drain_reserve_permits"),
        ("drain_reserve_attempts = 0", "drain_reserve_attempts"),
        ("drain_reserve_attempts = 11", "drain_reserve_attempts"),
        (
            "drain_reserve_permit_wait_millis = 0",
            "drain_reserve_permit_wait_millis",
        ),
        (
            "drain_reserve_permit_wait_millis = 10001",
            "drain_reserve_permit_wait_millis",
        ),
        (
            "drain_reserve_backoff_base_millis = 0",
            "drain_reserve_backoff_base_millis",
        ),
        (
            "drain_reserve_backoff_cap_millis = 1001",
            "drain_reserve_backoff_cap_millis",
        ),
        (
            "drain_reserve_backoff_base_millis = 50\ndrain_reserve_backoff_cap_millis = 40",
            "drain_reserve_backoff_cap_millis",
        ),
    ] {
        let error = match settings(&with(line)) {
            Ok(_) => panic!("{line} must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(field), "{line}: got {error}");
    }
}

/// Row 80 reserve contention: the documented default literals, the
/// reserve keys' independence from the stage I/O wait knobs in both
/// directions, and a misspelled reserve key refused rather than ignored.
#[test]
fn drain_reserve_keys_are_independent_of_the_stage_wait_knobs_and_misspellings_are_refused() {
    let complete = valid_write_behind_block();
    let settings = |text: &str| {
        validated_write_behind_settings(PLUGIN_NAME, &raw_write_behind(text))
            .map(|composition| composition.settings)
    };
    let with = |lines: &str| {
        let mutated = complete.replace(
            "sample_interval_millis = 5000",
            &format!("sample_interval_millis = 5000\n{lines}"),
        );
        assert_ne!(
            mutated, complete,
            "the fixture must set sample_interval_millis"
        );
        mutated
    };
    // The documented values, as literals rather than the crate constants.
    let defaulted = settings(&complete).unwrap();
    assert_eq!(defaulted.drain_reserve.permits, 1);
    assert_eq!(
        defaulted.drain_reserve.permit_wait,
        Duration::from_millis(1000)
    );
    assert_eq!(defaulted.drain_reserve.attempts, 5);
    assert_eq!(
        defaulted.drain_reserve.backoff_base,
        Duration::from_millis(5)
    );
    assert_eq!(
        defaulted.drain_reserve.backoff_cap,
        Duration::from_millis(80)
    );
    // Bounds are inclusive at both ends.
    let edges = settings(&with(
        "drain_reserve_permits = 8\ndrain_reserve_attempts = 10\n\
         drain_reserve_permit_wait_millis = 10000\n\
         drain_reserve_backoff_base_millis = 1000\n\
         drain_reserve_backoff_cap_millis = 1000",
    ))
    .unwrap();
    assert_eq!(edges.drain_reserve.permits, 8);
    assert_eq!(edges.drain_reserve.attempts, 10);
    let floor = settings(&with(
        "drain_reserve_permits = 1\ndrain_reserve_attempts = 1\n\
         drain_reserve_permit_wait_millis = 1\n\
         drain_reserve_backoff_base_millis = 1\n\
         drain_reserve_backoff_cap_millis = 1",
    ))
    .unwrap();
    assert_eq!(floor.drain_reserve.attempts, 1);
    // Reserve keys do not move the stage waits.
    let reserve_only = settings(&with(
        "drain_reserve_permits = 3\ndrain_reserve_permit_wait_millis = 9000",
    ))
    .unwrap();
    assert_eq!(reserve_only.stage_io_wait, defaulted.stage_io_wait);
    assert_eq!(reserve_only.stage_read_wait, defaulted.stage_read_wait);
    // Stage waits do not move the reserve settings.
    let stage_only = settings(&with(
        "stage_io_wait_millis = 7000\nstage_read_wait_millis = 6000",
    ))
    .unwrap();
    assert_eq!(stage_only.drain_reserve, defaulted.drain_reserve);
    assert_eq!(stage_only.stage_io_wait, Duration::from_millis(7000));
    assert_eq!(stage_only.stage_read_wait, Duration::from_millis(6000));
    // A refused reserve value never leaks into a stage-wait refusal.
    let error = match settings(&with(
        "stage_io_wait_millis = 10001\ndrain_reserve_permits = 0",
    )) {
        Ok(_) => panic!("both values are out of range"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("stage_io_wait_millis") || error.contains("drain_reserve_permits"),
        "got {error}"
    );
    // `deny_unknown_fields`: a near-miss key is an error, not a silent default.
    for typo in [
        "drain_reserve_permit = 2",
        "reserve_permits = 2",
        "drain_reserve_attempt = 2",
        "drain_reserve_backoff_millis = 5",
    ] {
        let error = match toml::from_str::<WriteBehindConfig>(typo) {
            Ok(_) => panic!("{typo} must be refused as an unknown key"),
            Err(error) => error.to_string(),
        };
        // Not a missing-field error: the key itself must be what is refused.
        assert!(error.contains("unknown field"), "{typo}: got {error}");
    }
}

/// Row 76: write-behind reserves one domain connection for its observer,
/// so a `domain_pool_max` below 2 would leave nothing for everything else.
/// Refused by name before any connection is attempted (the URL here
/// reaches nothing).
#[tokio::test]
async fn reserving_the_observer_connection_refuses_a_domain_pool_below_two() {
    for pool_max in [0, 1] {
        let config: toml::Value = toml::from_str(&format!(
            "url = \"postgres://unreachable.invalid/lore\"\ndomain_pool_max = {pool_max}"
        ))
        .expect("fixture parses");
        let layout = DomainPoolLayout::ReserveObserver {
            observe_interval: std::time::Duration::from_secs(1),
        };
        let error = match connect_domain_store(&config, layout).await {
            Ok(_) => panic!("domain_pool_max {pool_max} must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("domain_pool_max") && error.contains("2 or more"),
            "got {error}"
        );
    }
}

/// The inert-wiring refusal. The staged route is reached only from the
/// coordinated PUT path, so a legacy cell would prove a staging root, run
/// its sampler, publish a healthy admission picture, and never stage a
/// byte.
#[test]
fn an_enabled_write_behind_without_a_governed_route_is_refused() {
    for provider in ["", "[fragment_provider]\nenabled = false\n"] {
        let text = format!(
            r#"
url = "postgres://localhost/lore"
[object_store]
bucket = "fragments"
{provider}
{}
"#,
            valid_write_behind_block()
        );
        let parsed: PostgresStoreConfig =
            match toml::from_str::<toml::Value>(&text).and_then(toml::Value::try_into) {
                Ok(parsed) => parsed,
                Err(error) => panic!("fixture config must deserialize: {error}"),
            };
        let error = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
            Ok(_) => panic!("an enabled tier with no governed route must be refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("requires an enabled fragment_provider"),
            "the refusal must name the coupling; got {error}"
        );
    }
}

/// D13's boot-time half, on a host that cannot stage.
///
/// The compile-time half is `ConfinedRoot`'s `cfg(not(unix))` module, which
/// refuses every operation. This is the other half, and it is the one that
/// matters to an operator: without it a cell configured for staging boots,
/// reports healthy, and learns the truth one failed PUT at a time.
#[cfg(not(target_os = "linux"))]
#[test]
fn an_otherwise_valid_write_behind_block_is_refused_at_boot_off_linux() {
    let parsed = parsed_config_with(&valid_write_behind_block());
    let error = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
        Ok(_) => panic!("write-behind must be refused off Linux"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("requires a Linux host"),
        "the refusal must name the platform, not a field; got {error}"
    );
}

/// The same block, on the platform that can stage, must be accepted — so
/// the case above is proved to be refusing for its stated reason rather
/// than tripping over a fixture that was never valid anywhere.
#[cfg(target_os = "linux")]
#[test]
fn the_same_write_behind_block_is_accepted_on_linux() {
    let parsed = parsed_config_with(&valid_write_behind_block());
    let composition = match enabled_write_behind_settings(PLUGIN_NAME, &parsed) {
        Ok(Some(composition)) => composition,
        Ok(None) => panic!("an enabled block must produce settings"),
        Err(error) => panic!("an enabled block must be accepted on Unix: {error}"),
    };
    assert_eq!(composition.settings.root, PathBuf::from(staging_root()));
    assert_eq!(composition.shared_spool_root, PathBuf::from(spool_root()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn configured_domain_enforcement_reaches_the_published_postgres_mutable_store() {
    let Ok(url) = std::env::var("LORE_TEST_PG_URL") else {
        eprintln!("LORE_TEST_PG_URL unset; skipping real construction-path enforcement test");
        return;
    };
    let domain_store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("bootstrap domain schema");
    let direct = direct_client(&url).await;
    direct
        .execute(
            "UPDATE lore_domain_schema_state SET \
                backfill_state=3, residue_classified=true, \
                cutover_at=clock_timestamp(), enforcement_enabled=false, \
                updated_at=clock_timestamp() WHERE id=1",
            &[],
        )
        .await
        .expect("make the disposable cell ready for enforcement");
    domain_store
        .enable_enforcement()
        .await
        .expect("enable enforcement through the production schema-state API");

    let mut settings: Settings = toml::from_str(include_str!("../../../config/default.toml"))
        .expect("built-in settings fixture must deserialize");
    settings.mutable_store.mode = PLUGIN_NAME.to_string();
    settings.plugins.insert(
        PLUGIN_NAME.to_string(),
        toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
            .expect("Postgres plugin fixture config"),
    );
    let configured = lore_server::domain::configure_domain_context(&settings)
        .await
        .expect("real domain-context construction path");
    assert!(
        configured.context.is_some(),
        "Postgres cell has a coordinator"
    );
    let plugin_context = MutableStorePluginContext {
        domain_enforcement: configured.mutable_enforcement,
    };
    let immutable: Arc<dyn ImmutableStore> = lore_storage::LocalImmutableStore::new(
        None,
        lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
    )
    .await
    .expect("create unused immutable-store dependency");
    let mutable = PostgresMutableStorePluginFactory
        .create(
            settings
                .plugins
                .get(PLUGIN_NAME)
                .expect("Postgres plugin fixture exists"),
            immutable,
            &plugin_context,
        )
        .expect("real Postgres mutable plugin factory");

    let error = mutable
        .store(
            Partition::default(),
            Hash::from(rand::random::<[u8; 32]>()),
            Hash::from(rand::random::<[u8; 32]>()),
            KeyType::BranchLatestPointer,
        )
        .await
        .expect_err(
            "the published mutable store must share configure_domain_context's armed fence",
        );
    assert!(
        error.to_string().contains("BranchLatestPointer"),
        "fail-closed rejection must name the governed key type: {error}"
    );

    direct
        .execute(
            "UPDATE lore_domain_schema_state SET enforcement_enabled=false, \
                updated_at=clock_timestamp() WHERE id=1",
            &[],
        )
        .await
        .expect("restore disposable schema-state enforcement flag");
}

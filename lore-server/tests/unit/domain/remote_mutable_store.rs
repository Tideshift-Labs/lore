// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the boot refusal for `mutable_store.mode = "remote"`
//! on a server that writes domain-owned keys through its own mutable store.
//! The remote server refuses those key types on its generic mutable RPCs, so
//! the refusal moves the failure from the first push to boot.

use lore_server::domain::mutable_store_domain_writers;
use lore_server::domain::refuse_remote_mutable_store_writers;
use lore_server::settings::Settings;

const DEFAULT: &str = include_str!("../../../config/default.toml");
const THIN_EXAMPLE: &str = include_str!("../../../config/thin.example.toml");

const WRITERS: [&str; 3] = [
    "[server.grpc_public_services.revision_service]",
    "[server.grpc_public_services.repository_service]",
    "[server.grpc_internal]",
];

/// Overlays `overlay` onto `base` table by table, as layered config files do.
fn merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) => merge(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn layered(overlays: &[&str]) -> Settings {
    let mut value: toml::Value = toml::from_str(DEFAULT).expect("default.toml parses");
    for overlay in overlays {
        merge(&mut value, toml::from_str(overlay).expect("overlay parses"));
    }
    value.try_into().expect("layered settings deserialize")
}

fn remote(settings: &mut Settings) {
    settings.mutable_store.mode = "remote".to_owned();
}

/// The pytest thin server (`configure_thin_server` plus
/// `LORE__SERVER__GRPC_INTERNAL__ENABLED=false`): only thin-client gRPC, no
/// public QUIC, no HTTP, no internal gRPC.
fn thin_front() -> Settings {
    let mut settings = layered(&[]);
    remote(&mut settings);
    let services = &mut settings.server.grpc_public_services;
    for service in [
        &mut services.admin_service,
        &mut services.storage_service,
        &mut services.revision_service,
        &mut services.repository_service,
        &mut services.environment_service,
        &mut services.lock_service,
        &mut services.notification_service,
    ] {
        service.enabled = false;
    }
    settings.server.quic.as_mut().expect("default quic").enabled = false;
    settings.server.http.as_mut().expect("default http").enabled = false;
    settings
        .server
        .grpc_internal
        .as_mut()
        .expect("default grpc_internal")
        .enabled = false;
    settings
}

fn enable(settings: &mut Settings, writer: &str) {
    let services = &mut settings.server.grpc_public_services;
    match writer {
        "[server.grpc_public_services.revision_service]" => {
            services.revision_service.enabled = true;
        }
        "[server.grpc_public_services.repository_service]" => {
            services.repository_service.enabled = true;
        }
        "[server.grpc_internal]" => {
            settings
                .server
                .grpc_internal
                .as_mut()
                .expect("grpc_internal")
                .enabled = true;
        }
        other => panic!("unknown writer {other}"),
    }
}

// --- read-only fronts boot ----------------------------------------------------

#[test]
fn the_pytest_thin_front_boots() {
    let settings = thin_front();
    assert!(mutable_store_domain_writers(&settings).is_empty());
    assert!(refuse_remote_mutable_store_writers(&settings).is_ok());
}

#[test]
fn the_shipped_thin_example_boots() {
    let settings = layered(&[THIN_EXAMPLE]);
    assert_eq!(settings.mutable_store.mode, "remote", "fixture check");
    assert!(
        refuse_remote_mutable_store_writers(&settings).is_ok(),
        "{:?}",
        mutable_store_domain_writers(&settings)
    );
}

/// Surfaces that write no domain key through this server's own mutable store
/// may stay on: storage gRPC and public QUIC (their client domain-key writes
/// are refused before any store call), admin, HTTP, internal QUIC and the
/// read-side gRPC services.
#[test]
fn non_writing_surfaces_do_not_refuse() {
    let mut settings = thin_front();
    let services = &mut settings.server.grpc_public_services;
    services.admin_service.enabled = true;
    services.storage_service.enabled = true;
    services.environment_service.enabled = true;
    services.lock_service.enabled = true;
    services.notification_service.enabled = true;
    settings.server.quic.as_mut().expect("quic").enabled = true;
    settings.server.http.as_mut().expect("http").enabled = true;
    settings
        .server
        .quic_internal
        .as_mut()
        .expect("quic_internal")
        .enabled = true;
    assert!(refuse_remote_mutable_store_writers(&settings).is_ok());
}

// --- writing fronts are refused -------------------------------------------------

#[test]
fn each_writer_alone_is_refused_and_named() {
    for writer in WRITERS {
        let mut settings = thin_front();
        enable(&mut settings, writer);
        assert_eq!(mutable_store_domain_writers(&settings), vec![writer]);
        let text = format!(
            "{:#}",
            refuse_remote_mutable_store_writers(&settings)
                .expect_err("a remote mutable store with a writer must refuse")
        );
        assert!(text.contains(writer), "{writer}: {text}");
        assert!(
            text.contains("mutable_store.mode = \"remote\""),
            "names the mode: {text}"
        );
        assert!(text.contains("this fork"), "names the divergence: {text}");
    }
}

/// A default server pointed at a remote mutable store, as the upstream Helm
/// handler pod is, names every writing surface it has on.
#[test]
fn a_default_server_with_a_remote_mutable_store_is_refused() {
    let mut settings = layered(&[]);
    remote(&mut settings);
    let text = format!(
        "{:#}",
        refuse_remote_mutable_store_writers(&settings).expect_err("must refuse")
    );
    for writer in &WRITERS[..2] {
        assert!(text.contains(writer), "{writer}: {text}");
    }
    assert!(
        !text.contains("[server.grpc_internal]"),
        "internal gRPC is off by default: {text}"
    );
}

#[test]
fn non_remote_modes_never_refuse() {
    for mode in ["local", "postgres", "aws"] {
        let mut settings = layered(&[]);
        for writer in WRITERS {
            enable(&mut settings, writer);
        }
        settings.mutable_store.mode = mode.to_owned();
        assert!(
            refuse_remote_mutable_store_writers(&settings).is_ok(),
            "{mode}"
        );
    }
}

// --- wiring ---------------------------------------------------------------------

const SERVER: &str = include_str!("../../../src/server.rs");

fn code_only(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The serving path calls the refusal once, outside maintenance mode, before
/// any store-serving listener starts, and propagates its error.
#[test]
fn async_main_refuses_before_any_store_listener() {
    let server = code_only(SERVER);
    let body = &server[server
        .find("async fn async_main(")
        .expect("async_main must exist")..];
    let call = "refuse_remote_mutable_store_writers(&settings)?";
    assert_eq!(server.matches(call).count(), 1, "exactly one call site");
    let call_at = body.find(call).expect("async_main must call the refusal");

    let guard = "if !is_maintenance {";
    let guard_at = body[..call_at]
        .rfind(guard)
        .expect("the call must sit in a maintenance guard");
    assert!(
        !body[guard_at..call_at].contains('}'),
        "the call must be directly inside the guard"
    );

    for listener in [
        "launch_grpc_server(",
        "launch_grpc_internal_server(",
        "launch_quinn_server(",
        "launch_http_server(",
    ] {
        let listener_at = body
            .find(listener)
            .unwrap_or_else(|| panic!("async_main must start {listener}"));
        assert!(call_at < listener_at, "the refusal must precede {listener}");
    }
}

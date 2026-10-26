// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Process-level contract for `cell-schema-install`'s TLS posture.
//!
//! Every connection the installer opens is either explicitly plaintext (`sslmode=disable` and no CA)
//! or TLS verified against the pinned CA (`sslmode=require` and
//! `LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM`). There is no silent plaintext fallback.
//!
//! These cases need no database. The discriminator is the port: it is **closed**, so any case that
//! reaches a connection attempt exits 1 ("could not connect"), and a case that exits 2 therefore
//! proved the refusal came before any connection was tried. The TLS handshake itself, against a real
//! server, is the live tier's job (`cell_schema_install_live.rs`).

use std::net::TcpListener;
use std::process::Command;
use std::process::Output;

const URL_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL";
const CA_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM";
const PASSWORD: &str = "hunter2-not-a-real-password";

/// A loopback port nothing listens on, so a connection attempt is refused immediately.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    port
}

fn url(port: u16, sslmode: Option<&str>) -> String {
    let query = sslmode.map_or_else(String::new, |mode| format!("?sslmode={mode}"));
    format!(
        "postgresql://object_dispatch_retention_migrator:{PASSWORD}@127.0.0.1:{port}/cell{query}"
    )
}

fn test_ca_pem() -> String {
    let key = rcgen::KeyPair::generate().expect("test CA key");
    rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("test CA params")
        .self_signed(&key)
        .expect("test CA certificate")
        .pem()
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cell-schema-install"));
    command.env_clear();
    // Winsock needs the system root on Windows; nothing here carries cell configuration.
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.arg("attest");
    command
}

fn run(url_value: Option<&str>, ca: Option<&str>) -> Output {
    let mut command = command();
    if let Some(value) = url_value {
        command.env(URL_ENV, value);
    }
    if let Some(value) = ca {
        command.env(CA_ENV, value);
    }
    command.output().expect("spawn cell-schema-install")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_never_echoed(output: &Output, secrets: &[&str]) {
    let text = format!(
        "{}{}",
        stderr(output),
        String::from_utf8_lossy(&output.stdout)
    );
    for secret in secrets {
        assert!(!text.contains(secret), "output echoed {secret:?}: {text}");
    }
}

const CONNECT_FAILURE: &str = "could not connect to the cell authority database";

#[test]
fn a_ca_beside_any_sslmode_but_require_is_refused_before_connecting() {
    let port = closed_port();
    let pem = test_ca_pem();
    for sslmode in [Some("disable"), Some("prefer"), None] {
        let output = run(Some(&url(port, sslmode)), Some(&pem));
        assert_eq!(output.status.code(), Some(2), "sslmode {sslmode:?}");
        assert!(
            !stderr(&output).contains(CONNECT_FAILURE),
            "sslmode {sslmode:?} reached a connection attempt"
        );
        assert_never_echoed(&output, &[PASSWORD, "BEGIN CERTIFICATE", "127.0.0.1"]);
    }
}

#[test]
fn no_ca_beside_any_sslmode_but_disable_is_refused_before_connecting() {
    let port = closed_port();
    for sslmode in [Some("require"), Some("prefer"), None] {
        let output = run(Some(&url(port, sslmode)), None);
        assert_eq!(output.status.code(), Some(2), "sslmode {sslmode:?}");
        assert!(
            !stderr(&output).contains(CONNECT_FAILURE),
            "sslmode {sslmode:?} reached a connection attempt"
        );
        assert_never_echoed(&output, &[PASSWORD, "127.0.0.1"]);
    }
}

#[test]
fn an_empty_or_whitespace_ca_is_refused_not_treated_as_unset() {
    // Treating an empty variable as unset would turn a botched secret injection into plaintext.
    let port = closed_port();
    for pem in ["", "   ", "\r\n\t\n"] {
        let output = run(Some(&url(port, Some("disable"))), Some(pem));
        assert_eq!(output.status.code(), Some(2), "pem {pem:?}");
        assert!(!stderr(&output).contains(CONNECT_FAILURE), "pem {pem:?}");
        let output = run(Some(&url(port, Some("require"))), Some(pem));
        assert_eq!(output.status.code(), Some(2), "pem {pem:?}");
        assert!(!stderr(&output).contains(CONNECT_FAILURE), "pem {pem:?}");
    }
}

#[test]
fn an_unusable_ca_is_refused_before_connecting_and_never_echoed() {
    let port = closed_port();
    let garbage =
        "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1ieXRlcw==\n-----END PRIVATE KEY-----\n";
    for pem in [garbage, "not a certificate at all"] {
        let output = run(Some(&url(port, Some("require"))), Some(pem));
        assert_eq!(output.status.code(), Some(2), "pem {pem:?}");
        assert!(!stderr(&output).contains(CONNECT_FAILURE), "pem {pem:?}");
        assert_never_echoed(
            &output,
            &[
                PASSWORD,
                "c2VjcmV0LWtleS1ieXRlcw",
                "not a certificate",
                "127.0.0.1",
            ],
        );
    }
}

#[test]
fn a_non_unicode_ca_is_refused_before_connecting() {
    #[cfg(unix)]
    let value = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0x66, 0x80, 0x6f])
    };
    #[cfg(windows)]
    let value = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0x0066, 0xD800, 0x006f])
    };
    let port = closed_port();
    let output = command()
        .env(URL_ENV, url(port, Some("require")))
        .env(CA_ENV, value)
        .output()
        .expect("spawn cell-schema-install");
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr(&output).contains(CONNECT_FAILURE));
    assert_never_echoed(&output, &[PASSWORD]);
}

#[test]
fn a_missing_or_unparsable_url_is_refused_without_echoing_it() {
    let output = run(None, None);
    assert_eq!(output.status.code(), Some(2));
    let bad = format!("postgresql://user:{PASSWORD}@host:notaport/db");
    let output = run(Some(&bad), None);
    assert_eq!(output.status.code(), Some(2));
    assert!(!stderr(&output).contains(CONNECT_FAILURE));
    assert_never_echoed(&output, &[PASSWORD, "notaport"]);
}

const BACKUP_REF_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_UPGRADE_BACKUP_REF";

fn run_action(action: &str, backup_ref: Option<&str>) -> Output {
    let port = closed_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cell-schema-install"));
    command.env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command.arg(action).env(URL_ENV, url(port, Some("disable")));
    if let Some(value) = backup_ref {
        command.env(BACKUP_REF_ENV, value);
    }
    command.output().expect("spawn cell-schema-install")
}

#[test]
fn upgrade_without_a_backup_ref_is_refused_before_connecting() {
    // WP-115 f2: the R32 step deletes spool custody rows, so the operator must name the pre-upgrade
    // volume copy. Exit 2 with the closed port proves the refusal came before any connection.
    for backup_ref in [None, Some("")] {
        let output = run_action("upgrade", backup_ref);
        assert_eq!(output.status.code(), Some(2), "backup ref {backup_ref:?}");
        assert!(
            !stderr(&output).contains(CONNECT_FAILURE),
            "backup ref {backup_ref:?} reached a connection attempt: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(BACKUP_REF_ENV),
            "the refusal must name the variable: {}",
            stderr(&output)
        );
        assert_never_echoed(&output, &[PASSWORD, "127.0.0.1"]);
    }
}

#[test]
fn upgrade_with_a_backup_ref_reaches_a_connection_attempt() {
    // The positive control for the refusal above: the same command with the variable set is not
    // refused up front, it tries (and, on the closed port, fails) to connect.
    let output = run_action("upgrade", Some("volume-copy-2026-10-26"));
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(CONNECT_FAILURE),
        "{}",
        stderr(&output)
    );
    assert_never_echoed(&output, &[PASSWORD, "127.0.0.1"]);
}

#[test]
fn the_backup_ref_is_required_by_upgrade_only() {
    // attest, install and measure keep working with no backup ref: they reach a connection attempt.
    for action in ["attest", "install", "measure"] {
        let output = run_action(action, None);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{action}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(CONNECT_FAILURE),
            "{action} must not need a backup ref: {}",
            stderr(&output)
        );
    }
}

#[test]
fn explicit_plaintext_is_accepted_and_reaches_a_connection_attempt() {
    let port = closed_port();
    let output = run(Some(&url(port, Some("disable"))), None);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains(CONNECT_FAILURE),
        "{}",
        stderr(&output)
    );
    assert_never_echoed(&output, &[PASSWORD, "127.0.0.1"]);
}

#[test]
fn a_pinned_ca_with_sslmode_require_is_accepted_and_reaches_a_connection_attempt() {
    let port = closed_port();
    let pem = test_ca_pem();
    let output = run(Some(&url(port, Some("require"))), Some(&pem));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains(CONNECT_FAILURE),
        "{}",
        stderr(&output)
    );
    assert_never_echoed(&output, &[PASSWORD, "BEGIN CERTIFICATE", "127.0.0.1"]);
}

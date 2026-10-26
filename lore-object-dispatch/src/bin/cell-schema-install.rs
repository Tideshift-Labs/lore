// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! One-shot operator command for WP-114 CD-1: install or attest a cell's authority schema.
//!
//! This is **not** the separate-process dispatch service that CR-033 D6/P2 deleted, and it is not a
//! step toward reintroducing one. It opens one connection, performs one action, prints one verdict,
//! and exits. It has no listener, no socket, no RPC surface, no scheduler, and no run loop. Runtime
//! never invokes it; it is run by an operator, out of band, against a cell database.
//!
//! Usage:
//!
//! ```text
//! $env:LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL = "postgresql://.../cell?sslmode=disable"
//! # or, for a TLS-only database such as managed PostgreSQL:
//! $env:LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL = "postgresql://.../cell?sslmode=require"
//! $env:LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM = Get-Content -Raw ca-certificate.crt
//! cell-schema-install install    # install the CR-033 D5 set, then attest
//! cell-schema-install attest     # attest only; never writes schema
//! cell-schema-install upgrade    # CR-038: move an attested older cell to current, offline
//! cell-schema-install measure    # print the live catalog manifest digests
//! ```
//!
//! `upgrade` also requires `LORE_OBJECT_DISPATCH_CELL_UPGRADE_BACKUP_REF`, naming the stopped-volume
//! copy of the cell database taken before the upgrade, and refuses before connecting without it.
//! The R31 -> R32 step deletes released spool custody rows and an older loreserver refuses an R32
//! cell, so that copy is the only rollback (CR-041). The installer cannot check the copy; it prints
//! the reference so the run's log records it.
//!
//! `upgrade` requires every replica stopped. It checks once, before its transaction, that no other
//! session is connected to the cell database; a later connection is refused only if it holds a cell
//! table when the step's `LOCK TABLE ... NOWAIT` runs. It commits a forward step only after the new state attests inside the same
//! transaction. After any interruption, run it again: it classifies the cell before it acts.
//!
//! `install`, `upgrade` and `attest` each take the cell schema session lock and refuse at once if
//! another session holds it.
//!
//! The connection **must** authenticate as `object_dispatch_retention_migrator`; every action
//! refuses otherwise, `attest` and `measure` included, and so does the revoke pass inside `install`.
//! The check is on `session_user`, which `SET ROLE` cannot forge. The URL is read only from the
//! environment so it never appears in a process argument list, and it is never echoed, including on
//! failure.
//!
//! TLS follows the dispatch pool's rule (`dispatch_pool::cell_tls_connector`). With
//! `LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM` set, the URL must say `sslmode=require`, and the
//! server is verified against exactly that PEM bundle, chain and host name both (libpq's
//! `verify-full`). Without it, the URL must say `sslmode=disable`. `prefer`, which falls back to
//! plaintext when the handshake fails, is refused either way. The PEM is read only from the
//! environment and never echoed.
//!
//! `install` additionally requires that no transaction is already open on the connection, which for
//! this binary is always true. It cannot run inside one: every frozen artifact carries its own
//! `BEGIN`/`COMMIT`, and every layer install procedure requires `SERIALIZABLE`. Only `attest` is
//! safe to call from inside a caller's transaction.
//!
//! Exit codes: `0` success, `1` refused or drifted, `2` misuse or missing environment.

use std::process::ExitCode;

use lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SECTIONS;
use lore_object_dispatch::cell_schema_install::CellAttestation;
use lore_object_dispatch::cell_schema_install::LayerIdentity;
use lore_object_dispatch::cell_schema_install::acquire_cell_schema_lock;
use lore_object_dispatch::cell_schema_install::attest_cell_schema;
use lore_object_dispatch::cell_schema_install::install_cell_schema;
use lore_object_dispatch::cell_schema_install::measure_catalog_manifest;
use lore_object_dispatch::cell_schema_install::release_cell_schema_lock;
use lore_object_dispatch::cell_schema_install::upgrade_cell_schema;
use lore_object_dispatch::dispatch_pool::DispatchPoolError;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;
use lore_object_dispatch::dispatch_pool::cell_tls_connector;
use tokio_util::task::AbortOnDropHandle;

/// Environment variable naming the cell database, under the crate's bytewise config prefix.
const MIGRATOR_URL_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL";

/// Environment variable carrying the PEM root CA bundle for a TLS cell database.
const MIGRATOR_CA_PEM_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM";

/// Environment variable naming the pre-upgrade volume copy that `upgrade` requires (CR-041).
const UPGRADE_BACKUP_REF_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_UPGRADE_BACKUP_REF";

const USAGE: &str = "usage: cell-schema-install <install|attest|upgrade|measure>\n\
     the cell database URL is read from LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL\n\
     for TLS, set LORE_OBJECT_DISPATCH_CELL_MIGRATOR_CA_PEM and sslmode=require\n\
     (verify-full semantics; libpq's sslmode=verify-full and sslrootcert are not accepted)";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Install,
    Attest,
    Upgrade,
    Measure,
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let Some(action) = arguments.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let action = match action.as_str() {
        "install" => Action::Install,
        "attest" => Action::Attest,
        "upgrade" => Action::Upgrade,
        "measure" => Action::Measure,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    if action == Action::Upgrade {
        match std::env::var(UPGRADE_BACKUP_REF_ENV) {
            Ok(reference) if !reference.trim().is_empty() => {
                println!("upgrade: pre-upgrade volume copy: {reference}");
            }
            _ => {
                eprintln!(
                    "upgrade refused: set {UPGRADE_BACKUP_REF_ENV} to the stopped-volume copy of the \
                     cell database taken before this upgrade. The R31 -> R32 step deletes released \
                     spool custody rows and an older Lore binary refuses an R32 cell, so that copy \
                     is the only rollback."
                );
                return ExitCode::from(2);
            }
        }
    }

    let Ok(url) = std::env::var(MIGRATOR_URL_ENV) else {
        eprintln!("{MIGRATOR_URL_ENV} is not set");
        return ExitCode::from(2);
    };
    if url.is_empty() {
        eprintln!("{MIGRATOR_URL_ENV} is empty");
        return ExitCode::from(2);
    }
    let tls = match std::env::var(MIGRATOR_CA_PEM_ENV) {
        Ok(pem) if !pem.trim().is_empty() => DispatchTlsMode::PinnedRootCa(pem),
        Ok(_) => {
            eprintln!("{MIGRATOR_CA_PEM_ENV} is set but empty");
            return ExitCode::from(2);
        }
        Err(std::env::VarError::NotPresent) => DispatchTlsMode::Disabled,
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("{MIGRATOR_CA_PEM_ENV} is not valid Unicode");
            return ExitCode::from(2);
        }
    };
    // Never echo the URL or the parser diagnostic; either can carry credentials.
    let Ok(config) = url.parse::<tokio_postgres::Config>() else {
        eprintln!(
            "{MIGRATOR_URL_ENV} is not a valid PostgreSQL URL (sslmode must be disable or require)"
        );
        return ExitCode::from(2);
    };
    let connector = match cell_tls_connector(&config, &tls) {
        Ok(connector) => connector,
        Err(DispatchPoolError::InvalidConfiguration(_)) => {
            if matches!(tls, DispatchTlsMode::PinnedRootCa(_)) {
                eprintln!(
                    "{MIGRATOR_CA_PEM_ENV} is set, so {MIGRATOR_URL_ENV} must say sslmode=require"
                );
            } else {
                eprintln!(
                    "{MIGRATOR_URL_ENV} must say sslmode=disable, or set {MIGRATOR_CA_PEM_ENV} and sslmode=require"
                );
            }
            return ExitCode::from(2);
        }
        // Fixed text only; never the PEM.
        Err(error) => {
            eprintln!("{MIGRATOR_CA_PEM_ENV}: {error}");
            return ExitCode::from(2);
        }
    };

    let runtime = if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        runtime
    } else {
        eprintln!("could not start the local async runtime");
        return ExitCode::from(2);
    };
    runtime.block_on(run(action, &config, connector))
}

async fn run(
    action: Action,
    config: &tokio_postgres::Config,
    connector: tokio_postgres_rustls::MakeRustlsConnect,
) -> ExitCode {
    // No client certificate: the mandatory-mTLS contract was written for the retired cross-region
    // authority database and does not survive CR-033's re-scope. Server verification, when TLS is
    // configured, is the dispatch pool's.
    let (client, connection) = if let Ok(pair) = config.connect(connector).await {
        pair
    } else {
        // Never echo the URL or the driver diagnostic; either can carry credentials.
        eprintln!("could not connect to the cell authority database");
        return ExitCode::from(1);
    };
    let _connection_task = AbortOnDropHandle::new(lore_base::lore_spawn!(
        "cell-schema-install-postgres",
        async move {
            let _ = connection.await;
        }
    ));

    match action {
        Action::Install => match install_cell_schema(&client).await {
            Ok(report) => {
                println!("install: {:?}", report.disposition);
                for (id, outcome) in report.layer_outcomes {
                    println!("  layer {}: {outcome:?}", id.label());
                }
                print_attestation(&report.attestation);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("install refused: {error}");
                ExitCode::from(1)
            }
        },
        Action::Attest => {
            if let Err(error) = acquire_cell_schema_lock(&client).await {
                eprintln!("attestation failed: {error}");
                return ExitCode::from(1);
            }
            let attested = attest_cell_schema(&client).await;
            let released = release_cell_schema_lock(&client).await;
            match (attested, released) {
                (Ok(attestation), Ok(())) => {
                    print_attestation(&attestation);
                    ExitCode::SUCCESS
                }
                (Err(error), _) | (Ok(_), Err(error)) => {
                    eprintln!("attestation failed: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Action::Upgrade => match upgrade_cell_schema(&client).await {
            Ok(report) => {
                println!("upgrade: {:?}", report.disposition);
                print_attestation(&report.attestation);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("upgrade refused: {error}");
                ExitCode::from(1)
            }
        },
        Action::Measure => match measure_catalog_manifest(&client).await {
            Ok((sections, whole)) => {
                for (index, name) in CELL_CATALOG_MANIFEST_SECTIONS.iter().enumerate() {
                    println!("section {name} {}", hex(&sections[index]));
                }
                println!("manifest {}", hex(&whole));
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("manifest measurement failed: {error}");
                ExitCode::from(1)
            }
        },
    }
}

fn print_attestation(attestation: &CellAttestation) {
    println!("  schema state: {}", attestation.schema_revision.label());
    for (id, identity) in &attestation.layers {
        match identity {
            LayerIdentity::Absent => println!("  identity {}: ABSENT", id.label()),
            LayerIdentity::Valid {
                install_revision,
                installed_at_unix_ms,
            } => println!(
                "  identity {}: VALID revision={install_revision} installed_at={installed_at_unix_ms}",
                id.label()
            ),
        }
    }
    println!("  catalog manifest: {}", hex(&attestation.catalog_blake3));
    println!(
        "  retention readback: {}",
        attestation.retention_read_state_result
    );
    let retired: Vec<String> = attestation
        .retired_readbacks
        .iter()
        .map(|(layer, sqlstate)| format!("{layer}({sqlstate})"))
        .collect();
    println!("  retired readbacks: {}", retired.join(", "));
    println!(
        "  replaced functions revoked: {}",
        attestation.replaced_functions_revoked
    );
    println!(
        "  inert retention tables: {}",
        attestation.inert_tables_present
    );
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in bytes {
        text.push(char::from(nibble(byte >> 4)));
        text.push(char::from(nibble(byte & 0x0f)));
    }
    text
}

const fn nibble(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}

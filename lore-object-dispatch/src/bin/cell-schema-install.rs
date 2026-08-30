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
//! $env:LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL = "postgresql://.../cell"
//! cell-schema-install install    # install the CR-033 D5 set, then attest
//! cell-schema-install attest     # attest only; never writes schema
//! cell-schema-install measure    # print the live catalog manifest digests
//! ```
//!
//! The connection **must** authenticate as `object_dispatch_retention_migrator`; the command
//! refuses otherwise. The URL is read only from the environment so it never appears in a process
//! argument list, and it is never echoed, including on failure.
//!
//! Exit codes: `0` success, `1` refused or drifted, `2` misuse or missing environment.

use std::process::ExitCode;

use lore_object_dispatch::cell_schema_install::CELL_CATALOG_MANIFEST_SECTIONS;
use lore_object_dispatch::cell_schema_install::CellAttestation;
use lore_object_dispatch::cell_schema_install::LayerIdentity;
use lore_object_dispatch::cell_schema_install::attest_cell_schema;
use lore_object_dispatch::cell_schema_install::install_cell_schema;
use lore_object_dispatch::cell_schema_install::measure_catalog_manifest;
use tokio_util::task::AbortOnDropHandle;

/// Environment variable naming the cell database, under the crate's bytewise config prefix.
const MIGRATOR_URL_ENV: &str = "LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL";

const USAGE: &str = "usage: cell-schema-install <install|attest|measure>\n\
     the cell database URL is read from LORE_OBJECT_DISPATCH_CELL_MIGRATOR_URL";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Install,
    Attest,
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
        "measure" => Action::Measure,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let Ok(url) = std::env::var(MIGRATOR_URL_ENV) else {
        eprintln!("{MIGRATOR_URL_ENV} is not set");
        return ExitCode::from(2);
    };
    if url.is_empty() {
        eprintln!("{MIGRATOR_URL_ENV} is empty");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("could not start the local async runtime");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(run(action, &url))
}

async fn run(action: Action, url: &str) -> ExitCode {
    // NoTls: the cell authority is the cell's own database, reached inside the cell. The external
    // endpoint contract (pinned CA, mandatory client certificate) was written for the retired
    // cross-region authority database and does not survive CR-033's re-scope.
    let (client, connection) = match tokio_postgres::connect(url, tokio_postgres::NoTls).await {
        Ok(pair) => pair,
        Err(_) => {
            // Never echo the URL or the driver diagnostic; either can carry credentials.
            eprintln!("could not connect to the cell authority database");
            return ExitCode::from(1);
        }
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
        Action::Attest => match attest_cell_schema(&client).await {
            Ok(attestation) => {
                print_attestation(&attestation);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("attestation failed: {error}");
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
    println!(
        "  retired readbacks: {}",
        attestation.retired_readbacks.join(", ")
    );
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

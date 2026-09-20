// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! One-shot maintenance publication. Serving processes never call this command.
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::dispatch_client::DispatchDatabaseIdentity;
use lore_object_dispatch::dispatch_pool::DispatchConnectionBudget;
use lore_object_dispatch::dispatch_pool::DispatchPoolConfig;
use lore_object_dispatch::dispatch_pool::DispatchPoolRole;
use lore_object_dispatch::dispatch_pool::DispatchRuntimePool;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;
use lore_object_dispatch::drain_policy::DrainClient;
use lore_object_dispatch::drain_policy::DrainPolicy;
use lore_object_dispatch::drain_policy::decode_digest;
use lore_object_dispatch::drain_policy::hex;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    system_identifier: String,
    database_oid: u32,
    drain: DrainPolicy,
    previous: Option<PreviousPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousPolicy {
    revision: String,
    digest: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cell-drain-policy-configure: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (action, path, offline) = match args.as_slice() {
        [action, path] => (action, path, false),
        [action, path, acknowledgement] if acknowledgement == "--replicas-excluded" => (action, path, true),
        _ => return Err("usage: cell-drain-policy-configure <publish|verify|rotate> <json-path> [--replicas-excluded]".into()),
    };
    let publish = match action.as_str() {
        "publish" => true,
        "verify" => false,
        "rotate" if offline => false,
        _ => {
            return Err(
                "action must be publish, verify, or rotate with --replicas-excluded".into(),
            );
        }
    };
    let file = std::fs::File::open(path).map_err(|_error| "configuration unavailable")?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 32769), &mut bytes)
        .map_err(|_error| "configuration unreadable")?;
    if bytes.len() > 32768 {
        return Err("configuration too large".into());
    }
    let config: Configuration =
        serde_json::from_slice(&bytes).map_err(|_error| "configuration invalid")?;
    let digest = config.drain.digest().map_err(|e| e.to_string())?;
    let url = std::env::var("LORE_CELL_BUDGET_MAINTENANCE_URL")
        .map_err(|_error| "LORE_CELL_BUDGET_MAINTENANCE_URL required")?;
    let ca = std::env::var("LORE_CELL_BUDGET_CA_PEM")
        .map_err(|_error| "LORE_CELL_BUDGET_CA_PEM required")?;
    if ca.trim().is_empty() {
        return Err("LORE_CELL_BUDGET_CA_PEM required".into());
    }
    let identity = DispatchDatabaseIdentity::new(
        config
            .system_identifier
            .parse()
            .map_err(|_error| "identity invalid")?,
        config.database_oid,
    )
    .map_err(|_error| "identity invalid")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_error| "runtime unavailable")?;
    runtime.block_on(async {
        let pool = DispatchRuntimePool::new(DispatchPoolConfig {
            postgres_url: url,
            role: DispatchPoolRole::Maintenance,
            expected_database_identity: identity,
            pool_max: 1,
            connect_timeout: Duration::from_secs(10),
            acquire_timeout: Duration::from_secs(10),
            statement_timeout: Duration::from_secs(10),
            lock_timeout: Duration::from_secs(2),
            tls: DispatchTlsMode::PinnedRootCa(ca),
            budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0)
                .map_err(|_error| "connection budget invalid")?,
        })
        .map_err(|_error| "maintenance pool refused")?;
        let client = DrainClient::new(Arc::new(pool));
        if action == "rotate" {
            let previous = config
                .previous
                .as_ref()
                .ok_or("previous policy pin required")?;
            client
                .rotate(
                    &config.drain,
                    &previous.revision,
                    &decode_digest(&previous.digest).map_err(|e| e.to_string())?,
                )
                .await
                .map_err(|e| e.to_string())
        } else {
            if config.previous.is_some() || offline {
                return Err(
                    "previous pin and exclusion acknowledgement are only valid for rotate".into(),
                );
            }
            client
                .configure(&config.drain, publish)
                .await
                .map_err(|e| e.to_string())
        }
    })?;
    println!(
        "{}",
        serde_json::json!({"cell":config.drain.cell,"revision":config.drain.revision,"digest":hex(&digest)})
    );
    Ok(())
}

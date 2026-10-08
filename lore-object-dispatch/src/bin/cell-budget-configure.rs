// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Operator command. Credentials and CA bytes are environment-only and never printed.
use std::process::ExitCode;

use lore_object_dispatch::cell_budget_configure::BudgetAction;
use lore_object_dispatch::cell_budget_configure::CellConfigBinding;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
use lore_object_dispatch::cell_budget_configure::configure_budget;
use lore_object_dispatch::cell_budget_configure::configure_budget_for_cell;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;

const USAGE: &str = "usage: cell-budget-configure <publish|verify|reconcile> <json-path> \
                     [--cell-config <toml-path>]...";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cell-budget-configure: {message}");
            ExitCode::FAILURE
        }
    }
}

fn read_bounded(path: &str, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut file =
        std::fs::File::open(path).map_err(|_err| format!("{label} file cannot be opened"))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, limit), &mut bytes)
        .map_err(|_err| format!("{label} file cannot be read"))?;
    Ok(bytes)
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [action, path, rest @ ..] = args.as_slice() else {
        return Err(USAGE.into());
    };
    let action = match action.as_str() {
        "publish" => BudgetAction::Publish,
        "verify" => BudgetAction::Verify,
        "reconcile" => BudgetAction::Reconcile,
        _ => return Err("action must be publish, verify or reconcile".into()),
    };
    // Loreserver configuration layers in load order, for the cell binding check.
    let mut layers = Vec::new();
    let mut rest = rest.iter();
    while let Some(flag) = rest.next() {
        let (Some(layer), "--cell-config") = (rest.next(), flag.as_str()) else {
            return Err(USAGE.into());
        };
        let bytes = read_bounded(layer, 1_048_577, "cell configuration")?;
        if bytes.len() > 1_048_576 {
            return Err("cell configuration file is too large".into());
        }
        layers.push(String::from_utf8(bytes).map_err(|_err| "cell configuration is not UTF-8")?);
    }
    let bytes = read_bounded(path, 16_385, "configuration")?;
    let config = LocalBudgetConfiguration::from_json(&bytes).map_err(|e| e.to_string())?;
    let cell = if layers.is_empty() {
        None
    } else {
        Some(CellConfigBinding::from_toml_layers(&layers).map_err(|e| e.to_string())?)
    };
    let url = std::env::var("LORE_CELL_BUDGET_MAINTENANCE_URL")
        .map_err(|_err| "LORE_CELL_BUDGET_MAINTENANCE_URL is required")?;
    let tls = match std::env::var("LORE_CELL_BUDGET_CA_PEM") {
        Ok(pem) if !pem.trim().is_empty() => DispatchTlsMode::PinnedRootCa(pem),
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            return Err("LORE_CELL_BUDGET_CA_PEM is required and must be nonempty".into());
        }
        Err(_) => return Err("LORE_CELL_BUDGET_CA_PEM is invalid".into()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_err| "async runtime unavailable")?;
    let receipt = runtime
        .block_on(async {
            match &cell {
                Some(cell) => configure_budget_for_cell(&config, cell, &url, tls, action).await,
                None => configure_budget(&config, &url, tls, action).await,
            }
        })
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|_err| "receipt encoding failed")?
    );
    Ok(())
}

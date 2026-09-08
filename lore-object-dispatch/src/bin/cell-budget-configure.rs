// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Local operator command. Credentials and CA bytes are environment-only and never printed.
use std::process::ExitCode;

use lore_object_dispatch::cell_budget_configure::BudgetAction;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
use lore_object_dispatch::cell_budget_configure::configure_budget;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("cell-budget-configure: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [action, path] = args.as_slice() else {
        return Err("usage: cell-budget-configure <publish|verify|reconcile> <json-path>".into());
    };
    let action = match action.as_str() {
        "publish" => BudgetAction::Publish,
        "verify" => BudgetAction::Verify,
        "reconcile" => BudgetAction::Reconcile,
        _ => return Err("action must be publish, verify or reconcile".into()),
    };
    let mut file = std::fs::File::open(path).map_err(|_| "configuration file cannot be opened")?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&mut file, 16_385), &mut bytes)
        .map_err(|_| "configuration file cannot be read")?;
    let config = LocalBudgetConfiguration::from_json(&bytes).map_err(|e| e.to_string())?;
    let url = std::env::var("LORE_CELL_BUDGET_MAINTENANCE_URL")
        .map_err(|_| "LORE_CELL_BUDGET_MAINTENANCE_URL is required")?;
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
        .map_err(|_| "async runtime unavailable")?;
    let receipt = runtime
        .block_on(configure_budget(&config, &url, tls, action))
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|_| "receipt encoding failed")?
    );
    Ok(())
}

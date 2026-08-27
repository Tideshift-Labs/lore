// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ServiceConfig;
use lore_object_dispatch::ServiceConfigError;
use lore_object_dispatch::ServiceServerError;
use lore_object_dispatch::serve;
use thiserror::Error;

#[tokio::main]
async fn main() -> Result<(), MainError> {
    let config = ServiceConfig::from_env()?;
    serve(&config, shutdown_signal()).await?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    match terminate {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[derive(Debug, Error)]
enum MainError {
    #[error("object-dispatch service configuration failed")]
    Configuration(#[from] ServiceConfigError),
    #[error("object-dispatch service failed")]
    Server(#[from] ServiceServerError),
}

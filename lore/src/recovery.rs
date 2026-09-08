// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Rust-only original-namespace receipt reads. Stored requests are never replayed.
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_transport::AttemptId;
use lore_transport::DomainAttemptReceipt;
use lore_transport::ProtocolError;

pub async fn receipt_get(
    store: &RepositoryAttemptStore,
    attempt: &AttemptId,
) -> Result<DomainAttemptReceipt, ProtocolError> {
    let binding = store.recovery_context(attempt).await?;
    let dial_url = lore_transport::caller_operation::recovery_dial_url(&binding.endpoint)?;
    lore_transport::with_caller_recovery(binding.clone(), async {
        let connection = lore_transport::connection::connect(
            &dial_url,
            "",
            binding.repository,
            lore_transport::connection::MAX_STORAGE_CONNECTIONS,
            "",
            "",
        )
        .await?;
        connection
            .domain_operations(binding.repository)
            .await?
            .attempt_receipt_get(attempt)
            .await
    })
    .await
}

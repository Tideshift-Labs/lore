// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_postgres::domain::fragments::FragmentDrainCandidate;
use lore_postgres::domain::fragments::FragmentDrainCandidateBatch;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;

/// Obtain the production witness before the race or barrier being tested.
pub async fn candidate(
    coordinator: &PostgresFragmentCoordinator,
    hash: &[u8],
) -> FragmentDrainCandidate {
    let mut cursor = Vec::new();
    loop {
        let rows = coordinator
            .staged_drain_candidates_after(FragmentDrainCandidateBatch::new(256).unwrap(), &cursor)
            .await
            .expect("read bounded production drain candidates");
        if let Some(found) = rows.iter().find(|row| row.hash() == hash) {
            return found.clone();
        }
        cursor = rows
            .last()
            .expect("fixture must expose its source before installing a barrier")
            .hash()
            .to_vec();
    }
}

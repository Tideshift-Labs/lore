// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the verdict rule of `revision::sync_settled`.

use lore_revision::revision::sync_settled::SyncSettled;

#[test]
fn verdict_table() {
    assert_eq!(SyncSettled::from_observation(0, 0), SyncSettled::Settled);
    assert_eq!(SyncSettled::from_observation(1, 0), SyncSettled::Behind);
    assert_eq!(SyncSettled::from_observation(0, 1), SyncSettled::Dirty);
    // Behind wins over dirty. Neither clears doubt, so the order only names the state.
    assert_eq!(SyncSettled::from_observation(3, 2), SyncSettled::Behind);
    assert!(SyncSettled::Settled.is_settled());
    assert!(!SyncSettled::Behind.is_settled());
    assert!(!SyncSettled::Dirty.is_settled());
}

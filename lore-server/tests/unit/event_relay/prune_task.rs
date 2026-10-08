// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;
use lore_server::event_relay::config::RetentionConfig;

/// The shipped cadence must stay orders of magnitude below the floor it
/// sweeps against. A sweep interval anywhere near seven days would mean a
/// reapable row waits most of a second retention window to be reaped.
#[test]
fn the_default_cadence_is_far_below_the_retention_floor() {
    let retention = RetentionConfig::default();
    assert!(retention.sweep_interval < MIN_RETENTION_AGE);
    assert!(retention.sweep_interval < MIN_DEAD_LETTER_RETENTION);
    assert_eq!(retention.consumer_safe_age, MIN_RETENTION_AGE);
    assert_eq!(retention.dead_letter_age, MIN_DEAD_LETTER_RETENTION);
    assert_eq!(retention.batch_rows, MAX_PRUNE_BATCH);
}

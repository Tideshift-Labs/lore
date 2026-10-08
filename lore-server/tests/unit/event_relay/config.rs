// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;

use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;
use lore_server::event_relay::config::*;
use lore_server::settings::OutboxRelaySettings;

fn raw() -> OutboxRelaySettings {
    OutboxRelaySettings {
        enabled: true,
        ..OutboxRelaySettings::default()
    }
}

#[test]
fn the_shipped_defaults_are_cr_032s_pinned_values() {
    let config = EventRelayConfig::from_settings(&raw()).expect("defaults are in bounds");
    assert_eq!(config.batch_size, MAX_CLAIM_BATCH);
    assert_eq!(config.claim_lease, Duration::from_secs(30));
    assert_eq!(config.publish_deadline, MAX_PUBLISH_DEADLINE);
    assert_eq!(config.max_oldest_unpublished, Duration::from_secs(30));
    assert_eq!(
        config.admission.max_oldest_pending_age,
        Duration::from_secs(300)
    );
    assert_eq!(config.admission.max_pending_rows, 1_000_000);
    assert_eq!(config.admission.max_pending_bytes, 5 * 1024 * 1024 * 1024);
}

#[test]
fn a_batch_over_the_contract_bound_is_refused_not_clamped() {
    let settings = OutboxRelaySettings {
        batch_size: MAX_CLAIM_BATCH + 1,
        ..raw()
    };
    assert!(matches!(
        EventRelayConfig::from_settings(&settings),
        Err(EventRelayConfigError::OutOfBounds {
            field: "batch_size",
            ..
        })
    ));
}

#[test]
fn a_publish_deadline_over_ten_seconds_is_refused() {
    let settings = OutboxRelaySettings {
        publish_deadline_seconds: 11,
        claim_lease_seconds: 300,
        ..raw()
    };
    assert!(matches!(
        EventRelayConfig::from_settings(&settings),
        Err(EventRelayConfigError::OutOfBounds {
            field: "publish_deadline_seconds",
            ..
        })
    ));
}

/// The cross-field bound, which neither knob can violate on its own.
#[test]
fn a_deadline_that_does_not_fit_twice_inside_the_lease_is_refused() {
    let settings = OutboxRelaySettings {
        publish_deadline_seconds: 10,
        claim_lease_seconds: 15,
        ..raw()
    };
    let err = EventRelayConfig::from_settings(&settings).expect_err("must be refused");
    assert!(
        matches!(
            &err,
            EventRelayConfigError::OutOfBounds {
                field: "publish_deadline_seconds",
                detail
            } if detail.contains("claim lease")
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn a_lease_outside_the_reviewed_range_is_refused_at_both_ends() {
    for seconds in [4u64, 301] {
        let settings = OutboxRelaySettings {
            claim_lease_seconds: seconds,
            publish_deadline_seconds: 1,
            ..raw()
        };
        assert!(
            matches!(
                EventRelayConfig::from_settings(&settings),
                Err(EventRelayConfigError::OutOfBounds {
                    field: "claim_lease_seconds",
                    ..
                })
            ),
            "{seconds}s must be refused"
        );
    }
}

#[test]
fn an_over_wide_owner_is_refused() {
    let settings = OutboxRelaySettings {
        owner: Some("o".repeat(MAX_CLAIM_OWNER_BYTES + 1)),
        ..raw()
    };
    assert!(matches!(
        EventRelayConfig::from_settings(&settings),
        Err(EventRelayConfigError::OwnerWidth(_))
    ));
}

#[test]
fn the_default_owner_fits_the_column_bound() {
    let owner = default_owner();
    assert!(!owner.is_empty());
    assert!(owner.len() <= MAX_CLAIM_OWNER_BYTES);
}

#[test]
fn backoff_doubles_to_the_cap_and_never_past_it() {
    let backoff = RelayBackoff {
        base: Duration::from_millis(100),
        cap: Duration::from_secs(1),
    };
    // Full jitter at 1.0 is the ceiling itself, which is what makes the
    // doubling observable at all.
    assert_eq!(backoff.next_delay(0, 1.0), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(1, 1.0), Duration::from_millis(200));
    assert_eq!(backoff.next_delay(2, 1.0), Duration::from_millis(400));
    assert_eq!(backoff.next_delay(3, 1.0), Duration::from_millis(800));
    assert_eq!(backoff.next_delay(4, 1.0), Duration::from_millis(1000));
    assert_eq!(backoff.next_delay(40, 1.0), Duration::from_millis(1000));
}

/// The whole point of jitter: two rows with the same attempt count must be
/// able to land on different delays.
#[test]
fn jitter_spans_zero_to_the_ceiling_with_a_one_millisecond_floor() {
    let backoff = RelayBackoff {
        base: Duration::from_millis(1000),
        cap: Duration::from_secs(30),
    };
    assert_eq!(backoff.next_delay(0, 0.0), Duration::from_millis(1));
    assert_eq!(backoff.next_delay(0, 0.5), Duration::from_millis(500));
    assert_eq!(backoff.next_delay(0, 1.0), Duration::from_millis(1000));
}

/// An enormous attempt count must not shift past the width of the
/// multiplier and wrap the ceiling back down to something small.
#[test]
fn an_absurd_attempt_count_stays_at_the_cap() {
    let backoff = RelayBackoff {
        base: Duration::from_millis(250),
        cap: Duration::from_secs(30),
    };
    for attempts in [31, 32, 33, 64, 1_000, i32::MAX] {
        assert_eq!(
            backoff.next_delay(attempts, 1.0),
            Duration::from_secs(30),
            "attempt {attempts} must stay at the cap"
        );
    }
}

#[test]
fn a_negative_attempt_count_is_treated_as_the_first_attempt() {
    let backoff = RelayBackoff {
        base: Duration::from_millis(250),
        cap: Duration::from_secs(30),
    };
    assert_eq!(backoff.next_delay(-5, 1.0), Duration::from_millis(250));
}

#[test]
fn a_non_finite_jitter_draw_takes_the_full_ceiling() {
    let backoff = RelayBackoff {
        base: Duration::from_millis(250),
        cap: Duration::from_secs(30),
    };
    assert_eq!(backoff.next_delay(0, f64::NAN), Duration::from_millis(250));
}

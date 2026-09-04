// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The relay's validated configuration and its retry schedule.
//!
//! `settings::OutboxRelaySettings` is the raw TOML shape. This is the shape the
//! worker actually runs on, and the conversion between them is where CR-032's
//! "configurable only within reviewed bounds" is enforced. A value outside a
//! bound is a named startup failure, never a silent clamp: an operator who set
//! a 60-second publish deadline needs to be told the contract caps it at ten,
//! not to run for a month believing the value took effect.

use std::time::Duration;

use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::prune::MAX_PRUNE_BATCH;
use lore_postgres::domain::outbox::prune::MIN_DEAD_LETTER_RETENTION;
use lore_postgres::domain::outbox::prune::MIN_RETENTION_AGE;
use lore_postgres::domain::outbox::relay::MAX_CLAIM_BATCH;

use crate::event_relay::admission::ADMISSION_RETRY_DELAY;
use crate::settings::OutboxRelaySettings;

/// CR-032's publish deadline ceiling.
pub const MAX_PUBLISH_DEADLINE: Duration = Duration::from_secs(10);
/// Reviewed lease bounds. The contract pins 30 seconds; the range exists so a
/// slow cell can widen it without a code change, not so it can be disabled.
pub const MIN_CLAIM_LEASE: Duration = Duration::from_secs(5);
/// Upper reviewed bound on the lease. A longer lease means a dead worker's rows
/// stay unreclaimable for longer, which is the failure mode the lease exists to
/// bound.
pub const MAX_CLAIM_LEASE: Duration = Duration::from_secs(300);

/// Why a `[outbox_relay]` section was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventRelayConfigError {
    /// A numeric knob is outside its reviewed bound.
    #[error("[outbox_relay] {field} is outside its reviewed bound: {detail}")]
    OutOfBounds {
        /// The offending TOML key.
        field: &'static str,
        /// What the bound is and what was supplied.
        detail: String,
    },
    /// `owner` was supplied but is empty or over the column's 128-byte bound.
    #[error("[outbox_relay] owner must be 1..=128 bytes, got {0}")]
    OwnerWidth(usize),
}

/// The bounded jittered retry schedule for a transient publish failure.
///
/// Full jitter over an exponential ceiling, which is what keeps a cell's
/// workers from resynchronising into a thundering herd after a broker outage:
/// every row's next attempt is drawn uniformly from `[0, ceiling]` rather than
/// landing on the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayBackoff {
    /// Delay ceiling for the first retry.
    pub base: Duration,
    /// Ceiling on the doubling.
    pub cap: Duration,
}

impl RelayBackoff {
    /// The delay before the next attempt of a row that has already made
    /// `attempt_count` attempts.
    ///
    /// `rand01` is the caller's uniform draw from `[0, 1]`, passed in rather
    /// than taken here so the schedule is a pure function and a test can pin
    /// both edges of the jitter window without a seeded generator.
    ///
    /// A negative `attempt_count` cannot occur (the column is
    /// `CHECK (attempt_count >= 0)`), and is treated as zero rather than
    /// wrapping into an enormous shift.
    pub fn next_delay(&self, attempt_count: i32, rand01: f64) -> Duration {
        let attempts = attempt_count.max(0) as u32;
        // Saturating rather than wrapping: at 64 shifts the ceiling is already
        // pinned to `cap`, so the exact shift count past that point is
        // irrelevant and only the overflow would be observable.
        let multiplier = 1u64.checked_shl(attempts.min(32)).unwrap_or(u64::MAX);
        let ceiling_millis = (self.base.as_millis() as u64)
            .saturating_mul(multiplier)
            .min(self.cap.as_millis() as u64);
        let fraction = if rand01.is_finite() {
            rand01.clamp(0.0, 1.0)
        } else {
            // A non-finite draw is a caller bug, not a schedule input. Taking
            // the full ceiling is the conservative reading: it backs off more,
            // never less.
            1.0
        };
        // The floor keeps a row from being re-claimed in the same millisecond
        // it failed in, which would spin the loop against a broker that is
        // still down.
        let millis = ((ceiling_millis as f64) * fraction).round() as u64;
        Duration::from_millis(millis.max(1))
    }
}

/// Reviewed bounds on the retention sweep cadence (WP-119 Phase 8).
///
/// The lower bound is not a busy-loop guard. A sweep is up to five bounded
/// transactions against the hottest table in the relay's scan path, and CR-032's
/// shortest retention floor is seven days — so a cadence measured in seconds
/// buys nothing and contends with the publish loop for the same rows.
pub const MIN_PRUNE_INTERVAL: Duration = Duration::from_secs(10);
/// Upper bound. A sweep an hour apart already reaps far faster than a seven-day
/// floor accrues; beyond that the schedule stops being one.
pub const MAX_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Upper bound on transactions per sweep. At CR-032's thousand-row transaction
/// bound this is 32,000 rows a sweep, which drains a very large backlog inside
/// an hour at the default cadence without any single sweep holding a connection
/// for long.
pub const MAX_PRUNE_BATCHES_PER_SWEEP: usize = 32;

/// The validated retention schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// How often a sweep runs.
    pub sweep_interval: Duration,
    /// Consumer-safe rows must be at least this old. Refused below CR-032's
    /// seven-day floor by the store itself, and again here so the refusal
    /// happens at startup rather than on the first sweep.
    pub consumer_safe_age: Duration,
    /// Dispositioned dead letters must be at least this old. Thirty-day floor,
    /// same rule.
    pub dead_letter_age: Duration,
    /// Rows per prune transaction, capped by CR-032's own thousand.
    pub batch_rows: i64,
    /// Consumer-safe prune transactions per sweep.
    pub batches_per_sweep: usize,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            sweep_interval: Duration::from_secs(60),
            consumer_safe_age: MIN_RETENTION_AGE,
            dead_letter_age: MIN_DEAD_LETTER_RETENTION,
            batch_rows: MAX_PRUNE_BATCH,
            batches_per_sweep: 4,
        }
    }
}

/// Everything the relay worker needs, already checked.
#[derive(Debug, Clone)]
pub struct EventRelayConfig {
    /// Whether the worker runs at all.
    pub enabled: bool,
    /// Lease owner recorded on every claim.
    pub owner: String,
    /// Rows per claim transaction.
    pub batch_size: usize,
    /// Claim lease.
    pub claim_lease: Duration,
    /// Per-publish deadline.
    pub publish_deadline: Duration,
    /// Sleep after an empty claim.
    pub idle_interval: Duration,
    /// Transient-failure schedule.
    pub backoff: RelayBackoff,
    /// Backlog refresh cadence for readiness.
    pub readiness_probe_interval: Duration,
    /// Oldest-unpublished age above which relay readiness is false.
    pub max_oldest_unpublished: Duration,
    /// Required-event mutation admission limits.
    pub admission: AdmissionLimits,
    /// The retention sweep's own schedule and floors.
    pub retention: RetentionConfig,
}

impl EventRelayConfig {
    /// Validate a raw section.
    pub fn from_settings(raw: &OutboxRelaySettings) -> Result<Self, EventRelayConfigError> {
        let owner = match raw.owner.as_deref() {
            Some(owner) => {
                if owner.is_empty() || owner.len() > MAX_CLAIM_OWNER_BYTES {
                    return Err(EventRelayConfigError::OwnerWidth(owner.len()));
                }
                owner.to_string()
            }
            None => default_owner(),
        };

        if raw.batch_size == 0 || raw.batch_size > MAX_CLAIM_BATCH {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "batch_size",
                detail: format!("must be 1..={MAX_CLAIM_BATCH}, got {}", raw.batch_size),
            });
        }

        let claim_lease = Duration::from_secs(raw.claim_lease_seconds);
        if claim_lease < MIN_CLAIM_LEASE || claim_lease > MAX_CLAIM_LEASE {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "claim_lease_seconds",
                detail: format!(
                    "must be {}..={} seconds, got {}",
                    MIN_CLAIM_LEASE.as_secs(),
                    MAX_CLAIM_LEASE.as_secs(),
                    raw.claim_lease_seconds
                ),
            });
        }

        let publish_deadline = Duration::from_secs(raw.publish_deadline_seconds);
        if publish_deadline.is_zero() || publish_deadline > MAX_PUBLISH_DEADLINE {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "publish_deadline_seconds",
                detail: format!(
                    "must be 1..={} seconds (CR-032's ceiling), got {}",
                    MAX_PUBLISH_DEADLINE.as_secs(),
                    raw.publish_deadline_seconds
                ),
            });
        }

        // The publish deadline has to fit inside the lease with room for the
        // acknowledgement write, or every long publish races its own claim
        // expiry and the row is republished by a second worker. This is the one
        // cross-field bound, and it is the reason the two cannot be validated
        // independently.
        if publish_deadline * 2 > claim_lease {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "publish_deadline_seconds",
                detail: format!(
                    "twice the publish deadline ({}s) must fit inside the claim lease ({}s), \
                     so an acknowledgement is written well before the lease expires",
                    publish_deadline.as_secs() * 2,
                    claim_lease.as_secs()
                ),
            });
        }

        if raw.idle_interval_millis == 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "idle_interval_millis",
                detail: "must be at least 1; a zero idle interval is a busy loop".to_string(),
            });
        }
        if raw.backoff_base_millis == 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "backoff_base_millis",
                detail: "must be at least 1".to_string(),
            });
        }
        let backoff = RelayBackoff {
            base: Duration::from_millis(raw.backoff_base_millis),
            cap: Duration::from_secs(raw.backoff_cap_seconds),
        };
        if backoff.cap < backoff.base {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "backoff_cap_seconds",
                detail: format!(
                    "must be at least backoff_base_millis ({}ms), got {}s",
                    raw.backoff_base_millis, raw.backoff_cap_seconds
                ),
            });
        }

        if raw.readiness_probe_interval_seconds == 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "readiness_probe_interval_seconds",
                detail: "must be at least 1".to_string(),
            });
        }
        // The second cross-field bound, and the reason it exists is in
        // `ADMISSION_RETRY_DELAY`'s own documentation: the admission gate reads
        // a verdict this interval refreshes, so a client told to retry sooner
        // than one whole interval is guaranteed to read the identical cached
        // verdict. Refused rather than clamped — an operator who widened the
        // probe interval to reduce database load needs to know it would have
        // silently made every admission retry a no-op.
        let probe_interval = Duration::from_secs(raw.readiness_probe_interval_seconds);
        if probe_interval >= ADMISSION_RETRY_DELAY {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "readiness_probe_interval_seconds",
                detail: format!(
                    "must be below the admission retry delay ({}s), or a rejected client's retry \
                     reads the same cached verdict it was already refused on; got {}",
                    ADMISSION_RETRY_DELAY.as_secs(),
                    raw.readiness_probe_interval_seconds
                ),
            });
        }
        if raw.max_oldest_unpublished_seconds == 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "max_oldest_unpublished_seconds",
                detail: "must be at least 1".to_string(),
            });
        }
        if raw.admission_max_pending_rows <= 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "admission_max_pending_rows",
                detail: format!("must be positive, got {}", raw.admission_max_pending_rows),
            });
        }
        if raw.admission_max_pending_bytes <= 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "admission_max_pending_bytes",
                detail: format!("must be positive, got {}", raw.admission_max_pending_bytes),
            });
        }
        if raw.admission_max_oldest_pending_age_seconds == 0 {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "admission_max_oldest_pending_age_seconds",
                detail: "must be at least 1".to_string(),
            });
        }

        let retention = Self::retention_from(raw)?;

        Ok(Self {
            enabled: raw.enabled,
            owner,
            batch_size: raw.batch_size,
            claim_lease,
            publish_deadline,
            idle_interval: Duration::from_millis(raw.idle_interval_millis),
            backoff,
            readiness_probe_interval: Duration::from_secs(raw.readiness_probe_interval_seconds),
            max_oldest_unpublished: Duration::from_secs(raw.max_oldest_unpublished_seconds),
            admission: AdmissionLimits {
                max_oldest_pending_age: Duration::from_secs(
                    raw.admission_max_oldest_pending_age_seconds,
                ),
                max_pending_rows: raw.admission_max_pending_rows,
                max_pending_bytes: raw.admission_max_pending_bytes,
            },
            retention,
        })
    }

    /// Validate the retention half of a raw section.
    ///
    /// Split out because it is the one group of knobs with no interaction with
    /// the publish loop's own bounds, and because the retention *floors* are
    /// owned by `lore_postgres` rather than by this module — the checks here
    /// exist so a cell that configured a shorter window is refused at startup
    /// instead of on its first sweep, days later, in a `warn!` nobody reads.
    fn retention_from(raw: &OutboxRelaySettings) -> Result<RetentionConfig, EventRelayConfigError> {
        let sweep_interval = Duration::from_secs(raw.prune_interval_seconds);
        if sweep_interval < MIN_PRUNE_INTERVAL || sweep_interval > MAX_PRUNE_INTERVAL {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "prune_interval_seconds",
                detail: format!(
                    "must be {}..={} seconds, got {}",
                    MIN_PRUNE_INTERVAL.as_secs(),
                    MAX_PRUNE_INTERVAL.as_secs(),
                    raw.prune_interval_seconds
                ),
            });
        }

        // `checked_mul` rather than `days * 86_400`: an operator typing a very
        // large day count would otherwise wrap to a *short* window, which is
        // the one direction CR-032 forbids — and it would then pass the floor
        // check below for the wrong reason.
        let consumer_safe_age =
            days(raw.retention_days).ok_or_else(|| EventRelayConfigError::OutOfBounds {
                field: "retention_days",
                detail: format!("{} days is not a representable window", raw.retention_days),
            })?;
        if consumer_safe_age < MIN_RETENTION_AGE {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "retention_days",
                detail: format!(
                    "must be at least {} days (CR-032's replay window), got {}",
                    MIN_RETENTION_AGE.as_secs() / 86_400,
                    raw.retention_days
                ),
            });
        }

        let dead_letter_age = days(raw.dead_letter_retention_days).ok_or_else(|| {
            EventRelayConfigError::OutOfBounds {
                field: "dead_letter_retention_days",
                detail: format!(
                    "{} days is not a representable window",
                    raw.dead_letter_retention_days
                ),
            }
        })?;
        if dead_letter_age < MIN_DEAD_LETTER_RETENTION {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "dead_letter_retention_days",
                detail: format!(
                    "must be at least {} days (CR-032's dead-letter floor), got {}",
                    MIN_DEAD_LETTER_RETENTION.as_secs() / 86_400,
                    raw.dead_letter_retention_days
                ),
            });
        }

        if raw.prune_batch_rows < 1 || raw.prune_batch_rows > MAX_PRUNE_BATCH {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "prune_batch_rows",
                detail: format!(
                    "must be 1..={MAX_PRUNE_BATCH} (CR-032's transaction bound), got {}",
                    raw.prune_batch_rows
                ),
            });
        }
        if raw.prune_batches_per_sweep < 1
            || raw.prune_batches_per_sweep > MAX_PRUNE_BATCHES_PER_SWEEP
        {
            return Err(EventRelayConfigError::OutOfBounds {
                field: "prune_batches_per_sweep",
                detail: format!(
                    "must be 1..={MAX_PRUNE_BATCHES_PER_SWEEP}, got {}",
                    raw.prune_batches_per_sweep
                ),
            });
        }

        Ok(RetentionConfig {
            sweep_interval,
            consumer_safe_age,
            dead_letter_age,
            batch_rows: raw.prune_batch_rows,
            batches_per_sweep: raw.prune_batches_per_sweep,
        })
    }
}

/// A whole number of days as a `Duration`, or `None` when it cannot be
/// represented.
fn days(count: u64) -> Option<Duration> {
    count.checked_mul(24 * 60 * 60).map(Duration::from_secs)
}

/// The `claim_owner` column's bound, mirrored here so the config refuses a
/// too-wide owner at startup rather than on the first claim.
const MAX_CLAIM_OWNER_BYTES: usize = 128;

/// Hostname plus process id, truncated to the column bound.
///
/// Two workers on one host are distinguishable, and a restarted worker gets a
/// new owner rather than inheriting the dead one's leases. It never has to be
/// unique for correctness: `claim_generation` is the fence, and the owner is a
/// diagnostic plus the second half of `renew_claim`'s two-field predicate.
fn default_owner() -> String {
    let host = hostname().unwrap_or_else(|| "unknown-host".to_string());
    let mut owner = format!("{host}/{}", std::process::id());
    if owner.len() > MAX_CLAIM_OWNER_BYTES {
        owner.truncate(MAX_CLAIM_OWNER_BYTES);
        // Truncating mid-character would leave invalid UTF-8; `truncate` panics
        // on a non-boundary index, so shrink to the previous boundary instead.
        while !owner.is_char_boundary(owner.len()) {
            owner.pop();
        }
    }
    owner
}

fn hostname() -> Option<String> {
    // No new dependency for one diagnostic string: every platform this server
    // targets exports one of these.
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(key)
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

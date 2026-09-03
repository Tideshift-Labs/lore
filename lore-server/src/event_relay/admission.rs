// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Required-event mutation admission (CR-032 Phase 8).
//!
//! One handle, one question: may this cell accept another mutation that will
//! append an outbox row? The answer comes from **local Postgres facts only** —
//! unpublished row count, unpublished payload bytes, and oldest unpublished
//! age. CR-032 forbids this gate from querying live broker lag, gateway health,
//! or a receiver over the network, and the shape of `relay::admission_check`
//! makes that unrepresentable rather than merely discouraged: nothing reachable
//! from here leaves the database.
//!
//! The gate runs **before** the owning mutation transaction opens. A mutation
//! that already committed stays successful; only a pre-commit rejection exists,
//! and it maps to `RESOURCE_EXHAUSTED` with bounded `RetryInfo`. The server
//! performs no hidden retry of its own.
//!
//! # Failing open on a probe error is deliberate
//!
//! If the probe itself fails, this returns the error to the caller rather than
//! guessing. The caller ([`crate::domain::DomainContext::admit`]) then declines
//! to close admission on it, because a backlog probe that cannot run is not
//! evidence of a backlog — and the mutation is about to open its own
//! transaction against the same database, which will fail honestly on its own
//! terms if Postgres is really unreachable. Closing admission here would turn
//! one transient probe failure into a cell-wide mutation outage with a
//! misleading reason.

use std::time::Duration;

use lore_postgres::domain::DomainError;
use lore_postgres::domain::outbox::AdmissionLimits;
use lore_postgres::domain::outbox::AdmissionRejection;
use lore_postgres::domain::outbox::AdmissionVerdict;
use lore_postgres::domain::outbox::relay;
use lore_postgres::pool::Pool;
use tonic::Status;

use crate::event_relay::metrics;
use crate::event_relay::retry_info;

/// The bounded retry hint attached to a rejection.
///
/// CR-032 requires the `RetryInfo` to be bounded and to fit one measured
/// end-to-end elapsed and attempt budget with the real Lore client policy. A
/// fixed small delay is the conservative choice while that budget is still
/// unmeasured: it cannot exceed a client's patience on its own, and the backlog
/// that caused the rejection drains on the relay's timescale, not the client's.
///
/// PIN(WP-119): the value is a placeholder until Phase 8's load test measures
/// the real drain rate. Raising it is a reviewed change, not a tuning knob.
pub const ADMISSION_RETRY_DELAY: Duration = Duration::from_secs(5);

/// The server-side admission handle.
#[derive(Debug, Clone)]
pub struct OutboxAdmission {
    pool: Pool,
    limits: AdmissionLimits,
}

impl OutboxAdmission {
    /// Bind the gate to the relay's pool and the cell's reviewed limits.
    pub fn new(pool: Pool, limits: AdmissionLimits) -> Self {
        Self { pool, limits }
    }

    /// The configured limits, for diagnostics and tests.
    pub fn limits(&self) -> &AdmissionLimits {
        &self.limits
    }

    /// Ask whether one more required-event mutation may be admitted.
    pub async fn check(&self) -> Result<AdmissionVerdict, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::Transient(format!("outbox admission pool: {e}")))?;
        let verdict = relay::admission_check(&**client, &self.limits).await?;
        if let AdmissionVerdict::Reject(rejection) = &verdict {
            metrics::record_admission_rejection(limit_label(rejection));
        }
        Ok(verdict)
    }
}

/// The bounded metric label for the limit that tripped.
pub const fn limit_label(rejection: &AdmissionRejection) -> &'static str {
    match rejection {
        AdmissionRejection::OldestPendingAge { .. } => metrics::ADMISSION_AGE,
        AdmissionRejection::PendingRows { .. } => metrics::ADMISSION_ROWS,
        AdmissionRejection::PendingBytes { .. } => metrics::ADMISSION_BYTES,
    }
}

/// The status a closed gate returns to the client.
///
/// The message names the limit that tripped but carries no repository, event,
/// or actor identity: it reaches an unauthenticated-to-this-cell caller, and a
/// backlog is a cell-wide condition rather than anything about the caller's
/// own request.
pub fn rejection_status(rejection: &AdmissionRejection) -> Status {
    let message = match rejection {
        AdmissionRejection::OldestPendingAge { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog is \
             older than its configured limit"
        }
        AdmissionRejection::PendingRows { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog \
             exceeds its configured row limit"
        }
        AdmissionRejection::PendingBytes { .. } => {
            "This cell is not accepting required-event mutations: the durable event backlog \
             exceeds its configured byte budget"
        }
    };
    Status::with_details(
        tonic::Code::ResourceExhausted,
        message,
        retry_info::retry_info_details(ADMISSION_RETRY_DELAY, message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejections() -> Vec<AdmissionRejection> {
        vec![
            AdmissionRejection::OldestPendingAge {
                observed: Duration::from_secs(600),
                limit: Duration::from_secs(300),
            },
            AdmissionRejection::PendingRows {
                observed: 1_000_001,
                limit: 1_000_000,
            },
            AdmissionRejection::PendingBytes {
                observed: 6 * 1024 * 1024 * 1024,
                limit: 5 * 1024 * 1024 * 1024,
            },
        ]
    }

    #[test]
    fn every_rejection_is_resource_exhausted_with_a_readable_retry_delay() {
        for rejection in rejections() {
            let status = rejection_status(&rejection);
            assert_eq!(status.code(), tonic::Code::ResourceExhausted);
            assert_eq!(
                retry_info::decode_retry_delay(status.details()),
                Some(ADMISSION_RETRY_DELAY),
                "every rejection must carry a bounded RetryInfo"
            );
        }
    }

    /// The message reaches a client, so it must not leak the observed backlog
    /// numbers of a cell serving other tenants.
    #[test]
    fn a_rejection_message_carries_no_observed_values() {
        for rejection in rejections() {
            let status = rejection_status(&rejection);
            let message = status.message();
            for leaked in ["1000001", "600", "6442450944"] {
                assert!(
                    !message.contains(leaked),
                    "message leaked an observed value: {message}"
                );
            }
        }
    }

    #[test]
    fn each_limit_maps_to_a_distinct_bounded_label() {
        let mut labels: Vec<&'static str> = rejections().iter().map(limit_label).collect();
        let total = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), total);
    }
}

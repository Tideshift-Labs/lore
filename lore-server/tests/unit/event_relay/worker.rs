// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use lore_postgres::domain::outbox::CasOutcome;
use lore_postgres::domain::outbox::ClaimedEvent;
use lore_server::event_relay::envelope_map::EnvelopeSource;
use lore_server::event_relay::envelope_map::MapFailure;
use lore_server::event_relay::publisher::DurablePublisher;
use lore_server::event_relay::readiness::EventRelayReadiness;
use lore_server::event_relay::worker::*;
use lore_server::plugins::remote_notification::BrokerAcceptance;
use lore_server::plugins::remote_notification::EventId;
use lore_server::plugins::remote_notification::PublishFailure;
use lore_server::plugins::remote_notification::TerminalClass;

fn acceptance() -> BrokerAcceptance {
    BrokerAcceptance {
        event_id: EventId::from_bytes([7u8; 16]),
        stream_identity: "durable".to_string(),
        stream_epoch: 1,
        broker_sequence: 42,
        publisher_contract_version: 1,
        broker_accepted_at: None,
    }
}

#[test]
fn an_in_range_acceptance_becomes_a_store_record() {
    let record = acceptance_record(&acceptance()).expect("in range");
    assert_eq!(record.stream_identity, "durable");
    assert_eq!(record.stream_epoch, 1);
    assert_eq!(record.broker_sequence, 42);
    assert_eq!(record.publisher_contract_version, 1);
}

/// A clamp here would put silently wrong evidence into the checkpoint
/// vector, so an out-of-range value must be refused instead.
#[test]
fn an_out_of_range_broker_sequence_is_refused_not_clamped() {
    let mut acceptance = acceptance();
    acceptance.broker_sequence = u64::MAX;
    assert!(acceptance_record(&acceptance).is_err());

    let mut acceptance = self::acceptance();
    acceptance.stream_epoch = u64::MAX;
    assert!(acceptance_record(&acceptance).is_err());

    let mut acceptance = self::acceptance();
    acceptance.publisher_contract_version = u32::MAX;
    assert!(acceptance_record(&acceptance).is_err());
}

#[test]
fn every_cas_outcome_has_a_distinct_bounded_label() {
    let outcomes = [
        CasOutcome::Applied,
        CasOutcome::StaleClaim {
            current_claim_generation: 3,
        },
        CasOutcome::AlreadyAccepted,
        CasOutcome::Vanished,
    ];
    let mut labels: Vec<&'static str> = outcomes.iter().map(cas_label).collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), total);
}

/// Every class this module can persist — as a dead letter's
/// `terminal_class` or as a row's `last_error_class` — must fit its column
/// and stay a bounded metric label. The three module constants are easy to
/// add without noticing they are also a metric dimension.
#[test]
fn every_persisted_class_is_a_bounded_column_safe_label() {
    let mut classes: Vec<&'static str> = vec![
        ACCEPTANCE_OUT_OF_RANGE,
        ACCEPT_WRITE_FAILED,
        LEASE_RENEWAL_FAILED,
    ];
    classes.extend(
        [
            MapFailure::RepositoryIdWidth(1),
            MapFailure::ZeroRepository,
            MapFailure::CellIdMismatch {
                row: "a".into(),
                configured: "b".into(),
            },
            MapFailure::NegativeRepositoryGeneration(-1),
            MapFailure::ZeroRepositoryGeneration,
            MapFailure::EventKindWidth,
            MapFailure::AggregateKindWidth,
            MapFailure::AggregateIdentityNotTransportable(0),
            MapFailure::AggregateVersionUndecodable("x".into()),
            MapFailure::AggregateVersionIdentityNotTransportable(0),
            MapFailure::NegativePayloadSchemaVersion(-1),
            MapFailure::PayloadOverCap(0),
        ]
        .iter()
        .map(MapFailure::as_terminal_class),
    );
    classes.extend(
        [
            TerminalClass::ScopeMismatch,
            TerminalClass::UnsupportedSchema,
            TerminalClass::InvalidRequest,
            TerminalClass::LocallyRejected,
        ]
        .into_iter()
        .map(TerminalClass::as_metric_label),
    );

    let total = classes.len();
    for class in &classes {
        assert!(!class.is_empty());
        assert!(class.is_ascii());
        assert!(!class.contains(' '));
        // `terminal_class` and `last_error_class` are both bounded at 64
        // bytes by their column CHECKs.
        assert!(class.len() <= 64, "`{class}` will not fit its column");
    }
    classes.sort_unstable();
    classes.dedup();
    assert_eq!(classes.len(), total, "persisted classes must be distinct");
}

/// The three classes that are properties of the row are terminal on sight.
#[test]
fn a_row_specific_terminal_class_is_final_on_the_first_attempt() {
    let _worker = policy_worker();
    // A row that has already failed some OTHER way, so a test that passed
    // only because `last_error_class` happened to be `None` would not.
    let previously_failed = claimed_row(3, Some("timeout"));

    for class in [
        TerminalClass::ScopeMismatch,
        TerminalClass::UnsupportedSchema,
        TerminalClass::LocallyRejected,
    ] {
        assert!(
            EventRelayWorker::terminal_is_final(class.as_metric_label(), &previously_failed),
            "{} is a property of the row and is terminal on sight",
            class.as_metric_label()
        );
    }
}

/// The rule that keeps one misbehaving gateway from emptying a cell's
/// backlog into dead letters. "Repeated" means the immediately preceding
/// attempt failed the same way, so a transient failure in between breaks
/// the run.
#[test]
fn an_answer_specific_class_is_final_only_after_the_same_class_twice_running() {
    let _worker = policy_worker();

    for class in [
        TerminalClass::InvalidRequest.as_metric_label(),
        ACCEPTANCE_OUT_OF_RANGE,
    ] {
        assert!(
            !EventRelayWorker::terminal_is_final(class, &claimed_row(0, None)),
            "{class}: a first rejection must requeue"
        );
        assert!(
            EventRelayWorker::terminal_is_final(class, &claimed_row(1, Some(class))),
            "{class}: a second consecutive rejection is terminal"
        );
    }
}

/// `attempt_count` counts every release, including timeouts and 5xx, so a
/// row that survived a broker outage arrives at its first genuine rejection
/// with a large count. Keying on that count instead of the previous class
/// is what would dead-letter the whole backlog the moment a gateway came
/// partly back, and this is the assertion that catches it.
#[test]
fn a_long_run_of_transient_failures_does_not_make_the_first_rejection_terminal() {
    let _worker = policy_worker();
    let after_an_outage = claimed_row(500, Some("broker_unavailable"));
    for class in [
        TerminalClass::InvalidRequest.as_metric_label(),
        ACCEPTANCE_OUT_OF_RANGE,
    ] {
        assert!(
            !EventRelayWorker::terminal_is_final(class, &after_an_outage),
            "{class}: 500 transient retries are not 500 rejections"
        );
    }
}

/// Two different answer-specific failures alternating are not a repetition
/// of either.
#[test]
fn alternating_rejection_classes_never_reach_terminal() {
    let _worker = policy_worker();
    assert!(!EventRelayWorker::terminal_is_final(
        TerminalClass::InvalidRequest.as_metric_label(),
        &claimed_row(9, Some(ACCEPTANCE_OUT_OF_RANGE))
    ));
    assert!(!EventRelayWorker::terminal_is_final(
        ACCEPTANCE_OUT_OF_RANGE,
        &claimed_row(9, Some(TerminalClass::InvalidRequest.as_metric_label()))
    ));
}

// -- fixtures for the policy tests ------------------------------------

/// A worker with a pool and publisher that are never reached.
///
/// `terminal_is_final` is pure over its two arguments, so it is decidable
/// without a database. The pool is built lazily by `deadpool-postgres` and
/// never connected here.
fn policy_worker() -> EventRelayWorker {
    use lore_server::event_relay::config::EventRelayConfig;
    use lore_server::settings::OutboxRelaySettings;

    #[derive(Debug)]
    struct NeverPublishes;

    #[async_trait::async_trait]
    impl DurablePublisher for NeverPublishes {
        async fn publish(
            &self,
            _envelope: &lore_server::plugins::remote_notification::DurableEnvelopeV1,
            _deadline: Duration,
        ) -> Result<BrokerAcceptance, PublishFailure> {
            unreachable!("the terminal-classification policy never publishes")
        }
    }

    let pool = lore_postgres::pool::build_pool(
        "postgresql://unused@127.0.0.1:1/unused",
        1,
        &lore_postgres::pool::TlsConfig::default(),
    )
    .expect("a lazily-built pool needs no server");
    let config = EventRelayConfig::from_settings(&OutboxRelaySettings {
        enabled: true,
        ..OutboxRelaySettings::default()
    })
    .expect("the shipped defaults are in bounds");
    let readiness = Arc::new(EventRelayReadiness::new(
        config.max_oldest_unpublished,
        config.readiness_probe_interval,
        config.publish_deadline,
    ));
    EventRelayWorker::new(
        pool,
        Arc::new(NeverPublishes),
        config,
        readiness,
        EnvelopeSource {
            cell_id: "cell-a".to_string(),
            placement_epoch: 1,
            producer_instance_id: "loreserver-1".to_string(),
        },
    )
}

fn claimed_row(attempt_count: i32, last_error_class: Option<&str>) -> ClaimedEvent {
    use lore_postgres::domain::outbox::AggregateVersion;
    use lore_postgres::domain::outbox::OutboxEventRecord;

    ClaimedEvent {
        event: OutboxEventRecord {
            event_id: uuid::Uuid::from_bytes([5u8; 16]),
            cell_id: "cell-a".to_string(),
            idempotency_key: [1u8; 32],
            repository_id: vec![2u8; 16],
            repository_generation: 3,
            event_kind: "branch.pushed".to_string(),
            aggregate_kind: "branch".to_string(),
            aggregate_id: b"main".to_vec(),
            aggregate_version: AggregateVersion::ordinal_only(1).encode(),
            payload_schema_version: 1,
            payload: b"{}".to_vec(),
            created_at: SystemTime::now(),
        },
        claim_generation: 1,
        claim_expires_at: SystemTime::now() + Duration::from_secs(30),
        attempt_count,
        last_error_class: last_error_class.map(str::to_string),
    }
}

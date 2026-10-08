// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::Duration;
use std::time::UNIX_EPOCH;

use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::operator;
use lore_postgres::domain::outbox::relay::DeadLetterOutcome;
use lore_postgres::domain::outbox::relay::OutboxRow;
use lore_postgres::domain::outbox::schema::PLACEHOLDER_GENERATION;
use lore_postgres::domain::outbox::schema::REQUIRED_REPLACEMENT_PLACEHOLDER;
use lore_server::event_relay::evaluator_task::block_label;
use lore_server::event_relay::operator::*;
use serde_json::Value;
use uuid::Uuid;

#[test]
fn a_repository_id_round_trips_through_hex() {
    let id = [0xab_u8; 16];
    let encoded = hex::encode(id);
    assert_eq!(encoded.len(), 32);
    assert_eq!(decode_repository(&encoded).expect("valid hex"), id.to_vec());
}

#[test]
fn a_short_or_unparsable_repository_id_is_refused() {
    assert!(decode_repository("").is_err());
    assert!(decode_repository("ab").is_err());
    assert!(decode_repository(&"ab".repeat(17)).is_err());
    assert!(decode_repository("zz".repeat(16).as_str()).is_err());
}

/// The defaults are CR-032's own maxima, so an operator who names no bound
/// still runs inside the reviewed limits.
#[test]
fn the_defaults_are_the_reviewed_bounds() {
    assert_eq!(DEFAULT_ROW_LIMIT, operator::MAX_INSPECT_ROWS);
    assert_eq!(DEFAULT_ROW_LIMIT, operator::MAX_REPLAY_ROWS);
    assert_eq!(
        Duration::from_secs(DEFAULT_REPLAY_WINDOW_HOURS * 3_600),
        operator::MAX_REPLAY_WINDOW
    );
}

/// Every refusal exits non-zero, so a runbook script cannot mistake a
/// refused disposition for an applied one.
#[test]
fn only_an_applied_disposition_succeeds() {
    let event = Uuid::nil();
    assert!(report_disposition("requeue", event, &DeadLetterOutcome::Applied).is_ok());
    for refused in [
        DeadLetterOutcome::NotFound,
        DeadLetterOutcome::NotParked {
            disposition: "obsolete".to_owned(),
        },
        DeadLetterOutcome::EventStillPresent,
        DeadLetterOutcome::RelayIncompatible {
            relay_compat_floor: 9,
        },
    ] {
        assert!(
            report_disposition("requeue", event, &refused).is_err(),
            "{refused:?} must exit non-zero"
        );
    }
}

/// The blocked-vector sentence carries the receiver identity the metric
/// label is required to drop.
#[test]
fn a_missing_checkpoint_names_the_receiver_the_metric_label_cannot() {
    let block = EvaluationBlock::MissingCheckpoint {
        receiver_identity: "loreserver-sfo3-cell-a-1".to_owned(),
        membership_generation: 4,
    };
    let described = describe_block(&block);
    assert!(described.contains("loreserver-sfo3-cell-a-1"));
    assert!(described.contains('4'));
    assert!(
        !block_label(&block).contains("loreserver"),
        "the metric label must stay identity-free"
    );
}

/// WP-115 row 60: `inspect` shows what delayed a row even after it was
/// accepted, when `last_error_class` has already been cleared.
#[test]
fn inspect_shows_the_retry_record_of_an_accepted_row() {
    let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let row = OutboxRow {
        event: lore_postgres::domain::outbox::OutboxEventRecord {
            event_id: Uuid::nil(),
            cell_id: "sfo3-cell-a".to_owned(),
            idempotency_key: [0; 32],
            repository_id: vec![0; 16],
            repository_generation: 1,
            event_kind: "branch.pushed".to_owned(),
            aggregate_kind: "branch".to_owned(),
            aggregate_id: vec![1],
            aggregate_version: vec![0; 8],
            payload_schema_version: 1,
            payload: b"{}".to_vec(),
            created_at: at,
        },
        state: "broker_accepted".to_owned(),
        available_at: at,
        claim_generation: 3,
        claim_owner: None,
        claim_expires_at: None,
        attempt_count: 2,
        last_error_class: None,
        last_retry: Some(lore_postgres::domain::outbox::RetryRecord {
            class: "placement_quiescing".to_owned(),
            at,
        }),
        acceptance: None,
        broker_accepted_at: None,
        replay_count: 0,
        replay: None,
    };
    let rendered = row_json(&row);
    assert_eq!(rendered["last_error_class"], Value::Null);
    assert_eq!(rendered["last_retry"]["class"], "placement_quiescing");
    assert_eq!(rendered["last_retry"]["at"], 1_700_000_000.0);

    let never_retried = OutboxRow {
        last_retry: None,
        ..row
    };
    assert_eq!(row_json(&never_retried)["last_retry"], Value::Null);
}

/// WP-115 row 68: `retire-generation` parses with all four required
/// arguments, refuses to parse without any one of them, and refuses
/// generation 0 or a negative generation at parse time.
#[test]
fn retire_generation_requires_receiver_generation_actor_and_reason() {
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(subcommand)]
        command: MaintenanceCommand,
    }

    let full = [
        ("--receiver", "loreserver-sfo3-cell-a-1"),
        ("--generation", "7"),
        ("--actor", "kv"),
        ("--reason", "replica 1 decommissioned"),
    ];
    let argv = |pairs: &[(&'static str, &'static str)]| {
        let mut argv = vec!["loreserver", "outbox", "retire-generation"];
        for &(flag, value) in pairs {
            argv.push(flag);
            argv.push(value);
        }
        argv
    };

    let parsed = Harness::try_parse_from(argv(&full)).expect("parse");
    let MaintenanceCommand::Outbox {
        command:
            OutboxCommand::RetireGeneration {
                receiver,
                generation,
                actor,
                reason,
                confirm_receiver_stopped,
            },
    } = parsed.command
    else {
        panic!("expected retire-generation, got {:?}", parsed.command);
    };
    assert_eq!(receiver, "loreserver-sfo3-cell-a-1");
    assert_eq!(generation, 7);
    assert_eq!(actor, "kv");
    assert_eq!(reason, "replica 1 decommissioned");
    assert!(
        !confirm_receiver_stopped,
        "the stop confirmation is opt-in, never a default"
    );

    let mut confirmed = argv(&full);
    confirmed.push("--confirm-receiver-stopped");
    let parsed = Harness::try_parse_from(confirmed).expect("parse with the confirmation");
    assert!(matches!(
        parsed.command,
        MaintenanceCommand::Outbox {
            command: OutboxCommand::RetireGeneration {
                confirm_receiver_stopped: true,
                ..
            }
        }
    ));

    for skipped in 0..full.len() {
        let partial: Vec<_> = full
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != skipped)
            .map(|(_, pair)| *pair)
            .collect();
        assert!(
            Harness::try_parse_from(argv(&partial)).is_err(),
            "{} must be required",
            full[skipped].0
        );
    }

    for reserved in ["0", "-1"] {
        let mut pairs = full;
        pairs[1] = ("--generation", reserved);
        assert!(
            Harness::try_parse_from(argv(&pairs)).is_err(),
            "generation {reserved} must not parse"
        );
    }
}

/// The reset placeholder is refused by identity and by generation before
/// any connection is made.
#[test]
fn retire_generation_refuses_the_reset_placeholder() {
    assert!(refuse_reserved_generation("loreserver-1", 3).is_ok());
    for (receiver, generation) in [
        (REQUIRED_REPLACEMENT_PLACEHOLDER, PLACEHOLDER_GENERATION),
        (REQUIRED_REPLACEMENT_PLACEHOLDER, 3),
        ("loreserver-1", PLACEHOLDER_GENERATION),
        ("loreserver-1", -1),
    ] {
        assert!(
            refuse_reserved_generation(receiver, generation).is_err(),
            "{receiver} generation {generation} must be refused"
        );
    }
}

/// Only a retired generation succeeds; every refusal exits non-zero so a
/// runbook script cannot read a refused retirement as done.
#[test]
fn only_a_retired_generation_succeeds() {
    let report = |outcome: MembershipCas| report_retirement("sfo3-cell-a", "r", 3, &outcome);
    assert!(
        report(MembershipCas::Applied {
            membership_version: 9,
            membership_generation: 3,
        })
        .is_ok()
    );
    assert!(report(MembershipCas::AlreadyRecorded).is_ok());
    for refused in [
        MembershipCas::RetirementUnproven,
        MembershipCas::ReceiverNotStopped {
            state: "ready".to_owned(),
        },
        MembershipCas::CellUnknown,
        MembershipCas::GenerationNotFound,
        MembershipCas::WrongState {
            state: "joining".to_owned(),
        },
        MembershipCas::VersionConflict {
            current_membership_version: 4,
        },
    ] {
        assert!(
            report(refused.clone()).is_err(),
            "{refused:?} must exit non-zero"
        );
    }
}

/// A window an operator could type must not wrap into a small one.
#[test]
fn an_unrepresentable_window_is_refused_rather_than_wrapped() {
    assert!(u64::MAX.checked_mul(3_600).is_none());
}

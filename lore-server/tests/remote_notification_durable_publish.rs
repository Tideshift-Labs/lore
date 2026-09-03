// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Integration tests for CR-027 / WP-111 Phase 1-2's durable publish entry point,
//! `PrivateGatewayClient::publish_durable_invalidation`.
//!
//! `client.rs`'s own unit tests already exhaustively pin the pure classification functions
//! (`classify_result`, `classify_status`) against hand-built `wire::PublishResultV1`/`tonic::Status`
//! values — this file does not duplicate that matrix. What this file adds:
//!
//! 1. the classification wired end-to-end through the real `publish_durable_invalidation` call
//!    (envelope encode -> transport -> classify), driven by a subset of
//!    `lorehub/docs/contracts/fixtures/lore-notification-plane/publish-result.json`'s vectors, so
//!    the classification is proven against the reviewed fixture too, not only hand-built cases;
//! 2. the deadline clamp (`MAX_DURABLE_PUBLISH_DEADLINE` = 10s) is actually applied, not just a
//!    declared constant;
//! 3. exactly one transport call per `publish_durable_invalidation` call — this client never
//!    retries internally (CR-032's relay owns durable retry).
//!
//! `PublishTransport` (`client::PublishTransport`) is a public trait specifically so component
//! tests can drive the real classification without a socket (see `client.rs`'s own module doc).
//! This file implements a small scripted double locally, independent of `fake_gateway.rs`'s own
//! `FakeGateway`/`ScriptedResponse` (which `remote_notification_sender.rs` uses) — both satisfy the
//! same `PublishTransport` trait, so either is a valid double; keeping this file's own is simplest
//! for a pure classification proof that doesn't need `fake_gateway.rs`'s broker-sequence/event-id
//! echoing behavior.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_server::plugins::remote_notification::client::BrokerAcceptance;
use lore_server::plugins::remote_notification::client::MAX_DURABLE_PUBLISH_DEADLINE;
use lore_server::plugins::remote_notification::client::PrivateGatewayClient;
use lore_server::plugins::remote_notification::client::PublishTransport;
use lore_server::plugins::remote_notification::config::RemoteNotificationConfig;
use lore_server::plugins::remote_notification::envelope::AggregateVersion;
use lore_server::plugins::remote_notification::envelope::DurableEnvelopeV1;
use lore_server::plugins::remote_notification::envelope::DurableInvalidationBody;
use lore_server::plugins::remote_notification::envelope::EnvelopeCommon;
use lore_server::plugins::remote_notification::envelope::EventId;
use lore_server::plugins::remote_notification::error::NotAcceptedReason;
use lore_server::plugins::remote_notification::error::PublishFailure;
use lore_server::plugins::remote_notification::error::TerminalClass;
use lore_server::plugins::remote_notification::error::TransientClass;
use lore_server::plugins::remote_notification::wire;
use serde_json::Value;
use tonic::Status;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("lorehub")
        .join("docs")
        .join("contracts")
        .join("fixtures")
        .join("lore-notification-plane")
}

fn load_fixture(name: &str) -> Value {
    let path = fixture_dir().join(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("required fixture missing or unreadable at {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("fixture {path:?} is not valid JSON: {e}"))
}

/// A scripted [`PublishTransport`]. Each call pops the next scripted answer (repeating the last one
/// once exhausted) and records the envelope it was called with.
#[derive(Debug, Default)]
struct ScriptedTransport {
    calls: AtomicUsize,
    answers: std::sync::Mutex<Vec<TransportAnswer>>,
}

#[derive(Debug, Clone)]
enum TransportAnswer {
    Result(wire::PublishResultV1),
    Status(tonic::Code),
    /// Sleeps this long before answering `Result`. Used for the deadline-clamp proof under a
    /// paused clock.
    DelayedResult(Duration, wire::PublishResultV1),
}

impl ScriptedTransport {
    fn new(answers: Vec<TransportAnswer>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            answers: std::sync::Mutex::new(answers),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PublishTransport for ScriptedTransport {
    async fn publish(
        &self,
        _envelope: wire::PrivateEnvelopeV1,
    ) -> Result<wire::PublishResultV1, tonic::Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = {
            let mut answers = self.answers.lock().expect("scripted answers lock");
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers
                    .first()
                    .cloned()
                    .expect("at least one scripted answer")
            }
        };
        match answer {
            TransportAnswer::Result(result) => Ok(result),
            TransportAnswer::Status(code) => Err(Status::new(code, "scripted failure")),
            TransportAnswer::DelayedResult(delay, result) => {
                tokio::time::sleep(delay).await;
                Ok(result)
            }
        }
    }
}

/// A minimal, valid `[plugins.remote]` config — mirrors `config.rs`'s own `MINIMAL` test fixture,
/// so this file stays in sync with the real parser rather than hand-building a `RemoteNotificationConfig`
/// (whose fields are not all `pub` for construction outside `config.rs`).
fn minimal_config() -> RemoteNotificationConfig {
    let toml_text = r#"
        gateway_uri = "https://gateway.internal:8443"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
        client_cert_path = "/secrets/tls.crt"
        client_key_path = "/secrets/tls.key"
        trust_roots_path = "/secrets/ca.crt"
    "#;
    let table: toml::Value = toml::from_str(toml_text).expect("valid TOML");
    RemoteNotificationConfig::parse(&table).expect("valid minimal config")
}

fn client_with(transport: Arc<ScriptedTransport>) -> PrivateGatewayClient {
    PrivateGatewayClient::with_transport(&minimal_config(), transport)
}

fn repository() -> RepositoryId {
    RepositoryId::from([0x9fu8; 16])
}

fn durable_envelope(event_id: EventId) -> DurableEnvelopeV1 {
    DurableEnvelopeV1 {
        common: EnvelopeCommon {
            cell_id: "sfo3-cell-a".to_string(),
            placement_epoch: 12,
            event_id,
            repository: repository(),
            producer_instance_id: "loreserver-sfo3-cell-a-2".to_string(),
            produced_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
        },
        body: DurableInvalidationBody {
            payload_version: 1,
            idempotency_key: [3u8; 32],
            event_kind: "branch.tip_advanced".to_string(),
            repository_generation: 8814,
            aggregate_kind: "branch".to_string(),
            aggregate_identity: "b1c2d3e4f5061728".to_string(),
            aggregate_version: AggregateVersion {
                ordinal: 417,
                identity: Some("revision:2c9f0a7b4d1e6358a0b1c2d3e4f50617".to_string()),
            },
            payload: Bytes::from_static(b"{}"),
            committed_at: UNIX_EPOCH + Duration::from_secs(1_787_000_000),
            actor: Some("user:0193f2ac-7b41-7c92-a5d1-4e8f0b3c6d27".to_string()),
        },
    }
}

fn accepted_result_for(event_id: EventId) -> wire::PublishResultV1 {
    wire::PublishResultV1 {
        transport_version: wire::TRANSPORT_VERSION,
        outcome: wire::PublishOutcomeV1::Accepted as i32,
        event_id: Bytes::copy_from_slice(event_id.as_bytes()),
        stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        stream_epoch: 8,
        broker_sequence: 918,
        publisher_contract_version: 1,
        broker_accepted_at: None,
        failure_class: 0,
    }
}

#[tokio::test]
async fn a_versioned_complete_acceptance_returns_ok_broker_acceptance() {
    let event_id = EventId::new_v4();
    let transport =
        ScriptedTransport::new(vec![TransportAnswer::Result(accepted_result_for(event_id))]);
    let client = client_with(transport.clone());

    let accepted = client
        .publish_durable_invalidation(&durable_envelope(event_id), Duration::from_secs(2))
        .await
        .expect("expected acceptance");

    assert_eq!(accepted.stream_identity, "DURABLE-sfo3-cell-a");
    assert_eq!(accepted.stream_epoch, 8);
    assert_eq!(accepted.broker_sequence, 918);
    assert_eq!(accepted.publisher_contract_version, 1);
    assert_eq!(accepted.event_id, event_id);
    assert_eq!(
        transport.call_count(),
        1,
        "a single publish_durable_invalidation call must issue exactly one transport request"
    );
}

#[tokio::test]
async fn a_transient_or_terminal_failure_still_issues_exactly_one_request() {
    // "the client makes exactly ONE request per durable publish call (no hidden retry)" — proven
    // for both failure families, not just the accepted path above. CR-032's relay, not this
    // client, owns retry for durable publication.
    for code in [tonic::Code::Unavailable, tonic::Code::InvalidArgument] {
        let event_id = EventId::new_v4();
        let transport = ScriptedTransport::new(vec![TransportAnswer::Status(code)]);
        let client = client_with(transport.clone());

        let outcome = client
            .publish_durable_invalidation(&durable_envelope(event_id), Duration::from_secs(2))
            .await;
        assert!(
            outcome.is_err(),
            "expected {code:?} to classify as a failure"
        );
        assert_eq!(
            transport.call_count(),
            1,
            "no internal retry for {code:?}, even on a retryable classification"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_deadline_above_the_cr_032_maximum_is_clamped_rather_than_honored() {
    // CR-032 caps a relay's publish deadline at 10s (`MAX_DURABLE_PUBLISH_DEADLINE`). Ask for a
    // much larger deadline (1 hour) but have the transport take 11s (a pure timer sleep, not real
    // I/O, so a paused clock is sound here per the fork's own async-test guidance) to answer. If
    // the client actually clamps to 10s, the call must time out before the transport's own delay
    // elapses; if it honored the full hour, it would not.
    assert_eq!(MAX_DURABLE_PUBLISH_DEADLINE, Duration::from_secs(10));

    let event_id = EventId::new_v4();
    let transport = ScriptedTransport::new(vec![TransportAnswer::DelayedResult(
        Duration::from_secs(11),
        accepted_result_for(event_id),
    )]);
    let client = client_with(transport.clone());
    let envelope = durable_envelope(event_id);

    // No manual `tokio::time::advance` needed: under `start_paused = true`, awaiting this future
    // directly auto-advances the virtual clock to the earliest pending timer once nothing else is
    // runnable — here that is the client's own clamped 10s timeout, registered before the
    // transport's 11s sleep ever elapses. Same pattern as `drain.rs`'s
    // `run_drain_bounded_mode_returns_at_deadline_with_connection_still_active`.
    let outcome = client
        .publish_durable_invalidation(&envelope, Duration::from_secs(3600))
        .await;
    assert_eq!(
        outcome,
        Err(PublishFailure::Transient(TransientClass::Timeout)),
        "a deadline above 10s must be clamped to 10s, not honored as requested"
    );
}

/// Builds a `PublishResultV1`/`tonic::Status` scripted answer plus the expected `PublishFailure`
/// (or `Ok`) from a `publish-result.json` "results" vector, for the subset this file exercises
/// end-to-end. Only entries with a stable, reproducible shape are included; the stale-claim-
/// generation and epoch-reset vectors describe relay-side bookkeeping this client has no part in.
fn expected_outcome_for_result_vector(id: &str) -> Result<(), PublishFailure> {
    match id {
        "accepted" | "accepted-duplicate-same-keys" => Ok(()),
        "retryable-broker-unavailable" => {
            Err(PublishFailure::Transient(TransientClass::BrokerUnavailable))
        }
        "retryable-placement-quiescing" => Err(PublishFailure::Transient(
            TransientClass::PlacementQuiescing,
        )),
        "retryable-discard-new-rejected" => {
            Err(PublishFailure::Transient(TransientClass::StreamFull))
        }
        "retryable-timeout-outcome-unknown" => {
            Err(PublishFailure::Transient(TransientClass::Timeout))
        }
        "terminal-scope-mismatch" => Err(PublishFailure::Terminal(TerminalClass::ScopeMismatch)),
        "terminal-unsupported-producer-schema" => {
            Err(PublishFailure::Terminal(TerminalClass::UnsupportedSchema))
        }
        "unversioned-or-unrecognized-response" => Err(PublishFailure::NotAccepted(
            NotAcceptedReason::UnversionedResponse,
        )),
        other => panic!("no expected-outcome mapping for publish-result.json vector {other:?}"),
    }
}

/// Builds the scripted transport answer for one of the vectors `expected_outcome_for_result_vector`
/// covers, using `event_id` so an accepted case's echoed id matches the claim.
fn transport_answer_for_result_vector(id: &str, event_id: EventId) -> TransportAnswer {
    match id {
        "accepted" | "accepted-duplicate-same-keys" => {
            TransportAnswer::Result(accepted_result_for(event_id))
        }
        "retryable-broker-unavailable" => TransportAnswer::Status(tonic::Code::Unavailable),
        "retryable-placement-quiescing" => TransportAnswer::Status(tonic::Code::FailedPrecondition),
        "retryable-discard-new-rejected" => TransportAnswer::Result(wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Retryable as i32,
            failure_class: wire::PublishFailureClassV1::StreamFull as i32,
            ..accepted_result_for(event_id)
        }),
        "retryable-timeout-outcome-unknown" => TransportAnswer::Result(wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Timeout as i32,
            ..accepted_result_for(event_id)
        }),
        "terminal-scope-mismatch" => TransportAnswer::Result(wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Terminal as i32,
            failure_class: wire::PublishFailureClassV1::ScopeMismatch as i32,
            ..accepted_result_for(event_id)
        }),
        "terminal-unsupported-producer-schema" => TransportAnswer::Result(wire::PublishResultV1 {
            transport_version: wire::TRANSPORT_VERSION,
            outcome: wire::PublishOutcomeV1::Terminal as i32,
            failure_class: wire::PublishFailureClassV1::UnsupportedSchema as i32,
            ..accepted_result_for(event_id)
        }),
        "unversioned-or-unrecognized-response" => TransportAnswer::Result(wire::PublishResultV1 {
            transport_version: 0,
            ..accepted_result_for(event_id)
        }),
        other => panic!("no scripted-answer mapping for publish-result.json vector {other:?}"),
    }
}

#[tokio::test]
async fn publish_result_fixture_vectors_classify_end_to_end_through_the_real_client() {
    let fixture = load_fixture("publish-result.json");
    let results = fixture["results"].as_array().expect("results is an array");

    let covered_ids = [
        "accepted",
        "accepted-duplicate-same-keys",
        "retryable-broker-unavailable",
        "retryable-placement-quiescing",
        "retryable-discard-new-rejected",
        "retryable-timeout-outcome-unknown",
        "terminal-scope-mismatch",
        "terminal-unsupported-producer-schema",
        "unversioned-or-unrecognized-response",
    ];
    for id in covered_ids {
        assert!(
            results.iter().any(|r| r["id"] == id),
            "publish-result.json must still contain vector {id:?} this file maps"
        );
    }

    for id in covered_ids {
        let event_id = EventId::new_v4();
        let transport =
            ScriptedTransport::new(vec![transport_answer_for_result_vector(id, event_id)]);
        let client = client_with(transport);

        let outcome = client
            .publish_durable_invalidation(&durable_envelope(event_id), Duration::from_secs(2))
            .await;

        match expected_outcome_for_result_vector(id) {
            Ok(()) => {
                let accepted: BrokerAcceptance =
                    outcome.unwrap_or_else(|e| panic!("case {id}: expected acceptance, got {e}"));
                assert_eq!(accepted.event_id, event_id, "case {id}");
            }
            Err(expected_failure) => {
                let failure = outcome.expect_err(&format!("case {id}: expected a failure"));
                assert_eq!(failure, expected_failure, "case {id}");
            }
        }
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Conformance tests for CR-027 / WP-111 Phases 1-2 (the remote notification plugin's private
//! envelope mapping and Publish-result wire shape), pinned against the reviewed-not-signed-off
//! notification-plane fixtures in
//! `lorehub/docs/contracts/fixtures/lore-notification-plane/{private-envelope,publish-result}.json`.
//!
//! Contract: `lorehub/docs/contracts/lore-notification-plane.md` ("Private envelope version 1",
//! "Publication and delivery semantics"). CR: `lorehub/docs/lore-change-requests/cr-027-remote-notification-plugin.md`.
//!
//! # Scope
//!
//! Only LIVE_HINT and DURABLE_INVALIDATION envelope encoding through the real
//! `envelope::HintEnvelopeV1::encode`/`envelope::DurableEnvelopeV1::encode`, and the accepted
//! Publish-result wire shape. SHADOW_OBSERVATION is out of WP-111 Phase 1-2 scope. Most of the
//! fixture's `invalid` vectors are already covered by `envelope.rs`'s own unit tests
//! (`EnvelopeViolation` cases for cell id, zero repository, event-id/idempotency-key width,
//! class/body mismatch, transport version, width bounds); this file does not duplicate those.
//! What's left out here specifically: several invalid vectors
//! (`envelope-cell-differs-from-mtls-cell`, `wildcard-subject`, `stale-placement-epoch`, ...) are
//! gateway-side Publish rejections our client only ever observes as a `PublishFailure` outcome,
//! never a pre-flight `EnvelopeViolation` — that classification is
//! `remote_notification_durable_publish.rs`'s job, driven off `publish-result.json`.
//!
//! Per the fixture's own `encoding_note`, these are semantic vectors, not wire bytes. This file
//! checks that the real mapping produces a wire envelope with the fixture's field values and that
//! it round-trips through protobuf, not that a fixture byte string matches an encoder's output byte
//! for byte.
//!
//! # Fixture resolution: standalone checkout vs. fixture drift
//!
//! `lorehub` is a sibling checkout of this repo's own `lorehub-all` container, and is always
//! present in our workspace. If it is absent entirely (a standalone checkout of just this repo,
//! e.g. an upstream contributor's clone), these tests print one loud notice and skip -- see
//! `common/fixture_resolution.rs`. If the sibling repo IS present but a named fixture file under
//! it is missing or unreadable, that is fixture drift in OUR OWN workspace and every such test
//! MUST FAIL, never silently pass or skip -- the sibling is always present here, so this is the
//! only branch this workspace's own CI can ever actually take.

#[path = "common/fixture_resolution.rs"]
mod fixture_resolution;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use lore_base::types::RepositoryId;
use lore_proto::lore::notification::BranchPushed;
use lore_proto::lore::notification::Event as LoreEvent;
use lore_proto::lore::notification::event::Event as LoreEventPayload;
use lore_server::plugins::remote_notification::envelope::AggregateVersion;
use lore_server::plugins::remote_notification::envelope::DurableEnvelopeV1;
use lore_server::plugins::remote_notification::envelope::DurableInvalidationBody;
use lore_server::plugins::remote_notification::envelope::EnvelopeCommon;
use lore_server::plugins::remote_notification::envelope::EventId;
use lore_server::plugins::remote_notification::envelope::HintEnvelopeV1;
use lore_server::plugins::remote_notification::wire;
use prost::Message;
use serde_json::Value;

/// Loads and parses a fixture file for `test_name`. Returns `None` (after printing a loud skip
/// notice) when this is a standalone checkout with no sibling `lorehub` repo at all. Otherwise
/// panics (fails the test) rather than returning `None` on a missing/unreadable file or invalid
/// JSON, per the "must FAIL, not skip" requirement for fixture drift within an existing sibling —
/// a silent skip there would report every downstream test's assertions as vacuously true.
fn load_fixture(test_name: &str, name: &str) -> Option<Value> {
    let dir = match fixture_resolution::resolve_fixture_set_dir() {
        fixture_resolution::FixtureSetLocation::Directory(dir) => dir,
        fixture_resolution::FixtureSetLocation::Standalone { searched } => {
            fixture_resolution::print_standalone_skip_notice(test_name, &searched);
            return None;
        }
    };
    let path = dir.join(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("required fixture missing or unreadable at {path:?}: {e}"));
    Some(
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("fixture {path:?} is not valid JSON: {e}")),
    )
}

fn hex_to_array<const N: usize>(hex: &str, field: &str) -> [u8; N] {
    let decoded = hex::decode(hex).unwrap_or_else(|e| panic!("{field} must be valid hex: {e}"));
    decoded.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("{field} must be exactly {N} raw bytes, got {}", v.len())
    })
}

fn parse_system_time(s: &str) -> SystemTime {
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("fixture timestamp {s:?} must be RFC 3339: {e}"));
    UNIX_EPOCH
        + Duration::from_millis(u64::try_from(dt.timestamp_millis()).expect("positive epoch"))
}

fn repository_from_hex(hex: &str) -> RepositoryId {
    RepositoryId::from(hex_to_array::<16>(hex, "repository_hex"))
}

/// Builds `EnvelopeCommon` from a fixture `envelope` object shared by every delivery class.
fn common_from_fixture(envelope: &Value) -> EnvelopeCommon {
    assert_eq!(
        envelope["transport_version"].as_u64(),
        Some(1),
        "fixture common fields carry transport_version 1"
    );
    EnvelopeCommon {
        cell_id: envelope["cell_id"]
            .as_str()
            .expect("cell_id present")
            .to_string(),
        placement_epoch: envelope["placement_epoch"]
            .as_str()
            .expect("placement_epoch present as string")
            .parse()
            .expect("placement_epoch parses as u64"),
        event_id: EventId::from_bytes(hex_to_array::<16>(
            &envelope["event_id"]
                .as_str()
                .expect("event_id present")
                .replace('-', ""),
            "event_id",
        )),
        repository: repository_from_hex(
            envelope["repository_hex"]
                .as_str()
                .expect("repository_hex present"),
        ),
        producer_instance_id: envelope["producer_instance_id"]
            .as_str()
            .expect("producer_instance_id present")
            .to_string(),
        produced_at: parse_system_time(
            envelope["produced_at"]
                .as_str()
                .expect("produced_at present"),
        ),
    }
}

/// Builds the real public `lore.notification.Event` a `live-hint-*` fixture vector's `lore_event`
/// field describes. Every fixture `lore_event` in this contract is a `BranchPushed` payload today;
/// extend the match once other Lore event variants appear in the fixture set.
fn lore_event_from_fixture(lore_event: &Value, repository: RepositoryId) -> LoreEvent {
    assert_eq!(
        lore_event["message"], "lore.notification.Event",
        "fixture lore_event.message must name the real public proto message"
    );
    let id = lore_event["id"].as_str().expect("lore_event.id present");
    let repo_bytes = Bytes::copy_from_slice(repository.data());
    let payload = match lore_event["event"].as_str() {
        Some("branch_pushed") => LoreEventPayload::BranchPushed(BranchPushed {
            revision: Bytes::from_static(&[0u8; 32]),
            revision_number: 1,
            branch: repo_bytes.clone(),
            user_id: "conformance-fixture-user".to_string(),
        }),
        other => panic!("unmodelled fixture lore_event.event variant: {other:?}"),
    };
    LoreEvent {
        id: id.to_string(),
        time: None,
        repository: repo_bytes,
        event: Some(payload),
    }
}

fn durable_body_from_fixture(body: &Value) -> DurableInvalidationBody {
    DurableInvalidationBody {
        payload_version: body["payload_version"].as_u64().expect("payload_version") as u32,
        idempotency_key: hex_to_array::<32>(
            body["idempotency_key_hex"]
                .as_str()
                .expect("idempotency_key_hex present"),
            "idempotency_key_hex",
        ),
        event_kind: body["event_kind"]
            .as_str()
            .expect("event_kind present")
            .to_string(),
        repository_generation: body["repository_generation"]
            .as_str()
            .expect("repository_generation present as string")
            .parse()
            .expect("repository_generation parses as u64"),
        aggregate_kind: body["aggregate_kind"]
            .as_str()
            .expect("aggregate_kind present")
            .to_string(),
        aggregate_identity: body["aggregate_identity"]
            .as_str()
            .expect("aggregate_identity present")
            .to_string(),
        aggregate_version: AggregateVersion {
            ordinal: body["aggregate_version"]["ordinal"]
                .as_str()
                .expect("aggregate_version.ordinal present as string")
                .parse()
                .expect("aggregate_version.ordinal parses as u64"),
            identity: body["aggregate_version"]["identity"]
                .as_str()
                .map(str::to_string),
        },
        payload: Bytes::from(serde_json::to_vec(&body["payload"]).expect("payload re-serializes")),
        committed_at: parse_system_time(
            body["committed_at"].as_str().expect("committed_at present"),
        ),
        actor: body["actor"].as_str().map(str::to_string),
    }
}

/// Every `valid` fixture vector whose `delivery_class` is `LIVE_HINT`. `None` means this is a
/// standalone checkout and `test_name` has already had its skip notice printed.
fn valid_live_hint_vectors(test_name: &str) -> Option<Vec<Value>> {
    let fixture = load_fixture(test_name, "private-envelope.json")?;
    Some(
        fixture["valid"]
            .as_array()
            .expect("valid is an array")
            .iter()
            .filter(|v| v["delivery_class"] == "LIVE_HINT")
            .cloned()
            .collect(),
    )
}

/// Every `valid` fixture vector whose `delivery_class` is `DURABLE_INVALIDATION`. `None` means
/// this is a standalone checkout and `test_name` has already had its skip notice printed.
fn valid_durable_vectors(test_name: &str) -> Option<Vec<Value>> {
    let fixture = load_fixture(test_name, "private-envelope.json")?;
    Some(
        fixture["valid"]
            .as_array()
            .expect("valid is an array")
            .iter()
            .filter(|v| v["delivery_class"] == "DURABLE_INVALIDATION")
            .cloned()
            .collect(),
    )
}

#[test]
fn private_envelope_fixture_has_the_expected_live_hint_and_durable_vectors() {
    let test_name = "remote_notification_conformance::private_envelope_fixture_has_the_expected_live_hint_and_durable_vectors";
    // A guard against a future fixture edit silently dropping the two classes this file exercises
    // — a regression here would otherwise show up only as "0 cases" inside the loops below, which
    // `cargo test`'s summary reports identically to "every case passed".
    let Some(live_hints) = valid_live_hint_vectors(test_name) else {
        return;
    };
    let durables = valid_durable_vectors(test_name)
        .expect("sibling lorehub already confirmed present by the live-hint load above");
    assert!(
        !live_hints.is_empty(),
        "expected at least one LIVE_HINT vector in private-envelope.json"
    );
    assert!(
        !durables.is_empty(),
        "expected at least one DURABLE_INVALIDATION vector in private-envelope.json"
    );
}

#[test]
fn live_hint_envelope_mapping_matches_every_valid_fixture_vector() {
    let Some(vectors) = valid_live_hint_vectors(
        "remote_notification_conformance::live_hint_envelope_mapping_matches_every_valid_fixture_vector",
    ) else {
        return;
    };
    for vector in vectors {
        let id = vector["id"].as_str().unwrap_or("<unnamed>").to_string();
        let envelope_json = &vector["envelope"];
        let common = common_from_fixture(envelope_json);
        let lore_event = lore_event_from_fixture(&envelope_json["lore_event"], common.repository);

        let hint = HintEnvelopeV1 {
            common: common.clone(),
            shadow: false,
            lore_event: lore_event.clone(),
        };

        assert_eq!(
            hint.subject(),
            vector["subject"].as_str().expect("fixture subject present"),
            "case {id}: subject must match the fixture's exact-repository subject"
        );

        let encoded = hint
            .encode()
            .unwrap_or_else(|e| panic!("case {id}: expected a valid live hint, got {e}"));

        assert_eq!(
            encoded.transport_version,
            wire::TRANSPORT_VERSION,
            "case {id}"
        );
        assert_eq!(
            encoded.delivery_class,
            wire::DeliveryClassV1::LiveHint as i32,
            "case {id}"
        );
        assert_eq!(encoded.cell_id, common.cell_id, "case {id}");
        assert_eq!(
            encoded.event_id.as_ref(),
            common.event_id.as_bytes().as_slice(),
            "case {id}: the stable event id must be carried through unchanged"
        );
        assert_eq!(
            encoded.repository.as_ref(),
            common.repository.data().as_slice(),
            "case {id}"
        );

        // Round-trip through real protobuf encode/decode.
        let decoded = wire::PrivateEnvelopeV1::decode(wire::encode(&encoded))
            .unwrap_or_else(|e| panic!("case {id}: envelope must decode: {e}"));
        assert_eq!(
            encoded, decoded,
            "case {id}: envelope must round-trip unchanged"
        );
    }
}

#[test]
fn durable_invalidation_envelope_mapping_matches_every_valid_fixture_vector() {
    let Some(vectors) = valid_durable_vectors(
        "remote_notification_conformance::durable_invalidation_envelope_mapping_matches_every_valid_fixture_vector",
    ) else {
        return;
    };
    for vector in vectors {
        let id = vector["id"].as_str().unwrap_or("<unnamed>").to_string();
        let envelope_json = &vector["envelope"];
        let common = common_from_fixture(envelope_json);
        let body = durable_body_from_fixture(&envelope_json["body"]);

        let durable = DurableEnvelopeV1 {
            common: common.clone(),
            body: body.clone(),
        };

        assert_eq!(
            durable.subject(),
            vector["subject"].as_str().expect("fixture subject present"),
            "case {id}"
        );

        let encoded = durable
            .encode(1..=1)
            .unwrap_or_else(|e| panic!("case {id}: expected a valid durable envelope, got {e}"));

        assert_eq!(
            encoded.transport_version,
            wire::TRANSPORT_VERSION,
            "case {id}"
        );
        assert_eq!(
            encoded.delivery_class,
            wire::DeliveryClassV1::DurableInvalidation as i32,
            "case {id}"
        );

        let wire::private_envelope_v1::Body::DurableInvalidation(wire_body) =
            encoded.body.clone().expect("durable body present")
        else {
            panic!("case {id}: expected a DurableInvalidation body");
        };
        assert_eq!(
            wire_body.payload_version,
            wire::DURABLE_PAYLOAD_VERSION,
            "case {id}"
        );
        assert_eq!(wire_body.event_kind, body.event_kind, "case {id}");
        assert_eq!(
            wire_body
                .aggregate_version
                .expect("aggregate_version present")
                .ordinal,
            body.aggregate_version.ordinal,
            "case {id}"
        );

        // `durable-invalidation-no-actor` is the fixture's explicit proof that `actor` is optional.
        if id == "durable-invalidation-no-actor" {
            assert!(
                body.actor.is_none(),
                "case {id}: source actor must be absent"
            );
            assert!(
                wire_body.actor.is_empty(),
                "case {id}: encoded actor must be empty"
            );
        }
        if id == "durable-invalidation-branch-tip" {
            assert!(
                body.actor.is_some(),
                "case {id}: source actor must be present"
            );
            assert!(
                !wire_body.actor.is_empty(),
                "case {id}: encoded actor must be non-empty"
            );
        }

        let decoded = wire::PrivateEnvelopeV1::decode(wire::encode(&encoded))
            .unwrap_or_else(|e| panic!("case {id}: envelope must decode: {e}"));
        assert_eq!(
            encoded, decoded,
            "case {id}: envelope must round-trip unchanged"
        );
    }
}

#[test]
fn durable_invalidation_max_payload_vector_encodes_within_the_derived_envelope_ceiling() {
    // `durable-invalidation-max-payload` is the fixture's own worst-case proof: every variable-
    // width field at its maximum plus a 64 KiB payload must still fit the 80 KiB durable envelope
    // cap. `envelope.rs`'s own `a_maximal_durable_envelope_is_still_transportable` already proves
    // this against hand-built maximal-width data; this test proves the SAME real `encode()` path
    // accepts the fixture's specific worst-case vector, not just an independently-constructed one.
    let Some(fixture) = load_fixture(
        "remote_notification_conformance::durable_invalidation_max_payload_vector_encodes_within_the_derived_envelope_ceiling",
        "private-envelope.json",
    ) else {
        return;
    };
    let vector = fixture["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "durable-invalidation-max-payload")
        .expect("durable-invalidation-max-payload vector present");
    let envelope_json = &vector["envelope"];

    let declared_payload_bytes = vector["declared_sizes"]["payload_bytes"].as_u64().unwrap();
    assert_eq!(declared_payload_bytes, 65536);

    let common = common_from_fixture(envelope_json);
    let mut body = durable_body_from_fixture(&envelope_json["body"]);
    // The fixture's payload field is a placeholder string, not real 64 KiB content — build an
    // actual 65536-byte payload to exercise the real cap the way a maximal production payload
    // would, while keeping every other field exactly as the fixture declares it.
    body.payload = Bytes::from(vec![0u8; declared_payload_bytes as usize]);

    let encoded = DurableEnvelopeV1 { common, body }
        .encode(1..=1)
        .expect("the fixture's worst-case vector must be accepted");

    let cap = fixture["bounds"]["durable_envelope_max_bytes"]
        .as_u64()
        .unwrap() as usize;
    let asserted_ceiling = vector["declared_sizes"]["asserted_envelope_ceiling_bytes"]
        .as_u64()
        .unwrap() as usize;
    assert!(
        encoded.encoded_len() <= cap,
        "real encoded worst-case envelope ({} bytes) must stay within the durable envelope cap ({cap} bytes)",
        encoded.encoded_len()
    );
    assert!(
        encoded.encoded_len() <= asserted_ceiling,
        "real encoded length ({} bytes) must not exceed the fixture's own asserted ceiling ({asserted_ceiling} bytes)",
        encoded.encoded_len()
    );
}

/// Every `publish-result.json` entry whose `result.outcome` is `ACCEPTED` with a real
/// `transport_version` — the only shape allowed to prove broker acceptance. `None` means this is
/// a standalone checkout and `test_name` has already had its skip notice printed.
fn accepted_result_vectors(test_name: &str) -> Option<Vec<Value>> {
    let fixture = load_fixture(test_name, "publish-result.json")?;
    Some(
        fixture["results"]
            .as_array()
            .expect("results is an array")
            .iter()
            .filter(|entry| {
                entry["result"]["outcome"] == "ACCEPTED"
                    && entry["result"]["transport_version"] == 1
            })
            .cloned()
            .collect(),
    )
}

#[test]
fn accepted_publish_result_fixture_decodes_into_the_wire_type_with_every_acceptance_field() {
    let Some(vectors) = accepted_result_vectors(
        "remote_notification_conformance::accepted_publish_result_fixture_decodes_into_the_wire_type_with_every_acceptance_field",
    ) else {
        return;
    };
    assert!(
        !vectors.is_empty(),
        "expected at least one versioned ACCEPTED result in publish-result.json"
    );

    for vector in vectors {
        let id = vector["id"].as_str().unwrap_or("<unnamed>").to_string();
        let result = &vector["result"];

        let decoded = wire::PublishResultV1 {
            transport_version: result["transport_version"].as_u64().unwrap() as u32,
            outcome: wire::PublishOutcomeV1::Accepted as i32,
            event_id: Bytes::copy_from_slice(&hex_to_array::<16>(
                &result["event_id"]
                    .as_str()
                    .expect("event_id present")
                    .replace('-', ""),
                "event_id",
            )),
            stream_identity: result["stream_identity"]
                .as_str()
                .expect("stream_identity present")
                .to_string(),
            stream_epoch: result["stream_epoch"]
                .as_str()
                .expect("stream_epoch present as string")
                .parse()
                .expect("stream_epoch parses as u64"),
            broker_sequence: result["broker_sequence"]
                .as_str()
                .expect("broker_sequence present as string")
                .parse()
                .expect("broker_sequence parses as u64"),
            publisher_contract_version: result["publisher_contract_version"].as_u64().unwrap()
                as u32,
            broker_accepted_at: result["broker_accepted_at"].as_str().map(|s| {
                let system_time = parse_system_time(s);
                prost_types::Timestamp::from(system_time)
            }),
            failure_class: wire::PublishFailureClassV1::Unspecified as i32,
        };

        assert_eq!(
            decoded.transport_version,
            wire::TRANSPORT_VERSION,
            "case {id}"
        );
        assert_eq!(decoded.publisher_contract_version, 1, "case {id}");
        assert!(
            !decoded.stream_identity.is_empty(),
            "case {id}: stream_identity must be present"
        );
        let round_tripped = wire::PublishResultV1::decode(wire::encode(&decoded))
            .unwrap_or_else(|e| panic!("case {id}: result must decode: {e}"));
        assert_eq!(decoded, round_tripped, "case {id}");
    }
}

#[test]
fn unversioned_accepted_result_is_never_treated_as_a_valid_acceptance() {
    // publish-result.json's own invariant: a response that does not prove broker acceptance under
    // the pinned event-plane version must be treated as not-accepted. Assert the fixture vector
    // itself is excluded from `accepted_result_vectors` (i.e. this file's own filter honors that
    // rule), which is what the real client's classification path (tested in
    // remote_notification_durable_publish.rs) must also do.
    let test_name = "remote_notification_conformance::unversioned_accepted_result_is_never_treated_as_a_valid_acceptance";
    let Some(fixture) = load_fixture(test_name, "publish-result.json") else {
        return;
    };
    let unversioned = fixture["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == "unversioned-or-unrecognized-response")
        .expect("unversioned-or-unrecognized-response vector present");

    assert!(unversioned["result"]["transport_version"].is_null());
    let vectors = accepted_result_vectors(test_name)
        .expect("sibling lorehub already confirmed present by the load above");
    assert!(
        vectors
            .iter()
            .all(|v| v["id"] != "unversioned-or-unrecognized-response"),
        "an unversioned response must never be treated as a valid acceptance source"
    );
}

// ---------------------------------------------------------------------------
// fixture_resolution::resolve_from proof -- executed, not merely inspected.
// Deliberately NOT #[cfg(test)]: this file is compiled as an integration-test
// binary, so cfg(test) is never set here and a #[cfg(test)] mod would compile
// out silently, which is exactly the vacuous-pass shape this whole
// fixture-resolution change exists to avoid. Collected once, in this one
// consuming binary, rather than once per file that includes the module.
// ---------------------------------------------------------------------------

/// A fresh, empty, uniquely-named directory under the OS temp dir, removed when the guard drops.
/// Deliberately hand-rolled rather than adding a `tempfile` dev-dependency just for this proof.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lore-fixture-resolution-test-{label}-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create scratch dir for fixture_resolution proof");
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.clone()
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn resolve_from_reports_standalone_when_the_lorehub_root_does_not_exist() {
    let parent = ScratchDir::new("standalone-parent");
    let missing_lorehub_root = parent.path().join("lorehub-does-not-exist");
    match fixture_resolution::resolve_from(None, missing_lorehub_root.clone()) {
        fixture_resolution::FixtureSetLocation::Standalone { searched } => {
            assert_eq!(searched, missing_lorehub_root);
        }
        fixture_resolution::FixtureSetLocation::Directory(dir) => {
            panic!("expected Standalone for a nonexistent lorehub root, got Directory({dir:?})");
        }
    }
}

#[test]
fn resolve_from_finds_the_fixture_directory_shape_even_when_the_fixture_directory_itself_is_absent()
{
    // The discrimination that matters: an EXISTING sibling `lorehub` repo root with no
    // `docs/contracts/fixtures/lore-notification-plane` beneath it must still resolve to
    // `Directory`, never `Standalone` -- that absence is fixture drift in an existing sibling,
    // which the caller must panic on, not silently skip.
    let lorehub_root = ScratchDir::new("existing-lorehub-root");
    match fixture_resolution::resolve_from(None, lorehub_root.path()) {
        fixture_resolution::FixtureSetLocation::Directory(dir) => {
            let expected_suffix = PathBuf::from("docs")
                .join("contracts")
                .join("fixtures")
                .join("lore-notification-plane");
            assert!(
                dir.ends_with(&expected_suffix),
                "expected the fixture-set path shape ending in {expected_suffix:?}, got {dir:?}"
            );
            assert!(
                !dir.is_dir(),
                "this test's premise is that the fixture directory does NOT exist yet"
            );
        }
        fixture_resolution::FixtureSetLocation::Standalone { searched } => {
            panic!(
                "an existing sibling lorehub root must never resolve to Standalone, even with no \
                 fixtures beneath it; wrongly searched {searched:?}"
            );
        }
    }
}

#[test]
fn resolve_from_prefers_an_existing_override_directory_over_a_standalone_lorehub_root() {
    let overridden = ScratchDir::new("override-dir");
    let missing_lorehub_root = overridden.path().join("never-created-lorehub");
    match fixture_resolution::resolve_from(Some(overridden.path()), missing_lorehub_root) {
        fixture_resolution::FixtureSetLocation::Directory(dir) => {
            assert_eq!(dir, overridden.path());
        }
        fixture_resolution::FixtureSetLocation::Standalone { searched } => {
            panic!(
                "an existing override directory must win over a standalone lorehub root; \
                 wrongly reported Standalone searching {searched:?}"
            );
        }
    }
}

#[test]
#[should_panic(expected = "is not a directory")]
fn resolve_from_panics_when_the_override_directory_does_not_exist() {
    let parent = ScratchDir::new("panic-probe-parent");
    let nonexistent_override = parent.path().join("does-not-exist");
    let _ = fixture_resolution::resolve_from(Some(nonexistent_override), parent.path());
}
